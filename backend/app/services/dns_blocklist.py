"""Service layer for DNS blocking lists.

Produces a backend-neutral representation (`EffectiveBlocklist`) of the set of
blocked domains + exceptions that apply to a given DNS view or server group.
The DNS driver layer (BIND9 RPZ emitter Lua emitter, etc.) consumes
this structure to generate actual server config.

Driver-abstraction rule (CLAUDE.md #10): no BIND9 specifics live in
this module.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import case, exists, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.dns import (
    DNSBlockList,
    DNSBlockListEntry,
    DNSBlockListException,
    DNSServerGroup,
    DNSView,
)

# Feed parsing lives in a dependency-free module (#3522) so the monthly
# catalog check can load the same parser without the app; re-exported here
# for the callers that import it from this module.
from app.services.dns_blocklist_parse import (  # noqa: F401
    FeedSkipCounts,
    ParsedFeed,
    dedupe_domains,
    looks_like_html,
    parse_feed,
    parse_feed_detailed,
)

__all__ = [
    "EffectiveBlocklist",
    "EffectiveEntry",
    "FeedSkipCounts",
    "ParsedFeed",
    "build_effective_for_group",
    "build_effective_for_view",
    "dedupe_domains",
    "effective_lists_for_group",
    "effective_lists_for_view",
    "exception_domains",
    "has_entries",
    "parse_feed",
    "looks_like_html",
    "parse_feed_detailed",
    "stream_entries",
]


@dataclass(frozen=True, slots=True)
class EffectiveEntry:
    """Backend-neutral representation of a blocked domain entry."""

    domain: str
    # action: block | redirect | nxdomain
    action: str
    # block_mode inherited from the list: nxdomain | sinkhole
    block_mode: str
    sinkhole_ip: str | None
    target: str | None
    is_wildcard: bool
    list_id: uuid.UUID
    list_name: str


@dataclass
class EffectiveBlocklist:
    """The set of effective entries and exceptions for a given scope.

    The driver iterates `entries`, skipping any domain in `exceptions`.
    """

    scope: str  # "view" | "group"
    scope_id: uuid.UUID
    entries: list[EffectiveEntry] = field(default_factory=list)
    exceptions: set[str] = field(default_factory=set)
    lists: list[uuid.UUID] = field(default_factory=list)


def _entry_rows(list_id: uuid.UUID) -> Any:
    """One list's entries as column rows, in ``domain`` order (see below)."""
    return (
        select(
            DNSBlockListEntry.domain,
            DNSBlockListEntry.entry_type,
            DNSBlockListEntry.target,
            DNSBlockListEntry.is_wildcard,
        )
        .where(DNSBlockListEntry.list_id == list_id)
        .order_by(DNSBlockListEntry.domain)
    )


#: Rows fetched per round trip by ``_collect_lists``'s single cursor.
_COLLECT_BATCH = 10_000


async def _collect_lists(
    db: AsyncSession, lists: list[DNSBlockList]
) -> tuple[list[EffectiveEntry], set[str], list[uuid.UUID]]:
    enabled = _enabled(lists)
    list_ids = [bl.id for bl in enabled]

    # Column rows, not ORM entities (#1109, the #948 pattern): a Family
    # filter profile is ~596k entries, and hydrating each into a tracked
    # DNSBlockListEntry on every bundle build is the cost #948 removed for
    # records. ONE query across every enabled list (``list_id IN (...)``)
    # rather than one per list (a server-side cursor, so the driver never buffers
    # more than a batch of rows), so the statement count does not follow the
    # number of lists. The rows come back in ``(list_id, domain)`` order, which
    # the ``(list_id, domain)`` unique index serves without a sort; they are
    # bucketed per list and emitted in the CALLER's list order, because that
    # order decides which list wins a duplicate owner name (#878). Within a
    # list the ``domain`` order keeps the bundle, and its ETag, stable between
    # builds instead of following the heap order; ``domain`` is unique per
    # list, so the order is total.
    #
    # Each row carries its list's POSITION in the caller's order (a small int
    # the database computes) rather than its ``list_id``: a UUID object per
    # row is ~200k allocations on a Family-filter-sized profile.
    by_list: list[list[EffectiveEntry]] = [[] for _ in enabled]
    if enabled:
        position = case(
            {bl.id: i for i, bl in enumerate(enabled)}, value=DNSBlockListEntry.list_id
        ).label("position")
        result = await db.stream(
            select(
                position,
                DNSBlockListEntry.domain,
                DNSBlockListEntry.entry_type,
                DNSBlockListEntry.target,
                DNSBlockListEntry.is_wildcard,
            )
            .where(DNSBlockListEntry.list_id.in_(list_ids))
            .order_by(DNSBlockListEntry.list_id, DNSBlockListEntry.domain)
            .execution_options(yield_per=_COLLECT_BATCH)
        )
        try:
            async for rows in result.partitions():
                for pos, domain, entry_type, target, is_wildcard in rows:
                    bl = enabled[pos]
                    by_list[pos].append(
                        EffectiveEntry(
                            domain=domain.lower(),
                            action=entry_type,
                            block_mode=bl.block_mode,
                            sinkhole_ip=bl.sinkhole_ip,
                            target=target,
                            is_wildcard=is_wildcard,
                            list_id=bl.id,
                            list_name=bl.name,
                        )
                    )
        finally:
            await result.close()

    entries: list[EffectiveEntry] = []
    for bucket in by_list:
        entries.extend(bucket)

    exceptions = await exception_domains(db, lists)
    return entries, exceptions, list_ids


def _stable_list_order(lists: list[DNSBlockList]) -> list[DNSBlockList]:
    """Order lists deterministically, by their (unique) name.

    The ``blocklists`` relationships carry no ``order_by``, so they arrive in
    whatever order Postgres returns the association rows. The list order
    decides which list wins a duplicate owner name (#878) and feeds the
    bundle's ETag, so leaving it to the heap made both flap between builds.
    ``name`` rather than ``created_at`` because it is always set client-side:
    a server default can be expired on a just-flushed row, and touching it
    would lazy-load inside the async session.
    """
    return sorted(lists, key=lambda bl: bl.name)


async def effective_lists_for_view(
    db: AsyncSession, view_id: uuid.UUID
) -> list[DNSBlockList] | None:
    """The lists a view's RPZ zone draws on, in the order that decides a
    duplicate owner name: the view's own, then its group's. ``None`` when
    the view does not exist."""
    view = (
        await db.execute(
            select(DNSView)
            .where(DNSView.id == view_id)
            .options(
                selectinload(DNSView.blocklists),
                selectinload(DNSView.group).selectinload(DNSServerGroup.blocklists),
            )
        )
    ).scalar_one_or_none()

    if view is None:
        return None

    # View-scoped lists precede the group's, so a view's own list wins a
    # duplicate owner name; each tier is in a stable order of its own.
    combined = {bl.id: bl for bl in _stable_list_order(list(view.blocklists))}
    if view.group is not None:
        for bl in _stable_list_order(list(view.group.blocklists)):
            combined.setdefault(bl.id, bl)
    return list(combined.values())


async def effective_lists_for_group(
    db: AsyncSession, group_id: uuid.UUID
) -> list[DNSBlockList] | None:
    """The lists a server group's RPZ zone draws on, in a stable order.
    ``None`` when the group does not exist."""
    group = (
        await db.execute(
            select(DNSServerGroup)
            .where(DNSServerGroup.id == group_id)
            .options(selectinload(DNSServerGroup.blocklists))
        )
    ).scalar_one_or_none()

    if group is None:
        return None
    return _stable_list_order(list(group.blocklists))


async def build_effective_for_view(db: AsyncSession, view_id: uuid.UUID) -> EffectiveBlocklist:
    """Compute the effective blocklist for a DNS view.

    Combines:
      - Blocklists assigned directly to the view
      - Blocklists assigned to the view's parent server group
    """
    lists = await effective_lists_for_view(db, view_id)
    if lists is None:
        return EffectiveBlocklist(scope="view", scope_id=view_id)

    entries, exceptions, list_ids = await _collect_lists(db, lists)
    return EffectiveBlocklist(
        scope="view",
        scope_id=view_id,
        entries=entries,
        exceptions=exceptions,
        lists=list_ids,
    )


async def build_effective_for_group(db: AsyncSession, group_id: uuid.UUID) -> EffectiveBlocklist:
    """Compute the effective blocklist for a DNS server group (all views)."""
    lists = await effective_lists_for_group(db, group_id)
    if lists is None:
        return EffectiveBlocklist(scope="group", scope_id=group_id)

    entries, exceptions, list_ids = await _collect_lists(db, lists)
    return EffectiveBlocklist(
        scope="group",
        scope_id=group_id,
        entries=entries,
        exceptions=exceptions,
        lists=list_ids,
    )


# ── Streaming the entries (#1662) ─────────────────────────────────────────────
#
# The DNS agent bundle carries every entry of every list a zone draws on. The
# catalog's largest feed is ~582k domains, and ``_collect_lists`` holds all of
# them at once, as rows and then as one ``EffectiveEntry`` each: the render of
# such a bundle took the whole 1 GiB worker. The render reads them through
# these instead, one batch at a time, in exactly ``_collect_lists``'s order.

#: (domain, action, block_mode, target, is_wildcard, sinkhole_ip) — what the
#: bundle ships.
RenderEntry = tuple[str, str, str, str | None, bool, str | None]


def _enabled(lists: list[DNSBlockList]) -> list[DNSBlockList]:
    return [bl for bl in lists if bl.enabled]


async def has_entries(db: AsyncSession, lists: list[DNSBlockList]) -> bool:
    """Does any enabled list of ``lists`` carry an entry?"""
    ids = [bl.id for bl in _enabled(lists)]
    if not ids:
        return False
    return bool(await db.scalar(select(exists().where(DNSBlockListEntry.list_id.in_(ids)))))


def _ancestors(name: str) -> list[str]:
    """``a.b.example.com`` → ``[b.example.com, example.com, com]``."""
    labels = name.split(".")
    return [".".join(labels[i:]) for i in range(1, len(labels))]


def _like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


async def _pooled_feed_exceptions(
    db: AsyncSession, enabled: list[DNSBlockList], feed: dict[uuid.UUID, set[str]]
) -> set[str]:
    """The feed exceptions (``source='feed'``, adblock ``@@``) that may join
    the pooled exception set (#2123, decided on #2124).

    Every renderer applies the pooled set to EVERY list of the zone: BIND
    emits ``N`` and ``*.N`` as ``rpz-passthru`` and drops any entry equal to
    ``N``; Technitium puts ``N`` in its allowed set, which unblocks ``N`` and
    everything under it. A remote feed may only carve exceptions out of its
    OWN blocks, so a feed's exception ``N`` is pooled only when:

    * the feed's own list blocks it through a wildcard ancestor (``||p^``
      with ``@@||n.p^``) — otherwise there is nothing of its own to carve
      out of, and an exact block of ``N`` the parser already dropped;
    * no OTHER list of the zone blocks ``N`` itself or through a wildcard
      ancestor; and
    * no other list blocks a name under ``N`` (Technitium's allowed set
      covers the whole subtree).

    Every other feed exception is stored, shown and has no effect. That
    over-blocks rather than under-blocks: a carve-out lost to another list
    is what that other list asked for.
    """
    candidates: dict[uuid.UUID, set[str]] = {}
    for bl in enabled:
        names = feed.get(bl.id)
        if not names:
            continue
        lookup = {a for n in names for a in _ancestors(n)}
        if not lookup:
            continue
        rows = await db.execute(
            select(DNSBlockListEntry.domain).where(
                DNSBlockListEntry.list_id == bl.id,
                DNSBlockListEntry.is_wildcard.is_(True),
                DNSBlockListEntry.domain.in_(lookup),
            )
        )
        own = {d.lower() for d in rows.scalars()}
        useful = {n for n in names if any(a in own for a in _ancestors(n))}
        if useful:
            candidates[bl.id] = useful

    pooled: set[str] = set()
    for list_id, names in candidates.items():
        others = [bl.id for bl in enabled if bl.id != list_id]
        if not others:
            pooled |= names
            continue
        lookup = set(names) | {a for n in names for a in _ancestors(n)}
        cover = await db.execute(
            select(DNSBlockListEntry.domain, DNSBlockListEntry.is_wildcard).where(
                DNSBlockListEntry.list_id.in_(others),
                DNSBlockListEntry.domain.in_(lookup),
            )
        )
        exact: set[str] = set()
        wild: set[str] = set()
        for d, is_wild in cover.tuples():
            exact.add(d.lower())
            if is_wild:
                wild.add(d.lower())
        safe = {n for n in names if n not in exact and not any(a in wild for a in _ancestors(n))}
        if not safe:
            continue
        # A name UNDER a carve-out, blocked by another list. One pass over
        # the other lists' entries, and only for the few carve-outs that
        # survived the indexed checks above.
        patterns = [f"%.{_like_escape(n)}" for n in sorted(safe)]
        rows = await db.execute(
            select(DNSBlockListEntry.domain).where(
                DNSBlockListEntry.list_id.in_(others),
                or_(*(DNSBlockListEntry.domain.like(p) for p in patterns)),
            )
        )
        under = {d.lower() for d in rows.scalars()}
        pooled |= {n for n in safe if not any(u.endswith("." + n) for u in under)}
    return pooled


async def exception_domains(db: AsyncSession, lists: list[DNSBlockList]) -> set[str]:
    """The exceptions every renderer applies across all of ``lists``.

    An operator's exception (``source='manual'``) applies to every list of
    the zone, as it always has. A feed's own ``@@`` rule (``source='feed'``,
    #2123) applies only to that feed's list: see
    :func:`_pooled_feed_exceptions`.
    """
    enabled = _enabled(lists)
    out: set[str] = set()
    feed: dict[uuid.UUID, set[str]] = {}
    if not enabled:
        return out
    # One query across every enabled list; only the feed rules need to know
    # which list they came from.
    rows = await db.execute(
        select(
            DNSBlockListException.list_id,
            DNSBlockListException.domain,
            DNSBlockListException.source,
        ).where(DNSBlockListException.list_id.in_([bl.id for bl in enabled]))
    )
    for list_id, domain, source in rows.tuples():
        name = domain.lower().rstrip(".")
        if source == "feed":
            feed.setdefault(list_id, set()).add(name)
        else:
            out.add(domain.lower())
    if feed:
        out |= await _pooled_feed_exceptions(db, enabled, feed)
    return out


async def stream_entries(
    db: AsyncSession, lists: list[DNSBlockList], batch: int
) -> AsyncGenerator[list[RenderEntry], None]:
    """Every entry ``_collect_lists`` collects for ``lists``, in the same order,
    at most ``batch`` at a time: one server-side cursor per list, so neither
    the driver nor this process ever holds more than a batch of a list."""
    for bl in _enabled(lists):
        block_mode, sinkhole_ip = bl.block_mode, bl.sinkhole_ip
        result = await db.stream(_entry_rows(bl.id).execution_options(yield_per=batch))
        try:
            async for rows in result.partitions():
                yield [
                    (
                        domain.lower(),
                        entry_type,
                        block_mode,
                        target,
                        is_wildcard,
                        sinkhole_ip,
                    )
                    for domain, entry_type, target, is_wildcard in rows
                ]
        finally:
            await result.close()
