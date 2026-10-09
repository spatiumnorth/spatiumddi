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
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.dns import (
    DNSBlockList,
    DNSBlockListEntry,
    DNSBlockListException,
    DNSServerGroup,
    DNSView,
)


@dataclass(frozen=True, slots=True)
class EffectiveEntry:
    """Backend-neutral representation of a blocked domain entry."""

    domain: str
    # action: block | redirect | nxdomain
    action: str
    # block_mode inherited from the list: nxdomain | sinkhole | refused
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


async def _collect_lists(
    db: AsyncSession, lists: list[DNSBlockList]
) -> tuple[list[EffectiveEntry], set[str], list[uuid.UUID]]:
    entries: list[EffectiveEntry] = []
    exceptions: set[str] = set()
    list_ids: list[uuid.UUID] = []

    # Column rows, not ORM entities (#1109, the #948 pattern): a Family
    # filter profile is ~596k entries, and hydrating each into a tracked
    # DNSBlockListEntry on every bundle build is the cost #948 removed for
    # records. Still one query per list, in the caller's list order, because
    # that order decides which list wins a duplicate owner name (#878); within
    # a list the rows come in ``domain`` order so the bundle, and its ETag, are
    # stable between builds instead of following the heap order. ``domain`` is
    # unique per list, so the order is total, and it is served by the
    # ``(list_id, domain)`` unique index rather than a sort of every row (``id``
    # is a random UUID, so ordering by it bought nothing an index could serve).
    for bl in lists:
        if not bl.enabled:
            continue
        list_ids.append(bl.id)

        entry_result = await db.execute(_entry_rows(bl.id))
        block_mode, sinkhole_ip, list_id, list_name = bl.block_mode, bl.sinkhole_ip, bl.id, bl.name
        entries.extend(
            EffectiveEntry(
                domain=domain.lower(),
                action=entry_type,
                block_mode=block_mode,
                sinkhole_ip=sinkhole_ip,
                target=target,
                is_wildcard=is_wildcard,
                list_id=list_id,
                list_name=list_name,
            )
            for domain, entry_type, target, is_wildcard in entry_result.tuples()
        )

        exc_result = await db.execute(
            select(DNSBlockListException.domain).where(DNSBlockListException.list_id == bl.id)
        )
        exceptions.update(domain.lower() for domain in exc_result.scalars())

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

#: (domain, action, block_mode, target, is_wildcard) — what the bundle ships.
RenderEntry = tuple[str, str, str, str | None, bool]


def _enabled(lists: list[DNSBlockList]) -> list[DNSBlockList]:
    return [bl for bl in lists if bl.enabled]


async def has_entries(db: AsyncSession, lists: list[DNSBlockList]) -> bool:
    """Does any enabled list of ``lists`` carry an entry?"""
    ids = [bl.id for bl in _enabled(lists)]
    if not ids:
        return False
    return bool(await db.scalar(select(exists().where(DNSBlockListEntry.list_id.in_(ids)))))


async def exception_domains(db: AsyncSession, lists: list[DNSBlockList]) -> set[str]:
    """The exceptions of the enabled lists of ``lists``, as ``_collect_lists``
    collects them."""
    out: set[str] = set()
    for bl in _enabled(lists):
        rows = await db.execute(
            select(DNSBlockListException.domain).where(DNSBlockListException.list_id == bl.id)
        )
        out.update(domain.lower() for domain in rows.scalars())
    return out


async def stream_entries(
    db: AsyncSession, lists: list[DNSBlockList], batch: int
) -> AsyncIterator[list[RenderEntry]]:
    """Every entry ``_collect_lists`` collects for ``lists``, in the same order,
    at most ``batch`` at a time: one server-side cursor per list, so neither
    the driver nor this process ever holds more than a batch of a list."""
    for bl in _enabled(lists):
        block_mode = bl.block_mode
        result = await db.stream(_entry_rows(bl.id).execution_options(yield_per=batch))
        try:
            async for rows in result.partitions():
                yield [
                    (domain.lower(), entry_type, block_mode, target, is_wildcard)
                    for domain, entry_type, target, is_wildcard in rows
                ]
        finally:
            await result.close()


# ── Feed parsing (manual / hosts / domains / adblock) ────────────────────────


@dataclass(frozen=True)
class ParsedFeed:
    """A parsed feed plus what its syntax said about subdomains.

    ``wildcard_count`` is how many lines arrived `*.`-prefixed. The
    caller needs it because that prefix is the feed *declaring* it means
    "and every subdomain" — so a list configured apex-only
    (``feed_entries_are_wildcard=False``, #894) against such a feed is
    overriding a stated intent, which is worth saying out loud rather
    than doing silently.
    """

    domains: list[str]
    wildcard_count: int


def parse_feed(content: str, feed_format: str) -> list[str]:
    """Parse raw feed text into a deduped list of domains.

    Thin wrapper over :func:`parse_feed_detailed` for the many callers
    (and tests) that only want the names.
    """
    return parse_feed_detailed(content, feed_format).domains


def parse_feed_detailed(content: str, feed_format: str) -> ParsedFeed:
    """Parse raw feed text into deduped domains + wildcard-syntax count.

    Accepts:
      - `hosts`: `0.0.0.0 ads.example.com` (or `127.0.0.1`)
      - `domains`: one domain per line, optionally `*.`-prefixed
      - `adblock`: `||ads.example.com^`

    Ignores blank lines and comments (`#`, `!`). A leading `*.` is
    stripped rather than kept — see the comment at the strip site.
    """
    out: list[str] = []
    seen: set[str] = set()
    wildcard_count = 0

    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue

        domain: str | None = None

        if feed_format == "adblock":
            # ||ads.example.com^  or ||ads.example.com
            if line.startswith("||"):
                rest = line[2:]
                for sep in ("^", "$", "/"):
                    idx = rest.find(sep)
                    if idx != -1:
                        rest = rest[:idx]
                        break
                domain = rest
        elif feed_format == "hosts":
            # Strip inline comment
            line = line.split("#", 1)[0].strip()
            parts = line.split()
            if len(parts) >= 2:
                domain = parts[1]
            elif len(parts) == 1:
                domain = parts[0]
        else:  # "domains"
            line = line.split("#", 1)[0].strip()
            if line:
                domain = line.split()[0]

        if not domain:
            continue
        domain = domain.lower().strip(".")
        # Several feeds publish wildcard syntax (`*.example.com` — OISD's
        # `domainswild`, Hagezi's `wildcard/`). The star is how the feed
        # says "and every subdomain", which is what a blocklist entry
        # means here anyway, so it is stripped rather than stored: kept
        # literally it produces an RPZ rule matching subdomains ONLY,
        # leaving the apex resolving normally.
        if domain.startswith("*."):
            domain = domain[2:]
            wildcard_count += 1
        if not domain or "." not in domain:
            continue
        if domain in seen:
            continue
        seen.add(domain)
        out.append(domain)

    return ParsedFeed(domains=out, wildcard_count=wildcard_count)


def dedupe_domains(domains: list[str]) -> list[str]:
    """Return a deduped, lowercased, sorted-by-input-order list of valid domains."""
    seen: set[str] = set()
    out: list[str] = []
    for d in domains:
        dd = d.strip().lower().strip(".")
        if not dd or "." not in dd or dd in seen:
            continue
        seen.add(dd)
        out.append(dd)
    return out
