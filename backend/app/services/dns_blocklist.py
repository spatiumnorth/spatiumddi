"""Service layer for DNS blocking lists.

Produces a backend-neutral representation (`EffectiveBlocklist`) of the set of
blocked domains + exceptions that apply to a given DNS view or server group.
The DNS driver layer (BIND9 RPZ emitter Lua emitter, etc.) consumes
this structure to generate actual server config.

Driver-abstraction rule (CLAUDE.md #10): no BIND9 specifics live in
this module.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import exists, or_, select
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


async def _collect_lists(
    db: AsyncSession, lists: list[DNSBlockList]
) -> tuple[list[EffectiveEntry], set[str], list[uuid.UUID]]:
    entries: list[EffectiveEntry] = []
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
    for bl in enabled:
        rows = await db.execute(
            select(DNSBlockListException.domain, DNSBlockListException.source).where(
                DNSBlockListException.list_id == bl.id
            )
        )
        for domain, source in rows.tuples():
            name = domain.lower().rstrip(".")
            if source == "feed":
                feed.setdefault(bl.id, set()).add(name)
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
                    (domain.lower(), entry_type, block_mode, target, is_wildcard, sinkhole_ip)
                    for domain, entry_type, target, is_wildcard in rows
                ]
        finally:
            await result.close()


# ── Feed parsing (manual / hosts / domains / adblock) ────────────────────────


@dataclass(frozen=True)
class FeedSkipCounts:
    """Rules an adblock-format feed carried that did not become entries (#2123).

    Each is a rule the feed's author wrote and this list does not enforce,
    so the operator is told how many rather than left to assume the list
    is the whole feed:

    * ``regex`` — ``/…/`` and ``@@/…/`` rules. RPZ matches names, not
      patterns.
    * ``modifier`` — a rule carrying a modifier DNS cannot express
      (``$domain=``, ``$third-party``, ``$client=``, ``$dnstype=``, …).
      Most of them NARROW a rule, so dropping the modifier and keeping the
      name would block more than the feed asked for; the rule is skipped
      instead. ``$important`` is the one exception: it only changes
      precedence, so the rule is kept as a plain block.
    * ``badfilter`` — ``$badfilter`` rules. Each disables the rule it
      names, which is dropped with it; neither becomes an entry.
    * ``malformed`` — anything else this parser cannot turn into a name:
      a path (``||host/ads``), a ``*`` inside a name, a ``|`` anchor, a
      bare word.
    """

    regex: int = 0
    modifier: int = 0
    badfilter: int = 0
    malformed: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "regex": self.regex,
            "modifier": self.modifier,
            "badfilter": self.badfilter,
            "malformed": self.malformed,
        }


@dataclass(frozen=True)
class ParsedFeed:
    """A parsed feed plus what its syntax said about subdomains.

    ``wildcard_count`` is how many lines declared "this name and every
    subdomain": ``*.``-prefixed lines, and in an adblock feed every
    ``||name^`` rule, since that is what ``||`` means. The caller needs it
    because a list configured apex-only (``feed_entries_are_wildcard=False``,
    #894) against such a feed is overriding a stated intent, which is worth
    saying out loud rather than doing silently.

    ``exceptions`` are the feed's own allow rules (adblock ``@@||name^``,
    #2123), stored as the list's exceptions. ``skipped`` counts the rules
    an adblock feed carried that became neither; it is None for the other
    formats, which have no rule syntax to lose.
    """

    domains: list[str]
    wildcard_count: int
    exceptions: list[str] = field(default_factory=list)
    skipped: FeedSkipCounts | None = None


def parse_feed(content: str, feed_format: str) -> list[str]:
    """Parse raw feed text into a deduped list of domains.

    Thin wrapper over :func:`parse_feed_detailed` for the many callers
    (and tests) that only want the names.
    """
    return parse_feed_detailed(content, feed_format).domains


#: A hostname as an adblock ``||`` rule may name it: labels of letters,
#: digits, ``-`` and ``_``, at least two of them, optionally ``*.``-led.
_ADBLOCK_HOST_RE = re.compile(r"^(?:\*\.)?[a-z0-9_-]+(?:\.[a-z0-9_-]+)+\.?$")

#: Modifiers that leave a rule's DNS meaning intact. ``important`` only
#: raises a rule's precedence over exceptions in the same engine.
_ADBLOCK_HARMLESS_MODIFIERS = frozenset({"important"})

#: Element-hiding / scriptlet separators. Those rules are for browsers, never
#: for DNS, so they are ignored rather than counted as lost.
_ADBLOCK_COSMETIC_MARKERS = ("##", "#@#", "#?#", "#$#", "#%#", "#@$#", "#@%#", "#@?#")


#: (is_exception, pattern, modifiers without badfilter) identifies a rule for
#: ``$badfilter``, which cancels the rule that is otherwise identical.
_RuleKey = tuple[bool, str, frozenset[str]]


def _parse_adblock(content: str) -> ParsedFeed:
    """The ``adblock`` branch of :func:`parse_feed_detailed` (#2123).

    The old parser read only ``||`` lines and cut each at the first ``^``,
    ``$`` or ``/``. So ``@@`` exceptions vanished (over-blocking whatever
    another rule covered), ``||x^$badfilter`` — "disable the rule for x" —
    became a block of x, and a ``$domain=`` rule, which narrows a block to
    requests from one site, became an unconditional block. Each is now
    handled for what it says, and every rule that cannot be honoured is
    counted rather than silently dropped.
    """
    blocks: list[tuple[_RuleKey, str]] = []
    allows: list[tuple[_RuleKey, str]] = []
    cancelled: set[_RuleKey] = set()
    regex = modifier = badfilter = malformed = 0
    wildcard_count = 0

    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith(("!", "#", "[")):
            continue  # comment, or an ``[Adblock Plus 2.0]`` header
        if any(marker in line for marker in _ADBLOCK_COSMETIC_MARKERS):
            continue

        is_exception = line.startswith("@@")
        body = line[2:] if is_exception else line
        if body.startswith("/"):
            regex += 1
            continue

        pattern, sep, mod_text = body.partition("$")
        mods = (
            frozenset(m.strip().lower() for m in mod_text.split(",") if m.strip())
            if sep
            else frozenset()
        )
        pattern = pattern.lower()
        if "badfilter" in mods:
            badfilter += 1
            cancelled.add((is_exception, pattern, mods - {"badfilter"}))
            continue
        if any(m.split("=", 1)[0] not in _ADBLOCK_HARMLESS_MODIFIERS for m in mods):
            modifier += 1
            continue

        if not pattern.startswith("||"):
            malformed += 1
            continue
        host = pattern[2:]
        if host.endswith("|"):
            host = host[:-1]
        if host.endswith("^"):
            host = host[:-1]
        if not _ADBLOCK_HOST_RE.match(host):
            malformed += 1
            continue
        host = host.strip(".")
        if host.startswith("*."):
            host = host[2:]
        key: _RuleKey = (is_exception, pattern, mods)
        (allows if is_exception else blocks).append((key, host))

    # ``$important`` raises a block over every exception that is not itself
    # ``$important`` — that is the modifier's whole meaning. So a plain
    # ``@@`` for a name an important block names is overruled, and is not
    # stored: a stored exception would unblock the name for every list on
    # the group, inverting the feed's intent.
    important_blocks = {
        host for key, host in blocks if key not in cancelled and "important" in key[2]
    }
    exceptions: list[str] = []
    excepted: set[str] = set()
    for key, host in allows:
        if key in cancelled or host in excepted:
            continue
        if host in important_blocks and "important" not in key[2]:
            continue
        excepted.add(host)
        exceptions.append(host)

    domains: list[str] = []
    seen: set[str] = set()
    for key, host in blocks:
        if key in cancelled:
            continue
        # ``||name^`` is adblock's "name and every subdomain" (#894).
        wildcard_count += 1
        # A name the feed also excepts never renders (the RPZ renderers skip
        # an entry equal to an exception), so storing it would only inflate
        # ``entry_count`` past what the list enforces.
        if host in seen or host in excepted:
            continue
        seen.add(host)
        domains.append(host)

    return ParsedFeed(
        domains=domains,
        wildcard_count=wildcard_count,
        exceptions=exceptions,
        skipped=FeedSkipCounts(
            regex=regex, modifier=modifier, badfilter=badfilter, malformed=malformed
        ),
    )


def parse_feed_detailed(content: str, feed_format: str) -> ParsedFeed:
    """Parse raw feed text into deduped domains + wildcard-syntax count.

    Accepts:
      - `hosts`: `0.0.0.0 ads.example.com` (or `127.0.0.1`)
      - `domains`: one domain per line, optionally `*.`-prefixed
      - `adblock`: `||ads.example.com^`, with `@@` exceptions and
        `$important` / `$badfilter`; see :func:`_parse_adblock`

    Ignores blank lines and comments (`#`, `!`). A leading `*.` is
    stripped rather than kept — see the comment at the strip site.
    """
    if feed_format == "adblock":
        return _parse_adblock(content)

    out: list[str] = []
    seen: set[str] = set()
    wildcard_count = 0

    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue

        domain: str | None = None

        if feed_format == "hosts":
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
