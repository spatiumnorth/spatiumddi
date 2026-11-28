"""Which blocking lists cover one domain name, and is it blocked (#4250).

A per-name lookup for the DNS query details modal's Block / Allow actions
and the "Blocked by" line. It reads only the rows that can cover the name
(the name and each parent suffix, served by the ``(list_id, domain)``
indexes), never a whole list (#1724).

The verdict follows what the renderers emit. A wildcard entry ``example.com``
renders ``example.com`` and ``*.example.com``; an exact entry renders only
the first. An exception ``d`` renders ``d`` and ``*.d`` as ``rpz-passthru``,
and an entry for the same name is not emitted (it would put two CNAMEs on
one owner). Within one RPZ zone the most specific owner wins, so an
exception for ``a.example.com`` carves that name out of a wildcard entry for
``example.com``, and an entry for ``a.example.com`` still blocks it under an
exception for ``example.com``. Technitium flattens the same data into a
blocked and an allowed set where the allowed set wins, which gives the same
answer for these two shapes.

A manual exception applies across every list assigned to the same scope; a
feed's own ``@@`` exception only to its own list's blocks (see
:func:`app.services.dns_blocklist.exception_domains`). Both are modelled.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.dns import (
    DNSBlockList,
    DNSBlockListEntry,
    DNSBlockListException,
)

__all__ = ["BlocklistMatch", "ExceptionMatch", "MatchResult", "match_domain", "normalize_domain"]


def normalize_domain(domain: str) -> str | None:
    """Lower-cased name without a trailing dot, or None when it cannot be
    a blocking-list name (empty, single label, or has whitespace)."""
    d = domain.strip().lower().rstrip(".")
    if not d or "." not in d or any(c.isspace() for c in d):
        return None
    if any(not label for label in d.split(".")):
        return None
    return d


def _suffixes(domain: str) -> list[str]:
    """``a.b.example.com`` -> itself and every parent with at least two labels."""
    labels = domain.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


@dataclass
class BlocklistMatch:
    list_id: uuid.UUID
    list_name: str
    source_type: str
    block_mode: str
    sinkhole_ip: str | None
    enabled: bool
    entry_id: uuid.UUID
    entry_domain: str
    is_wildcard: bool
    entry_source: str
    # block | redirect | nxdomain, and the redirect target, so a caller can
    # put back exactly the entry it removes.
    entry_type: str
    target: str | None
    reason: str
    applies_here: bool
    # True when an exception takes this entry out for the queried name.
    excepted: bool = False


@dataclass
class ExceptionMatch:
    list_id: uuid.UUID
    list_name: str
    exception_id: uuid.UUID
    domain: str
    source: str
    applies_here: bool


@dataclass
class MatchResult:
    domain: str
    effective: str  # "blocked" | "allowed" | "none"
    matches: list[BlocklistMatch] = field(default_factory=list)
    exceptions: list[ExceptionMatch] = field(default_factory=list)


def _rank(rule_domain: str, qname: str) -> tuple[int, int]:
    """Specificity of a rule for ``qname``: an exact owner beats any wildcard,
    then the longer suffix wins."""
    return (1 if rule_domain == qname else 0, rule_domain.count(".") + 1)


async def match_domain(
    db: AsyncSession,
    domain: str,
    *,
    group_id: uuid.UUID | None,
    view_id: uuid.UUID | None,
) -> MatchResult:
    qname = normalize_domain(domain)
    if qname is None:
        raise ValueError("invalid domain")
    names = _suffixes(qname)

    entry_rows = (
        await db.execute(
            select(DNSBlockListEntry, DNSBlockList)
            .join(DNSBlockList, DNSBlockList.id == DNSBlockListEntry.list_id)
            .where(DNSBlockListEntry.domain.in_(names))
            .options(
                selectinload(DNSBlockList.server_groups),
                selectinload(DNSBlockList.views),
            )
        )
    ).all()
    exc_rows = (
        await db.execute(
            select(DNSBlockListException, DNSBlockList)
            .join(DNSBlockList, DNSBlockList.id == DNSBlockListException.list_id)
            .where(DNSBlockListException.domain.in_(names))
            .options(
                selectinload(DNSBlockList.server_groups),
                selectinload(DNSBlockList.views),
            )
        )
    ).all()

    def applies(bl: DNSBlockList) -> bool:
        if not bl.enabled:
            return False
        if group_id is not None and any(g.id == group_id for g in bl.server_groups):
            return True
        return view_id is not None and any(v.id == view_id for v in bl.views)

    matches: list[BlocklistMatch] = []
    for entry, bl in entry_rows:
        d = entry.domain.lower()
        # An exact entry only names itself; a wildcard also covers subdomains.
        if d != qname and not entry.is_wildcard:
            continue
        matches.append(
            BlocklistMatch(
                list_id=bl.id,
                list_name=bl.name,
                source_type=bl.source_type,
                block_mode=bl.block_mode,
                sinkhole_ip=bl.sinkhole_ip,
                enabled=bl.enabled,
                entry_id=entry.id,
                entry_domain=d,
                is_wildcard=entry.is_wildcard,
                entry_source=entry.source,
                entry_type=entry.entry_type,
                target=entry.target,
                reason=entry.reason,
                applies_here=applies(bl),
            )
        )
    exceptions: list[ExceptionMatch] = []
    for exc, bl in exc_rows:
        exceptions.append(
            ExceptionMatch(
                list_id=bl.id,
                list_name=bl.name,
                exception_id=exc.id,
                domain=exc.domain.lower().rstrip("."),
                source=exc.source,
                applies_here=applies(bl),
            )
        )

    live_exceptions = [e for e in exceptions if e.applies_here]
    live_entries = [m for m in matches if m.applies_here]
    for m in live_entries:
        # A manual exception pools across the scope; a feed one only over its
        # own list's blocks. The entry loses when an exception for the same
        # name exists (it is not rendered) or one is more specific for qname.
        usable = [e for e in live_exceptions if e.source != "feed" or e.list_id == m.list_id]
        covering = [e for e in usable if e.domain == qname or qname.endswith("." + e.domain)]
        # Only the most specific rule decides the name; compare per entry.
        if covering:
            best_exc = max(_rank(e.domain, qname) for e in covering)
            m.excepted = best_exc >= _rank(m.entry_domain, qname)

    if any(not m.excepted for m in live_entries):
        effective = "blocked"
    elif live_entries:
        effective = "allowed"
    else:
        effective = "none"
    matches.sort(key=lambda m: (not m.applies_here, m.list_name, m.entry_domain))
    exceptions.sort(key=lambda e: (not e.applies_here, e.list_name, e.domain))
    return MatchResult(domain=qname, effective=effective, matches=matches, exceptions=exceptions)
