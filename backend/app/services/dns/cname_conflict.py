"""A CNAME is the only record at its name (#1381).

RFC 1034 §3.6.2 and RFC 2181 §10.1: a name that holds a CNAME holds nothing
else — not an A, not a TXT, not a second CNAME. (DNSSEC's own records are the
exception, and none of them is an operator record here.) Both engines hold a
zone to it: PowerDNS refused the agent's patch with 422 "Conflicts with
pre-existing RRset", and BIND's zone check refuses "CNAME and other data",
which quarantines the server's whole config bundle (#1378). The record API
stored such a pair with two 201s, so one record write took a zone, or a whole
server, out of service.

The paths an operator drives — REST create, update and bulk create, and the
Copilot — ask here before they store a row, the same set #1230's identity
check covers.

Two rows meet at a name when they belong to one zone, their owner names are
equal (DNS compares names case-insensitively) and their views overlap: a row
with no view renders in every view of the group, a scoped row only in its own
(``pool_geo.records_for_view``). The zone apex always holds the SOA and NS the
agent renders, so it never takes a CNAME.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord

APEX_CNAME_DETAIL = (
    "A CNAME cannot be at the zone apex: the apex always holds the zone's SOA "
    "and NS records, and a CNAME must be the only record at its name (RFC 1034 "
    "section 3.6.2, RFC 2181 section 10.1). Use A / AAAA records at the apex, "
    "or an ALIAS where the group's servers support one."
)

# The bulk create's ``skipped`` reason, beside #1230's two.
CNAME_CONFLICT_REASON = "a name with a CNAME can hold no other record"


def is_apex(name: str) -> bool:
    """Whether a relative owner name is the zone apex (``@``, or empty)."""
    return name.strip() in ("", "@")


def views_overlap(a: uuid.UUID | None, b: uuid.UUID | None) -> bool:
    """Whether rows scoped to views *a* and *b* render into one view."""
    return a is None or b is None or a == b


def types_conflict(record_type: str, other_type: str) -> bool:
    """Whether a record of *record_type* cannot share its name with one of
    *other_type*: a CNAME beside anything, or anything beside a CNAME."""
    return record_type.strip().upper() == "CNAME" or other_type.strip().upper() == "CNAME"


async def find_cname_conflict(
    db: AsyncSession,
    zone_id: uuid.UUID,
    *,
    view_id: uuid.UUID | None,
    name: str,
    record_type: str,
    exclude_id: uuid.UUID | None = None,
) -> DNSRecord | None:
    """A live row the described record cannot share its name with, or None.

    For a CNAME that is any row at the name in an overlapping view, a second
    CNAME included; for any other type it is a CNAME there. A row identical to
    the described one is #1230's business and is refused before this is asked.
    Soft-deleted rows are excluded by the session-wide filter, so a record in
    the trash blocks nothing.
    """
    stmt = select(DNSRecord).where(
        DNSRecord.zone_id == zone_id,
        func.lower(DNSRecord.name) == name.strip().lower(),
    )
    if view_id is not None:
        stmt = stmt.where(or_(DNSRecord.view_id.is_(None), DNSRecord.view_id == view_id))
    if record_type.strip().upper() != "CNAME":
        stmt = stmt.where(func.upper(DNSRecord.record_type) == "CNAME")
    if exclude_id is not None:
        stmt = stmt.where(DNSRecord.id != exclude_id)
    return (await db.execute(stmt.order_by(DNSRecord.created_at).limit(1))).scalars().first()


async def find_record_insert_conflict(
    db: AsyncSession,
    zone_id: uuid.UUID,
    *,
    name: str,
    record_type: str,
    own_fk: str,
    own_id: uuid.UUID,
) -> DNSRecord | None:
    """A non-owned row that blocks an integration mirror inserting a
    record at (zone, name) (#1561), or None.

    The record passes of the Kubernetes / Tailscale / NetBird mirrors
    only ever saw rows carrying their own FK, so they inserted beside
    operator records (and other integrations' records) at the same
    name: an unexplained extra round-robin A, or a CNAME beside an A —
    the state the record API refuses with 409 and BIND refuses to load.
    A row blocks the insert when it is NOT owned by the caller
    (``own_fk`` != ``own_id``) and either shares the type, or either
    side is a CNAME (``types_conflict`` — the same rule
    ``find_cname_conflict`` applies for the API). The caller's own rows
    never block: the pass manages those itself.
    """
    stmt = select(DNSRecord).where(
        DNSRecord.zone_id == zone_id,
        func.lower(DNSRecord.name) == name.strip().lower(),
    )
    rows = (await db.execute(stmt.order_by(DNSRecord.created_at))).scalars().all()
    rtype = record_type.strip().upper()
    for row in rows:
        if getattr(row, own_fk, None) == own_id:
            continue
        if row.record_type.strip().upper() == rtype or types_conflict(rtype, row.record_type):
            return row
    return None


def _describe(
    record_type: str,
    fqdn: str,
    other_type: str,
    other_value: str,
    other_id: uuid.UUID | None,
) -> str:
    name = fqdn.rstrip(".")
    rtype = record_type.strip().upper()
    ref = f" (id {other_id})" if other_id is not None else ""
    if other_type.upper() == "CNAME":
        if rtype == "CNAME":
            what = (
                f"{name} already has a CNAME to {other_value}{ref}, "
                "and a name holds at most one CNAME"
            )
        else:
            what = f"{name} is a CNAME to {other_value}{ref}, so it can hold no {rtype} record"
    else:
        what = f"{name} already holds data ({other_type} {other_value}{ref}), so it cannot take a CNAME"
    return (
        f"{what}. A CNAME must be the only record at its name (RFC 1034 section "
        "3.6.2, RFC 2181 section 10.1); PowerDNS and BIND both refuse a zone "
        "that breaks this, and the server stops applying it."
    )


def describe_cname_conflict(record_type: str, fqdn: str, existing: DNSRecord) -> str:
    """The refusal message, shared so REST and the Copilot say the same thing."""
    return _describe(record_type, fqdn, existing.record_type, existing.value, existing.id)


@dataclass(frozen=True)
class NameRow:
    """One record as the in-memory check sees it: an owner name relative to
    its zone (``@`` / empty is the apex), a type, rdata, and a view scope
    (None renders into every view)."""

    name: str
    record_type: str
    value: str = ""
    view_id: uuid.UUID | None = None


def _rel(name: str) -> str:
    n = name.strip().lower().rstrip(".")
    return "@" if n == "" else n


def _meet(a: NameRow, b: NameRow) -> bool:
    """The DB check's rule on two in-memory rows: one name (case-insensitive),
    overlapping views, and a CNAME on at least one side."""
    return (
        _rel(a.name) == _rel(b.name)
        and views_overlap(a.view_id, b.view_id)
        and types_conflict(a.record_type, b.record_type)
    )


def refused_by_cname_rule(
    new_rows: Sequence[NameRow], standing: Sequence[NameRow] = ()
) -> dict[int, str]:
    """The in-memory twin of :func:`find_cname_conflict`, for rows that are
    not in the database yet (an import batch). Returns ``{index into
    new_rows: reason}`` for every row that cannot be stored.

    ``standing`` are rows that stay where they are (records already in the
    target zone): they always win. Within ``new_rows`` the non-CNAME data
    wins over a CNAME at the same name (what BIND needs to load the zone),
    and of several CNAMEs at one name the first is kept. A CNAME at the apex
    is refused outright. DNSSEC's own types are never stored as operator
    records, so they never reach this check.
    """
    refused: dict[int, str] = {}
    for i, row in enumerate(new_rows):
        if row.record_type.strip().upper() == "CNAME":
            continue
        for st in standing:
            if _meet(row, st):
                refused[i] = _describe(row.record_type, row.name, st.record_type, st.value, None)
                break
    kept_cnames: list[NameRow] = []
    for i, row in enumerate(new_rows):
        if row.record_type.strip().upper() != "CNAME":
            continue
        if is_apex(row.name):
            refused[i] = APEX_CNAME_DETAIL
            continue
        other = next((st for st in standing if _meet(row, st)), None)
        if other is None:
            other = next(
                (
                    r
                    for j, r in enumerate(new_rows)
                    if j not in refused
                    and j != i
                    and _meet(row, r)
                    and r.record_type.strip().upper() != "CNAME"
                ),
                None,
            )
        if other is None:
            other = next((k for k in kept_cnames if _meet(row, k)), None)
        if other is not None:
            refused[i] = _describe("CNAME", row.name, other.record_type, other.value, None)
            continue
        kept_cnames.append(row)
    return refused
