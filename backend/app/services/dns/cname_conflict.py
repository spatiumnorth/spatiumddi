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


def describe_cname_conflict(record_type: str, fqdn: str, existing: DNSRecord) -> str:
    """The refusal message, shared so REST and the Copilot say the same thing."""
    name = fqdn.rstrip(".")
    rtype = record_type.strip().upper()
    if existing.record_type.upper() == "CNAME":
        if rtype == "CNAME":
            what = (
                f"{name} already has a CNAME to {existing.value} (id {existing.id}), "
                "and a name holds at most one CNAME"
            )
        else:
            what = (
                f"{name} is a CNAME to {existing.value} (id {existing.id}), so it "
                f"can hold no {rtype} record"
            )
    else:
        what = (
            f"{name} already holds data ({existing.record_type} {existing.value}, "
            f"id {existing.id}), so it cannot take a CNAME"
        )
    return (
        f"{what}. A CNAME must be the only record at its name (RFC 1034 section "
        "3.6.2, RFC 2181 section 10.1); PowerDNS and BIND both refuse a zone "
        "that breaks this, and the server stops applying it."
    )
