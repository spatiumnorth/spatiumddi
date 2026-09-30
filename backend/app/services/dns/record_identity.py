"""Whether a DNS record would duplicate one the zone already holds (#1230).

Two rows describing the same resource record are not harmless clutter. Every
record op carries the whole RRset the server should end up with, built from
the live rows, and a delete used to drop the deleted row's VALUE from it — so
deleting one of two identical rows retracted the record from the server while
the other row still listed it: a wrong DNS answer, with the UI showing a
record nothing serves. ``app.services.dns.rrset`` now drops the deleted ROW
instead, so twins that already exist no longer do that; this module stops new
ones being made by the paths an operator drives (REST create / update / bulk
create, and the Copilot).
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord


async def find_identical_record(
    db: AsyncSession,
    zone_id: uuid.UUID,
    *,
    view_id: uuid.UUID | None,
    name: str,
    record_type: str,
    value: str,
    priority: int | None,
    weight: int | None,
    port: int | None,
    exclude_id: uuid.UUID | None = None,
) -> DNSRecord | None:
    """A live record identical to the one described, or None.

    Identical means the same view, owner name, type, value and structured
    fields (priority / weight / port). TTL is not part of it: it belongs to
    the RRset, not to a member, which is the line the RRset fold draws too.
    Owner names compare case-insensitively, as DNS does; the value compares
    exactly after trimming, as the fold does. Soft-deleted rows are excluded by
    the session-wide filter, so a record in the trash does not block
    re-creating it.
    """
    stmt = select(DNSRecord).where(
        DNSRecord.zone_id == zone_id,
        DNSRecord.view_id.is_not_distinct_from(view_id),
        func.lower(DNSRecord.name) == name.lower(),
        func.upper(DNSRecord.record_type) == record_type.upper(),
        func.btrim(DNSRecord.value) == value.strip(),
        DNSRecord.priority.is_not_distinct_from(priority),
        DNSRecord.weight.is_not_distinct_from(weight),
        DNSRecord.port.is_not_distinct_from(port),
    )
    if exclude_id is not None:
        stmt = stmt.where(DNSRecord.id != exclude_id)
    return (await db.execute(stmt.limit(1))).scalars().first()


def describe_identical(existing: DNSRecord) -> str:
    """The refusal message, shared so REST and the Copilot say the same thing."""
    return (
        f"An identical {existing.record_type} record {existing.fqdn} -> "
        f"{existing.value} already exists (id {existing.id}). Deleting either "
        "copy would retract the record from the server while the other still "
        "lists it."
    )
