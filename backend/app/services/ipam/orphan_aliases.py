"""Which trashed DNS records are an orphan's withdrawn aliases (#2604, #3189).

Mark as Orphan withdraws an address's aliases (soft-deletes them under the
address's orphan batch, :func:`orphan_alias_batch_id`) so the address's own
Restore can bring them back, and an orphan has no time limit. While the
address is still an orphan those rows belong to it: the Trash does not offer
them alone, the retention sweep leaves them, and deleting the address for good
deletes them with it.

The batch id is what makes a row one of these, not "its address is an orphan
now": an alias the operator trashed by hand before the address was orphaned
keeps its own batch, is not brought back by the address's Restore, and so
stays an ordinary Trash row. Mark as Orphan leaves such a row in the Trash
(#3189), so the Trash refuses to restore it while the address is an orphan
(:func:`orphan_record_owners`): it would publish a name for a host that no
longer publishes one. It can still be deleted for good, and it ages out with
the retention sweep.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import false, select
from sqlalchemy.orm import aliased

from app.models.dns import DNSRecord, DNSZone
from app.models.ipam import IPAddress

# The namespace of the deletion batch an orphaned address's aliases are
# withdrawn under. One batch id per address, derived rather than stored, so
# the restore finds exactly the aliases the orphan withdrew (and not one the
# operator trashed by hand) with no column to carry it.
_ORPHAN_ALIAS_BATCH_NS = uuid.UUID("5b0f3c2e-8a41-4d6e-9f27-2604a11a5e00")


def orphan_alias_batch_id(ip_id: uuid.UUID) -> uuid.UUID:
    """The ``deletion_batch_id`` Mark as Orphan stamps on the address's aliases."""
    return uuid.uuid5(_ORPHAN_ALIAS_BATCH_NS, str(ip_id))


async def withdrawn_alias_owners(
    db: Any, record_ids: list[uuid.UUID] | None = None
) -> dict[uuid.UUID, str]:
    """``{record id: address}`` for the trashed aliases an orphan withdrew.

    The batch id is a uuid5 of the address id, which Postgres cannot compute
    without an extension, so the candidates (trashed aliases of an address
    that is an orphan, a small set) are read and matched here. ``record_ids``
    narrows the read to those rows.
    """
    stmt: Any = (
        select(
            DNSRecord.id,
            DNSRecord.ip_address_id,
            DNSRecord.deletion_batch_id,
            IPAddress.address,
        )
        .join(IPAddress, IPAddress.id == DNSRecord.ip_address_id)
        .where(
            DNSRecord.ip_alias.is_(True),
            DNSRecord.deleted_at.is_not(None),
            IPAddress.status == "orphan",
        )
        .execution_options(include_deleted=True)
    )
    if record_ids is not None:
        stmt = stmt.where(DNSRecord.id.in_(record_ids))
    return {
        rid: str(address)
        for rid, ip_id, batch_id, address in (await db.execute(stmt)).all()
        if batch_id == orphan_alias_batch_id(ip_id)
    }


async def orphan_record_owners(
    db: Any,
    *,
    record_ids: list[uuid.UUID] | None = None,
    batch_id: uuid.UUID | None = None,
) -> dict[uuid.UUID, tuple[str, str, str]]:
    """``{record id: (fqdn, record type, address)}`` for trashed IPAM records of an orphan
    that a restore of their own batch would bring back (#3189).

    Any batch but the zone's own: a record riding its zone's batch is purged
    when the address is orphaned (#3186), so one found there predates that
    and is left to the zone's restore as before. ``record_ids`` or
    ``batch_id`` narrows the read.
    """
    zone = aliased(DNSZone)
    stmt: Any = (
        select(DNSRecord.id, DNSRecord.fqdn, DNSRecord.record_type, IPAddress.address)
        .join(IPAddress, IPAddress.id == DNSRecord.ip_address_id)
        .join(zone, zone.id == DNSRecord.zone_id)
        .where(
            DNSRecord.auto_generated.is_(True),
            DNSRecord.deleted_at.is_not(None),
            IPAddress.status == "orphan",
            zone.deletion_batch_id.is_distinct_from(DNSRecord.deletion_batch_id),
        )
        .execution_options(include_deleted=True)
    )
    if record_ids is not None:
        stmt = stmt.where(DNSRecord.id.in_(record_ids))
    if batch_id is not None:
        stmt = stmt.where(DNSRecord.deletion_batch_id == batch_id)
    return {
        rid: (fqdn, rtype, str(address))
        for rid, fqdn, rtype, address in (await db.execute(stmt)).all()
    }


def orphan_record_reason(address: str) -> str:
    return (
        f"its IP address {address} is an orphan, so it would name a host that no "
        "longer publishes one. Restore the address first, then this record"
    )


def is_withdrawn_alias(ids: set[uuid.UUID] | dict[uuid.UUID, str]) -> Any:
    """SQL predicate over ``DNSRecord``: the row is one of ``ids``."""
    return DNSRecord.id.in_(list(ids)) if ids else false()


def refusal_reason(address: str) -> str:
    return (
        f"it is an alias withdrawn when IP address {address} was marked as orphan. "
        "Restore the address (or delete it permanently) and the alias follows it"
    )
