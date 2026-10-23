"""Idempotent IPAM mirror-row creation for DHCP lease ingestion (#564).

Several DHCP lease-ingestion paths mirror a lease (or static
reservation) into an ``ip_address`` row with an unguarded
``SELECT (subnet_id, address); if None: INSERT`` pattern:

* Kea agent lease push — ``api/v1/dhcp/agents.py``
* poll/sync path — ``services/dhcp/pull_leases.py`` (reachable from
  the **Sync DHCP** button)
* static-reservation mirroring — ``api/v1/dhcp/statics.py``

Under concurrency (the agent pushing ``/lease-events`` while an
operator clicks **Sync DHCP**, or a static reservation created for an
IP that currently holds a dynamic lease) two writers both look up the
address, both see "no row", both ``INSERT``, and the loser hits
``uq_ip_address_subnet_address`` — a 500 whose
``PendingRollbackError`` tail then poisons the rest of the batch. On a
busy DHCP host new leases arrive continuously, so it recurs and
*feels* persistent, though each occurrence self-heals.

The codebase already hardened this exact race elsewhere — the
``pg_try_advisory_lock`` guard in ``tasks/ipam_discovery.py`` (#515)
and the conflict-SELECT guard in ``unifi/reconcile.py``. This helper
brings the same protection to the DHCP paths using the savepoint
fall-through style: attempt the ``INSERT`` inside a SAVEPOINT so a
unique-violation rolls back only the nested transaction (leaving the
outer session usable — no ``PendingRollbackError`` tail), then
re-select the row the concurrent writer committed and hand it back so
the caller falls through to its update path.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.models.ipam import IPAddress


async def insert_ipam_mirror_row(db: Any, row: IPAddress) -> tuple[IPAddress, bool]:
    """INSERT ``row`` idempotently under concurrency.

    Adds ``row`` to the session and flushes it inside a SAVEPOINT.

    * On success returns ``(row, True)`` — ``row`` now has its PK
      assigned by the flush.
    * If a concurrent writer already committed the same
      ``(subnet_id, address)`` pair (the ``uq_ip_address_subnet_address``
      unique violation) the savepoint is rolled back — keeping the
      outer session alive, no ``PendingRollbackError`` tail — and the
      incumbent row is re-selected and returned as ``(existing, False)``
      so the caller can fall through to its update path.

    An ``IntegrityError`` that is *not* our ``(subnet_id, address)``
    tuple (i.e. re-selecting the pair finds nothing) is re-raised
    rather than swallowed, so an unrelated constraint violation still
    surfaces.
    """
    # Capture the identifying pair before the flush — after a savepoint
    # rollback ``row`` is expunged from the session, but these plain
    # attributes stay readable for the re-select.
    subnet_id = row.subnet_id
    address = row.address
    try:
        async with db.begin_nested():
            db.add(row)
            await db.flush()
        return row, True
    except IntegrityError:
        existing = (
            await db.execute(
                select(IPAddress).where(
                    IPAddress.subnet_id == subnet_id,
                    IPAddress.address == address,
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            # The violation wasn't the (subnet_id, address) tuple we
            # tried to insert — surface it instead of masking an
            # unrelated integrity error.
            raise
        return existing, False


async def lease_hostname_suppressed_subnets(
    db: Any, *, group_id: Any = None, subnet_ids: Any = None
) -> set[Any]:
    """Subnets whose scope says a lease's hostname must NOT reach IPAM (#2269).

    ``DHCPScope.hostname_to_ipam_sync`` is ``on_lease`` (write every lease's
    hostname onto its IPAM mirror row) or ``disabled`` / ``on_static_only``
    (the mirror row still exists — status, MAC, last-seen — but the lease's
    client-supplied hostname stays out of it). A subnet is suppressed when it
    has at least one scope in view and none of them is ``on_lease``; a subnet
    with no scope keeps the historical behaviour. ``group_id`` narrows to one
    server group's scopes (the ingest paths); ``subnet_ids`` narrows to the
    subnets in play.
    """
    from app.models.dhcp import DHCPScope

    stmt = select(DHCPScope.subnet_id, DHCPScope.hostname_to_ipam_sync)
    if group_id is not None:
        stmt = stmt.where(DHCPScope.group_id == group_id)
    if subnet_ids is not None:
        stmt = stmt.where(DHCPScope.subnet_id.in_(list(subnet_ids)))
    seen: set[Any] = set()
    writes: set[Any] = set()
    for subnet_id, mode in (await db.execute(stmt)).all():
        seen.add(subnet_id)
        if mode == "on_lease":
            writes.add(subnet_id)
    return seen - writes
