"""Keep an E911 binding when an automatic path would delete its address row (#3899).

``erl_binding.ip_address_id`` is ``ON DELETE CASCADE``, so every automatic path
that deletes an address row - a DHCP lease mirror going with its lease, a
reservation's mirror going with its reservation, its scope or its subnet - took
the ``ip`` binding on that row with it, and the phone's dispatchable location
fell back to a coarser one (or none) without a word. #3891 refuses the
operator-driven permanent deletes; these paths are not a request to delete that
address, so refusing would block a lease expiring. They keep the row instead,
as a free address that still carries the binding (what deleting a reservation
alone has always left), and a reservation that moves takes the binding along.
"""

from __future__ import annotations

import uuid
from collections.abc import Collection

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.e911 import ERLBinding
from app.models.ipam import IPAddress


async def bound_ip_ids(db: AsyncSession, ids: Collection[uuid.UUID]) -> set[uuid.UUID]:
    """The subset of these address rows an ``ip`` binding is keyed to."""
    if not ids:
        return set()
    res = await db.execute(
        select(ERLBinding.ip_address_id).where(ERLBinding.ip_address_id.in_(ids))
    )
    return {i for (i,) in res.all()}


async def keep_row_if_bound(db: AsyncSession, row: IPAddress) -> bool:
    """Instead of deleting ``row``: free it up and keep it when a binding names it.

    Returns True when the row was kept (the caller must not delete it, count it
    as removed or forget it); False when nothing is bound and the caller deletes
    as before. A kept row is a plain ``available`` address: whatever the lease or
    reservation put on it (client, name, MAC, links back to them) is cleared, the
    binding is the only thing it still carries.
    """
    if not await bound_ip_ids(db, [row.id]):
        return False
    row.status = "available"
    row.hostname = ""
    row.mac_address = None
    row.auto_from_lease = False
    row.dhcp_lease_id = None
    row.static_assignment_id = None
    return True


async def carry_ip_bindings(db: AsyncSession, old_id: uuid.UUID, new_id: uuid.UUID) -> bool:
    """Re-point the ``ip`` binding on ``old_id`` at ``new_id`` (a reservation that moved).

    Not when ``new_id`` already carries its own binding (one per address): the
    old row is then kept by :func:`keep_row_if_bound` rather than losing it.
    Returns True when a binding moved.
    """
    if not await bound_ip_ids(db, [old_id]) or await bound_ip_ids(db, [new_id]):
        return False
    await db.execute(
        update(ERLBinding)
        .where(ERLBinding.ip_address_id == old_id)
        .values(ip_address_id=new_id)
        .execution_options(synchronize_session=False)
    )
    return True
