"""Address-by-id lookups that respect the Trash (#3537).

``IPAddress`` is not soft-deletable: when a subnet goes to the Trash its
addresses stay in the table, which is what lets a restore bring them back.
So the global soft-delete filter never hides an address, and a bare
``db.get(IPAddress, id)`` happily returns one whose subnet is in the Trash.
A write through it (a MAC change writes an ``ip_mac_history`` row) is then
stored and raises alerts once the subnet is restored.

Every route that addresses a row by its own id goes through
:func:`get_live_address` (or filters with :func:`live_subnet_clause`) instead,
so a trashed subnet reads exactly as it does on ``GET /subnets/{id}``: 404.
The ``Subnet`` select inside the clause is auto-filtered to
``deleted_at IS NULL``; trashing a block or space stamps its subnets in the
same batch, so the subnet is the one thing to check.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ColumnElement, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress, Subnet


def live_subnet_clause() -> ColumnElement[bool]:
    """``IPAddress`` rows whose subnet is not in the Trash."""
    return IPAddress.subnet_id.in_(select(Subnet.id))


async def get_live_address(db: AsyncSession, address_id: uuid.UUID) -> IPAddress | None:
    """The address, or None when it does not exist or its subnet is trashed."""
    return (
        await db.execute(select(IPAddress).where(IPAddress.id == address_id, live_subnet_clause()))
    ).scalar_one_or_none()
