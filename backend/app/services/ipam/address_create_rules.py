"""The refusals the REST address create makes before it writes a row.

One home so the REST ``create_address`` handler and the request portal's
submit-time check (#2903, #2905) apply the same rules, statuses and wording
instead of two copies. Each function raises a 4xx ``HTTPException``.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import ColumnElement, func, or_, select
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress, Subnet


def assert_subnet_takes_addresses(subnet: Subnet) -> None:
    """Multicast subnets hold stream identities, not endpoint rows (422)."""
    if subnet.kind == "multicast":
        raise HTTPException(
            status_code=422,
            detail=(
                "This is a multicast subnet — addresses are stream identities. "
                "Create a multicast group under /multicast/groups instead of an "
                "IPAM address row."
            ),
        )


def assert_static_dhcp_has_mac(addr_status: str | None, mac_address: str | None) -> None:
    """``static_dhcp`` needs a MAC to reserve (422)."""
    if addr_status == "static_dhcp" and not mac_address:
        raise HTTPException(
            status_code=422,
            detail="mac_address is required when status is 'static_dhcp'",
        )


def holds_address() -> ColumnElement[bool]:
    """A row that holds its address. An ``available`` row is a free slot the
    counters already call free (#2980), unless a DHCP reservation still
    points at it. Shared by the picker and Specific IP so both agree."""
    return or_(IPAddress.status != "available", IPAddress.static_assignment_id.is_not(None))


async def assert_address_unallocated(db: AsyncSession, subnet_id: uuid.UUID, address: str) -> None:
    """The address must not already be held in the subnet (409).

    A row with status ``available`` is a free slot the counters already call
    free (#2980), so it does not hold the address; the create reclaims it with
    ``reclaim_available_row``.
    """
    existing = await db.scalar(
        select(func.count())
        .select_from(IPAddress)
        .where(IPAddress.subnet_id == subnet_id)
        .where(IPAddress.address == address)
        .where(holds_address())
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Address {address} is already allocated in this subnet",
        )


# Columns a reclaimed row keeps: its identity. Everything else is reset to the
# value a brand-new row starts with, then the create writes its own fields.
# ``modified_at`` moves by its own ``onupdate``.
_RECLAIM_KEEPS = frozenset({"id", "subnet_id", "address", "created_at", "modified_at"})


def _fresh_value(column: Any) -> Any:
    """The value a new row gets for ``column`` before the create sets it."""
    default = column.default
    if default is None:
        return None
    if default.is_callable:
        # SQLAlchemy wraps a zero-argument callable (``dict``, ``list``) to
        # take the execution context, which it ignores.
        return default.arg(None)
    if default.is_scalar:
        return default.arg
    return None


async def reclaim_available_row(
    db: AsyncSession, subnet: Subnet, address: str, user: Any
) -> IPAddress | None:
    """Take over the ``available`` row at ``address`` for a create (#2980).

    An ``available`` row is a free slot: the counters call it free, so the
    picker and Specific IP hand its address out. The row is NOT deleted and
    replaced. It can still carry what an earlier tenant left on it: the
    reservation sweep flips an expired ``reserved`` row to ``available`` with
    its hostname and its published A / PTR / alias records intact, and the rows
    hanging off ``ip_address.id`` include CASCADE children (OT / BACnet / E911 /
    multicast registrations, MAC history) that a delete would destroy and
    ``SET NULL`` ones (DNS records) that a delete would leave served with no
    row behind them. So the row keeps its id, its DNS records are retracted
    the way a permanent delete retracts them, every other column is reset to a
    new row's value, and the reclaim is audited with what it replaced. The
    caller then writes the new allocation's fields onto the returned row.

    A row still linked to a DHCP reservation is not a free slot whatever its
    status says (409). Returns ``None`` when the address has no
    ``available`` row.
    """
    from app.api.v1.ipam.router import (  # noqa: PLC0415 — avoid a cycle
        _purge_withdrawn_aliases,
        _sync_dns_record,
    )
    from app.models.audit import AuditLog  # noqa: PLC0415
    from app.models.dhcp import DHCPStaticAssignment  # noqa: PLC0415

    row = (
        await db.execute(
            select(IPAddress)
            .where(IPAddress.subnet_id == subnet.id)
            .where(IPAddress.address == address)
            .where(IPAddress.status == "available")
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if row is None:
        return None

    linked_static = row.static_assignment_id is not None or bool(
        await db.scalar(
            select(func.count())
            .select_from(DHCPStaticAssignment)
            .where(DHCPStaticAssignment.ip_address_id == row.id)
        )
    )
    if linked_static:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Address {address} is marked available but is still linked to a "
                "DHCP reservation; remove the reservation first."
            ),
        )

    old_value = {
        "status": row.status,
        "hostname": row.hostname,
        "fqdn": row.fqdn,
        "mac_address": str(row.mac_address) if row.mac_address else None,
        "description": row.description,
        "reason": "reclaimed_available_row",
    }
    # Retract what the previous tenant published before its name is cleared.
    await _sync_dns_record(db, row, subnet, action="delete")
    await _purge_withdrawn_aliases(db, [row.id])

    for attr in sa_inspect(IPAddress).column_attrs:
        column = attr.columns[0]
        if attr.key in _RECLAIM_KEEPS or (not column.nullable and column.default is None):
            # Identity, or a server-side default only: nothing to reset to.
            continue
        setattr(row, attr.key, _fresh_value(column))

    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="update",
            resource_type="ip_address",
            resource_id=str(row.id),
            resource_display=str(address),
            old_value=old_value,
            new_value={"status": "reclaimed", "reason": "reclaimed_available_row"},
            result="success",
        )
    )
    await db.flush()
    return row


async def take_address_row(
    db: AsyncSession, subnet: Subnet, address: str, user: Any, **fields: Any
) -> IPAddress:
    """The row a create writes ``address`` into: the reclaimed ``available``
    row (``reclaim_available_row``) with ``fields`` set on it, or a new row.
    Flushes."""
    row = await reclaim_available_row(db, subnet, address, user)
    if row is None:
        row = IPAddress(subnet_id=subnet.id, address=address, **fields)
        db.add(row)
    else:
        for key, value in fields.items():
            setattr(row, key, value)
    await db.flush()
    return row
