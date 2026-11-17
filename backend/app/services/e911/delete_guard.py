"""Refuse the hard delete of an object an E911 binding is keyed to (#3891).

Every foreign key of ``erl_binding`` (subnet, VLAN, address, interface, site)
is ``ON DELETE CASCADE``, so deleting the bound object for good removes the
binding with it and every device that matched it falls back to a coarser
location, or none. #2298 closed that for a site; this is the same rule for the
other doors: a VLAN or a router's VLANs, a subnet (and the addresses that go
with it), an address, a device's interfaces.

A wrong or missing dispatchable location is not something to find out on the
next conformity pass, so the delete is refused and the binding named; the
operator removes it deliberately (Network > E911 > Bindings) and deletes.
The soft delete of a subnet is not gated: the binding stays while the subnet
is in the Trash, and only the permanent delete loses it.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable

from fastapi import HTTPException
from sqlalchemy import exists, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.e911 import EmergencyResponseLocation, ERLBinding
from app.models.ipam import IPAddress, Subnet
from app.models.network import NetworkDevice, NetworkInterface
from app.models.vlans import VLAN


async def e911_bindings_blocking(
    db: AsyncSession,
    *,
    vlan_ids: Iterable[uuid.UUID] = (),
    subnet_ids: Iterable[uuid.UUID] = (),
    ip_ids: Iterable[uuid.UUID] = (),
    device_ids: Iterable[uuid.UUID] = (),
) -> list[str]:
    """Human-readable lines for every binding a hard delete of these rows would remove.

    ``subnet_ids`` also covers the bindings on the addresses inside those
    subnets, since the subnet's delete cascades them; ``device_ids`` covers the
    bindings on the devices' interfaces. Empty list = nothing in the way.
    """
    vlan_ids, subnet_ids = list(vlan_ids), list(subnet_ids)
    ip_ids, device_ids = list(ip_ids), list(device_ids)
    lines: list[str] = []

    if vlan_ids:
        res = await db.execute(
            select(VLAN.vlan_id, VLAN.name, EmergencyResponseLocation.name)
            .select_from(ERLBinding)
            .join(VLAN, VLAN.id == ERLBinding.vlan_ref_id)
            .join(EmergencyResponseLocation, EmergencyResponseLocation.id == ERLBinding.erl_id)
            .where(ERLBinding.vlan_ref_id.in_(vlan_ids))
            .order_by(VLAN.vlan_id)
        )
        lines += [f'VLAN {tag} ({name}) -> ERL "{erl}"' for tag, name, erl in res.all()]

    if subnet_ids:
        res = await db.execute(
            select(Subnet.network, EmergencyResponseLocation.name)
            .select_from(ERLBinding)
            .join(Subnet, Subnet.id == ERLBinding.subnet_id)
            .join(EmergencyResponseLocation, EmergencyResponseLocation.id == ERLBinding.erl_id)
            .where(ERLBinding.subnet_id.in_(subnet_ids))
            .order_by(Subnet.network)
            .execution_options(include_deleted=True)
        )
        lines += [f'subnet {net} -> ERL "{erl}"' for net, erl in res.all()]
    if ip_ids or subnet_ids:
        res = await db.execute(
            select(IPAddress.address, EmergencyResponseLocation.name)
            .select_from(ERLBinding)
            .join(IPAddress, IPAddress.id == ERLBinding.ip_address_id)
            .join(EmergencyResponseLocation, EmergencyResponseLocation.id == ERLBinding.erl_id)
            .where(or_(IPAddress.id.in_(ip_ids), IPAddress.subnet_id.in_(subnet_ids)))
            .order_by(IPAddress.address)
        )
        lines += [f'address {addr} -> ERL "{erl}"' for addr, erl in res.all()]
    if device_ids:
        res = await db.execute(
            select(NetworkDevice.name, NetworkInterface.name, EmergencyResponseLocation.name)
            .select_from(ERLBinding)
            .join(NetworkInterface, NetworkInterface.id == ERLBinding.network_interface_id)
            .join(NetworkDevice, NetworkDevice.id == NetworkInterface.device_id)
            .join(EmergencyResponseLocation, EmergencyResponseLocation.id == ERLBinding.erl_id)
            .where(NetworkInterface.device_id.in_(device_ids))
            .order_by(NetworkDevice.name, NetworkInterface.name)
        )
        lines += [f'switch port {dev}/{ifn} -> ERL "{erl}"' for dev, ifn, erl in res.all()]
    return lines


def e911_refusal_detail(what: str, lines: list[str]) -> str:
    shown = "; ".join(lines[:5]) + (f" and {len(lines) - 5} more" if len(lines) > 5 else "")
    return (
        f"Cannot delete {what}: E911 location binding(s) still point at it ({shown}). "
        "Deleting would silently remove the emergency location for every device "
        "that matched them. Remove the binding(s) under Network > E911 > Bindings first."
    )


async def refuse_if_e911_bound(
    db: AsyncSession,
    what: str,
    *,
    vlan_ids: Iterable[uuid.UUID] = (),
    subnet_ids: Iterable[uuid.UUID] = (),
    ip_ids: Iterable[uuid.UUID] = (),
    device_ids: Iterable[uuid.UUID] = (),
) -> None:
    """409 naming the bindings when any of the rows still carries one."""
    lines = await e911_bindings_blocking(
        db, vlan_ids=vlan_ids, subnet_ids=subnet_ids, ip_ids=ip_ids, device_ids=device_ids
    )
    if lines:
        raise HTTPException(status_code=409, detail=e911_refusal_detail(what, lines))


def subnet_e911_bound_clause() -> object:
    """SQL predicate: this ``Subnet`` row, or an address in it, carries a binding.

    For the nightly Trash sweep, which holds such a subnet back rather than
    purging it.
    """
    return exists().where(ERLBinding.subnet_id == Subnet.id) | exists().where(
        ERLBinding.ip_address_id == IPAddress.id, IPAddress.subnet_id == Subnet.id
    )
