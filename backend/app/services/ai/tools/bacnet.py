"""Operator-Copilot tools for BACnet/IP building automation (#541).

Read-only tools over the BACnet device registry — device instance
numbers, vendors, and BBMD topology. All gated on the
``network.bacnet`` feature module so they leave the registry in
lock-step with the feature surface.

No ``propose_*`` write tools. Every write on this surface is plain CRUD
an operator performs in the UI, and shipping write proposals for a
brand-new table before anyone has used it would be speculative.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.bacnet import BACnetDevice
from app.models.ipam import IPAddress
from app.services.ai.tools.base import register_tool
from app.services.bacnet.vendors import resolve_vendor_label

_MODULE = "network.bacnet"


class FindBACnetDevicesArgs(BaseModel):
    device_instance: int | None = Field(
        default=None,
        ge=0,
        le=4194302,
        description="Exact device instance number (0-4194302, unique internetwork-wide).",
    )
    vendor_id: int | None = Field(default=None, description="ASHRAE-assigned vendor id.")
    subnet_id: UUID | None = Field(default=None, description="Restrict to one subnet.")
    is_bbmd: bool | None = Field(
        default=None, description="True = only BBMDs, False = only non-BBMDs."
    )
    q: str | None = Field(
        default=None,
        description="Case-insensitive substring on device name, model, or vendor name.",
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_bacnet_devices",
    permission=("read", "bacnet_device"),
    description=(
        "List BACnet/IP devices with their device instance number, vendor, "
        "model, IP address and BBMD flag. Use this to answer 'which device "
        "holds instance N', 'what BACnet gear is on this subnet', or to find "
        "a controller by name or vendor."
    ),
    args_model=FindBACnetDevicesArgs,
    category="network",
    module=_MODULE,
    # Read-only building-automation inventory; no secrets, no control access.
    default_enabled=True,
)
async def find_bacnet_devices(
    db: AsyncSession, user: User, args: FindBACnetDevicesArgs
) -> list[dict[str, Any]]:
    _ = user
    stmt = select(BACnetDevice, IPAddress).outerjoin(
        IPAddress, IPAddress.id == BACnetDevice.ip_address_id
    )
    if args.device_instance is not None:
        stmt = stmt.where(BACnetDevice.device_instance == args.device_instance)
    if args.vendor_id is not None:
        stmt = stmt.where(BACnetDevice.vendor_id == args.vendor_id)
    if args.subnet_id is not None:
        stmt = stmt.where(BACnetDevice.subnet_id == args.subnet_id)
    if args.is_bbmd is not None:
        stmt = stmt.where(BACnetDevice.is_bbmd.is_(args.is_bbmd))
    if args.q:
        needle = f"%{args.q}%"
        stmt = stmt.where(
            or_(
                BACnetDevice.device_name.ilike(needle),
                BACnetDevice.model_name.ilike(needle),
                BACnetDevice.vendor_name.ilike(needle),
            )
        )
    stmt = stmt.order_by(BACnetDevice.device_instance).limit(args.limit)

    return [
        {
            "id": str(dev.id),
            "device_instance": dev.device_instance,
            "device_name": dev.device_name,
            "model_name": dev.model_name,
            "vendor_id": dev.vendor_id,
            "vendor": resolve_vendor_label(dev.vendor_id, dev.vendor_name),
            "firmware_rev": dev.firmware_rev,
            "location": dev.location,
            "address": str(ip.address) if ip is not None else None,
            "subnet_id": str(dev.subnet_id) if dev.subnet_id else None,
            "network_number": dev.network_number,
            "udp_port": dev.udp_port,
            "is_bbmd": dev.is_bbmd,
            "is_foreign_device": dev.is_foreign_device,
            "seen_via": dev.seen_via,
            "last_seen_at": dev.last_seen_at.isoformat() if dev.last_seen_at else None,
        }
        for dev, ip in (await db.execute(stmt)).all()
    ]


class CountBACnetDevicesArgs(BaseModel):
    subnet_id: UUID | None = Field(default=None, description="Restrict to one subnet.")


@register_tool(
    name="count_bacnet_devices",
    permission=("read", "bacnet_device"),
    description=(
        "Count BACnet devices with a breakdown of BBMDs, foreign devices, and "
        "how many report no usable vendor id. Quick health rollup for a "
        "building-automation estate."
    ),
    args_model=CountBACnetDevicesArgs,
    category="network",
    module=_MODULE,
    default_enabled=True,
)
async def count_bacnet_devices(
    db: AsyncSession, user: User, args: CountBACnetDevicesArgs
) -> dict[str, Any]:
    _ = user
    stmt = select(
        func.count(BACnetDevice.id),
        func.count(BACnetDevice.id).filter(BACnetDevice.is_bbmd.is_(True)),
        func.count(BACnetDevice.id).filter(BACnetDevice.is_foreign_device.is_(True)),
        func.count(BACnetDevice.id).filter(
            or_(BACnetDevice.vendor_id.is_(None), BACnetDevice.vendor_id == 0)
        ),
    )
    if args.subnet_id is not None:
        stmt = stmt.where(BACnetDevice.subnet_id == args.subnet_id)
    total, bbmds, foreign, no_vendor = (await db.execute(stmt)).one()
    return {
        "total": int(total),
        "bbmds": int(bbmds),
        "foreign_devices": int(foreign),
        "missing_vendor_id": int(no_vendor),
    }


class FindBBMDsArgs(BaseModel):
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_bbmds",
    permission=("read", "bacnet_device"),
    description=(
        "List BACnet Broadcast Management Devices with their subnet and the "
        "size of their Broadcast Distribution and Foreign Device tables. Each "
        "BACnet subnet should have exactly one BBMD — zero leaves its devices "
        "unreachable across routers, more than one duplicates broadcasts."
    ),
    args_model=FindBBMDsArgs,
    category="network",
    module=_MODULE,
    default_enabled=True,
)
async def find_bbmds(db: AsyncSession, user: User, args: FindBBMDsArgs) -> list[dict[str, Any]]:
    _ = user
    stmt = (
        select(BACnetDevice, IPAddress)
        .outerjoin(IPAddress, IPAddress.id == BACnetDevice.ip_address_id)
        .where(BACnetDevice.is_bbmd.is_(True))
        .order_by(BACnetDevice.device_instance)
        .limit(args.limit)
    )
    return [
        {
            "id": str(dev.id),
            "device_instance": dev.device_instance,
            "device_name": dev.device_name,
            "vendor": resolve_vendor_label(dev.vendor_id, dev.vendor_name),
            "address": str(ip.address) if ip is not None else None,
            "subnet_id": str(dev.subnet_id) if dev.subnet_id else None,
            "bdt_entries": len(dev.bdt or []),
            "fdt_entries": len(dev.fdt or []),
        }
        for dev, ip in (await db.execute(stmt)).all()
    ]
