"""Operator-Copilot tools for industrial / OT network awareness (#542).

Read-only tools over the OT device registry and Purdue-model zoning.
All gated on the ``network.ot`` feature module so they leave the
registry in lock-step with the feature surface.

**Read-only by design, not just by phase.** This module identifies and
inventories industrial devices; it never reads tags, writes coils or
registers, or otherwise touches a control protocol. That boundary is a
safety posture, not a roadmap gap — see ``docs/features/VERTICALS.md``.

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
from app.models.ipam import IPAddress
from app.models.ot import OT_PROTOCOLS, OT_ROLES, OTDevice, OTZone
from app.services.ai.tools.base import register_tool
from app.services.ot.zones import purdue_to_str

_MODULE = "network.ot"


class FindOTDevicesArgs(BaseModel):
    ot_protocol: str | None = Field(
        default=None,
        description=(
            "Filter to one industrial protocol: profinet / ethernet_ip / "
            "modbus_tcp / opc_ua / s7comm / bacnet_ip / dnp3 / iec61850 / other."
        ),
    )
    ot_role: str | None = Field(
        default=None,
        description=(
            "Filter to one role: plc / io_device / hmi / drive / gateway / "
            "sensor / historian / ews / switch / other."
        ),
    )
    purdue_level: float | None = Field(
        default=None, ge=0, le=5, description="Filter to one Purdue level (0-5; 3.5 is the DMZ)."
    )
    cell_area: str | None = Field(default=None, description="Exact cell / area name.")
    subnet_id: UUID | None = Field(default=None, description="Restrict to one subnet.")
    q: str | None = Field(
        default=None,
        description=(
            "Case-insensitive substring on PROFINET device name, vendor, " "product, or serial."
        ),
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_ot_devices",
    permission=("read", "ot_device"),
    description=(
        "List industrial / OT devices (PROFINET, EtherNet/IP, Modbus TCP, "
        "OPC UA, S7) with their protocol, role, vendor, PROFINET device name "
        "and Purdue level. Use this to answer 'what PLCs are on this subnet', "
        "'find the device named X', or 'what sits at Purdue level N'."
    ),
    args_model=FindOTDevicesArgs,
    category="network",
    module=_MODULE,
    # Read-only industrial inventory. Identification only — this tool
    # cannot read or write any control protocol.
    default_enabled=True,
)
async def find_ot_devices(
    db: AsyncSession, user: User, args: FindOTDevicesArgs
) -> list[dict[str, Any]]:
    _ = user
    if args.ot_protocol is not None and args.ot_protocol not in OT_PROTOCOLS:
        return [
            {
                "error": (
                    f"Unknown ot_protocol {args.ot_protocol!r}. "
                    f"Valid: {', '.join(sorted(OT_PROTOCOLS))}."
                )
            }
        ]
    if args.ot_role is not None and args.ot_role not in OT_ROLES:
        return [
            {"error": (f"Unknown ot_role {args.ot_role!r}. Valid: {', '.join(sorted(OT_ROLES))}.")}
        ]

    stmt = select(OTDevice, IPAddress).outerjoin(IPAddress, IPAddress.id == OTDevice.ip_address_id)
    if args.ot_protocol is not None:
        stmt = stmt.where(OTDevice.ot_protocol == args.ot_protocol)
    if args.ot_role is not None:
        stmt = stmt.where(OTDevice.ot_role == args.ot_role)
    if args.purdue_level is not None:
        stmt = stmt.where(OTDevice.purdue_level == args.purdue_level)
    if args.cell_area:
        stmt = stmt.where(OTDevice.cell_area == args.cell_area)
    if args.subnet_id is not None:
        stmt = stmt.where(IPAddress.subnet_id == args.subnet_id)
    if args.q:
        needle = f"%{args.q}%"
        stmt = stmt.where(
            or_(
                OTDevice.profinet_device_name.ilike(needle),
                OTDevice.ot_vendor.ilike(needle),
                OTDevice.ot_product.ilike(needle),
                OTDevice.ot_serial.ilike(needle),
            )
        )
    stmt = stmt.limit(args.limit)

    return [
        {
            "id": str(dev.id),
            "address": str(ip.address) if ip is not None else None,
            "subnet_id": str(ip.subnet_id) if ip is not None and ip.subnet_id else None,
            "ot_protocol": dev.ot_protocol,
            "ot_role": dev.ot_role,
            "profinet_device_name": dev.profinet_device_name,
            "ot_vendor": dev.ot_vendor,
            "ot_product": dev.ot_product,
            "ot_serial": dev.ot_serial,
            "firmware_rev": dev.firmware_rev,
            "purdue_level": purdue_to_str(dev.purdue_level),
            "cell_area": dev.cell_area,
            "seen_via": dev.seen_via,
            "last_seen_at": dev.last_seen_at.isoformat() if dev.last_seen_at else None,
        }
        for dev, ip in (await db.execute(stmt)).all()
    ]


class CountOTDevicesArgs(BaseModel):
    group_by: str = Field(
        default="ot_protocol",
        description="Group the counts by 'ot_protocol', 'ot_role', or 'purdue_level'.",
    )


@register_tool(
    name="count_ot_devices",
    permission=("read", "ot_device"),
    description=(
        "Count industrial / OT devices grouped by protocol, role, or Purdue "
        "level. Use for an estate rollup such as 'how many PLCs do we have' "
        "or 'how is the plant distributed across Purdue levels'."
    ),
    args_model=CountOTDevicesArgs,
    category="network",
    module=_MODULE,
    default_enabled=True,
)
async def count_ot_devices(
    db: AsyncSession, user: User, args: CountOTDevicesArgs
) -> dict[str, Any]:
    _ = user
    columns = {
        "ot_protocol": OTDevice.ot_protocol,
        "ot_role": OTDevice.ot_role,
        "purdue_level": OTDevice.purdue_level,
    }
    column = columns.get(args.group_by)
    if column is None:
        return {
            "error": (
                f"Unknown group_by {args.group_by!r}. " f"Valid: {', '.join(sorted(columns))}."
            )
        }
    rows = (await db.execute(select(column, func.count(OTDevice.id)).group_by(column))).all()
    counts = {("(unset)" if key is None else str(key)): int(n) for key, n in rows}
    return {
        "total": sum(counts.values()),
        "group_by": args.group_by,
        "counts": counts,
    }


class FindOTZonesArgs(BaseModel):
    purdue_level: float | None = Field(
        default=None, ge=0, le=5, description="Filter to one Purdue level."
    )
    cell_area: str | None = Field(default=None, description="Exact cell / area name.")
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_ot_zones",
    permission=("read", "ot_device"),
    description=(
        "List OT zone records — which subnet is zoned at which Purdue level "
        "and cell/area. This is the segmentation documentation the "
        "ot_device_crosses_purdue_boundary conformity check evaluates against."
    ),
    args_model=FindOTZonesArgs,
    category="network",
    module=_MODULE,
    default_enabled=True,
)
async def find_ot_zones(
    db: AsyncSession, user: User, args: FindOTZonesArgs
) -> list[dict[str, Any]]:
    _ = user
    stmt = select(OTZone)
    if args.purdue_level is not None:
        stmt = stmt.where(OTZone.purdue_level == args.purdue_level)
    if args.cell_area:
        stmt = stmt.where(OTZone.cell_area == args.cell_area)
    stmt = stmt.limit(args.limit)

    return [
        {
            "id": str(z.id),
            "subnet_id": str(z.subnet_id),
            "purdue_level": purdue_to_str(z.purdue_level),
            "cell_area": z.cell_area,
            "name": z.name,
            "description": z.description,
        }
        for z in (await db.execute(stmt)).scalars().all()
    ]
