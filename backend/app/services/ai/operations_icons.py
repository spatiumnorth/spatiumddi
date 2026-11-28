"""Copilot write operations for built-in icons (#5022).

``set_ip_address_icon`` and ``set_dns_record_icon`` set or clear the explicit
icon on one address or one DNS record. Both are display-only changes: no DNS
op, no zone serial bump, no ``user_modified_at`` stamp. They are reached
through the single ``propose_set_icon`` tool (``tools/icons.py``), which picks
the operation by target, so each operation declares the gate of its REST twin.
"""

from __future__ import annotations

import ipaddress
import uuid
from typing import Any

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp._audit import write_audit
from app.models.auth import User
from app.models.dns import DNSRecord
from app.models.ipam import Subnet
from app.services.ai.operations import (
    _OPERATIONS,
    Operation,
    OperationPermissionError,
    PreviewResult,
    _address_write_refusal,
    _user_can_write_zone_records,
    _zone_records_refusal,
    enforce_operation_permission,
    register,
)
from app.services.icons import icon_label, validate_icon
from app.services.ipam.live_address import get_live_address

_ICON_FIELD = Field(
    default=None,
    description=(
        "Built-in icon name as returned by find_icons, like 'mdi:printer'. "
        "Omit or null to clear the choice and go back to the automatic icon."
    ),
)


def _uuid_text(v: Any) -> Any:
    """Keep the id as text (the proposal row stores the args as JSON) but refuse
    anything that is not a UUID."""
    if isinstance(v, uuid.UUID):
        return str(v)
    if isinstance(v, str):
        try:
            return str(uuid.UUID(v))
        except ValueError:
            raise ValueError("must be a UUID") from None
    return v


class SetIPAddressIconArgs(BaseModel):
    address_id: str = Field(
        description="UUID of the IP address row.", json_schema_extra={"x-resource": "ip_address"}
    )
    icon: str | None = _ICON_FIELD

    @field_validator("address_id", mode="before")
    @classmethod
    def _id(cls, v: Any) -> Any:
        return _uuid_text(v)

    @field_validator("icon", mode="before")
    @classmethod
    def _icon(cls, v: Any) -> Any:
        return validate_icon(v)


class SetDNSRecordIconArgs(BaseModel):
    record_id: str = Field(
        description="UUID of the DNS record.", json_schema_extra={"x-resource": "dns_record"}
    )
    icon: str | None = _ICON_FIELD

    @field_validator("record_id", mode="before")
    @classmethod
    def _id(cls, v: Any) -> Any:
        return _uuid_text(v)

    @field_validator("icon", mode="before")
    @classmethod
    def _icon(cls, v: Any) -> Any:
        return validate_icon(v)


def _describe(what: str, old: str | None, new: str | None) -> str:
    if new is None:
        return f"Clear the explicit icon on {what} (currently {old or 'none'}); it goes back to automatic."
    return f"Set the icon of {what} to **{icon_label(new)}** (`{new}`), was {old or 'automatic'}."


async def _ip_target(
    db: AsyncSession, user: User, address_id: str
) -> tuple[Any, OperationPermissionError | None]:
    ip = await get_live_address(db, uuid.UUID(address_id))
    if ip is None:
        return None, None
    subnet = await db.get(Subnet, ip.subnet_id)
    if subnet is None:
        return None, None
    refusal = await _address_write_refusal(db, user, subnet, ipaddress.ip_address(str(ip.address)))
    return ip, refusal


async def _preview_set_ip_icon(
    db: AsyncSession, user: User, args: SetIPAddressIconArgs
) -> PreviewResult:
    ip, refusal = await _ip_target(db, user, args.address_id)
    if ip is None:
        return PreviewResult(ok=False, detail=f"IP address {args.address_id} not found")
    if refusal is not None:
        return PreviewResult(ok=False, detail=str(refusal), forbidden_detail=str(refusal))
    if ip.auto_from_lease:
        return PreviewResult(
            ok=False,
            detail="This IP mirrors a dynamic DHCP lease and is managed by the DHCP server",
        )
    return PreviewResult(
        ok=True,
        detail="ready",
        preview_text=_describe(f"**{ip.address}**", ip.icon, args.icon),
        idempotent=ip.icon == args.icon,
    )


async def _apply_set_ip_icon(
    db: AsyncSession, user: User, args: SetIPAddressIconArgs
) -> dict[str, Any]:
    enforce_operation_permission(user, _OPERATIONS["set_ip_address_icon"])
    ip, refusal = await _ip_target(db, user, args.address_id)
    if ip is None:
        raise ValueError(f"IP address {args.address_id} not found")
    if refusal is not None:
        raise refusal
    if ip.auto_from_lease:
        raise ValueError("This IP mirrors a dynamic DHCP lease and is managed by the DHCP server")
    old = ip.icon
    ip.icon = args.icon
    if old != args.icon:
        write_audit(
            db,
            user=user,
            action="update",
            resource_type="ip_address",
            resource_id=str(ip.id),
            resource_display=str(ip.address),
            changed_fields=["icon"],
            old_value={"icon": old},
            new_value={"icon": args.icon, "via": "ai_proposal"},
        )
    await db.commit()
    return {"id": str(ip.id), "icon": ip.icon, "changed": old != args.icon}


async def _record(db: AsyncSession, record_id: str) -> DNSRecord | None:
    return (
        await db.execute(select(DNSRecord).where(DNSRecord.id == uuid.UUID(record_id)))
    ).scalar_one_or_none()


def _record_refusal(user: User, record: DNSRecord) -> OperationPermissionError | None:
    if _user_can_write_zone_records(user, record.zone_id):
        return None
    return _zone_records_refusal(user, record.zone_id)


async def _preview_set_record_icon(
    db: AsyncSession, user: User, args: SetDNSRecordIconArgs
) -> PreviewResult:
    record = await _record(db, args.record_id)
    if record is None:
        return PreviewResult(ok=False, detail=f"DNS record {args.record_id} not found")
    refusal = _record_refusal(user, record)
    if refusal is not None:
        return PreviewResult(ok=False, detail=str(refusal), forbidden_detail=str(refusal))
    return PreviewResult(
        ok=True,
        detail="ready",
        preview_text=_describe(f"**{record.fqdn}** ({record.record_type})", record.icon, args.icon),
        idempotent=record.icon == args.icon,
    )


async def _apply_set_record_icon(
    db: AsyncSession, user: User, args: SetDNSRecordIconArgs
) -> dict[str, Any]:
    enforce_operation_permission(user, _OPERATIONS["set_dns_record_icon"])
    record = await _record(db, args.record_id)
    if record is None:
        raise ValueError(f"DNS record {args.record_id} not found")
    refusal = _record_refusal(user, record)
    if refusal is not None:
        raise refusal
    old = record.icon
    record.icon = args.icon
    if old != args.icon:
        write_audit(
            db,
            user=user,
            action="update",
            resource_type="dns_record",
            resource_id=str(record.id),
            resource_display=record.fqdn,
            changed_fields=["icon"],
            old_value={"icon": old},
            new_value={"icon": args.icon, "via": "ai_proposal"},
        )
    await db.commit()
    return {"id": str(record.id), "icon": record.icon, "changed": old != args.icon}


register(
    Operation(
        name="set_ip_address_icon",
        description=(
            "Set or clear the explicit built-in icon on one IP address. Always go "
            "through propose_set_icon."
        ),
        args_model=SetIPAddressIconArgs,
        preview=_preview_set_ip_icon,
        apply=_apply_set_ip_icon,
        category="ipam",
        # The REST address write: write on the owning subnet, or on an address
        # set covering the address (#103); ``_ip_target`` holds it to its own row.
        required_permission=("write", "subnet"),
        scoped_grant_types=("subnet", "address_set"),
    )
)

register(
    Operation(
        name="set_dns_record_icon",
        description=(
            "Set or clear the explicit built-in icon on one DNS record. Always go "
            "through propose_set_icon."
        ),
        args_model=SetDNSRecordIconArgs,
        preview=_preview_set_record_icon,
        apply=_apply_set_record_icon,
        category="dns",
        required_permission=("write", "dns_record"),
    )
)
