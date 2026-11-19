"""Operator Copilot read tool for the appliance LLDP surface (issue #343).

Surfaces the singleton ``platform_settings`` LLDP config so an operator can
ask the Copilot "is LLDP on?", "what interfaces does it advertise on?", or
"what TTL are we sending?". No secrets — LLDP advertises public identity, so
the response mirrors the stored shape directly.

The neighbour-data tool ``find_lldp_neighbors`` (joining the appliance's
discovered L2 neighbours into IPAM) is Phase 2 — it needs the supervisor to
ship ``lldpcli show neighbors`` back to the control plane first. This tool is
the Phase-1 config-visibility counterpart, matching ``find_snmp_settings``.
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import Appliance
from app.models.auth import User
from app.models.network import ApplianceLldpNeighbour
from app.models.settings import PlatformSettings
from app.services.ai.tools.base import register_tool


class FindLLDPSettingsArgs(BaseModel):
    """No arguments — there is exactly one LLDP config row."""

    pass


@register_tool(
    name="find_lldp_settings",
    permission="authenticated",
    description=(
        "Return the appliance LLDP configuration — master toggle, transmit "
        "interval + hold (and the advertised TTL = interval × hold), which "
        "extra neighbour protocols (CDP / EDP / FDP / SONMP) are received, the "
        "interface allowlist pattern, the management-address pattern, and any "
        "system-name / description overrides. Use to answer 'is LLDP on?', "
        "'what interfaces do we advertise on?', 'what TTL are neighbours told?'. "
        "lldpd runs on every SpatiumDDI appliance host; on docker / k8s deploys "
        "these settings still drive registered appliance agents."
    ),
    args_model=FindLLDPSettingsArgs,
    category="admin",
    # Default enabled (NN #13) — read-only, no secrets, no off-prem calls.
    # module=None: LLDP is plain host-config (like SNMP/NTP), not a feature
    # module, so it stays unambiguously always-available.
    default_enabled=True,
    module=None,
)
async def find_lldp_settings(
    db: AsyncSession, user: User, args: FindLLDPSettingsArgs
) -> dict[str, Any]:
    settings = await db.get(PlatformSettings, 1)
    if settings is None:
        return {"enabled": False, "note": "platform_settings row missing"}
    interval = int(settings.lldp_tx_interval or 30)
    hold = int(settings.lldp_tx_hold or 4)
    return {
        "enabled": bool(settings.lldp_enabled),
        "tx_interval_seconds": interval,
        "tx_hold": hold,
        "advertised_ttl_seconds": max(1, interval) * max(1, hold),
        "extra_protocols_received": list(settings.lldp_protocols or []),
        "interface_pattern": settings.lldp_interface_pattern,
        "management_pattern": settings.lldp_management_pattern or "(auto)",
        "system_name_override": settings.lldp_sys_name or None,
        "system_description_override": settings.lldp_sys_description or None,
    }


class FindLLDPNeighborsArgs(BaseModel):
    appliance_id: str | None = Field(
        default=None, description="Filter to one appliance UUID (the host that saw the neighbour)."
    )
    limit: int = Field(default=200, ge=1, le=1000)


@register_tool(
    name="find_lldp_neighbors",
    permission=("read", "appliance"),
    description=(
        "List LLDP neighbours discovered by SpatiumDDI appliance hosts via their "
        "local lldpd — local interface, the remote switch/device's chassis-id, "
        "port-id, system name, management IP, and capabilities. Use to answer "
        "'what is appliance X plugged into?', 'which switch/port is it on?', or "
        "'what are my appliances' L2 neighbours?'. Populated by the supervisor "
        "heartbeat (issue #347), absence-deleted when a neighbour ages out."
    ),
    args_model=FindLLDPNeighborsArgs,
    category="network",
    default_enabled=True,
    module=None,
)
async def find_lldp_neighbors(
    db: AsyncSession, user: User, args: FindLLDPNeighborsArgs
) -> list[dict[str, Any]]:
    stmt = select(ApplianceLldpNeighbour, Appliance.hostname).join(
        Appliance, Appliance.id == ApplianceLldpNeighbour.appliance_id
    )
    if args.appliance_id:
        try:
            aid = uuid.UUID(args.appliance_id)
        except ValueError:
            # Malformed UUID — return empty rather than letting a bad value
            # hit the UUID column (driver-dependent error).
            return []
        stmt = stmt.where(ApplianceLldpNeighbour.appliance_id == aid)
    stmt = stmt.order_by(ApplianceLldpNeighbour.last_seen.desc()).limit(args.limit)
    rows = (await db.execute(stmt)).all()
    return [
        {
            "appliance_id": str(n.appliance_id),
            "appliance_hostname": hostname,
            "local_iface": n.local_iface,
            "remote_chassis_id": n.remote_chassis_id,
            "remote_port_id": n.remote_port_id,
            "remote_port_descr": n.remote_port_descr,
            "remote_sys_name": n.remote_sys_name,
            "remote_mgmt_ip": n.remote_mgmt_ip,
            "remote_caps": n.remote_caps,
            "last_seen": n.last_seen.isoformat() if n.last_seen else None,
        }
        for n, hostname in rows
    ]
