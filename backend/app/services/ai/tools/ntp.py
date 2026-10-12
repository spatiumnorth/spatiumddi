"""Operator Copilot read tool for the appliance NTP surface (issue #154).

Surfaces the singleton ``platform_settings`` NTP config so an operator
can ask the Copilot "is the appliance pointing at internal NTP?",
"which servers does it use?", or "is this appliance also serving
NTP to clients?". No redaction — NTP server hostnames are not
sensitive (contrast with the SNMP community in #153).

A ``propose_update_ntp_settings`` write tool isn't worth shipping for
the first cut — the dedicated UI form is the friendly path and there
aren't compelling LLM-driven NTP workflows yet. Easy follow-up if
demand surfaces (e.g. "rotate to internal NTP for all of EU-WEST").
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services.ai.tools.base import register_tool


class FindNTPSettingsArgs(BaseModel):
    """No arguments — there is exactly one NTP config row."""

    pass


@register_tool(
    name="find_ntp_settings",
    permission="authenticated",
    description=(
        "Return the appliance NTP / chrony configuration: source "
        "mode (``pool`` / ``servers`` / ``mixed``), the list of "
        "configured pool servers, the list of custom unicast "
        "servers (each with ``iburst`` + ``prefer`` flags), and "
        "whether this appliance is also acting as an NTP server for "
        "clients (with the allowed-client CIDR list). chrony is "
        "always running on appliance hosts — this tool answers "
        "'what time sources is the appliance using?' and 'is it "
        "serving NTP to clients?'. On docker / k8s deploys the "
        "settings still drive any registered appliance agents in a "
        "hybrid topology, but the local control plane host runs "
        "its own time-sync stack."
    ),
    args_model=FindNTPSettingsArgs,
    category="admin",
    default_enabled=True,
)
async def find_ntp_settings(
    db: AsyncSession, user: User, args: FindNTPSettingsArgs
) -> dict[str, Any]:
    settings = await db.get(PlatformSettings, 1)
    if settings is None:
        return {"configured": False, "note": "platform_settings row missing"}

    pool_servers = list(settings.ntp_pool_servers or [])
    custom_servers = list(settings.ntp_custom_servers or [])
    mode = settings.ntp_source_mode

    has_pool = mode in ("pool", "mixed") and bool(pool_servers)
    has_custom = mode in ("servers", "mixed") and bool(custom_servers)

    return {
        "source_mode": mode,
        "pool_servers": pool_servers,
        "custom_servers": [
            {
                "host": s.get("host", ""),
                "iburst": bool(s.get("iburst")),
                "prefer": bool(s.get("prefer")),
            }
            for s in custom_servers
        ],
        "allow_clients": bool(settings.ntp_allow_clients),
        "allow_client_networks": list(settings.ntp_allow_client_networks or []),
        # Aggregate signal for the LLM: is this config actually able
        # to provide time? Either the pool or the custom list needs
        # to be populated.
        "configured": has_pool or has_custom,
    }
