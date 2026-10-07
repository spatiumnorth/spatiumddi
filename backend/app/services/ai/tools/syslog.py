"""Operator Copilot read tool for the appliance syslog surface (issue #156).

Surfaces the singleton ``platform_settings`` rsyslog-forwarding config so an
operator can ask the Copilot "is the appliance shipping logs?", "where do
they go?", or "what filter/format are we forwarding?". Per-target CA PEMs are
NEVER returned — each target's ``ca_cert_pem`` is redacted to a
``ca_cert_set`` boolean (mirrors ``find_ntp_settings`` returning hostnames
but the SNMP tooling redacting the community).

A ``propose_update_syslog_settings`` write tool lives in
``tools/proposals.py`` (default-disabled — it handles a secret CA PEM + ships
logs off-prem). This read tool is the always-available config-visibility
counterpart, matching ``find_snmp_settings`` / ``find_ntp_settings`` /
``find_lldp_settings``.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services.ai.tools.base import register_tool


class FindSyslogSettingsArgs(BaseModel):
    """No arguments — there is exactly one syslog config row."""

    pass


@register_tool(
    name="find_syslog_settings",
    permission="authenticated",
    description=(
        "Return the appliance syslog (rsyslog) forwarding configuration: the "
        "master toggle, each forward target (host / port / protocol "
        "(udp/tcp/tls) / wire format (rfc5424/rfc3164/json), with the per-target "
        "CA PEM redacted to a ``ca_cert_set`` boolean), the rsyslog selector "
        "filter, and whether disk-assisted buffering is on. Use to answer 'is "
        "the appliance shipping logs off-box?', 'where do logs go?', 'what "
        "filter / format do we forward?'. rsyslog runs on every SpatiumDDI "
        "appliance host; on docker / k8s deploys these settings still drive any "
        "registered appliance agents in a hybrid topology."
    ),
    args_model=FindSyslogSettingsArgs,
    category="admin",
    # Default enabled (NN #13) — read-only, secrets redacted, no off-prem calls.
    # module=None: syslog is plain host-config (like SNMP/NTP/LLDP), not a
    # feature module, so it stays unambiguously always-available.
    default_enabled=True,
    module=None,
)
async def find_syslog_settings(
    db: AsyncSession, user: User, args: FindSyslogSettingsArgs
) -> dict[str, Any]:
    settings = await db.get(PlatformSettings, 1)
    if settings is None:
        return {"enabled": False, "note": "platform_settings row missing"}
    targets = list(settings.syslog_targets or [])
    return {
        "enabled": bool(settings.syslog_enabled),
        "targets": [
            {
                "host": (t.get("host") or "") if isinstance(t, dict) else "",
                "port": int(t.get("port") or 514) if isinstance(t, dict) else 514,
                "protocol": (t.get("protocol") or "udp") if isinstance(t, dict) else "udp",
                "format": (t.get("format") or "rfc5424") if isinstance(t, dict) else "rfc5424",
                # CA PEM is a secret — redact to a presence boolean.
                "ca_cert_set": bool(t.get("ca_cert_pem")) if isinstance(t, dict) else False,
            }
            for t in targets
        ],
        "filter": settings.syslog_filter or "*.*",
        "buffer_disk": bool(settings.syslog_buffer_disk),
        # Aggregate signal for the LLM: is forwarding actually able to ship?
        # Enabled with at least one target.
        "configured": bool(settings.syslog_enabled) and bool(targets),
    }
