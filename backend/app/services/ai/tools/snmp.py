"""Operator Copilot read tool for the appliance SNMP surface (issue #153).

Surfaces the singleton ``platform_settings`` SNMP config so an operator
can ask the Copilot "is SNMP configured?", "what community / v3 users
are set up?", or "which CIDRs are allowed to query SNMP?". The
response shape matches the ``GET /api/v1/settings/`` redaction:
``snmp_community_set`` + per-user ``auth_pass_set`` / ``priv_pass_set``
booleans, never plaintext.

Why no ``propose_update_snmp_settings`` here:

* Updating SNMP touches multiple Fernet-encrypted fields + an atomic-
  replace merge for v3 users. The dedicated Settings → Appliance →
  SNMP form is the friendly path; a Copilot ``propose_*`` over the
  same surface would re-implement that complexity without much benefit.
* SNMP is a low-frequency operator task. Read visibility is the high
  value-per-token tool; write goes through the UI.

A follow-up PR may add ``propose_update_snmp_settings`` once we have
a use case for it (e.g. fleet-wide compliance rotation).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services.ai.tools.base import register_tool


class FindSNMPSettingsArgs(BaseModel):
    """No arguments — there is exactly one SNMP config row."""

    pass


@register_tool(
    name="find_snmp_settings",
    permission="authenticated",
    description=(
        "Return the appliance SNMP configuration — master toggle, "
        "version (v2c | v3), whether the community string is set, "
        "configured v3 users (with redacted ``*_pass_set`` booleans, "
        "never plaintext), allowed-source CIDR list, and the "
        "``sysContact`` / ``sysLocation`` strings. Use to answer "
        "'is SNMP on?', 'what version is configured?', 'which users "
        "or CIDRs are allowed?'. snmpd itself runs on every "
        "SpatiumDDI appliance host (local + every registered remote "
        "agent); on docker / k8s deploys these settings still drive "
        "the appliance agents' rollout but the local control plane "
        "doesn't run snmpd."
    ),
    args_model=FindSNMPSettingsArgs,
    category="admin",
    # Default enabled (NN #13) — read-only, no secrets in response,
    # no off-prem calls. Admins discover it without having to opt in.
    default_enabled=True,
)
async def find_snmp_settings(
    db: AsyncSession, user: User, args: FindSNMPSettingsArgs
) -> dict[str, Any]:
    settings = await db.get(PlatformSettings, 1)
    if settings is None:
        return {"enabled": False, "configured": False, "note": "platform_settings row missing"}

    v3_users_redacted: list[dict[str, Any]] = []
    for u in settings.snmp_v3_users or []:
        v3_users_redacted.append(
            {
                "username": u.get("username", ""),
                "auth_protocol": u.get("auth_protocol") or "none",
                "auth_pass_set": bool(u.get("auth_pass_enc")),
                "priv_protocol": u.get("priv_protocol") or "none",
                "priv_pass_set": bool(u.get("priv_pass_enc")),
            }
        )

    return {
        "enabled": bool(settings.snmp_enabled),
        "version": settings.snmp_version,
        "community_set": bool(settings.snmp_community_encrypted),
        "v3_users": v3_users_redacted,
        "v3_user_count": len(v3_users_redacted),
        "allowed_sources": list(settings.snmp_allowed_sources or []),
        "sys_contact": settings.snmp_sys_contact or "",
        "sys_location": settings.snmp_sys_location or "",
        # Quick "is this configured enough to actually answer queries?"
        # signal for the LLM's summarisation.
        "configured": (
            bool(settings.snmp_enabled)
            and (
                (
                    settings.snmp_version == "v2c"
                    and bool(settings.snmp_community_encrypted)
                    and bool(settings.snmp_allowed_sources)
                )
                or (settings.snmp_version == "v3" and bool(settings.snmp_v3_users))
            )
        ),
    }
