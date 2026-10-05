"""Operator Copilot read tool for the appliance APT surface (issue #155).

Surfaces the singleton ``platform_settings`` APT config so an operator
can ask the Copilot "is APT management on?", "what mirrors are
configured?", "is a proxy set?", or "are private-mirror creds
configured?". The response matches the ``GET /api/v1/settings/``
redaction: GPG armoured-key text + auth passwords fold into
``armoured_text_set`` / ``password_set`` booleans, never plaintext, and
a credential embedded in a proxy URL reads as ``***``.

Read-only. No ``propose_update_apt_settings`` — same reasoning as the
SNMP tool: APT management touches Fernet-encrypted fields + a
validate-before-swap host runner, and the friendly path is the
Settings → Appliance → APT form (which has the all-important Validate
button). Read visibility is the high value-per-token tool here.

``module=None`` (always available) — there is no ``appliance.apt``
feature module in the catalog; appliance host-config tools are gated at
the handler level (superadmin / appliance mode), like the SNMP / NTP
host-config tools (issue #479).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services.ai.tools.base import register_tool
from app.services.appliance.apt import mask_proxy_url


class FindAptSettingsArgs(BaseModel):
    """No arguments — there is exactly one APT config row."""

    pass


@register_tool(
    name="find_apt_settings",
    description=(
        "Return the appliance APT configuration — whether SpatiumDDI "
        "manages apt (apt_managed), the configured repository sources "
        "(name / uri / suites / components / enabled), how many GPG "
        "keys + private-mirror credentials are set (redacted booleans, "
        "never the armoured key text or passwords), the HTTP/HTTPS proxy "
        "URLs (any embedded credential masked as ***) + no_proxy list, and whether unattended-upgrades is on. "
        "Use to answer 'is apt managed?', 'what mirror are we pulling "
        "from?', 'is a proxy configured?', or 'are security updates "
        "enabled?'. Managed apt config rolls out to every SpatiumDDI "
        "appliance host; docker / k8s control planes still drive the "
        "appliance agents' rollout but don't apply it locally."
    ),
    args_model=FindAptSettingsArgs,
    category="admin",
    # Default enabled (NN #13) — read-only, no secrets in response.
    default_enabled=True,
)
async def find_apt_settings(
    db: AsyncSession, user: User, args: FindAptSettingsArgs
) -> dict[str, Any]:
    settings = await db.get(PlatformSettings, 1)
    if settings is None:
        return {"managed": False, "note": "platform_settings row missing"}

    sources = [
        {
            "name": s.get("name", ""),
            "uri": s.get("uri", ""),
            "suites": s.get("suites", ""),
            "components": s.get("components", ""),
            "signed_by_key_id": s.get("signed_by_key_id", ""),
            "enabled": bool(s.get("enabled", True)),
        }
        for s in (settings.apt_sources or [])
        if isinstance(s, dict)
    ]
    return {
        "managed": bool(settings.apt_managed),
        "sources": sources,
        "source_count": len(sources),
        "enabled_source_count": sum(1 for s in sources if s["enabled"]),
        "gpg_key_count": len(settings.apt_gpg_keys or []),
        "auth_entry_count": len(settings.apt_auth or []),
        # GHSA-j77h-pqg7-h2g4 — same masking as ``GET /settings``.
        "proxy_http": mask_proxy_url(settings.apt_proxy_http),
        "proxy_https": mask_proxy_url(settings.apt_proxy_https),
        "no_proxy": settings.apt_proxy_no_proxy or "",
        "unattended_upgrades_enabled": bool(settings.apt_unattended_upgrades_enabled),
        # Issue #164 — unattended-upgrades policy (the WHEN/HOW of auto-applying).
        "unattended_allowed_origins": list(settings.apt_unattended_origins or []),
        "unattended_blocklist": list(settings.apt_unattended_blocklist or []),
        "unattended_automatic_reboot": bool(settings.apt_unattended_automatic_reboot),
        "unattended_reboot_time": settings.apt_unattended_reboot_time or "02:00",
    }
