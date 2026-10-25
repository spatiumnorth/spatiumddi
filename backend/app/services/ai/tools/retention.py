"""Operator Copilot read tool for the data-retention settings (issue #2273).

Answers "how long do we keep query logs / metrics / lease history?" from
the singleton ``platform_settings`` row — the same windows the nightly
prune tasks read. Nothing here is sensitive.

No ``propose_*`` write tool, deliberately (non-negotiable #13): shortening
a window deletes data on the next nightly sweep, which is the
broad-blast-radius shape that guidance keeps off the copilot. The
Settings → Data Retention form and ``PUT /settings`` are the write paths.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services.ai.tools.base import register_tool


class FindRetentionSettingsArgs(BaseModel):
    """No arguments — there is exactly one settings row."""


@register_tool(
    name="find_retention_settings",
    permission="authenticated",
    description=(
        "Return how long SpatiumDDI keeps the data it collects before the "
        "nightly prune deletes it: DNS query + DHCP activity logs "
        "(``log_retention_hours``), DNS/DHCP metric samples "
        "(``metric_retention_days``), DHCP lease history, trash "
        "(soft-deleted rows), packet captures, and revoked appliances. A "
        "value of 0 on lease history / trash / revoked appliances means "
        "never delete. The audit log is never pruned. Use for 'how far "
        "back can I see query logs?' or 'when will this deleted subnet be "
        "purged?'."
    ),
    args_model=FindRetentionSettingsArgs,
    category="admin",
    default_enabled=True,
)
async def find_retention_settings(
    db: AsyncSession, user: User, args: FindRetentionSettingsArgs
) -> dict[str, Any]:
    settings = await db.get(PlatformSettings, 1)
    if settings is None:
        return {"configured": False, "note": "platform_settings row missing"}
    return {
        "log_retention_hours": settings.log_retention_hours,
        "metric_retention_days": settings.metric_retention_days,
        "dhcp_lease_history_retention_days": settings.dhcp_lease_history_retention_days,
        "soft_delete_purge_days": settings.soft_delete_purge_days,
        "pcap_retention_days": settings.pcap_retention_days,
        "appliance_revoked_retention_days": settings.appliance_revoked_retention_days,
        "audit_log": "never pruned",
        "zero_means_keep_forever": [
            "dhcp_lease_history_retention_days",
            "soft_delete_purge_days",
            "appliance_revoked_retention_days",
        ],
    }
