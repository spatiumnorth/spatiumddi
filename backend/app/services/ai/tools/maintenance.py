"""Operator Copilot tools for system-wide maintenance mode (issue #57).

* ``maintenance_status`` — read-only. Reports whether the platform is in
  maintenance mode, the operator message, and when it started.
  Default-enabled (discovery, no secrets, read-only).

* ``set_maintenance_mode`` — write. Flips maintenance mode on / off (and
  optionally sets the banner message) through the same service path the
  Settings toggle uses: server-stamps ``maintenance_started_at``, writes
  an ``AuditLog`` row, and invalidates the middleware cache. Default-
  DISABLED — turning the whole platform read-only is a broad-blast-radius
  write per non-negotiable #13, so the operator opts this tool in.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import maintenance_mode as _maintenance_mode
from app.core.permissions import is_effective_superadmin
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services.ai.tools.base import register_tool

# ── maintenance_status (read) ───────────────────────────────────────


class MaintenanceStatusArgs(BaseModel):
    pass


@register_tool(
    name="maintenance_status",
    permission="authenticated",
    description=(
        "Report whether SpatiumDDI is in system-wide maintenance mode "
        "(issue #57). Returns the enabled flag, the operator-set banner "
        "message, and the ISO-8601 timestamp the window started (null when "
        "off). When maintenance mode is on the platform is read-only — every "
        "mutating API request 503s except for superadmins and a small exempt "
        "allow-list (auth / settings / health / agent endpoints). Read-only."
    ),
    args_model=MaintenanceStatusArgs,
    category="ops",
    default_enabled=True,
    module=None,
)
async def maintenance_status(
    db: AsyncSession,
    user: User,  # noqa: ARG001 — no per-user scoping; state is platform-global
    args: MaintenanceStatusArgs,  # noqa: ARG001 — no args
) -> dict[str, Any]:
    enabled, message, started_at = await _maintenance_mode.get_maintenance_state(db)
    started_iso = started_at.isoformat() if started_at else None
    return {
        "enabled": enabled,
        "message": message,
        "started_at": started_iso,
        "summary": (
            f"Maintenance mode is ON (since {started_iso}) — the platform is read-only."
            if enabled
            else "Maintenance mode is off — the platform is fully writable."
        ),
    }


# ── set_maintenance_mode (write, default-disabled) ──────────────────


class SetMaintenanceModeArgs(BaseModel):
    enabled: bool = Field(
        description="Desired state: true puts the whole platform read-only, false lifts it."
    )
    message: str | None = Field(
        default=None,
        description=(
            "Optional banner / 503-body message shown to operators while the "
            "window is active. Omit to leave the existing message unchanged. "
            "Max 500 characters."
        ),
    )


@register_tool(
    name="set_maintenance_mode",
    permission="superadmin",
    description=(
        "Turn system-wide maintenance mode on or off (issue #57). DISABLED by "
        "default — flipping maintenance mode makes the ENTIRE platform "
        "read-only (every mutating request 503s for non-superadmins), so this "
        "broad-blast-radius write is opt-in per non-negotiable #13. Superadmin "
        "only. Stamps the start time on enable, clears it on disable, and "
        "writes an audit row. Optionally set the operator banner message."
    ),
    args_model=SetMaintenanceModeArgs,
    writes=True,
    category="ops",
    default_enabled=False,
    module=None,
)
async def set_maintenance_mode(
    db: AsyncSession, user: User, args: SetMaintenanceModeArgs
) -> dict[str, Any]:
    if not is_effective_superadmin(user):
        return {
            "error": (
                "Maintenance mode can only be toggled by a superadmin. "
                "Ask your platform admin to run this."
            )
        }
    if args.message is not None and len(args.message) > 500:
        return {"error": "message must be 500 characters or fewer"}

    row = (
        await db.execute(select(PlatformSettings).where(PlatformSettings.id == 1))
    ).scalar_one_or_none()
    if row is None:
        row = PlatformSettings(id=1)
        db.add(row)

    prev = bool(row.maintenance_mode_enabled)
    row.maintenance_mode_enabled = args.enabled
    if args.message is not None:
        row.maintenance_message = args.message

    flipped = args.enabled != prev
    if flipped:
        row.maintenance_started_at = datetime.now(UTC) if args.enabled else None
        db.add(
            AuditLog(
                user_id=user.id,
                user_display_name=user.display_name,
                auth_source=user.auth_source,
                action=(
                    "maintenance_mode.enabled" if args.enabled else "maintenance_mode.disabled"
                ),
                resource_type="platform_settings",
                resource_id="maintenance",
                resource_display="Maintenance mode",
                result="success",
                new_value={"enabled": args.enabled, "message": row.maintenance_message or ""},
            )
        )

    await db.commit()
    await db.refresh(row)
    _maintenance_mode.invalidate_cache()

    return {
        "ok": True,
        "enabled": bool(row.maintenance_mode_enabled),
        "message": row.maintenance_message or "",
        "started_at": (
            row.maintenance_started_at.isoformat() if row.maintenance_started_at else None
        ),
        "changed": flipped,
    }


__all__ = ["maintenance_status", "set_maintenance_mode"]
