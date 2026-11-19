"""Operator Copilot tools for system-wide maintenance mode (issue #57).

* ``maintenance_status`` — read-only. Reports whether the platform is in
  maintenance mode, the operator message, and when it started.
  Default-enabled (discovery, no secrets, read-only).

* ``propose_set_maintenance_mode``: stages turning maintenance mode on or
  off (and optionally the banner message) as a proposal. The
  ``set_maintenance_mode`` operation (``services/ai/operations_writes.py``)
  runs only when the operator applies it, through the same rules as the
  Settings toggle: server-stamped ``maintenance_started_at``, an
  ``AuditLog`` row, and the middleware cache invalidated (#3415).
  Default-DISABLED: turning the whole platform read-only is a
  broad-blast-radius write per non-negotiable #13, so the operator opts
  this tool in from the Tool Catalog.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import maintenance_mode as _maintenance_mode
from app.models.auth import User
from app.services.ai.operations_writes import SetMaintenanceModeArgs
from app.services.ai.tools.base import register_tool

# ── maintenance_status (read) ───────────────────────────────────────


class MaintenanceStatusArgs(BaseModel):
    pass


@register_tool(
    name="maintenance_status",
    honours_token_binding=True,
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


# ── propose_set_maintenance_mode (proposal, default-disabled) ───────


@register_tool(
    name="propose_set_maintenance_mode",
    permission="superadmin",
    description=(
        "Propose turning system-wide maintenance mode on or off (issue #57), "
        "optionally with the operator banner message. Preview/apply: the "
        "model proposes, the operator clicks Apply. Maintenance mode makes "
        "the ENTIRE platform read-only (every mutating request 503s for "
        "non-superadmins), so this broad-blast-radius write is disabled by "
        "default per non-negotiable #13. Superadmin only."
    ),
    args_model=SetMaintenanceModeArgs,
    writes=False,  # The propose tool itself is read-only; apply is the write.
    category="ops",
    default_enabled=False,
    module=None,
)
async def propose_set_maintenance_mode(
    db: AsyncSession, user: User, args: SetMaintenanceModeArgs
) -> dict[str, Any]:
    from app.services.ai.tools.proposals import _propose_via  # noqa: PLC0415

    return await _propose_via(db=db, user=user, operation_name="set_maintenance_mode", args=args)


__all__ = ["maintenance_status", "propose_set_maintenance_mode"]
