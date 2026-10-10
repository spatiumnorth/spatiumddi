"""Operator Copilot tools for service lifecycle control (issue #890).

* ``find_services`` — the live inventory plus the capability answer
  (which lifecycle backend this deployment has, and what it can do).
  Read-only, default-enabled, superadmin-only.
* ``propose_restart_service`` — gated write, **default-DISABLED**. A
  restart interrupts live DNS / DHCP / API traffic, which is the widest
  non-destructive blast radius in the product, so an operator opts in
  before the copilot can even offer it (non-negotiable #13).

Both go through ``app.services.service_control``, the same module the
REST routes use, so the copilot cannot see or act on a service the API
would not.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import is_effective_superadmin
from app.models.auth import User
from app.services import service_control
from app.services.ai import operations
from app.services.ai.tools.base import register_tool

_SUPERADMIN_ONLY = (
    "Service lifecycle control can interrupt DNS / DHCP / API traffic and "
    "is restricted to superadmin users. Ask your platform admin."
)


class FindServicesArgs(BaseModel):
    state: str | None = Field(
        default=None,
        description=("Filter by state: running / degraded / stopped / exited. Omit for all."),
    )
    name: str | None = Field(default=None, description="Substring match on service id or name.")


@register_tool(
    name="find_services",
    permission="superadmin",
    description=(
        "List the SpatiumDDI services this deployment can control, and report "
        "which lifecycle backend is live (kubernetes / compose / none), whether "
        "control is enabled, and which actions it supports. Each row carries an "
        "id, kind, state, image and readiness detail. Use to answer 'can I "
        "restart the DNS server from here?' or 'is the worker running?'. "
        "Read-only and superadmin-only."
    ),
    args_model=FindServicesArgs,
    category="ops",
    default_enabled=True,
)
async def find_services(db: AsyncSession, user: User, args: FindServicesArgs) -> dict[str, Any]:
    if not is_effective_superadmin(user):
        return {"error": _SUPERADMIN_ONLY}

    cap = await service_control.capability()
    out: dict[str, Any] = {
        "backend": cap.backend,
        "flavor": cap.flavor,
        "control_enabled": cap.enabled,
        "supported_actions": list(cap.supported_actions),
        "reason": cap.reason,
    }
    try:
        rows = await service_control.list_services(cap)
    except service_control.ServiceControlError as exc:
        # An available-but-unqueryable backend is reported as an error,
        # never as an empty inventory — "nothing to restart" and "I was
        # not allowed to look" are opposite answers.
        out["services"] = []
        out["count"] = 0
        out["error"] = str(exc)
        return out

    needle = (args.name or "").strip().lower()
    filtered = [
        r
        for r in rows
        if (not args.state or r.state == args.state)
        and (not needle or needle in r.id.lower() or needle in r.name.lower())
    ]
    out["services"] = [
        {
            "id": r.id,
            "name": r.name,
            "kind": r.kind,
            "state": r.state,
            "image": r.image,
            "detail": r.detail,
            "actions": list(r.actions),
            **({"component": r.extra["component"]} if r.extra.get("component") else {}),
        }
        for r in filtered
    ]
    out["count"] = len(filtered)
    return out


@register_tool(
    name="propose_restart_service",
    permission="superadmin",
    description=(
        "Prepare a proposal to restart one SpatiumDDI service — a compose "
        "container or a Kubernetes workload rollout. The operator must click "
        "Apply; the restart interrupts whatever that service serves. Returns "
        "kind='proposal'; surface the preview and wait for the decision. Get "
        "the service id from find_services — ids differ between docker-compose "
        "and Kubernetes."
    ),
    args_model=operations.RestartServiceArgs,
    writes=False,  # the propose tool is read-only; apply is the write
    category="admin",
    default_enabled=False,
)
async def propose_restart_service(
    db: AsyncSession, user: User, args: operations.RestartServiceArgs
) -> dict[str, Any]:
    from app.services.ai.tools.proposals import _persist_proposal, _proposal_result  # noqa: PLC0415

    op = operations.get_operation("restart_service")
    if op is None:
        return {"error": "Operation 'restart_service' is not registered"}
    preview = await op.preview(db, user, args)
    if not preview.ok:
        return {
            "kind": "proposal_rejected",
            "operation": "restart_service",
            "detail": preview.detail,
        }
    proposal = await _persist_proposal(
        db,
        user=user,
        operation="restart_service",
        args=args.model_dump(),
        preview_text=preview.preview_text,
    )
    return _proposal_result(proposal, preview_text=preview.preview_text)
