"""Appliance system info + lifecycle endpoints (Phase 4f).

Mounted at ``/api/v1/appliance/system``:
    GET   /info                — read-only snapshot
    POST  /maintenance         — set maintenance-mode flag (body: {enabled})
    POST  /reboot              — schedule a host reboot (10 s grace)
"""

from __future__ import annotations

from dataclasses import asdict

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.api.deps import DB, CurrentUser
from app.core.permissions import require_permission
from app.models.audit import AuditLog
from app.services.appliance.cluster_guard import (
    clustered_refusal,
    control_plane_node_count,
    reject_if_clustered,
)
from app.services.appliance.setup import (
    get_setup_state,
    mark_setup_complete,
)
from app.services.appliance.system import (
    get_system_info,
    request_reboot,
    set_maintenance_mode,
)

logger = structlog.get_logger(__name__)

router = APIRouter()

_REBOOT_ALTERNATIVE = (
    "Use Fleet's per-appliance reboot (POST /api/v1/appliance/appliances/"
    "{appliance_id}/reboot), which targets a node by id and lets that "
    "node's own supervisor reboot it."
)


class MaintenanceRequest(BaseModel):
    enabled: bool


@router.get(
    "/info",
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="Hostname / IPs / uptime / maintenance + reboot status",
)
async def info(db: DB) -> dict:
    out = asdict(get_system_info())
    # #3011 — the local reboot acts on whichever node answers; on a
    # multi-node control plane the UI shows a Fleet link instead.
    nodes = await control_plane_node_count(db)
    out["reboot_available"] = nodes <= 1
    out["reboot_unavailable_reason"] = (
        clustered_refusal("Reboot", nodes, _REBOOT_ALTERNATIVE) if nodes > 1 else None
    )
    return out


@router.post(
    "/maintenance",
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Toggle maintenance-mode flag",
)
async def set_maintenance(
    body: MaintenanceRequest,
    db: DB,
    user: CurrentUser,
) -> dict:
    try:
        state = set_maintenance_mode(body.enabled)
    except RuntimeError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="set_maintenance_mode",
            resource_type="appliance",
            resource_id="maintenance",
            resource_display="maintenance",
            new_value={"enabled": state},
            result="success",
        )
    )
    await db.commit()
    return {"maintenance_mode": state}


@router.get(
    "/setup",
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="Get web-setup-wizard completion state",
)
async def get_setup() -> dict:
    return get_setup_state()


@router.post(
    "/setup/complete",
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Mark the setup wizard as complete",
)
async def complete_setup(db: DB, user: CurrentUser) -> dict:
    try:
        stamp = mark_setup_complete(user.username)
    except RuntimeError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="setup_complete",
            resource_type="appliance",
            resource_id="setup",
            resource_display="setup wizard",
            new_value={"completed_at": stamp},
            result="success",
        )
    )
    await db.commit()
    return {"complete": True, "completed_at": stamp}


@router.post(
    "/reboot",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Schedule a host reboot (10 s grace)",
)
async def post_reboot(db: DB, user: CurrentUser) -> dict:
    await reject_if_clustered(db, "Reboot", _REBOOT_ALTERNATIVE)
    try:
        request_reboot(grace_seconds=10)
    except RuntimeError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="reboot_requested",
            resource_type="appliance",
            resource_id="reboot",
            resource_display="reboot",
            result="success",
        )
    )
    await db.commit()
    logger.info("appliance_reboot_endpoint_fired", user=user.username)
    return {"scheduled": True, "grace_seconds": 10}
