"""Phase 8b-3 — operator-facing slot upgrade endpoint.

Mounted at ``/api/v1/appliance/slot-upgrade``. Endpoints:
    GET    /            — slot status + log tail (polled by UI)
    POST   /apply       — schedule an apply (writes apply trigger)
    POST   /rollback    — Phase 8c-3: durably switch to the inactive
                          slot (writes rollback trigger; operator
                          reboots when ready)
"""

from __future__ import annotations

from typing import Literal

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.api.deps import DB, CurrentUser
from app.config import settings
from app.core.permissions import require_permission
from app.models.appliance import CLUSTER_ROLES, Appliance
from app.models.audit import AuditLog
from app.services.appliance.slot import (
    SlotStatus,
    can_rollback,
    get_slot_status,
    is_apply_in_flight,
    schedule_apply,
    schedule_rollback,
)
from app.services.upgrades.schema_rollback import (
    SchemaRollbackCheck,
    check_release_can_run,
    enforce,
)

logger = structlog.get_logger(__name__)

router = APIRouter()


class SlotStatusResponse(BaseModel):
    # WHICH NODE THIS ANSWER IS ABOUT. Every other field here is read from
    # the responding pod's own host mounts, and the api Deployment runs one
    # replica per control-plane node behind a Service with no session
    # affinity — so on a cluster consecutive polls of this endpoint are
    # answered by different nodes, even when the caller addressed one node's
    # own IP. Without this field that is invisible: each response is a
    # well-formed 200 describing a machine the caller never named.
    #
    # Empty string on non-appliance deploys (no downward API, and only one
    # place the answer could have come from).
    node: str
    appliance_mode: bool
    current_slot: str | None
    durable_default: str | None
    is_trial_boot: bool
    upgrade_state: str
    upgrade_state_at: str | None
    log_tail: str
    # Per-slot installed APPLIANCE_VERSION sourced from the
    # ``slot-versions.json`` sidecar that spatium-upgrade-slot maintains.
    # None when the sidecar is missing (pre-Phase-8 install, or this
    # appliance hasn't booted post-upgrade yet so firstboot hasn't
    # written it).
    slot_a_version: str | None
    slot_b_version: str | None


class ApplyRequest(BaseModel):
    image_url: str = Field(
        min_length=1,
        max_length=2048,
        description="URL or absolute filesystem path to a slot .raw.xz image",
    )
    checksum_url: str | None = Field(
        default=None,
        max_length=2048,
        description="Optional URL or path to a SHA-256 sidecar (single hash + filename line)",
    )


class ApplyResponse(BaseModel):
    scheduled: str


async def _reject_if_clustered(db: DB, action: str) -> None:
    """Refuse a node-local WRITE when this deployment has more than one
    appliance node.

    ``schedule_apply``/``schedule_rollback`` write trigger files into
    ``/var/lib/spatiumddi-host/release-state``, which is a hostPath on the
    node the responding pod happens to occupy. That is correct on a
    single-node appliance — there is exactly one node, and it is this one.
    On a cluster it is not: the api Deployment runs one replica per
    control-plane node behind a Service with no session affinity, so the
    node that receives this POST is chosen by the load balancer. The
    operator asks to upgrade an appliance and an arbitrary machine writes
    its inactive slot; addressing a node's own IP does not change that,
    because the IP selects an ingress, not a pod.

    A wrong-node upgrade is silent — 202 Accepted, a real upgrade, on a
    host nobody named — so this refuses rather than guesses. The
    per-appliance endpoints
    (``POST /appliance/appliances/{id}/upgrade``, ``/set-next-boot``,
    ``/set-default-slot``) are the node-addressed path: they stamp desired
    state on that appliance's row and the target node's own supervisor
    writes the trigger on its own disk.

    Counts CONTROL-PLANE nodes, not approved appliances: ``cluster_role`` is
    NULL for a data-plane appliance and for a single node that has not been
    promoted, and becomes primary/member only on promotion. That is the same
    quantity the api Deployment's replica count tracks, so it is exactly the
    condition that makes "which node answered?" ambiguous — a single-node
    control plane with paired data-plane appliances stays unambiguous and
    keeps working.
    """
    nodes = (
        await db.execute(
            select(func.count())
            .select_from(Appliance)
            .where(Appliance.cluster_role.in_(CLUSTER_ROLES))
        )
    ).scalar_one()
    if nodes > 1:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{action} is unavailable on a clustered deployment: this endpoint "
            f"acts on whichever node serves the request ({settings.node_name or 'unknown'}), "
            f"not on one you can choose, and this cluster has {nodes} control-plane nodes. "
            "Use POST /api/v1/appliance/appliances/{appliance_id}/upgrade, which "
            "targets a node by id and lets that node's own supervisor apply it.",
        )


def _serialise(s: SlotStatus) -> SlotStatusResponse:
    return SlotStatusResponse(
        node=settings.node_name,
        appliance_mode=s.appliance_mode,
        current_slot=s.current_slot,
        durable_default=s.durable_default,
        is_trial_boot=s.is_trial_boot,
        upgrade_state=s.upgrade_state,
        upgrade_state_at=s.upgrade_state_at,
        log_tail=s.log_tail,
        slot_a_version=s.slot_a_version,
        slot_b_version=s.slot_b_version,
    )


@router.get(
    "",
    response_model=SlotStatusResponse,
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="Current A/B slot state + upgrade progress",
)
async def get_status() -> SlotStatusResponse:
    return _serialise(get_slot_status())


@router.post(
    "/apply",
    response_model=ApplyResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Schedule a slot upgrade — writes the image to the inactive slot + arms next-boot",
)
async def apply(
    body: ApplyRequest,
    db: DB,
    user: CurrentUser,
) -> ApplyResponse:
    await _reject_if_clustered(db, "slot-upgrade apply")
    if is_apply_in_flight():
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "a slot upgrade is already in flight — wait for it to finish",
        )
    try:
        schedule_apply(body.image_url, body.checksum_url)
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="apply_slot_upgrade",
            resource_type="appliance",
            resource_id="slot",
            resource_display=body.image_url,
            new_value={"image_url": body.image_url, "checksum_url": body.checksum_url},
            result="success",
        )
    )
    await db.commit()
    logger.info(
        "appliance_slot_upgrade_apply_requested", image_url=body.image_url, user=user.username
    )
    return ApplyResponse(scheduled=body.image_url)


class RollbackRequest(BaseModel):
    target_slot: Literal["slot_a", "slot_b"] | None = Field(
        default=None,
        description=(
            "Explicit slot to commit as the durable default. When omitted, "
            "the host-side runner picks the inactive slot — the typical "
            "'go back to the previously-running slot' intent."
        ),
    )
    acknowledge_schema_rollback: bool = Field(
        default=False,
        description=(
            "Proceed even though the target slot's release cannot run on the "
            "database as it is now (#1227). Without it that case is a 409 "
            "whose detail.code is 'schema_rollback_unsafe'."
        ),
    )


class SchemaRollbackCheckOut(BaseModel):
    """Whether a release can start on the database as it is now (#1227)."""

    # "incompatible" is only ever returned with the acknowledgement; without
    # it that verdict is the 409.
    verdict: Literal["compatible", "incompatible", "unknown"]
    target_version: str | None
    target_head: str | None
    head_source: Literal["recorded", "bundled"] | None
    database_revision: str | None
    message: str


class RollbackResponse(BaseModel):
    scheduled: str
    target_slot: str | None
    # The target slot's release judged against the database. None when
    # rolling onto the slot already running, which changes nothing.
    schema_check: SchemaRollbackCheckOut | None = None


@router.post(
    "/rollback",
    response_model=RollbackResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary=(
        "Schedule a slot rollback — durably flips the inactive slot to be the "
        "next-boot default (operator reboots when ready)"
    ),
)
async def rollback(
    body: RollbackRequest,
    db: DB,
    user: CurrentUser,
) -> RollbackResponse:
    """Phase 8c-3 — operator-driven rollback.

    Distinct from the trial-boot auto-revert (which is the kernel-panic
    / health-check safety net during the trial window). This is the
    'I just upgraded and want to revert' button — explicit operator
    choice, no health gate. Calls ``grub-set-default`` durably; the
    swap doesn't take effect until the operator reboots.

    Refused with 409 when the target slot's release cannot run on the
    database as it is now, unless ``acknowledge_schema_rollback`` is set
    (#1227): the database survives the swap, and an older release cannot
    start on a schema a newer one migrated.
    """
    await _reject_if_clustered(db, "slot-upgrade rollback")
    if is_apply_in_flight():
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "a slot upgrade is in flight — wait for it to finish before rolling back",
        )
    if not can_rollback():
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "rollback isn't available — appliance_mode off, or active slot couldn't be detected",
        )

    # #1227 — the database stays on /var across the swap. Judge the release
    # being switched TO before writing the trigger, because afterwards the
    # only thing that can still answer is gone.
    slots = get_slot_status()
    target = body.target_slot or (
        "slot_b" if slots.current_slot == "slot_a" else "slot_a" if slots.current_slot else None
    )
    schema_check: SchemaRollbackCheck | None = None
    if target is not None and target != slots.current_slot:
        check = await check_release_can_run(
            db, slots.slot_a_version if target == "slot_a" else slots.slot_b_version
        )
        enforce(check, acknowledged=body.acknowledge_schema_rollback)
        schema_check = check

    try:
        schedule_rollback(body.target_slot)
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="rollback_slot_upgrade",
            resource_type="appliance",
            resource_id="slot",
            resource_display=body.target_slot or "(inactive)",
            new_value={
                "target_slot": body.target_slot,
                "schema_check": schema_check.to_dict() if schema_check else None,
                "acknowledge_schema_rollback": body.acknowledge_schema_rollback,
            },
            result="success",
        )
    )
    await db.commit()
    logger.info(
        "appliance_slot_upgrade_rollback_requested",
        target_slot=body.target_slot,
        user=user.username,
    )
    return RollbackResponse(
        scheduled="rollback",
        target_slot=body.target_slot,
        schema_check=(SchemaRollbackCheckOut(**schema_check.to_dict()) if schema_check else None),
    )
