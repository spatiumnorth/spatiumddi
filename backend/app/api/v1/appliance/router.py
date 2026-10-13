"""Appliance management — Phase 4 root router.

Phase 4a landed visibility gating + ``/info``. Sub-phases attach their
endpoints by including a sub-router into this APIRouter — keeps each
surface (TLS / releases / containers / etc.) in its own file but they
all share the same ``/api/v1/appliance`` prefix + permission gate.

Gating model:

* ``settings.appliance_mode`` — set by the appliance compose env. On
  non-appliance deploys the router stays mounted but ``/info`` reports
  ``appliance_mode=false`` and the frontend hides the sidebar entry.
* ``require_permission("read", "appliance")`` — RBAC gate. The
  "Appliance Operator" builtin role grants ``admin``; superadmin
  always bypasses. Layered on top of ``appliance_mode`` so a deploy
  on plain docker-compose can't smuggle out appliance-only data via
  a stolen non-superadmin token.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy import select

from app.api.deps import DB
from app.api.v1.appliance.acme import router as acme_router
from app.api.v1.appliance.cluster import router as cluster_router
from app.api.v1.appliance.containers import router as containers_router
from app.api.v1.appliance.diagnostics import router as diagnostics_router
from app.api.v1.appliance.pairing import router as pairing_router
from app.api.v1.appliance.releases import router as releases_router
from app.api.v1.appliance.slot import router as slot_router
from app.api.v1.appliance.slot_image_mirror import router as slot_image_mirror_router
from app.api.v1.appliance.supervisor import router as supervisor_router
from app.api.v1.appliance.system import router as system_router
from app.api.v1.appliance.tls import router as tls_router
from app.api.v1.appliance.upgrade_images import router as upgrade_images_router
from app.config import settings
from app.core.permissions import require_permission
from app.core.request_meta import get_trusted_client_ip
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.settings import PlatformSettings
from app.services.appliance.access import Door, effective_doors
from app.services.appliance.ownership import hostname_sql, k8s_node_name
from app.services.feature_modules import require_module

router = APIRouter()

# Sub-routers — each Phase 4 sub-surface adds itself here as its
# file lands. Prefixes are scoped under the appliance namespace so
# the URL stays /api/v1/appliance/<surface>/...
router.include_router(tls_router, prefix="/tls")
# #438 — embedded ACME client (Let's Encrypt via DNS-01). Gated behind
# the ``security.certificates`` feature module (404 when off) on top of
# the appliance read/admin permission gates on each route.
router.include_router(
    acme_router,
    prefix="/acme",
    dependencies=[Depends(require_module("security.certificates"))],
)
router.include_router(releases_router, prefix="/releases")
router.include_router(slot_router, prefix="/slot-upgrade")
# Upgrade-image management (#199 — renamed from slot-images): upload /
# import-from-github / list / download / delete. Routes already include
# the ``/upgrade-images`` prefix in their decorators (plus the legacy
# ``/slot-images`` 308-redirect shims), so no nested prefix here
# (matches the supervisor + pairing routers' shape).
router.include_router(upgrade_images_router)
# #296 Phase B — slot-image-mirror internal byte-op endpoints (PUT /
# GET / DELETE under /internal/slot-images/{id}) ONLY register on
# the mirror Deployment. The main api Deployment leaves the
# settings.slot_image_mirror_mode flag false, so requests landing
# here from a misrouted operator get a 404 from the router, not a
# 500 or a partial accept. The endpoints themselves verify the
# X-Mirror-Auth shared-secret header on top of this gate.
if settings.slot_image_mirror_mode:
    router.include_router(
        slot_image_mirror_router,
        prefix="/internal/slot-images",
    )
router.include_router(containers_router, prefix="/containers")
# #402 — Cluster health dashboard (nodes + pods + live kubelet usage).
router.include_router(cluster_router, prefix="/cluster")
router.include_router(diagnostics_router, prefix="/diagnostics")
router.include_router(system_router, prefix="/system")
# Pairing routes use no nested prefix so the URLs are
# ``/api/v1/appliance/pairing-codes`` + ``/api/v1/appliance/pair``
# rather than burying them under a redundant ``/pairing/`` segment.
router.include_router(pairing_router)
# Supervisor register routes — same no-prefix shape as pairing so the
# URL is ``/api/v1/appliance/supervisor/register`` rather than
# ``/api/v1/appliance/supervisor/supervisor/register``.
router.include_router(supervisor_router)


class RemoteDoor(BaseModel):
    """One source-restricted way in, and whether it admits this caller."""

    name: str
    restricted: bool
    allowed_cidrs: list[str]
    admits: bool


class RemoteAccessResponse(BaseModel):
    """Which remote doors currently admit the caller (#1013).

    Read by BOTH lockout-sensitive screens — Fleet \u2192 Firewall (the Web UI
    allow-list) and Fleet \u2192 SSH (the SSH allow-list) — so each can show
    the state of the OTHER door at the moment the operator is deciding. Same
    resolver the two write paths raise their 422s from, so the warning an
    operator reads and the refusal they hit cannot disagree.

    Lives on the always-mounted ``/appliance`` hub rather than under
    ``/appliance/firewall``: that sub-router is behind the
    ``appliance.firewall`` feature module, and the SSH screen must be able to
    ask this question with the module off.
    """

    caller_ip: str | None
    web_ui: RemoteDoor
    ssh: RemoteDoor
    #: True when neither door admits the caller — the console is all that is
    #: left. Already the case, not a prediction about a pending change.
    console_only: bool


def _door_out(door: Door) -> RemoteDoor:
    return RemoteDoor(
        name=door.name,
        restricted=door.restricted,
        allowed_cidrs=list(door.allowed_cidrs),
        admits=door.admits,
    )


@router.get(
    "/remote-access",
    response_model=RemoteAccessResponse,
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="Which remote doors admit this caller",
)
async def get_remote_access(request: Request, db: DB) -> RemoteAccessResponse:
    cfg = await db.get(PlatformSettings, 1)
    report = effective_doors(cfg, get_trusted_client_ip(request))
    return RemoteAccessResponse(
        caller_ip=report.caller_ip,
        web_ui=_door_out(report.web_ui),
        ssh=_door_out(report.ssh),
        console_only=report.console_only,
    )


class SelfApplianceInfo(BaseModel):
    """Identity + lifecycle of the LOCAL appliance for the browser Console
    view (#416), sourced from the self ``Appliance`` row the supervisor
    populates on heartbeat (matched by hostname, exactly as the Cluster
    Overview merge does in ``appliance/cluster.py``).

    Pure DB read — the api pod never touches host files or journald for
    this; every field rides the supervisor heartbeat. ``None`` on docker /
    k8s control planes (no supervisor) or before the local supervisor has
    registered + been approved.
    """

    state: str
    deployment_kind: str | None
    supervisor_version: str | None
    installed_appliance_version: str | None
    current_slot: str | None
    durable_default: str | None
    is_trial_boot: bool
    last_upgrade_state: str | None
    node_ip: str | None
    # ``{<compose-service>: {role, status, since, …}}`` — the supervisor's
    # service-container watchdog rollup; drives the Console's per-role
    # health chips.
    role_health: dict[str, Any]
    role_switch_state: str | None
    last_seen_at: datetime | None


class ApplianceInfo(BaseModel):
    appliance_mode: bool
    appliance_version: str | None
    appliance_hostname: str | None
    # #416 — local appliance lifecycle for the Console view; None off-box.
    self_appliance: SelfApplianceInfo | None = None


@router.get(
    "/info",
    response_model=ApplianceInfo,
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="Appliance identity + capabilities",
)
async def get_appliance_info(db: DB) -> ApplianceInfo:
    """Return the appliance's own self-description.

    Distinct from ``/api/v1/version`` (which is public so the sidebar
    can render before login). This endpoint sits behind the appliance
    read permission because it grows into a richer payload (capability
    flags, supervised container set, host network digest, the Console
    view's local lifecycle block, …) that the unauthenticated surface
    shouldn't expose.
    """
    self_info: SelfApplianceInfo | None = None
    hostname = settings.appliance_hostname or None
    if hostname:
        # Match the LOCAL appliance the same way cluster.py merges host
        # partitions: approved row whose hostname equals ours. Pick the
        # most-recently-seen if a stale re-register left duplicates.
        row = (
            await db.execute(
                select(Appliance)
                .where(
                    hostname_sql(Appliance.hostname) == k8s_node_name(hostname),
                    Appliance.state == APPLIANCE_STATE_APPROVED,
                )
                .order_by(Appliance.last_seen_at.desc().nullslast())
                .limit(1)
            )
        ).scalar_one_or_none()
        if row is not None:
            self_info = SelfApplianceInfo(
                state=row.state,
                deployment_kind=row.deployment_kind,
                supervisor_version=row.supervisor_version,
                installed_appliance_version=row.installed_appliance_version,
                current_slot=row.current_slot,
                durable_default=row.durable_default,
                is_trial_boot=row.is_trial_boot,
                last_upgrade_state=row.last_upgrade_state,
                node_ip=row.node_ip,
                role_health=row.role_health or {},
                role_switch_state=row.role_switch_state,
                last_seen_at=row.last_seen_at,
            )
    return ApplianceInfo(
        appliance_mode=settings.appliance_mode,
        appliance_version=settings.appliance_version or None,
        appliance_hostname=hostname,
        self_appliance=self_info,
    )
