"""Cross-cutting safety rails for the rolling-upgrade orchestrator (#296 Phase H).

Two surfaces:

1. **In-flight global mutex** — when a SystemUpgradeRun is non-
   terminal (``planned`` | ``running`` | ``halted``) the orchestrator
   owns the cluster. Operator-triggered "wreck the cluster"
   operations (full-system backup creation + restore, factory reset,
   future promote/role-change paths) must refuse rather than race the
   orchestrator's mid-flight state. ``assert_no_upgrade_in_flight``
   is the gate; endpoints call it after their other auth checks and
   before any mutation.

2. **Post-upgrade cluster verification** — Phase C's per-node
   ``_step_cluster_verify`` re-runs a cheap subset of preflight
   (replication lag + quorum). Phase H expands that with two
   cluster-wide checks: CNPG instance count =
   ``Cluster.status.readyInstances`` matches spec; every DaemonSet
   pod across the cluster reports Ready (closes failure-mode #21 at
   the cluster scope rather than just per-node). The MetalLB VIP
   Service endpoint check called out in the original issue body is
   deferred — it depends on the data-plane VIP work (#272 Ph10) for
   a shape-stable target to query.

The mutex doesn't try to be a transactional lock — concurrent reads
of the system_upgrade_run row are fine. A real race between the
mutex check + an upgrade.start would be caught later by the partial
unique index ``ix_system_upgrade_run_one_active``. This module's job
is the operator-facing nicety: surface a clear 409 with the
in-flight run's id + state rather than the bare unique-violation
error a race would otherwise produce.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any

import structlog
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.system_upgrade import SystemUpgradeRun
from app.services.appliance import k8s

logger = structlog.get_logger(__name__)


_NON_TERMINAL_STATES = ("planned", "running", "halted")

# #1829 — how long the post-upgrade verify waits for CNPG to report every
# instance ready before it judges, and how often it reads. The roll's last
# events (the last node's uncordon, the end-of-roll Deployment roll) can
# leave an instance rejoining for a while; one read failed a healthy run.
_CNPG_READY_WAIT_S = 600.0
_CNPG_POLL_INTERVAL_S = 5.0


async def is_upgrade_in_flight(db: AsyncSession) -> SystemUpgradeRun | None:
    """Return the in-flight SystemUpgradeRun row, or None.

    Read-only. Cheap (single indexed query against
    ``ix_system_upgrade_run_state``). Safe to call from any operator-
    facing endpoint.
    """
    return (
        await db.execute(
            select(SystemUpgradeRun)
            .where(SystemUpgradeRun.state.in_(_NON_TERMINAL_STATES))
            .limit(1)
        )
    ).scalar_one_or_none()


async def assert_no_upgrade_in_flight(
    db: AsyncSession,
    *,
    operation_hint: str = "this operation",
) -> None:
    """Raise 409 if an upgrade is in flight.

    ``operation_hint`` goes in the error message so the operator sees
    "factory reset refused: an upgrade to 2026.06.01-1 is in flight"
    rather than a generic 409. Endpoints call this AFTER auth + other
    preconditions so it's the last gate before any cluster-touching
    work.

    Pattern (in an endpoint):
        await assert_no_upgrade_in_flight(
            db, operation_hint="factory reset"
        )
    """
    row = await is_upgrade_in_flight(db)
    if row is None:
        return
    logger.warning(
        "upgrade_mutex_refused",
        run_id=str(row.id),
        run_state=row.state,
        run_target=row.target_version,
        operation_hint=operation_hint,
    )
    raise HTTPException(
        status.HTTP_409_CONFLICT,
        detail=(
            f"Refusing {operation_hint}: a cluster rolling upgrade "
            f"(id={row.id}, state={row.state}, target={row.target_version!r}) "
            "is in flight. Wait for it to finish, or abort it first via "
            "POST /api/v1/upgrades/{id}/abort."
        ),
    )


# ── Post-upgrade cluster verification ───────────────────────────────


@dataclass(frozen=True)
class VerificationCheck:
    """One post-upgrade verification row.

    Mirrors PreflightResult so the Fleet UI can render both surfaces
    with the same component (Phase G consumes this via the
    SystemUpgradeRun row's ``progress.cluster_verify`` blob).
    """

    name: str
    level: str  # "ok" | "warn" | "fail"
    message: str
    detail: dict[str, Any]


def check_cnpg_instances_ready(
    cluster_name: str,
    namespace: str | None = None,
) -> VerificationCheck:
    """Verify ``Cluster.status.readyInstances == spec.instances``.

    Empty cluster name (single-node / non-CNPG deploy) is a clean
    skip; non-existent cluster (404) is a warn rather than a fail
    because the operator may have intentionally torn the cluster down
    after the upgrade.
    """
    if not cluster_name:
        return VerificationCheck(
            name="cnpg_instances",
            level="ok",
            message="no CNPG cluster configured",
            detail={"skipped": True},
        )
    try:
        status_code, body = k8s.get_cnpg_cluster(cluster_name, namespace=namespace)
    except k8s.KubeapiUnavailableError as exc:
        return VerificationCheck(
            name="cnpg_instances",
            level="warn",
            message=f"kubeapi unreachable: {exc}",
            detail={"error": str(exc)},
        )
    if status_code == 404:
        return VerificationCheck(
            name="cnpg_instances",
            level="warn",
            message=f"CNPG Cluster {cluster_name!r} not found",
            detail={"status": 404},
        )
    if status_code != 200 or body is None:
        return VerificationCheck(
            name="cnpg_instances",
            level="warn",
            message=f"CNPG GET returned {status_code}",
            detail={"status": status_code},
        )
    spec_instances = int((body.get("spec") or {}).get("instances") or 0)
    status_block = body.get("status") or {}
    ready_instances = int(status_block.get("readyInstances") or 0)
    current_primary = status_block.get("currentPrimary")
    if spec_instances == 0:
        return VerificationCheck(
            name="cnpg_instances",
            level="ok",
            message="single-instance CNPG (nothing to verify)",
            detail={"spec_instances": 0},
        )
    if ready_instances < spec_instances:
        return VerificationCheck(
            name="cnpg_instances",
            level="fail",
            message=(
                f"only {ready_instances}/{spec_instances} CNPG instances "
                f"ready (primary: {current_primary})"
            ),
            detail={
                "spec_instances": spec_instances,
                "ready_instances": ready_instances,
                "current_primary": current_primary,
            },
        )
    return VerificationCheck(
        name="cnpg_instances",
        level="ok",
        message=f"{ready_instances}/{spec_instances} CNPG instances ready",
        detail={
            "spec_instances": spec_instances,
            "ready_instances": ready_instances,
            "current_primary": current_primary,
        },
    )


def check_daemonset_pods_ready(
    namespace: str = "kube-system",
    label_selector: str | None = None,
) -> VerificationCheck:
    """Every DaemonSet-owned pod in the namespace reports Ready.

    Cluster-wide post-upgrade DS readiness check — Phase C's
    convergence step verifies per-node, but a post-upgrade run that
    succeeded per-node could still have a stale DS pod on a node
    that came back NotReady mid-uncordon. This is the catch-net.
    """
    try:
        pods = k8s.list_pods(namespace=namespace)
    except k8s.KubeapiUnavailableError as exc:
        return VerificationCheck(
            name="daemonset_pods_ready",
            level="warn",
            message=f"kubeapi unreachable: {exc}",
            detail={"error": str(exc)},
        )
    ds_pods = [p for p in pods if k8s.pod_is_owned_by_daemonset(p) and not k8s.pod_is_terminal(p)]
    if label_selector:
        # ``list_pods`` doesn't support selectors directly; client-side
        # filter is fine since the pod count in kube-system is small.
        # Honour ``key=value`` style; ignore key-only for simplicity.
        if "=" in label_selector:
            k, _, v = label_selector.partition("=")
            ds_pods = [
                p for p in ds_pods if (p.get("metadata") or {}).get("labels", {}).get(k) == v
            ]
    not_ready: list[str] = []
    for pod in ds_pods:
        conditions = (pod.get("status") or {}).get("conditions") or []
        is_ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in conditions)
        if not is_ready:
            meta = pod.get("metadata") or {}
            not_ready.append(f"{meta.get('namespace')}/{meta.get('name')}")
    if not_ready:
        return VerificationCheck(
            name="daemonset_pods_ready",
            level="fail",
            message=(
                f"{len(not_ready)} of {len(ds_pods)} DaemonSet pod(s) "
                f"NotReady — manual investigation needed"
            ),
            detail={
                "ds_pod_count": len(ds_pods),
                "not_ready": not_ready[:20],
            },
        )
    return VerificationCheck(
        name="daemonset_pods_ready",
        level="ok",
        message=f"{len(ds_pods)} DaemonSet pod(s) Ready in {namespace!r}",
        detail={"ds_pod_count": len(ds_pods)},
    )


async def verify_post_upgrade(
    *,
    cnpg_cluster_name: str = "",
    cnpg_namespace: str | None = None,
    ds_namespace: str = "kube-system",
    cnpg_wait_s: float | None = None,
) -> list[VerificationCheck]:
    """Run the cluster-wide post-upgrade verification suite.

    Phase H adds two checks on top of Phase C's
    ``_step_cluster_verify``: CNPG instance count + DS pods Ready
    cluster-wide. The orchestrator stamps the result list into
    ``run.progress.post_upgrade_verify`` so the Fleet UI can render
    a checklist alongside the per-node progress.

    #1829 — the CNPG check is not one read: while it reads fewer ready
    instances than the spec asks for, it reads again, for up to
    ``cnpg_wait_s`` (default ``_CNPG_READY_WAIT_S``), and judges the last
    read. Only that "not yet ready" fail is waited on; a 404 or an
    unreachable kubeapi is reported as before.

    Returns the list of checks (caller decides whether any failure
    should flip the run to ``failed``).
    """
    wait_s = _CNPG_READY_WAIT_S if cnpg_wait_s is None else cnpg_wait_s
    deadline = time.monotonic() + wait_s
    cnpg = check_cnpg_instances_ready(cnpg_cluster_name, namespace=cnpg_namespace)
    while cnpg.level == "fail" and time.monotonic() < deadline:
        await asyncio.sleep(_CNPG_POLL_INTERVAL_S)
        cnpg = check_cnpg_instances_ready(cnpg_cluster_name, namespace=cnpg_namespace)
    return [
        cnpg,
        check_daemonset_pods_ready(namespace=ds_namespace),
    ]


def verification_overall(checks: list[VerificationCheck]) -> str:
    """Aggregate verdict — same worst-level-wins shape as preflight."""
    levels = {c.level for c in checks}
    if "fail" in levels:
        return "fail"
    if "warn" in levels:
        return "warn"
    return "ok"
