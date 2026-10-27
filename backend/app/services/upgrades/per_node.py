"""Per-node upgrade primitive (#296 Phase C).

The 14-step sequence for taking one control-plane node from version
N-1 to N safely. Encapsulated as a single idempotent + resumable
async function ``single_node_upgrade`` plus the individual step
functions so an orchestrator (Phase D) can also drive them ala carte
for testing / dry-run.

Step shape (one row per step in the issue body; ``CHAIN`` is the order):

    1. preflight gate                — reuse Phase A's run_all, then wait
                                        for the CNPG instance count (#1544)
    2. etcd snapshot                  — TODO follow-up; relies on k3s
                                        auto-snapshots (every 6 h) until
                                        the supervisor exposes a hook.
                                        Across a Kubernetes MINOR that
                                        window is the rollback exposure
                                        — see the step's docstring (#974)
    3. mirror ready                   — an uploaded image is fetched through
                                        the slot-image mirror: wait until it
                                        has a Ready replica (#1463, below)
    4. trigger slot apply             — write desired_* on the appliance row
    5. stage                          — wait for the host to download the
                                        image and write the inactive slot,
                                        while the node is still in service
                                        (#1463, below)
    6. CNPG nodeMaintenanceWindow     — patch_cnpg_maintenance_window
    7. cordon                         — cordon_node (triggers auto-
                                        switchover if primary's here)
    8. verify primary moved off       — poll Cluster.status.currentPrimary
   8b. move Redis master off          — SENTINEL FAILOVER when the master is
                                        on this node, then confirm it landed
                                        elsewhere; never fails the node
                                        (#2815, redis_master.py)
    9. drain                          — eviction loop (DS skip + terminal-
                                        pod skip + mirror-pod skip);
                                        --force NOT supported
   10. reboot                         — request the reboot into the staged
                                        slot (the host runner never reboots
                                        on its own, #1445)
   11. health gate                    — poll until installed_appliance_version
                                        == desired_appliance_version
   12. convergence                    — node Ready + DaemonSet pod Ready
   13. uncordon + clear window        — uncordon_node + maintenance off
   14. cluster verify                 — wait for the CNPG instance count
                                        and the control-plane Deployments
                                        (#1544), then re-run a small slice
                                        of preflight

A failure once the run holds the node — the CNPG maintenance window set, or
the node cordoned — runs a ``release_node`` compensation (#1542): it clears
the window and uncordons, except a node the run never cordoned or one already
cordoned before the upgrade. A failure before the window (mirror ready,
trigger slot apply, stage) holds nothing and releases nothing.

Stage before drain (#1463). A node fetches its image over HTTPS from the
appliance itself: an uploaded image is served through the slot-image mirror,
one pod whose local volume pins it to one node, and the URL names the node the
Plan was sent to, whose frontend runs on that node alone (#1708). Draining
first evicted the very pod the node was about to fetch from, so the mirror's
node and the Plan's node each failed their own fetch and the run stopped with
the node cordoned. Staging first keeps both serving through the fetch; the
drain now only clears the node for its reboot. A fetch that fails leaves the
node uncordoned, still serving, with no maintenance window open.

The mirror's own node still drains it before its reboot, and its replacement
can only start on that node once it is uncordoned again. So before a node is
told to fetch an uploaded image, ``mirror ready`` waits until the mirror has
a Ready replica: the next node's stamp would otherwise land in that gap, and
its fetch would answer 502.

Resumability (#2809): each step is idempotent in itself (cordon-already-
cordoned is a 200, evict-already-gone is 404 treated as success, a stamp
already on the row is not stamped again, etc.). Before each step runs, the
chain hands a checkpoint to the caller's ``checkpoint`` callback: the step
about to run, plus what a later invocation cannot re-learn (this run's stamp
time, and whether the node was unschedulable before this run cordoned it).
The orchestrator stores it on the run as ``progress.in_flight``. A drive that
takes the run over while a node is in flight passes it back as ``resume``,
and the chain re-runs the step that was running and continues from there.

Restarting such a node at ``preflight`` instead could never succeed: its
CNPG wait counts the node's own instance, which the earlier drive's drain
evicted and the cordon keeps Pending, so it timed out after 900 s and failed
the node with the cordon and the window still held (#2809).
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_wake import appliance_channel, publish_wake
from app.core.db_transient import is_transient_db_error
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.audit import AuditLog
from app.services.appliance import k8s
from app.services.appliance.ownership import hostname_sql, k8s_node_name
from app.services.appliance.reboot import request_reboot
from app.services.appliance.slot_image_target import (
    SlotImageArchitectureMismatch,
    SlotImageTarget,
    desired_slot_image_url,
    stamp_desired_slot_image,
)
from app.services.upgrades import chart_bump, preflight, redis_master, safety

# The classifier moved to kubeapi_retry (#2767) so the plan path shares it.
from app.services.upgrades.kubeapi_retry import _kubeapi_transient

logger = structlog.get_logger(__name__)


StepName = Literal[
    "preflight",
    "etcd_snapshot",
    "mirror_ready",
    "trigger_slot_apply",
    "stage",
    "cnpg_maintenance_on",
    "cordon",
    "verify_primary_moved",
    "move_redis_master",
    "drain",
    "reboot",
    "health_gate",
    "convergence",
    "uncordon",
    "cluster_verify",
    "release_node",
]

# The chain's order, once. ``single_node_upgrade`` runs it and resolves a
# ``start_step`` against it; the CNPG steps are skipped without a cluster name,
# and ``move_redis_master`` without a Sentinel-fronted Redis (#2815).
CHAIN: tuple[StepName, ...] = (
    "preflight",
    "etcd_snapshot",
    "mirror_ready",
    "trigger_slot_apply",
    "stage",
    "cnpg_maintenance_on",
    "cordon",
    "verify_primary_moved",
    "move_redis_master",
    "drain",
    "reboot",
    "health_gate",
    "convergence",
    "uncordon",
    "cluster_verify",
)

# The actor recorded on audit rows the upgrade writes on its own, with no
# operator behind them (#1449). ``user_display_name`` and ``auth_source``
# are NOT NULL.
SYSTEM_ACTOR = "system:upgrade-orchestrator"


# Default-but-overridable timeouts. The orchestrator (Phase D) will
# expose these on the upgrade-start request body so an operator with
# a slow disk / large CNPG can stretch them.
DEFAULT_DRAIN_TIMEOUT_S = 120.0
DEFAULT_STAGE_TIMEOUT_S = 3000.0  # 50 min — the host's 45 min apply ceiling + heartbeat lag
DEFAULT_HEALTH_GATE_TIMEOUT_S = 1800.0  # 30 min — reboot + first heartbeat from the new slot
DEFAULT_CONVERGENCE_TIMEOUT_S = 900.0  # 15 min — etcd rejoin + CNPG resync
DEFAULT_SWITCHOVER_TIMEOUT_S = 180.0  # 3 min — CNPG cordon-triggered switch
DEFAULT_CNPG_READY_TIMEOUT_S = 900.0  # 15 min — an evicted instance rescheduling + catching up
# 10 min — the mirror's pod back on its node after that node's reboot: its
# migrate-wait init container, then the api image cold-starting.
DEFAULT_MIRROR_READY_TIMEOUT_S = 600.0
# 10 min — the control-plane Deployments settled after a node rejoins (#1544):
# a pod rescheduled onto it, or a single-replica rollout's retire-first gap.
DEFAULT_CONTROL_PLANE_READY_TIMEOUT_S = 600.0

# Poll cadence — gentle on kubeapi + the appliance row. Slow enough
# that 30 min worth of polls is ~600 calls, fast enough that step
# transitions surface to the UI within a few seconds.
_POLL_INTERVAL_S = 3.0

# #2177 — a step that loses its database connection is retried in place for
# this long, from the first such error, before it is recorded as crashed. A
# CloudNativePG failover of a primary on a node that went NotReady took ~10 s
# from ``FailingOver`` to ``FailoverTarget`` on the repro rig, and a node
# loss can take 60-90 s to promote (#1083); the connect timeout (5 s) adds to
# each attempt. Every step that touches the database is idempotent: it
# re-reads the appliance row and judges it afresh (see the module docstring).
DB_FAILOVER_BUDGET_S = 90.0
_DB_RETRY_BACKOFF_S = (1.0, 2.0, 4.0, 8.0, 15.0)
# Separate outages one step rides out before the next one fails it.
_DB_MAX_OUTAGES_PER_STEP = 3

# #2449 — a transient kubeapi answer at an idempotent per-node write is retried
# in place, the way a shared-tag write is (orchestrator._retry_shared_tag_step).
# The API server behind a rolling control plane can answer a CNPG admission
# PATCH with a 500 while CloudNativePG's mutating webhook is briefly between
# endpoints (its operator pod rescheduling off a cordoned node). One 500 used to
# fail the step and the whole run at cnpg_maintenance_on. Only the writes that
# are safe to repeat retry, and only a kubeapi helper's own answer.
KUBEAPI_RETRY_STEPS: frozenset[StepName] = frozenset({"cnpg_maintenance_on", "cordon", "uncordon"})
KUBEAPI_RETRY_BUDGET_S = 300.0
_KUBEAPI_RETRY_INTERVAL_S = 15.0


@dataclass
class StepResult:
    """One step's outcome — captured for the SystemUpgradeRun row's
    ``progress.per_node[<node>].steps`` log."""

    name: StepName
    started_at: str
    finished_at: str | None = None
    ok: bool = False
    detail: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def finish(self, ok: bool, **detail: Any) -> StepResult:
        self.finished_at = _now_iso()
        self.ok = ok
        # ``error`` is the dataclass field, not a detail entry — pull
        # it out before merging the rest so a caller's
        # ``step.finish(False, error="oops")`` sets the canonical
        # field. Keeps it queryable in JSONB without scanning the
        # detail blob.
        if "error" in detail:
            self.error = detail.pop("error")
        if detail:
            self.detail.update(detail)
        return self


@dataclass
class NodeResume:
    """Where a node's chain was when the drive running it stopped (#2809).

    ``step`` is the step that was running, or about to run, and is run again:
    every step is idempotent. Built by the orchestrator from the checkpoint
    the chain reported (``progress.in_flight``); see ``resume_from_checkpoint``.
    """

    step: StepName
    # This run's stamp time, for the stage / reboot / health-gate reads of a
    # ``done`` or ``failed`` written before it. None: a re-driven node's stamp.
    stamped_at: datetime | None = None
    # The node's schedulability before this run cordoned it, from the cordon
    # step's own read. Re-reading it now would see this run's cordon.
    was_unschedulable: bool | None = None
    pre_cordon_known: bool = False


def checkpoint_entry(
    node_name: str,
    step: StepName,
    *,
    stamped_at: datetime | None,
    pre_cordon: dict[str, bool | None],
) -> dict[str, Any]:
    """The JSON the chain reports before running ``step`` (#2809)."""
    entry: dict[str, Any] = {
        "node": node_name,
        "step": step,
        "stamped_at": stamped_at.isoformat() if stamped_at is not None else None,
        "at": _now_iso(),
    }
    if "was_unschedulable" in pre_cordon:
        entry["was_unschedulable"] = pre_cordon["was_unschedulable"]
    return entry


def resume_from_checkpoint(entry: Any, node_name: str) -> NodeResume | None:
    """The resume point for ``node_name`` from a stored checkpoint, or None
    when there is none for it (the node starts at ``preflight``).

    A checkpoint naming another node, or a step this code does not know, is
    not a resume point for this one."""
    if not isinstance(entry, dict) or entry.get("node") != node_name:
        return None
    step = entry.get("step")
    if step not in CHAIN or step == "preflight":
        return None
    stamped_at: datetime | None = None
    raw = entry.get("stamped_at")
    if isinstance(raw, str):
        try:
            stamped_at = _aware(datetime.fromisoformat(raw))
        except ValueError:
            stamped_at = None
    known = "was_unschedulable" in entry
    was = entry.get("was_unschedulable") if known else None
    return NodeResume(
        step=step,
        stamped_at=stamped_at,
        was_unschedulable=was if isinstance(was, bool) else None,
        pre_cordon_known=known,
    )


Checkpoint = Callable[[dict[str, Any]], Awaitable[None]]


@dataclass
class SingleNodeResult:
    """Aggregate outcome of one node's 12-step upgrade."""

    node_name: str
    target_version: str
    ok: bool
    failed_at: StepName | None
    steps: list[StepResult]
    error: str | None = None


def _now_iso() -> str:
    """RFC3339-shaped UTC timestamp for step logs. Matches the renew_time
    format we already use on the Lease."""
    from datetime import UTC, datetime  # noqa: PLC0415

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── CNPG instance-count wait (#1544) ─────────────────────────────────


async def _wait_cnpg_instances_ready(
    cluster_name: str,
    namespace: str | None,
    *,
    timeout_s: float,
) -> tuple[bool, dict[str, Any]]:
    """Poll until the CNPG Cluster reads ``readyInstances == spec.instances``.

    Returns ``(ok, detail)``. Reuses ``safety.check_cnpg_instances_ready``,
    the read the post-run verification uses. ``ok`` with no cluster name, a
    single-instance cluster, or a 404 (cluster intentionally torn down,
    mirroring ``_step_verify_primary_moved``). Any other non-ok verdict —
    short an instance, kubeapi unreachable, a non-200 — keeps polling until
    ``timeout_s``.

    Callers run this only where the node being upgraded is SCHEDULABLE:
    after its uncordon, or before its cordon. Waiting while it is cordoned
    would wait on its own evicted instance, which the cordon holds Pending
    (ddi-pg's case 3 on #1610).
    """
    if not cluster_name:
        return True, {"cnpg_wait": "skipped: no CNPG cluster"}
    deadline = time.monotonic() + timeout_s
    while True:
        check = safety.check_cnpg_instances_ready(cluster_name, namespace=namespace)
        if check.level == "ok" or (check.level == "warn" and check.detail.get("status") == 404):
            return True, {
                "cnpg_ready_instances": check.detail.get("ready_instances"),
                "cnpg_spec_instances": check.detail.get("spec_instances"),
            }
        if time.monotonic() >= deadline:
            return False, {"cnpg_wait_error": check.message, "cnpg_wait_timeout_s": timeout_s}
        await asyncio.sleep(_POLL_INTERVAL_S)


# ── Control-plane Deployments wait (#1544) ───────────────────────────


def control_plane_selector(release: str) -> str:
    """Label selector for the release's own Deployments: the chart stamps
    ``app.kubernetes.io/name`` (the chart name) and ``/instance`` (the
    release) on every workload it renders, which leaves subchart workloads
    (their ``name`` differs) out and picks up a Deployment the chart adds
    later without a code change."""
    return f"app.kubernetes.io/name=spatiumddi,app.kubernetes.io/instance={release}"


def _deployment_settled(dep: dict[str, Any]) -> str | None:
    """None when the Deployment is fully available with no rollout in
    progress, else a short reason. Stricter than ``deployment_is_rolled_out``
    (``kubectl rollout status``): ``status.replicas`` above the desired count
    means an old ReplicaSet's pod is still draining."""
    name = (dep.get("metadata") or {}).get("name", "?")
    spec_replicas = int((dep.get("spec") or {}).get("replicas") or 0)
    if spec_replicas == 0:
        return None
    status = dep.get("status") or {}
    if not k8s.deployment_is_rolled_out(dep):
        return (
            f"{name}: available={int(status.get('availableReplicas') or 0)}"
            f"/{spec_replicas}, updated={int(status.get('updatedReplicas') or 0)}"
        )
    if int(status.get("replicas") or 0) > spec_replicas:
        return f"{name}: rollout in progress ({status.get('replicas')} pods for {spec_replicas})"
    return None


async def _wait_control_plane_ready(
    release: str,
    namespace: str | None,
    *,
    timeout_s: float,
) -> tuple[bool, dict[str, Any]]:
    """Poll until every control-plane Deployment of ``release`` reads
    available == desired with no rollout in progress.

    A single-replica Deployment is briefly at zero available while a
    retire-first rollout (#1659) replaces its pod: that is not-ready, so the
    wait continues through it until ``timeout_s``. ``ok`` (skipped) with no
    release name or no kubeapi (a shape without the chart).

    Fails at once, without polling, on two answers that waiting cannot
    change: 401 / 403 / 404 from the list call (missing RBAC or a wrong
    namespace), and a successful list matching NO Deployment. The second
    matters because the orchestrator itself runs inside the release, so
    an empty result means the selector or namespace is wrong; reporting it
    as "skipped" would turn the gate off without anyone noticing. Other
    kubeapi errors (5xx, unreachable) keep polling until ``timeout_s``.
    """
    if not release:
        return True, {"control_plane_wait": "skipped: no release"}
    if k8s.get_config() is None:
        return True, {"control_plane_wait": "skipped: kubeapi not reachable from here"}
    selector = control_plane_selector(release)
    deadline = time.monotonic() + timeout_s
    last = "not read yet"
    while True:
        try:
            status, items = k8s.list_deployments(selector, namespace=namespace)
        except k8s.KubeapiUnavailableError as exc:
            status, items, last = 0, [], f"kubeapi unavailable: {exc}"
        if status == 200:
            if not items:
                where = namespace or "the api's namespace"
                logger.error(
                    "upgrade_control_plane_no_deployments",
                    selector=selector,
                    namespace=namespace,
                )
                return False, {
                    "control_plane_wait_error": (
                        f"no Deployments match {selector} in {where}; the selector "
                        "or namespace does not fit this install, so the gate "
                        "cannot verify the control plane"
                    ),
                }
            pending = [r for r in (_deployment_settled(d) for d in items) if r]
            if not pending:
                return True, {"control_plane_deployments": len(items)}
            last = "; ".join(pending)
        elif status in (401, 403, 404):
            logger.error(
                "upgrade_control_plane_list_refused",
                status=status,
                selector=selector,
                namespace=namespace,
            )
            return False, {
                "control_plane_wait_error": (
                    f"kubeapi answered {status} listing Deployments ({selector}); "
                    "check the api ServiceAccount's RBAC (deployments: list) "
                    "and the release namespace"
                ),
            }
        elif status:
            last = f"kubeapi status {status}"
        if time.monotonic() >= deadline:
            return False, {
                "control_plane_wait_error": last,
                "control_plane_wait_timeout_s": timeout_s,
            }
        await asyncio.sleep(_POLL_INTERVAL_S)


# ── Step 1: preflight ────────────────────────────────────────────────


async def _step_preflight(
    target_version: str,
    lease_holder: str | None = None,
    *,
    cnpg_cluster_name: str = "",
    cnpg_namespace: str | None = None,
    cnpg_timeout_s: float = DEFAULT_CNPG_READY_TIMEOUT_S,
    slot_image_id: uuid.UUID | None = None,
    disk_nodes: list[str] | None = None,
) -> StepResult:
    step = StepResult(name="preflight", started_at=_now_iso())
    # The orchestrator holds the upgrade lease while it drives this chain;
    # without its identity, the in-flight check fails on that very lease.
    # #1709 — the run's uploaded target, which the mirror already holds by
    # now, needs no room on it; and /var is judged on the run's nodes still
    # to upgrade, not on the ones it has finished.
    report = await preflight.run_all(
        target_version=target_version,
        own_holder=lease_holder,
        slot_image_id=slot_image_id,
        disk_nodes=disk_nodes,
    )
    if report.overall == "fail":
        fails = [r.name for r in report.results if r.level == "fail"]
        return step.finish(
            False,
            error=f"preflight failed: {', '.join(fails)}",
            overall=report.overall,
            failed_checks=fails,
        )
    # #1544 — this node must not be cordoned and drained while CNPG is
    # short an instance: draining it then could take the database to one
    # instance, or none. The previous node's cluster_verify already waited
    # for this; waiting again here also covers a run that resumed or was
    # taken over between nodes. Nothing is held yet, so a timeout fails
    # cleanly with nothing to release. A drive that takes over in the MIDDLE
    # of a node does not come back here: it resumes at the step the earlier
    # drive was in (#2809), since this wait would count the node's own
    # instance, evicted by that drive's drain and held Pending by its cordon.
    ok, cnpg_detail = await _wait_cnpg_instances_ready(
        cnpg_cluster_name, cnpg_namespace, timeout_s=cnpg_timeout_s
    )
    if not ok:
        return step.finish(
            False,
            error=(
                f"CNPG instances not all ready within {cnpg_timeout_s:.0f}s: "
                f"{cnpg_detail.get('cnpg_wait_error')}"
            ),
            overall=report.overall,
            **cnpg_detail,
        )
    return step.finish(
        True,
        overall=report.overall,
        warns=[r.name for r in report.results if r.level == "warn"],
        **cnpg_detail,
    )


# ── Step 2: etcd snapshot (TODO follow-up) ───────────────────────────


async def _step_etcd_snapshot() -> StepResult:
    """No-op in Phase C v0.

    k3s auto-snapshots run every 6 h via ``--etcd-snapshot-schedule-cron``
    (``appliance/mkosi.extra/etc/rancher/k3s/config.yaml``, retention 8),
    so there is always a recent snapshot on disk to fall back to. A
    *fresh* snapshot before each node upgrade needs shell access to a
    k3s control-plane host, which the api pod does not have: the
    supervisor has no inbound HTTP, so it would take the trigger-file →
    systemd ``.path`` → host-runner shape the pcap and firewall planes
    use. Skipping with a structured comment in the step log rather than
    silently dropping the contract.

    **This mattered more from the k3s v1.36 bump on (#974).** Every
    earlier bump was same-minor, where an A/B slot revert is a real
    rollback. Across a Kubernetes MINOR it is not: the k3s datastore
    lives on persistent ``/var``, outside the slot, and an older
    apiserver is not supported against a store a newer one has written.
    So the rollback for a minor is slot revert **plus** an etcd restore
    from before the upgrade, which makes the age of the newest snapshot
    part of the upgrade's safety rather than a nicety. Until this step
    creates one, the exposure is up to the 6 h cron interval, and
    ``docs/deployment/APPLIANCE.md`` §5d tells the operator to take a
    manual snapshot before a minor.

    Follow-up (#296), cheaper than it looks: the seed already reports
    ``k3s etcd-snapshot list`` on every heartbeat into
    ``Appliance.etcd_snapshots`` (name / location / size /
    ``created_at``), so *verifying* a recent snapshot needs no new
    mechanism at all — only *creating* one does.
    """
    step = StepResult(name="etcd_snapshot", started_at=_now_iso())
    return step.finish(
        True,
        skipped=True,
        reason=(
            "supervisor-driven snapshot not yet exposed; relying on "
            "k3s auto-snapshots (every 6 h). Follow-up tracked in #296. "
            "Across a Kubernetes minor, rollback is slot revert + etcd "
            "restore — take a manual snapshot first (#974)."
        ),
    )


# ── Step 6: CNPG nodeMaintenanceWindow on ─────────────────────────────


async def _step_cnpg_maintenance_on(cluster_name: str, namespace: str | None) -> StepResult:
    step = StepResult(
        name="cnpg_maintenance_on",
        started_at=_now_iso(),
        detail={"cluster": cluster_name, "namespace": namespace or "<release>"},
    )
    ok, err = k8s.patch_cnpg_maintenance_window(
        cluster_name,
        in_progress=True,
        reuse_pvc=True,
        namespace=namespace,
    )
    if not ok:
        return step.finish(False, error=err or "patch failed")
    return step.finish(True)


# ── Step 7: cordon ────────────────────────────────────────────────────


async def _step_cordon(
    node_name: str, *, pre_cordon: dict[str, bool | None] | None = None
) -> StepResult:
    step = StepResult(name="cordon", started_at=_now_iso(), detail={"node": node_name})
    # Record whether the node was already unschedulable BEFORE this cordon,
    # so a failure's release (#1542) does not uncordon a node an operator
    # had cordoned on purpose. ``None`` = could not tell; the release then
    # uncordons, as it did before this was recorded.
    #
    # #2449 — the step is retried in place on a transient kubeapi answer, and
    # a PATCH whose answer was lost (a socket timeout) may still have landed.
    # Re-reading the node on the retry would then see this run's own cordon
    # and record it as the operator's, so the release would leave the node
    # cordoned after a failed run. ``pre_cordon`` carries the FIRST attempt's
    # reading across retries; only that one was taken before any cordon.
    was_unschedulable: bool | None = None
    if pre_cordon is not None and "was_unschedulable" in pre_cordon:
        was_unschedulable = pre_cordon["was_unschedulable"]
    else:
        try:
            status, node = k8s.get_node(node_name)
        except k8s.KubeapiUnavailableError:
            status, node = 0, None
        if status == 200 and node is not None:
            was_unschedulable = bool((node.get("spec") or {}).get("unschedulable"))
        if pre_cordon is not None:
            pre_cordon["was_unschedulable"] = was_unschedulable
    step.detail["was_unschedulable"] = was_unschedulable
    ok, err = k8s.cordon_node(node_name)
    if not ok:
        return step.finish(False, error=err or "cordon failed")
    return step.finish(True)


# ── Step 8: verify CNPG primary moved off ─────────────────────────────


async def _step_verify_primary_moved(
    cluster_name: str,
    node_name: str,
    namespace: str | None,
    *,
    timeout_s: float = DEFAULT_SWITCHOVER_TIMEOUT_S,
) -> StepResult:
    """Poll Cluster.status.currentPrimary until it's a pod NOT on
    ``node_name``. The CNPG operator triggers the switchover
    automatically when it sees the host node cordoned; we just verify
    it landed before draining.

    A single-replica CNPG cluster has no replica to fail over to —
    in that case we return a clean ``skipped=True`` so single-node
    test runs don't hit a false failure.
    """
    step = StepResult(
        name="verify_primary_moved",
        started_at=_now_iso(),
        detail={"node": node_name, "cluster": cluster_name},
    )
    deadline = time.monotonic() + timeout_s
    last_primary: str | None = None
    while time.monotonic() < deadline:
        status, body = k8s.get_cnpg_cluster(cluster_name, namespace=namespace)
        if status == 404:
            # No CNPG Cluster — single-node docker-compose / plain
            # k8s shape. Nothing to switch over.
            return step.finish(True, skipped=True, reason="no CNPG cluster")
        if status != 200 or body is None:
            await asyncio.sleep(_POLL_INTERVAL_S)
            continue
        spec = body.get("spec") or {}
        instances = int(spec.get("instances") or 1)
        if instances <= 1:
            return step.finish(True, skipped=True, reason="single-instance CNPG cluster")
        status_block = body.get("status") or {}
        current_primary = status_block.get("currentPrimary")
        last_primary = current_primary
        # #1445 — the primary has moved only when its pod runs on another
        # node. This used to return ok for any non-empty currentPrimary,
        # the one on the cordoned node included, so the drain that follows
        # evicted the primary itself instead of waiting for CNPG's
        # switchover. A pod we cannot read proves nothing either way, so it
        # is another poll, never a pass.
        if current_primary:
            pod_status, pod = k8s.get_pod(current_primary, namespace=namespace)
            primary_node = (
                ((pod or {}).get("spec") or {}).get("nodeName") if pod_status == 200 else None
            )
            if primary_node and primary_node != node_name:
                return step.finish(
                    True,
                    current_primary=current_primary,
                    primary_node=primary_node,
                    instances=instances,
                )
        await asyncio.sleep(_POLL_INTERVAL_S)
    return step.finish(
        False,
        error=(
            f"primary still on {node_name} after {timeout_s:.0f}s " f"(last seen: {last_primary})"
        ),
    )


# ── Step 8b: move the Redis master off (#2815) ────────────────────────


async def _step_move_redis_master(
    node_name: str,
    namespace: str | None,
    *,
    timeout_s: float = redis_master.DEFAULT_REDIS_SWITCH_TIMEOUT_S,
    remaining_nodes: list[str] | None = None,
) -> StepResult:
    """Fail the Redis master over to another node before the drain evicts it,
    so the broker never waits out a split Sentinel vote (~128 s) with the
    worker driving this upgrade cut off from it.

    Always ``ok``: a master that could not be moved is a ``warning`` in the
    detail and a log line, and the drain goes ahead, as it did before #2815.
    ``redis_master``'s docstring says why that beats failing the node."""
    step = StepResult(name="move_redis_master", started_at=_now_iso(), detail={"node": node_name})
    try:
        outcome = await redis_master.move_master_off_node(
            node_name, namespace=namespace, timeout_s=timeout_s, remaining_nodes=remaining_nodes
        )
    except Exception as exc:  # noqa: BLE001 — an optimisation must not fail the node
        logger.warning("upgrade_redis_master_move_crashed", node=node_name, error=str(exc))
        return step.finish(True, warning=f"moving the Redis master crashed: {exc}")
    detail: dict[str, Any] = dict(outcome.detail)
    if outcome.skipped:
        detail.update(skipped=True, reason=outcome.reason)
    if outcome.warning:
        detail["warning"] = outcome.warning
        logger.warning("upgrade_redis_master_not_moved", node=node_name, warning=outcome.warning)
    return step.finish(True, **detail)


# ── Step 9: drain ─────────────────────────────────────────────────────


async def _step_drain(
    node_name: str,
    *,
    timeout_s: float = DEFAULT_DRAIN_TIMEOUT_S,
) -> StepResult:
    """Evict every non-DS / non-terminal / non-mirror pod off the node.

    The eviction loop:
      * List pods on the node.
      * Filter out DaemonSet-owned (--ignore-daemonsets), terminal
        (already done), and static mirror pods (kubelet-managed, the
        eviction API can't touch them — same as kubectl).
      * POST Eviction for each remaining pod; track which ones got
        429 (PDB blocks) for retry.
      * Poll until the eviction list is empty or timeout.

    No ``--force`` semantics — a pod with no controller doesn't get
    re-created on another node, so blindly deleting it would silently
    lose data. The orchestrator's halt-on-failure policy catches the
    stuck case (Phase F).
    """
    step = StepResult(
        name="drain",
        started_at=_now_iso(),
        detail={"node": node_name, "timeout_s": timeout_s},
    )
    deadline = time.monotonic() + timeout_s
    evicted: list[str] = []
    blocked: list[dict[str, Any]] = []
    # The evictable pods the last poll still found on the node (#1804).
    remaining: list[str] = []

    while time.monotonic() < deadline:
        try:
            pods = k8s.list_pods_on_node(node_name)
        except k8s.KubeapiUnavailableError as exc:
            return step.finish(False, error=f"list pods failed: {exc}")

        # Filter to evictable pods.
        candidates: list[tuple[str, str]] = []  # [(name, namespace)]
        unowned: list[str] = []
        for pod in pods:
            if k8s.pod_is_owned_by_daemonset(pod):
                continue
            if k8s.pod_is_terminal(pod):
                continue
            if k8s.pod_is_mirror(pod):
                continue
            meta = pod.get("metadata") or {}
            name = meta.get("name")
            ns = meta.get("namespace")
            if not name or not ns:
                continue
            if not k8s.pod_has_controller(pod):
                # #1546 — a bare pod has no controller to re-create
                # it; evicting it deletes it for good. The docstring's
                # no-force rule forbids that, so the pod is a drain
                # blocker, never a candidate.
                unowned.append(f"{ns}/{name}")
                continue
            candidates.append((name, ns))

        if unowned:
            # Fail fast — an unowned pod never becomes evictable, so
            # polling until the timeout only delays the operator.
            # The pods are named in the step detail as blockers.
            return step.finish(
                False,
                error=(
                    f"drain blocked: {len(unowned)} pod(s) on {node_name} have "
                    "no controller owner and would not be re-created if "
                    "evicted (no --force semantics): " + ", ".join(sorted(unowned))
                ),
                evicted_count=len(set(evicted)),
                evicted=list(set(evicted)),
                unowned_pods=sorted(unowned),
                blocked=[{"pod": p, "reason": "no controller owner"} for p in sorted(unowned)],
            )

        if not candidates:
            return step.finish(
                True,
                evicted_count=len(set(evicted)),
                evicted=list(set(evicted)),
                blocked_count=len(blocked),
            )

        # Issue an eviction for each candidate. PDB blocks (429) +
        # transient 500s come back via the status; we retry on the
        # next poll iteration.
        cycle_blocked: list[dict[str, Any]] = []
        for name, ns in candidates:
            status, err = k8s.evict_pod(name, ns)
            if status in (200, 201, 404):
                evicted.append(f"{ns}/{name}")
            elif status == 429:
                cycle_blocked.append({"pod": f"{ns}/{name}", "reason": "PDB", "error": err})
            else:
                cycle_blocked.append({"pod": f"{ns}/{name}", "status": status, "error": err})
        blocked = cycle_blocked
        remaining = sorted(f"{ns}/{name}" for name, ns in candidates)
        await asyncio.sleep(_POLL_INTERVAL_S)

    # #1804 — count the pods still on the node, not the evictions the last
    # cycle had refused. A node whose kubelet is down accepts every eviction
    # and removes nothing, so the old count read "0 pod(s) still present"
    # while all of them were.
    refused = {b["pod"] for b in blocked}
    not_removed = [p for p in remaining if p not in refused]
    why: list[str] = []
    if refused:
        why.append(f"{len(refused)} eviction(s) refused")
    if not_removed:
        why.append(
            f"{len(not_removed)} evicted but never removed from the node, "
            "whose kubelet may be down"
        )
    error = f"drain timed out after {timeout_s:.0f}s — {len(remaining)} pod(s) still present"
    if why:
        error += f" ({'; '.join(why)})"
    return step.finish(
        False,
        error=error,
        evicted_count=len(set(evicted)),
        evicted=list(set(evicted)),
        blocked=blocked,
        remaining=remaining,
        not_removed=not_removed,
    )


# ── Step 3: wait for the slot-image mirror ──────────────────────────


def slot_image_mirror_deployment(chart_name: str) -> str:
    """The mirror Deployment of the release ``chart_name`` names: the chart's
    ``{fullname}-slot-image-mirror``, the shape ``chart_bump`` already uses
    for the api, worker and frontend Deployments."""
    return f"{chart_name}-spatiumddi-slot-image-mirror"


async def _step_mirror_ready(
    db: AsyncSession,
    node_name: str,
    target_version: str,
    slot_image: SlotImageTarget,
    *,
    deployment: str,
    namespace: str | None = None,
    timeout_s: float = DEFAULT_MIRROR_READY_TIMEOUT_S,
) -> StepResult:
    """Hold this node's stamp until the slot-image mirror can serve (#1463).

    An uploaded image reaches every node through the mirror: one replica on
    a local-path volume that pins it to one node. The drain before that
    node's reboot takes the mirror down, and its replacement can only start
    there once the node is uncordoned, so the next node's stamp could land
    before it is back; the api then answers that node's fetch 502 ("Mirror
    download failed") until the host runner gives up. Waiting here, before
    ``trigger_slot_apply``, leaves a node the mirror never comes back for
    untouched: not stamped, not cordoned, still serving.

    Nothing to wait for, so skipped, when nothing would fetch from the
    mirror: an operator-supplied URL (no sha256: the host fetches it
    directly), a cluster with no mirror Deployment (the api serves its own
    copy), a node already on the target, or a node already holding this
    exact stamp, whose apply the supervisor's fire-once marker will not
    repeat. That last one is a re-driven node; the mirror's own node,
    resumed after its drain with its mirror Pending, is one of them.
    """
    step = StepResult(
        name="mirror_ready",
        started_at=_now_iso(),
        detail={"node": node_name, "deployment": deployment},
    )
    if not slot_image.sha256:
        return step.finish(True, skipped=True, reason="the image is fetched from its own URL")
    # A fresh read: the previous node's chain has just written this table.
    await db.commit()
    appliance = await _resolve_appliance(db, node_name)
    if appliance is None:
        return step.finish(
            False, error=f"no single approved Appliance row with hostname={node_name!r}"
        )
    await db.refresh(appliance)
    if appliance.installed_appliance_version == target_version:
        return step.finish(True, skipped=True, reason="already running the target")
    if appliance.desired_slot_image_url == desired_slot_image_url(appliance, slot_image):
        return step.finish(
            True, skipped=True, reason="the node already holds this stamp; nothing new to fetch"
        )
    # End the read before the wait: nothing below needs the database, and a
    # connection held idle for minutes is one the database can close under the
    # stamp that follows.
    await db.commit()

    started = time.monotonic()
    deadline = started + timeout_s
    last = "not read yet"
    while True:
        try:
            status, body = k8s.get_deployment(deployment, namespace=namespace)
        except k8s.KubeapiUnavailableError as exc:
            status, body, last = None, None, f"kubeapi unavailable: {exc}"
        if status == 404:
            return step.finish(True, skipped=True, reason="no slot-image mirror on this cluster")
        if status == 200 and body is not None:
            ready = int((body.get("status") or {}).get("readyReplicas") or 0)
            if ready >= 1:
                return step.finish(
                    True, ready_replicas=ready, waited_s=round(time.monotonic() - started)
                )
            last = f"readyReplicas={ready}"
        elif status is not None:
            last = f"kubeapi status {status}"
        if time.monotonic() >= deadline:
            return step.finish(
                False,
                error=(
                    f"slot-image mirror {deployment} not ready after {timeout_s:.0f}s "
                    f"({last}); the node was not told to fetch"
                ),
            )
        await asyncio.sleep(_POLL_INTERVAL_S)


# ── Step 4: trigger slot apply ────────────────────────────────────────


async def _resolve_appliance(db: AsyncSession, node_name: str) -> Appliance | None:
    """Match a k8s Node to its Appliance row.

    Appliance.hostname == node.metadata.name for the standard appliance
    shape (spatium-install sets the hostname, k3s uses it as the node
    name by default). A future polish can grow an explicit
    ``Appliance.k8s_node_name`` column if operators rename either.
    """
    # Case-blind: k3s lowercases the host's name for the Node (#1757). Only an
    # APPROVED row, and only when exactly one matches: a revoked row keeps its
    # hostname (a re-paired box leaves one behind), and the case-blind match
    # also meets ``Ddi-1`` and ``ddi-1``. ``scalar_one_or_none`` raised on
    # either; picking one would stamp the upgrade onto the wrong appliance.
    stmt = (
        select(Appliance)
        .where(
            hostname_sql(Appliance.hostname) == k8s_node_name(node_name),
            Appliance.state == APPLIANCE_STATE_APPROVED,
        )
        .limit(2)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return rows[0] if len(rows) == 1 else None


async def _step_trigger_slot_apply(
    db: AsyncSession,
    node_name: str,
    target_version: str,
    slot_image: SlotImageTarget,
) -> StepResult:
    step = StepResult(
        name="trigger_slot_apply",
        started_at=_now_iso(),
        detail={"node": node_name, "target_version": target_version},
    )
    appliance = await _resolve_appliance(db, node_name)
    if appliance is None:
        return step.finish(
            False, error=f"no single approved Appliance row with hostname={node_name!r}"
        )
    # Stamps all four desired_* columns, not just version + URL. Setting
    # only those two is what made every per-node apply of an uploaded
    # image fetch our own self-signed cert with verification on, and left
    # any stale sha256 from an earlier per-box schedule to fail the new
    # image as corrupt (#787).
    previous_url = appliance.desired_slot_image_url
    try:
        stamp_desired_slot_image(appliance, slot_image, desired_version=target_version)
    except SlotImageArchitectureMismatch as exc:
        # #1026 — fail THIS node's step rather than raising out of the
        # orchestrator. A fleet-wide run over a mixed-architecture fleet
        # is a real shape (an arm64 node joined to an amd64 cluster), and
        # the right outcome is that the nodes the image fits still
        # upgrade while the one it does not is reported as failed with
        # the reason, not that the whole run dies at whichever node
        # happened to be scheduled first.
        return step.finish(False, error=str(exc))
    # ``fresh_stamp`` is False when the row already carried this exact URL: a
    # re-driven node, whose apply the supervisor's fire-once marker will not
    # repeat. The stage step then takes the staged state as it stands
    # instead of waiting for a new apply that is never coming.
    fresh = appliance.desired_slot_image_url != previous_url
    if fresh:
        _forget_previous_attempt(appliance)
    await db.flush()
    # Flushed, not committed: ``single_node_upgrade`` commits straight after
    # this step, before the stage step waits on the supervisor (#1445).
    return step.finish(True, appliance_id=str(appliance.id), fresh_stamp=fresh)


def _forget_previous_attempt(appliance: Appliance) -> None:
    """Drop our copy of the last upgrade's outcome when a new one is stamped.

    The stamp does not touch the ``last_upgrade_*`` columns, so a node whose
    previous apply failed still read ``failed`` the instant this run stamped
    a new image, and the reboot step failed it in the same second while the
    supervisor went on to run the apply with no drive watching (ddi-pg on
    #1449). Same four columns the Fleet clear resets (#786).

    Deliberately NOT the clear's host command (``clear_upgrade_requested``):
    that command removes the slot-upgrade trigger and the fire-once marker,
    and it stays raised until a later heartbeat, so it would delete or
    re-fire the trigger this stamp is about to produce. Without it the next
    heartbeat may re-publish the host's old ``failed``, with its old
    timestamp, which is why ``_stale_failure`` also guards the reads.
    """
    appliance.last_upgrade_state = None
    appliance.last_upgrade_state_at = None
    appliance.last_upgrade_progress = None
    appliance.last_upgrade_log_tail = None


# ── Step 5: stage the new slot ───────────────────────────────────────


def _aware(at: datetime | None) -> datetime | None:
    """``at`` as an aware datetime; a naive one is taken as UTC."""
    if at is None or at.tzinfo is not None:
        return at
    return at.replace(tzinfo=UTC)


def _slot_staged(appliance: Appliance, target_version: str, stamped_at: datetime | None) -> bool:
    """Whether the host has staged ``target_version`` for THIS request.

    The host runner ends a successful apply at state ``done`` with progress
    ``reboot-pending``, and leaves both in place, so they alone also
    describe the last upgrade this node ever staged. Rebooting on that would
    restart the node in the middle of the apply this run just asked for. So:

    * the inactive slot must carry ``target_version``, when the supervisor
      reports slot versions (the sidecar is refreshed at the end of every
      apply);
    * when this invocation stamped a new image URL (``stamped_at`` set),
      the ``done`` must have been written after the stamp. An apply takes
      minutes, so a few seconds of clock skew between the worker and the
      host cannot make a stale ``done`` look new.
    """
    if appliance.last_upgrade_state != "done":
        return False
    progress = appliance.last_upgrade_progress or {}
    if progress.get("step") != "reboot-pending":
        return False
    slots = {v for v in (appliance.slot_a_version, appliance.slot_b_version) if v}
    if slots and target_version not in slots:
        return False
    if stamped_at is not None:
        done_at = _aware(appliance.last_upgrade_state_at)
        if done_at is None or done_at < stamped_at:
            return False
    return True


def _stale_failure(appliance: Appliance, stamped_at: datetime | None) -> bool:
    """Whether a ``failed`` state belongs to an attempt before this run's stamp.

    The counterpart of the stale-``done`` test in ``_slot_staged``: when this
    invocation stamped a new image URL (``stamped_at`` set), a failure written
    before the stamp (or with no timestamp at all) describes a previous
    attempt, and the supervisor is still about to run this one. Without a
    stamp this run (a re-driven node) every ``failed`` counts, as before.
    """
    if appliance.last_upgrade_state != "failed" or stamped_at is None:
        return False
    failed_at = _aware(appliance.last_upgrade_state_at)
    return failed_at is None or failed_at < stamped_at


async def _wait_for_staged_slot(
    db: AsyncSession,
    step: StepResult,
    node_name: str,
    target_version: str,
    *,
    stamped_at: datetime | None,
    timeout_s: float,
) -> Appliance | StepResult:
    """Poll until the host has staged ``target_version`` for this request.

    Returns the appliance row when the slot is staged and the node still
    has to reboot into it; every other way out is ``step``, finished. Shared
    by ``stage`` and ``reboot``, so a run resumed at either one judges the
    host the same way.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        # End the read transaction each poll: the heartbeat writes these
        # columns from another session, and a fresh checkout is what lets
        # ``pool_pre_ping`` replace a connection lost to a database
        # switchover while this waits.
        await db.commit()
        appliance = await _resolve_appliance(db, node_name)
        if appliance is None:
            return step.finish(False, error=f"appliance row vanished mid-upgrade: {node_name}")
        await db.refresh(appliance)
        if appliance.installed_appliance_version == target_version:
            # A resumed run whose node already rebooted into the new slot.
            return step.finish(True, already_running_target=True)
        if appliance.last_upgrade_state == "failed" and not _stale_failure(appliance, stamped_at):
            return step.finish(False, error="supervisor reported upgrade failed")
        if appliance.reboot_requested:
            # A request is already outstanding (a resumed run, or an
            # operator's). Stamping another could reboot the node twice.
            return step.finish(True, reboot_already_requested=True)
        if _slot_staged(appliance, target_version, stamped_at):
            return appliance
        if time.monotonic() >= deadline:
            return step.finish(
                False,
                error=f"slot was not staged within {timeout_s:.0f}s",
                last_upgrade_state=appliance.last_upgrade_state,
            )
        await asyncio.sleep(_POLL_INTERVAL_S)


async def _step_stage(
    db: AsyncSession,
    node_name: str,
    target_version: str,
    *,
    stamped_at: datetime | None,
    timeout_s: float = DEFAULT_STAGE_TIMEOUT_S,
) -> StepResult:
    """Wait for the host to stage the new slot, and nothing more (#1463).

    Runs before the node is cordoned or drained, so the host fetches its
    image while every pod on the node still serves: the slot-image mirror,
    when it runs here, and the frontend behind the address in the image URL
    (#1708). The reboot is requested later, by ``reboot``, after the drain.
    """
    step = StepResult(
        name="stage",
        started_at=_now_iso(),
        detail={"node": node_name, "target_version": target_version},
    )
    outcome = await _wait_for_staged_slot(
        db, step, node_name, target_version, stamped_at=stamped_at, timeout_s=timeout_s
    )
    if isinstance(outcome, StepResult):
        return outcome
    return step.finish(True, appliance_id=str(outcome.id))


# ── Step 10: reboot into the staged slot ──────────────────────────────


async def _step_reboot(
    db: AsyncSession,
    node_name: str,
    target_version: str,
    *,
    stamped_at: datetime | None,
    timeout_s: float = DEFAULT_STAGE_TIMEOUT_S,
) -> StepResult:
    """Request the reboot into the staged slot, once it is staged.

    The host runner writes the inactive slot, arms the next boot and stops
    there ("upgrade staged — reboot to boot the new slot"); it never reboots
    on its own. Without this step the health gate below could only time out
    (found by ddi-pg on #1449). The request goes through the same flag as
    the Fleet reboot action, delivered by the supervisor's heartbeat.

    In the chain ``stage`` has already waited for the slot, so the first poll
    finds it staged; the wait stays here for a run resumed at this step.
    """
    step = StepResult(
        name="reboot",
        started_at=_now_iso(),
        detail={"node": node_name, "target_version": target_version},
    )
    outcome = await _wait_for_staged_slot(
        db, step, node_name, target_version, stamped_at=stamped_at, timeout_s=timeout_s
    )
    if isinstance(outcome, StepResult):
        return outcome
    appliance = outcome

    request_reboot(appliance)
    db.add(
        AuditLog(
            user_id=None,
            user_display_name=SYSTEM_ACTOR,
            auth_source="system",
            action="appliance.reboot_scheduled",
            resource_type="appliance",
            resource_id=str(appliance.id),
            resource_display=appliance.hostname,
            result="success",
            new_value={"reason": "rolling upgrade", "target_version": target_version},
        )
    )
    # Committed before the wake: the supervisor's heartbeat reads the flag
    # from another session.
    await db.commit()
    await publish_wake(appliance_channel(appliance.id))
    logger.info("upgrade_node_reboot_requested", node=node_name, target_version=target_version)
    return step.finish(True, appliance_id=str(appliance.id))


# ── Step 11: health gate ───────────────────────────────────────────────


async def _step_health_gate(
    db: AsyncSession,
    node_name: str,
    target_version: str,
    *,
    stamped_at: datetime | None = None,
    timeout_s: float = DEFAULT_HEALTH_GATE_TIMEOUT_S,
) -> StepResult:
    """Wait for the appliance's heartbeat to report
    ``installed_appliance_version == target_version`` AND
    ``last_upgrade_state`` of ``done`` or ``ready`` (the supervisor settles
    the former to the latter once the new slot is committed, #2007).

    Failure paths we surface:
      * ``last_upgrade_state == 'failed'`` — the apply itself failed. A
        failure older than this run's stamp (``stamped_at``) is a previous
        attempt's and is waited past, not reported: the reboot step's early
        exits hand over without having seen a fresh state (#1449).
      * Health-gate auto-revert (#138 Phase 8c): the host reboots back
        into the OLD slot. A supervisor with #2007 reports that as
        ``failed`` with ``reverted`` in the progress, surfaced here as
        ``auto_reverted``; an older one leaves ``done`` on the OLD slot,
        and installed_version never matching ends in the timeout.
      * Timeout — the host is taking too long; halt + alert.
    """
    step = StepResult(
        name="health_gate",
        started_at=_now_iso(),
        detail={"node": node_name, "target_version": target_version},
    )
    deadline = time.monotonic() + timeout_s
    # Last installed version we saw — Phase F's classifier uses this to
    # distinguish "node never came back up" (installed_version still
    # the pre-upgrade value past the timeout) from "node came back on
    # the old slot" (Phase 8c health-gate auto-revert — installed
    # moved but landed on the wrong slot).
    last_installed: str | None = None
    while time.monotonic() < deadline:
        # One transaction per poll, as in ``_step_reboot``: this wait spans
        # the node's reboot, and a dropped connection must be replaced at
        # the next checkout rather than crash the step.
        await db.commit()
        appliance = await _resolve_appliance(db, node_name)
        if appliance is None:
            return step.finish(False, error=f"appliance row vanished mid-upgrade: {node_name}")
        # Refresh so we see the supervisor's heartbeat updates.
        await db.refresh(appliance)
        last_installed = appliance.installed_appliance_version
        if appliance.last_upgrade_state == "failed" and not _stale_failure(appliance, stamped_at):
            # #2007 — the supervisor reports a node that came back on the
            # slot it did NOT stage as failed + ``reverted``. Named apart so
            # the alert classifier calls it the auto-revert it is, rather
            # than an apply that failed.
            if (appliance.last_upgrade_progress or {}).get("reverted") is True:
                return step.finish(
                    False,
                    error="auto_reverted: the node booted its previous slot",
                    installed_version=last_installed,
                )
            return step.finish(
                False,
                error="supervisor reported upgrade failed",
                installed_version=last_installed,
            )
        # ``ready`` as well as ``done`` (#2007): once the node is back on the
        # committed new slot the supervisor settles the host's stale
        # ``done``/``reboot-pending`` to ``ready``, and that can land before
        # the first heartbeat this step sees.
        if (
            appliance.installed_appliance_version == target_version
            and appliance.last_upgrade_state in (None, "done", "ready")
        ):
            return step.finish(
                True,
                installed_version=last_installed,
            )
        await asyncio.sleep(_POLL_INTERVAL_S)
    return step.finish(
        False,
        error=f"health gate timed out after {timeout_s:.0f}s",
        installed_version=last_installed,
    )


# ── Step 12: convergence ─────────────────────────────────────────────


async def _step_convergence(
    node_name: str,
    *,
    timeout_s: float = DEFAULT_CONVERGENCE_TIMEOUT_S,
) -> StepResult:
    """Wait for the node to be fully back in service:

    * k8s Node ``Ready=True`` — etcd member rejoined; kubelet up.
    * Every DaemonSet pod on the node reports Ready (the readiness-
      probe marker file from Phase A2 fires only after the agent has
      synced + the daemon is responding).

    It deliberately does NOT wait for the CNPG instance count (#1544).
    The node's own drain evicted its Postgres instance, whose local-path
    volume pins it to this node, and the cordon keeps the replacement pod
    Pending — so the count cannot recover until the uncordon that follows
    this step. The count is waited for in ``cluster_verify`` (after the
    uncordon) and in the next node's ``preflight`` (before its cordon).
    """
    step = StepResult(name="convergence", started_at=_now_iso(), detail={"node": node_name})
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            node_status, node = k8s.get_node(node_name)
        except k8s.KubeapiUnavailableError:
            # A node rejoining after its reboot is exactly when the API
            # times out; one timeout ending the step failed a run whose
            # node came back seconds later (#1449). Keep polling until the
            # window ends.
            await asyncio.sleep(_POLL_INTERVAL_S)
            continue
        if node_status != 200 or node is None:
            await asyncio.sleep(_POLL_INTERVAL_S)
            continue
        if not k8s.is_node_ready(node):
            await asyncio.sleep(_POLL_INTERVAL_S)
            continue
        # DS pods on the node — require every non-terminal one to be Ready.
        try:
            pods = k8s.list_pods_on_node(node_name)
        except k8s.KubeapiUnavailableError:
            await asyncio.sleep(_POLL_INTERVAL_S)
            continue
        ds_pods = [
            p for p in pods if k8s.pod_is_owned_by_daemonset(p) and not k8s.pod_is_terminal(p)
        ]
        not_ready = []
        for pod in ds_pods:
            conditions = (pod.get("status") or {}).get("conditions") or []
            is_ready = any(
                c.get("type") == "Ready" and c.get("status") == "True" for c in conditions
            )
            if not is_ready:
                meta = pod.get("metadata") or {}
                not_ready.append(f"{meta.get('namespace')}/{meta.get('name')}")
        if not not_ready:
            return step.finish(
                True,
                ds_pod_count=len(ds_pods),
            )
        await asyncio.sleep(_POLL_INTERVAL_S)
    return step.finish(
        False,
        error=f"convergence timed out after {timeout_s:.0f}s",
    )


# ── Step 13: uncordon + clear maintenance window ─────────────────────


async def _step_uncordon(
    node_name: str,
    cluster_name: str,
    namespace: str | None,
) -> StepResult:
    step = StepResult(
        name="uncordon",
        started_at=_now_iso(),
        detail={"node": node_name, "cluster": cluster_name},
    )
    ok, err = k8s.uncordon_node(node_name)
    if not ok:
        return step.finish(False, error=err or "uncordon failed")
    if not cluster_name:
        # #1545 — an empty cluster name is documented as "disables
        # CNPG-related steps", and the maintenance-window SET above is
        # skipped on that basis. The CLEAR must be skipped too:
        # patch_cnpg_maintenance_window("") PATCHes the clusters
        # collection URL, gets a non-200, and fails the step after a
        # successful uncordon — flipping a clean per-node upgrade to
        # failed at its last step.
        return step.finish(True, maintenance_window_clear_skipped=True)
    ok, err = k8s.patch_cnpg_maintenance_window(
        cluster_name,
        in_progress=False,
        reuse_pvc=True,
        namespace=namespace,
    )
    if not ok:
        # Uncordon succeeded but the maintenance window patch didn't.
        # That's a degraded state — return a partial-success warning so
        # the orchestrator can choose whether to alert or continue.
        return step.finish(
            False,
            error=f"uncordon ok, maintenance-window clear failed: {err}",
            uncordon_ok=True,
            # #2449 — the helper's own answer, so the retry can classify it:
            # the step's error is prefixed and no longer starts "kubeapi ".
            kubeapi_error=err,
        )
    return step.finish(True)


# ── Compensation: release the node after a failure ───────────────────


async def _step_release_node(
    node_name: str,
    cluster_name: str,
    namespace: str | None,
    *,
    clear_window: bool,
    uncordon_skip_reason: str | None = None,
) -> StepResult:
    """Compensating step for #1542 — best-effort release of a node
    whose upgrade failed once this run had started holding it.

    Uncordons the node and, when this run set the CNPG maintenance
    window, clears it. Both actions are idempotent (uncordoning an
    uncordoned node is a 200; clearing an unset window is a no-op
    patch), so this is safe to run even when the failing step
    partially released the node itself. The outcome is recorded as
    its own step in the per-node progress, so the operator can see
    whether the node was released or is still cordoned with the
    window on and needs a manual release.

    ``uncordon_skip_reason`` set means the uncordon must not happen: the
    run never cordoned the node (it failed at or before the cordon with
    the window already set), or the node was already unschedulable before
    the upgrade cordoned it, so uncordoning would undo an operator's
    cordon. The window clear still runs.
    """
    step = StepResult(
        name="release_node",
        started_at=_now_iso(),
        detail={"node": node_name, "cluster": cluster_name},
    )
    done: dict[str, Any] = {}
    if uncordon_skip_reason is not None:
        done["uncordon_skipped"] = uncordon_skip_reason
    else:
        ok, err = k8s.uncordon_node(node_name)
        if not ok:
            # The window clear is not attempted after a failed uncordon, so
            # a window this run set is still on as well (#1542).
            stuck = ["cordon"] + (["maintenance_window"] if clear_window and cluster_name else [])
            return step.finish(
                False,
                error=f"compensating uncordon failed: {err}",
                uncordon_ok=False,
                stuck=stuck,
            )
        done["uncordon_ok"] = True
    if not (clear_window and cluster_name):
        return step.finish(True, maintenance_window_clear_skipped=True, **done)
    ok, err = k8s.patch_cnpg_maintenance_window(
        cluster_name,
        in_progress=False,
        reuse_pvc=True,
        namespace=namespace,
    )
    if not ok:
        prefix = "uncordon ok, " if done.get("uncordon_ok") else ""
        return step.finish(
            False,
            error=f"{prefix}compensating maintenance-window clear failed: {err}",
            stuck=["maintenance_window"],
            **done,
        )
    return step.finish(True, maintenance_window_cleared=True, **done)


# ── Step 14: cluster verify ──────────────────────────────────────────


async def _step_cluster_verify(
    target_version: str,
    *,
    cnpg_cluster_name: str = "",
    cnpg_namespace: str | None = None,
    cnpg_timeout_s: float = DEFAULT_CNPG_READY_TIMEOUT_S,
    control_plane_release: str = "",
    control_plane_namespace: str | None = None,
    control_plane_timeout_s: float = DEFAULT_CONTROL_PLANE_READY_TIMEOUT_S,
) -> StepResult:
    """Wait for the node's Postgres instance and the control-plane
    Deployments (#1544), then re-run the cheap subset
    of preflight: replication lag + quorum.

    #1544 — runs after the uncordon, so the instance this node's drain
    evicted (pinned to the node by its local-path volume) can schedule
    again. The node is not reported done, and the next node is not started,
    until CNPG reads ``readyInstances == spec.instances``. This is also
    what makes the LAST node wait before the run reports success.

    Disk + version-path + inflight-lease aren't useful here — we just
    came out of the upgrade, those rows haven't changed enough to
    matter. The signal we care about is "CNPG repl is back streaming
    + every node is Ready again."
    """
    step = StepResult(name="cluster_verify", started_at=_now_iso())
    ok, cnpg_detail = await _wait_cnpg_instances_ready(
        cnpg_cluster_name, cnpg_namespace, timeout_s=cnpg_timeout_s
    )
    if not ok:
        return step.finish(
            False,
            error=(
                f"CNPG instances not all ready within {cnpg_timeout_s:.0f}s "
                f"after uncordon: {cnpg_detail.get('cnpg_wait_error')}"
            ),
            **cnpg_detail,
        )
    step.detail.update(cnpg_detail)
    ok, cp_detail = await _wait_control_plane_ready(
        control_plane_release, control_plane_namespace, timeout_s=control_plane_timeout_s
    )
    if not ok:
        return step.finish(
            False,
            error=(
                (
                    f"control-plane Deployments not all available within "
                    f"{control_plane_timeout_s:.0f}s after uncordon: "
                    f"{cp_detail.get('control_plane_wait_error')}"
                )
                if "control_plane_wait_timeout_s" in cp_detail
                else f"control-plane Deployments: {cp_detail.get('control_plane_wait_error')}"
            ),
            **cp_detail,
        )
    step.detail.update(cp_detail)
    repl = await preflight.check_replication_lag()
    quorum = preflight.check_quorum()
    results = {"replication_lag": repl.level, "quorum": quorum.level}
    if repl.level == "fail" or quorum.level == "fail":
        return step.finish(
            False,
            error="post-upgrade cluster verify failed",
            **results,
        )
    return step.finish(True, **results)


# ── Chained orchestration ────────────────────────────────────────────


async def single_node_upgrade(
    db: AsyncSession,
    *,
    node_name: str,
    target_version: str,
    slot_image: SlotImageTarget,
    cnpg_cluster_name: str = "",
    cnpg_namespace: str | None = None,
    start_step: StepName | None = None,
    lease_holder: str | None = None,
    mirror_deployment: str | None = None,
    control_plane_release: str | None = None,
    control_plane_namespace: str | None = None,
    remaining_nodes: list[str] | None = None,
    resume: NodeResume | None = None,
    checkpoint: Checkpoint | None = None,
) -> SingleNodeResult:
    """Drive one node through the 12-step rolling-upgrade primitive.

    Idempotent — each step short-circuits cleanly if its precondition
    is already met. Resumable via ``start_step``: pass the step name to
    skip-forward to (Phase D's orchestrator will compute this from the
    SystemUpgradeRun row's progress; Phase C tests + manual invocation
    pass it explicitly).

    Halt-on-failure: the first step that returns ``ok=False`` short-
    circuits the chain. The orchestrator decides recovery (auto-revert,
    operator confirm, …) — this function just reports.

    Args:
        cnpg_cluster_name: CNPG Cluster CR name (e.g.
            ``spatium-control-spatiumddi-postgresql`` on the appliance
            shape). Empty string skips CNPG-related steps for non-CNPG
            deploys.
        cnpg_namespace: namespace of the Cluster CR; defaults to the
            SA-mounted namespace.
        start_step: skip-ahead-to. Useful for resume + tests.
        lease_holder: identity holding the upgrade lease for this run, so
            the per-node preflight does not count that lease as another
            upgrade in flight.
        mirror_deployment: the slot-image mirror Deployment that serves an
            uploaded image; defaults to the default release's
            (``slot_image_mirror_deployment``).
        control_plane_release: Helm release whose Deployments must be
            available before the node is reported done (#1544); defaults
            to the default release.
        control_plane_namespace: namespace those Deployments live in;
            defaults to the api's own namespace.
        remaining_nodes: the run's nodes still to upgrade, this one
            included, in the order they will drain
            (``node_order.drain_order``); the preflight judges ``/var``
            headroom on those only, and the Redis master move steers the
            failover to the replica on the last of them (#2870). None judges
            every approved appliance, as Plan does, and leaves the failover
            unsteered.
        resume: where an earlier drive's chain for this node stopped
            (#2809). Takes precedence over ``start_step``. The step it names
            is run again, and the steps before it are taken as done, so a
            failure releases what they took.
        checkpoint: called before each step with ``checkpoint_entry``'s
            JSON, for the caller to store on ``db``. A connection error is
            retried after a rollback, as a step's is (``_store_checkpoint``);
            any other exception, or one outlasting the budget, is logged and
            the chain goes on.
    """
    steps_in_order: list[StepName] = list(CHAIN)
    if resume is not None:
        start_step = resume.step
    if start_step is not None:
        # Review polish — surface a typo'd / future-removed step name
        # loudly instead of silently restarting from step 0 (which would
        # re-cordon + re-drain a node that just finished its primitive
        # cleanly). The previous fall-through was a footgun for the
        # Phase D orchestrator's resume logic.
        if start_step not in steps_in_order:
            # ValueError rather than OrchestratorError to avoid pulling
            # the orchestrator module into per_node's import graph (it
            # already imports per_node). The orchestrator catches +
            # surfaces this when it drives the chain.
            raise ValueError(
                f"unknown resume step {start_step!r}; "
                f"expected one of: {', '.join(steps_in_order)}"
            )
        start_index = steps_in_order.index(start_step)
    else:
        start_index = 0

    results: list[StepResult] = []

    # #1542 — compensation state for a failure once this run holds the
    # node (window set and/or cordoned). On a resume past a step, the
    # earlier invocation already did it, so seed the flags from
    # start_index; the step runs below flip them as they complete in this
    # invocation.
    #
    # #2809 — a ``resume`` re-runs the step the earlier drive was IN, which
    # may have landed before that drive died: a window patch or a cordon
    # that took effect with nobody left to record it. So the step being
    # resumed counts as taken too (``>=``): clearing a window that is not set
    # and uncordoning a node this run cordoned are both safe.
    if resume is not None:
        cordon_done = start_index >= steps_in_order.index("cordon")
        window_set = bool(cnpg_cluster_name) and start_index >= steps_in_order.index(
            "cnpg_maintenance_on"
        )
    else:
        cordon_done = start_index > steps_in_order.index("cordon")
        window_set = bool(cnpg_cluster_name) and start_index > steps_in_order.index(
            "cnpg_maintenance_on"
        )
    released = start_index > steps_in_order.index("uncordon")
    # Set from the cordon step's pre-cordon read. A resumed run did not
    # read it, so it falls back to uncordoning, as before — unless the
    # checkpoint carried the earlier drive's read (#2809).
    pre_cordoned = bool(resume is not None and resume.was_unschedulable)
    # #2449 — shared across the cordon step's retries; see ``_step_cordon``.
    # #2809 — on a resume at or past the cordon, the earlier drive may
    # already have cordoned the node, so a fresh read would take this run's
    # own cordon for an operator's. Carry the earlier read, or "unknown".
    pre_cordon: dict[str, bool | None] = {}
    if resume is not None and start_index >= steps_in_order.index("cordon"):
        pre_cordon["was_unschedulable"] = (
            resume.was_unschedulable if resume.pre_cordon_known else None
        )
    # The stamp time of THIS run, for the stage / reboot / health-gate reads.
    stamped_at: datetime | None = (
        resume.stamped_at
        if resume is not None and start_index > steps_in_order.index("trigger_slot_apply")
        else None
    )

    async def _report(step: StepName) -> None:
        """Hand the caller a checkpoint before ``step`` runs (#2809)."""
        if checkpoint is None:
            return
        await _store_checkpoint(
            db,
            checkpoint,
            checkpoint_entry(node_name, step, stamped_at=stamped_at, pre_cordon=pre_cordon),
            node_name=node_name,
            step=step,
        )

    async def _fail(step: StepName) -> SingleNodeResult:
        """Fail the chain, first releasing what this run holds (#1542):
        the CNPG maintenance window it set, and the cordon it applied.
        Without the compensation the node stays cordoned and the window
        stays on until an operator releases them by hand."""
        if (cordon_done or window_set) and not released:
            skip: str | None = None
            if not cordon_done:
                skip = "the run never cordoned the node"
            elif pre_cordoned:
                skip = "the node was already cordoned before the upgrade"
            try:
                comp = await _step_release_node(
                    node_name,
                    cnpg_cluster_name,
                    cnpg_namespace,
                    clear_window=window_set,
                    uncordon_skip_reason=skip,
                )
            except Exception as exc:  # noqa: BLE001 — never mask the real failure
                # The compensation is best-effort: an exception here must
                # not escape and replace the step failure being reported.
                # What the crash left held is unknown, so name everything
                # this run took (#1542).
                crash_stuck = (["cordon"] if skip is None else []) + (
                    ["maintenance_window"] if window_set else []
                )
                comp = StepResult(name="release_node", started_at=_now_iso()).finish(
                    False,
                    error=f"compensating release crashed: {exc}",
                    stuck=crash_stuck,
                )
            results.append(comp)
            if not comp.ok:
                logger.error(
                    "single_node_upgrade_release_failed",
                    node=node_name,
                    failed_at=step,
                    error=comp.error,
                )
        return _failed(node_name, target_version, step, results)

    async def _run(step: StepName, make: Callable[[], Awaitable[StepResult]]) -> bool:
        if steps_in_order.index(step) < start_index:
            return True
        await _report(step)
        r = await _run_step_riding_db_failover(db, step, node_name, make)
        results.append(r)
        return r.ok

    # When this invocation first sent a fresh stamp's commit (#2177): set before
    # the commit, so a commit whose acknowledgement was lost still counts.
    fresh_stamp_sent_at: datetime | None = None

    async def _trigger_and_commit() -> StepResult:
        # #1445 — the supervisor reads the desired slot image from its
        # heartbeat, in another session, so it sees the stamp only once it is
        # committed. The orchestrator commits before and after this whole
        # chain, never between steps, so without this the health gate waited
        # out its timeout for a node that had never been told to upgrade. The
        # commit is part of the step (#2177): a commit lost to a database
        # failover discards the stamp, so the retry has to stamp again.
        nonlocal fresh_stamp_sent_at
        r = await _step_trigger_slot_apply(db, node_name, target_version, slot_image)
        if not r.ok:
            return r
        if r.detail.get("fresh_stamp"):
            fresh_stamp_sent_at = datetime.now(UTC)
        elif fresh_stamp_sent_at is not None:
            # #2177 — the previous attempt's commit landed and only its
            # acknowledgement was lost, so this attempt found its own stamp
            # already there. It is still this run's fresh stamp: judged as a
            # re-driven node's (no ``stamped_at``), a ``failed`` or ``done``
            # left from an earlier attempt would count as this one's.
            r.detail["fresh_stamp"] = True
            r.detail["stamp_commit_ack_lost"] = True
        await db.commit()
        return r

    if not await _run(
        "preflight",
        lambda: _step_preflight(
            target_version,
            lease_holder,
            cnpg_cluster_name=cnpg_cluster_name,
            cnpg_namespace=cnpg_namespace,
            slot_image_id=slot_image.image_id,
            disk_nodes=remaining_nodes,
        ),
    ):
        return await _fail("preflight")
    if not await _run("etcd_snapshot", _step_etcd_snapshot):
        return await _fail("etcd_snapshot")
    if not await _run(
        "mirror_ready",
        lambda: _step_mirror_ready(
            db,
            node_name,
            target_version,
            slot_image,
            deployment=mirror_deployment
            or slot_image_mirror_deployment(chart_bump.DEFAULT_CHART_NAME),
        ),
    ):
        return await _fail("mirror_ready")
    if not await _run("trigger_slot_apply", _trigger_and_commit):
        return await _fail("trigger_slot_apply")
    if start_index <= steps_in_order.index("trigger_slot_apply"):
        if results and results[-1].detail.get("fresh_stamp"):
            stamped_at = fresh_stamp_sent_at or datetime.now(UTC)
    # #1463 — the host fetches and writes the slot while the node is still in
    # service, before anything below takes the node out of it.
    if not await _run(
        "stage", lambda: _step_stage(db, node_name, target_version, stamped_at=stamped_at)
    ):
        return await _fail("stage")
    # End the stage's read before the node leaves service. Cordoning the node
    # that runs the CNPG primary switches it over, and the switchover closes
    # every connection the old primary held; the reboot after the drain has
    # to start on a fresh connection, not commit on one of those. The read
    # is all it ends, so a connection already lost to a failover (#2177) is
    # rolled back instead: there is nothing to keep.
    await _end_read(db)
    if cnpg_cluster_name:
        if not await _run(
            "cnpg_maintenance_on",
            lambda: _step_cnpg_maintenance_on(cnpg_cluster_name, cnpg_namespace),
        ):
            return await _fail("cnpg_maintenance_on")
        window_set = True
    if not await _run("cordon", lambda: _step_cordon(node_name, pre_cordon=pre_cordon)):
        # The window may already be set — release it (#1542). The node is
        # not uncordoned: this run did not cordon it.
        return await _fail("cordon")
    if start_index <= steps_in_order.index("cordon"):
        pre_cordoned = results[-1].detail.get("was_unschedulable") is True
    cordon_done = True
    if cnpg_cluster_name:
        if not await _run(
            "verify_primary_moved",
            lambda: _step_verify_primary_moved(cnpg_cluster_name, node_name, cnpg_namespace),
        ):
            return await _fail("verify_primary_moved")
    # #2815 — before the drain evicts the Redis master, so the broker moves
    # by a manual failover instead of a Sentinel election that can split.
    if redis_master.sentinel_configured():
        await _run(
            "move_redis_master",
            lambda: _step_move_redis_master(
                node_name, control_plane_namespace, remaining_nodes=remaining_nodes
            ),
        )
    if not await _run("drain", lambda: _step_drain(node_name)):
        return await _fail("drain")
    if not await _run(
        "reboot", lambda: _step_reboot(db, node_name, target_version, stamped_at=stamped_at)
    ):
        return await _fail("reboot")
    if not await _run(
        "health_gate",
        lambda: _step_health_gate(db, node_name, target_version, stamped_at=stamped_at),
    ):
        return await _fail("health_gate")
    if not await _run("convergence", lambda: _step_convergence(node_name)):
        return await _fail("convergence")
    if not await _run(
        "uncordon", lambda: _step_uncordon(node_name, cnpg_cluster_name, cnpg_namespace)
    ):
        return await _fail("uncordon")
    released = True
    if not await _run(
        "cluster_verify",
        lambda: _step_cluster_verify(
            target_version,
            cnpg_cluster_name=cnpg_cluster_name,
            cnpg_namespace=cnpg_namespace,
            control_plane_release=control_plane_release or chart_bump.DEFAULT_CHART_NAME,
            control_plane_namespace=control_plane_namespace,
        ),
    ):
        # The node is already uncordoned and its window cleared by the
        # uncordon step (``released``), so ``_fail`` releases nothing: the
        # node stays in service and the run stops before the next drain.
        return await _fail("cluster_verify")

    return SingleNodeResult(
        node_name=node_name,
        target_version=target_version,
        ok=True,
        failed_at=None,
        steps=results,
    )


async def _store_checkpoint(
    db: AsyncSession,
    checkpoint: Checkpoint,
    entry: dict[str, Any],
    *,
    node_name: str,
    step: StepName,
    budget_s: float | None = None,
) -> None:
    """Store one checkpoint, riding out a Postgres failover (#2809).

    The checkpoints before ``verify_primary_moved``, ``drain`` and ``reboot``
    fall inside the CNPG switchover the cordon of the primary's node starts,
    so a refused connect there is expected, not exceptional. It is retried
    after a rollback, on a fresh connection (the engine pings on checkout),
    with the same backoff and budget a step gets: a checkpoint lost there
    would make a later takeover resume at the step before, which every step
    tolerates, but the drive the walk found crashing (#2809) lost it to the
    switchover on every roll of the primary's node.

    The rollback expires every object the session holds, the run row among
    them; the drive reads that row back only through ``_fence``, which never
    loads an expired attribute (#2809). Anything else, and a database still
    unreachable once the budget is spent, is logged and the node goes on:
    bookkeeping never fails a node."""
    budget = DB_FAILOVER_BUDGET_S if budget_s is None else budget_s
    first_failure: float | None = None
    attempt = 0
    while True:
        try:
            await checkpoint(entry)
            return
        except Exception as exc:  # noqa: BLE001 — bookkeeping never fails the node
            await _rollback_quietly(db)
            if is_transient_db_error(exc):
                now = _db_retry_clock()
                if first_failure is None:
                    first_failure = now
                delay = _DB_RETRY_BACKOFF_S[min(attempt, len(_DB_RETRY_BACKOFF_S) - 1)]
                if now - first_failure + delay <= budget:
                    attempt += 1
                    logger.warning(
                        "single_node_upgrade_checkpoint_db_unavailable",
                        node=node_name,
                        step=step,
                        attempt=attempt,
                        retry_in_s=delay,
                        error=str(exc),
                    )
                    await _db_retry_sleep(delay)
                    continue
            logger.warning(
                "single_node_upgrade_checkpoint_failed",
                node=node_name,
                step=step,
                error=str(exc),
            )
            return


async def _rollback_quietly(db: AsyncSession) -> None:
    """Discard the session's failed transaction so the next statement checks
    out a fresh connection (``pool_pre_ping`` replaces the dead one). A
    rollback on a connection that is already gone can raise too; the retry
    that follows is what finds out whether the database is back."""
    try:
        await db.rollback()
    except Exception:  # noqa: BLE001 — the connection is gone; the retry decides
        logger.debug("single_node_upgrade_rollback_failed", exc_info=True)


async def _end_read(db: AsyncSession) -> None:
    """End a read-only transaction. A connection lost to a database failover
    is rolled back instead, since a read has nothing to keep (#2177)."""
    try:
        await db.commit()
    except Exception as exc:
        if not is_transient_db_error(exc):
            raise
        logger.warning("single_node_upgrade_end_read_db_unavailable", error=str(exc))
        await _rollback_quietly(db)


def _db_retry_clock() -> float:
    return time.monotonic()


async def _db_retry_sleep(delay_s: float) -> None:
    await asyncio.sleep(delay_s)


async def _run_step_riding_db_failover(
    db: AsyncSession,
    step: StepName,
    node_name: str,
    make: Callable[[], Awaitable[StepResult]],
    *,
    budget_s: float | None = None,
) -> StepResult:
    """Run one step; a step that crashed is a failed step.

    #2177 — a step that lost its database connection is retried in place,
    after a rollback, for ``DB_FAILOVER_BUDGET_S`` from the first such error:
    one refused connect during a Postgres failover used to fail the step (or,
    with the database still down, crash the whole drive). Only a connection
    error is retried (``is_transient_db_error``); anything else, and a
    database still unreachable once the budget is spent, is recorded as the
    step crashing, as before. ``make`` builds a fresh coroutine per attempt.

    #2449 — a step in ``KUBEAPI_RETRY_STEPS`` that *returned* a failed result
    whose error is a transient kubeapi answer (``_kubeapi_transient``) is tried
    again in place, for ``KUBEAPI_RETRY_BUDGET_S`` from the first such answer:
    a CNPG admission PATCH that met a 500 while CloudNativePG's mutating webhook
    was between endpoints used to fail the run. Only the idempotent writes retry,
    and a kubeapi error still failing once the budget is spent is returned as it
    was, as before.
    """
    budget = DB_FAILOVER_BUDGET_S if budget_s is None else budget_s
    first_failure: float | None = None
    outages = 0
    attempt = 0
    kubeapi_first: float | None = None
    kubeapi_attempt = 0
    while True:
        attempt_started = _db_retry_clock()
        try:
            result = await make()
        except Exception as exc:  # noqa: BLE001 — last-resort wrapper
            if is_transient_db_error(exc):
                now = _db_retry_clock()
                # An attempt that ran longer than the budget was served by the
                # database for a while: this is a second outage, with a budget
                # of its own. A wait step (stage, health gate) runs for many
                # minutes and can outlive one failover. Capped, so a step can
                # not be restarted indefinitely.
                if (
                    first_failure is not None
                    and now - attempt_started >= budget
                    and outages < _DB_MAX_OUTAGES_PER_STEP
                ):
                    first_failure = None
                    attempt = 0
                if first_failure is None:
                    first_failure = now
                    outages += 1
                delay = _DB_RETRY_BACKOFF_S[min(attempt, len(_DB_RETRY_BACKOFF_S) - 1)]
                if now - first_failure + delay <= budget:
                    attempt += 1
                    logger.warning(
                        "single_node_upgrade_step_db_unavailable",
                        step=step,
                        node=node_name,
                        attempt=attempt,
                        retry_in_s=delay,
                        exc_type=type(exc).__name__,
                        error=str(exc),
                    )
                    await _rollback_quietly(db)
                    await _db_retry_sleep(delay)
                    continue
                logger.exception(
                    "single_node_upgrade_step_crashed",
                    step=step,
                    node=node_name,
                    db_unavailable_s=round(now - first_failure),
                    db_outages=outages,
                )
                lost = (
                    f"database unreachable for {now - first_failure:.0f}s"
                    if now - attempt_started < budget
                    else f"database lost {outages + 1} times in one step"
                )
                return StepResult(name=step, started_at=_now_iso()).finish(
                    False, error=f"step crashed: {lost}: {exc}"
                )
            logger.exception("single_node_upgrade_step_crashed", step=step, node=node_name)
            return StepResult(name=step, started_at=_now_iso()).finish(
                False, error=f"step crashed: {exc}"
            )
        # #2449 — make() returned (no exception). An idempotent write that the
        # API server answered with a transient kubeapi error (a 5xx, 408, 409,
        # 429, or a socket error that never reached it) is tried again in place,
        # within ``KUBEAPI_RETRY_BUDGET_S`` from the first such answer, so a CNPG
        # admission webhook briefly between endpoints does not fail the run.
        # A step whose error wraps the helper's answer (uncordon's window clear)
        # carries the answer itself as ``detail["kubeapi_error"]``.
        kubeapi_error = result.detail.get("kubeapi_error", result.error)
        if not result.ok and step in KUBEAPI_RETRY_STEPS and _kubeapi_transient(kubeapi_error):
            now = _db_retry_clock()
            if kubeapi_first is None:
                kubeapi_first = now
            if now - kubeapi_first + _KUBEAPI_RETRY_INTERVAL_S <= KUBEAPI_RETRY_BUDGET_S:
                kubeapi_attempt += 1
                logger.warning(
                    "single_node_upgrade_step_kubeapi_transient",
                    step=step,
                    node=node_name,
                    attempt=kubeapi_attempt,
                    retry_in_s=_KUBEAPI_RETRY_INTERVAL_S,
                    error=result.error,
                )
                await _db_retry_sleep(_KUBEAPI_RETRY_INTERVAL_S)
                continue
            logger.warning(
                "single_node_upgrade_step_kubeapi_gave_up",
                step=step,
                node=node_name,
                attempts=kubeapi_attempt,
                kubeapi_unavailable_s=round(now - kubeapi_first),
                error=result.error,
            )
        return result


def _failed(
    node_name: str,
    target_version: str,
    failed_at: StepName,
    results: list[StepResult],
) -> SingleNodeResult:
    # The error is the FAILING step's, not the last recorded step's —
    # a #1542 release_node compensation step may have been appended
    # after the failure, and its outcome must not mask why the chain
    # actually failed.
    failed_step = next((r for r in reversed(results) if r.name == failed_at), None)
    if failed_step is not None:
        last_err = failed_step.error
    else:
        last_err = results[-1].error if results else "unknown"
    return SingleNodeResult(
        node_name=node_name,
        target_version=target_version,
        ok=False,
        failed_at=failed_at,
        steps=results,
        error=last_err,
    )


# ``build_slot_image_url`` used to live here so an orchestrator-driven
# start didn't have to import from the appliance router. It composed only
# the URL, which is precisely how this path lost the sha256 + tls_insecure
# hints (#787). Both surfaces now go through
# ``services.appliance.slot_image_target.resolve_slot_image_target``,
# which returns all three together.

__all__ = [
    "DEFAULT_CONVERGENCE_TIMEOUT_S",
    "DEFAULT_DRAIN_TIMEOUT_S",
    "DEFAULT_HEALTH_GATE_TIMEOUT_S",
    "DEFAULT_MIRROR_READY_TIMEOUT_S",
    "DEFAULT_SWITCHOVER_TIMEOUT_S",
    "SingleNodeResult",
    "StepResult",
    "single_node_upgrade",
    "slot_image_mirror_deployment",
]
