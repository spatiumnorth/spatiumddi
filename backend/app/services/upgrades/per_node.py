"""Per-node upgrade primitive (#296 Phase C).

The 14-step sequence for taking one control-plane node from version
N-1 to N safely. Encapsulated as a single idempotent + resumable
async function ``single_node_upgrade`` plus the individual step
functions so an orchestrator (Phase D) can also drive them ala carte
for testing / dry-run.

Step shape (one row per step in the issue body; ``CHAIN`` is the order):

    1. preflight gate                — reuse Phase A's run_all
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
    9. drain                          — eviction loop (DS skip + terminal-
                                        pod skip + mirror-pod skip);
                                        --force NOT supported
   10. reboot                         — request the reboot into the staged
                                        slot (the host runner never reboots
                                        on its own, #1445)
   11. health gate                    — poll until installed_appliance_version
                                        == desired_appliance_version
   12. convergence                    — node Ready + CNPG instance reported
                                        + DaemonSet pod Ready
   13. uncordon + clear window        — uncordon_node + maintenance off
   14. cluster verify                 — re-run a small slice of preflight

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

Resumability: each step is idempotent in itself (cordon-already-
cordoned is a 200, evict-already-gone is 404 treated as success,
etc.). The orchestrator records ``progress.current_step`` on the
SystemUpgradeRun row; on resume the function reads the row, fast-
forwards past completed steps, and continues. Phase C v0 doesn't
implement the fast-forward — the caller passes ``start_step`` to
resume; Phase D will add the read-from-row-and-continue logic.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_wake import appliance_channel, publish_wake
from app.models.appliance import Appliance
from app.models.audit import AuditLog
from app.services.appliance import k8s
from app.services.appliance.reboot import request_reboot
from app.services.appliance.slot_image_target import (
    SlotImageArchitectureMismatch,
    SlotImageTarget,
    desired_slot_image_url,
    stamp_desired_slot_image,
)
from app.services.upgrades import chart_bump, preflight

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
    "drain",
    "reboot",
    "health_gate",
    "convergence",
    "uncordon",
    "cluster_verify",
]

# The chain's order, once. ``single_node_upgrade`` runs it and resolves a
# ``start_step`` against it; the CNPG steps are skipped without a cluster name.
CHAIN: tuple[StepName, ...] = (
    "preflight",
    "etcd_snapshot",
    "mirror_ready",
    "trigger_slot_apply",
    "stage",
    "cnpg_maintenance_on",
    "cordon",
    "verify_primary_moved",
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
# 10 min — the mirror's pod back on its node after that node's reboot: its
# migrate-wait init container, then the api image cold-starting.
DEFAULT_MIRROR_READY_TIMEOUT_S = 600.0

# Poll cadence — gentle on kubeapi + the appliance row. Slow enough
# that 30 min worth of polls is ~600 calls, fast enough that step
# transitions surface to the UI within a few seconds.
_POLL_INTERVAL_S = 3.0


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


# ── Step 1: preflight ────────────────────────────────────────────────


async def _step_preflight(target_version: str, lease_holder: str | None = None) -> StepResult:
    step = StepResult(name="preflight", started_at=_now_iso())
    # The orchestrator holds the upgrade lease while it drives this chain;
    # without its identity, the in-flight check fails on that very lease.
    report = await preflight.run_all(target_version=target_version, own_holder=lease_holder)
    if report.overall == "fail":
        fails = [r.name for r in report.results if r.level == "fail"]
        return step.finish(
            False,
            error=f"preflight failed: {', '.join(fails)}",
            overall=report.overall,
            failed_checks=fails,
        )
    return step.finish(
        True,
        overall=report.overall,
        warns=[r.name for r in report.results if r.level == "warn"],
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


async def _step_cordon(node_name: str) -> StepResult:
    step = StepResult(name="cordon", started_at=_now_iso(), detail={"node": node_name})
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

    while time.monotonic() < deadline:
        try:
            pods = k8s.list_pods_on_node(node_name)
        except k8s.KubeapiUnavailableError as exc:
            return step.finish(False, error=f"list pods failed: {exc}")

        # Filter to evictable pods.
        candidates: list[tuple[str, str]] = []  # [(name, namespace)]
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
            candidates.append((name, ns))

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
        await asyncio.sleep(_POLL_INTERVAL_S)

    return step.finish(
        False,
        error=(f"drain timed out after {timeout_s:.0f}s — " f"{len(blocked)} pod(s) still present"),
        evicted_count=len(set(evicted)),
        evicted=list(set(evicted)),
        blocked=blocked,
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
        return step.finish(False, error=f"no Appliance row with hostname={node_name!r}")
    await db.refresh(appliance)
    if appliance.installed_appliance_version == target_version:
        return step.finish(True, skipped=True, reason="already running the target")
    if appliance.desired_slot_image_url == desired_slot_image_url(appliance, slot_image):
        return step.finish(
            True, skipped=True, reason="the node already holds this stamp; nothing new to fetch"
        )

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
    stmt = select(Appliance).where(Appliance.hostname == node_name)
    return (await db.execute(stmt)).scalar_one_or_none()


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
        return step.finish(False, error=f"no Appliance row with hostname={node_name!r}")
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
    ``last_upgrade_state == 'done'``.

    Failure paths we surface:
      * ``last_upgrade_state == 'failed'`` — the apply itself failed. A
        failure older than this run's stamp (``stamped_at``) is a previous
        attempt's and is waited past, not reported: the reboot step's early
        exits hand over without having seen a fresh state (#1449).
      * Health-gate auto-revert (#138 Phase 8c): the host reboots back
        into the OLD slot, so installed_version never matches +
        ``last_upgrade_state`` may be 'done' on the OLD slot. We
        catch this via the version comparison.
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
            return step.finish(
                False,
                error="supervisor reported upgrade failed",
                installed_version=last_installed,
            )
        if (
            appliance.installed_appliance_version == target_version
            and appliance.last_upgrade_state in (None, "done")
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

    CNPG instance-streaming + Redis-reconnected are nice-to-have but
    not load-bearing — CNPG's own readiness probe handles that
    through the Cluster.status block; we don't gate uncordon on it.
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
        )
    return step.finish(True)


# ── Step 14: cluster verify ──────────────────────────────────────────


async def _step_cluster_verify(target_version: str) -> StepResult:
    """Re-run the cheap subset of preflight: replication lag + quorum.

    Disk + version-path + inflight-lease aren't useful here — we just
    came out of the upgrade, those rows haven't changed enough to
    matter. The signal we care about is "CNPG repl is back streaming
    + every node is Ready again."
    """
    step = StepResult(name="cluster_verify", started_at=_now_iso())
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
    """
    steps_in_order: list[StepName] = list(CHAIN)
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

    async def _run(step: StepName, coro: Any) -> bool:
        if steps_in_order.index(step) < start_index:
            return True
        try:
            r = await coro
        except Exception as exc:  # noqa: BLE001 — last-resort wrapper
            logger.exception("single_node_upgrade_step_crashed", step=step, node=node_name)
            r = StepResult(name=step, started_at=_now_iso()).finish(
                False, error=f"step crashed: {exc}"
            )
        results.append(r)
        return r.ok

    if not await _run("preflight", _step_preflight(target_version, lease_holder)):
        return _failed(node_name, target_version, "preflight", results)
    if not await _run("etcd_snapshot", _step_etcd_snapshot()):
        return _failed(node_name, target_version, "etcd_snapshot", results)
    if not await _run(
        "mirror_ready",
        _step_mirror_ready(
            db,
            node_name,
            target_version,
            slot_image,
            deployment=mirror_deployment
            or slot_image_mirror_deployment(chart_bump.DEFAULT_CHART_NAME),
        ),
    ):
        return _failed(node_name, target_version, "mirror_ready", results)
    if not await _run(
        "trigger_slot_apply",
        _step_trigger_slot_apply(db, node_name, target_version, slot_image),
    ):
        return _failed(node_name, target_version, "trigger_slot_apply", results)
    # #1445 — the supervisor reads the desired slot image from its heartbeat,
    # in another session, so it sees the stamp only once it is committed. The
    # orchestrator commits before and after this whole chain, never between
    # steps, so without this the health gate waited out its timeout for a
    # node that had never been told to upgrade.
    stamped_at: datetime | None = None
    if start_index <= steps_in_order.index("trigger_slot_apply"):
        await db.commit()
        if results and results[-1].detail.get("fresh_stamp"):
            stamped_at = datetime.now(UTC)
    # #1463 — the host fetches and writes the slot while the node is still in
    # service, before anything below takes the node out of it.
    if not await _run("stage", _step_stage(db, node_name, target_version, stamped_at=stamped_at)):
        return _failed(node_name, target_version, "stage", results)
    if cnpg_cluster_name:
        if not await _run(
            "cnpg_maintenance_on",
            _step_cnpg_maintenance_on(cnpg_cluster_name, cnpg_namespace),
        ):
            return _failed(node_name, target_version, "cnpg_maintenance_on", results)
    if not await _run("cordon", _step_cordon(node_name)):
        return _failed(node_name, target_version, "cordon", results)
    if cnpg_cluster_name:
        if not await _run(
            "verify_primary_moved",
            _step_verify_primary_moved(cnpg_cluster_name, node_name, cnpg_namespace),
        ):
            return _failed(node_name, target_version, "verify_primary_moved", results)
    if not await _run("drain", _step_drain(node_name)):
        return _failed(node_name, target_version, "drain", results)
    if not await _run("reboot", _step_reboot(db, node_name, target_version, stamped_at=stamped_at)):
        return _failed(node_name, target_version, "reboot", results)
    if not await _run(
        "health_gate",
        _step_health_gate(db, node_name, target_version, stamped_at=stamped_at),
    ):
        return _failed(node_name, target_version, "health_gate", results)
    if not await _run("convergence", _step_convergence(node_name)):
        return _failed(node_name, target_version, "convergence", results)
    if not await _run("uncordon", _step_uncordon(node_name, cnpg_cluster_name, cnpg_namespace)):
        return _failed(node_name, target_version, "uncordon", results)
    if not await _run("cluster_verify", _step_cluster_verify(target_version)):
        return _failed(node_name, target_version, "cluster_verify", results)

    return SingleNodeResult(
        node_name=node_name,
        target_version=target_version,
        ok=True,
        failed_at=None,
        steps=results,
    )


def _failed(
    node_name: str,
    target_version: str,
    failed_at: StepName,
    results: list[StepResult],
) -> SingleNodeResult:
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
