"""Cluster health endpoints — issue #402 ("Cluster → Overview" dashboard).

Mounted at ``/api/v1/appliance/cluster``:

    GET  /health          one-shot snapshot (initial paint, MCP, scripting)
    GET  /health/stream   SSE — a fresh snapshot every ~2 s (live dashboard)

Both read the k3s cluster *underneath* the appliance via the api pod's
ServiceAccount (nodes + pods + kubelet Summary API). Live CPU / memory — and,
since Kubernetes 1.36, PSI stall percentages (#983) — come from the kubelet
Summary API because the appliance ships no metrics-server / Prometheus, the
same source the TTY console uses. That API is reached per node either
directly (``nodes/stats``) or through the apiserver proxy (``nodes/proxy``);
the snapshot reports which. See ``services/appliance/cluster_health.py`` for
the gather.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import anyio
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import DB
from app.core.permissions import require_permission
from app.core.responses import EventStreamResponse
from app.db import AsyncSessionLocal
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.services.appliance import k8s
from app.services.appliance.cluster_health import cluster_unavailable, get_cluster_health
from app.services.appliance.storage_health import evaluate_storage, worst_severity

logger = structlog.get_logger(__name__)

router = APIRouter()

# How often the SSE stream re-gathers + pushes a snapshot. 2 s is the sweet
# spot: kubelet's Summary API itself only refreshes every ~1–10 s, and a
# handful of kubeapi calls per tick is cheap, but it feels live in the UI.
_STREAM_INTERVAL_S = 2.0


class HostPartition(BaseModel):
    mount: str
    label: str
    total_bytes: int
    used_bytes: int


# ── #999 Part A — storage redundancy, as reported by the supervisor ──


class MdMember(BaseModel):
    device: str
    #: The kernel's own comma-joined member state (``in_sync`` /
    #: ``faulty`` / ``spare`` / ``write_mostly`` / …), verbatim rather
    #: than collapsed — "faulty" and "spare" call for opposite actions.
    state: str
    slot: int | None = None


class MdSync(BaseModel):
    """A rebuild / resync / scrub in progress. Absent when idle."""

    action: str
    percent: float | None = None
    eta_seconds: int | None = None


class MdArray(BaseModel):
    name: str
    level: str
    #: DERIVED, not copied from the kernel: a raid1 down to one member
    #: reports ``array_state=clean`` because the survivor is internally
    #: consistent, and reporting that verbatim would show a single point
    #: of failure as healthy. ``unknown`` when the member count could not
    #: be read, which is never to be rendered as healthy either.
    state: str
    array_state: str
    #: ``None`` when ``raid_disks`` was unreadable — never 0, which would
    #: make every degradation test false and drop the array through to
    #: "clean". ``state`` is ``unknown`` in that case.
    members_expected: int | None = None
    members_in_sync: int
    members_faulty: int
    spares: int
    #: How many more members can be lost before the array stops serving.
    #: This — not ``state`` — is what decides alert severity.
    redundancy_remaining: int | None = None
    min_working_members: int | None = None
    size_bytes: int | None = None
    members: list[MdMember] = []
    sync: MdSync | None = None


class MultipathPath(BaseModel):
    device: str
    #: dm-multipath's own verdict, which needs the device-mapper ioctl
    #: (``multipathd show topology``) — Part B tooling. Always
    #: ``unknown`` here; a fabricated ``active`` would turn a missing
    #: reading into a false all-clear.
    state: str
    #: The path's SCSI device state (``running`` / ``offline`` /
    #: ``blocked``), which sysfs does answer. ``None`` on a path that
    #: has none (an NVMe path).
    device_state: str | None = None


class MultipathMap(BaseModel):
    name: str
    dm_device: str
    uuid: str
    paths_total: int
    #: Paths whose SCSI device reports a DEFINITE fault. Counted the
    #: negative way round so an unreadable path never inflates a clean
    #: bill of health.
    paths_faulted: int
    size_bytes: int | None = None
    paths: list[MultipathPath] = []


class StorageFindingOut(BaseModel):
    """One classified thing worth saying about a node's redundancy."""

    severity: str
    kind: str
    name: str
    detail: str


class NodeStorage(BaseModel):
    """One node's storage-redundancy snapshot (#999 Part A).

    ``md_supported`` separates "the kernel has no md support" from "md
    is loaded and there are no arrays" — both produce an empty
    ``md_arrays``, and only the first means the reading is unavailable.

    ``findings`` is derived server-side by
    ``services/appliance/storage_health.evaluate_storage`` rather than
    left to each caller: the same function backs the
    ``appliance_storage_degraded`` alert and the ``find_appliance_storage``
    copilot tool, so a chip in the browser cannot say "clean" while the
    alert says "degraded". Re-deriving it in TypeScript would be a second
    copy of the rule, and the rule — severity from redundancy remaining,
    not from the state string — is the whole subtlety.
    """

    md_supported: bool = False
    md_arrays: list[MdArray] = []
    multipath_maps: list[MultipathMap] = []
    findings: list[StorageFindingOut] = []
    #: Worst severity among ``findings``; ``None`` when there is nothing
    #: to say.
    worst_severity: str | None = None


class PSIWindow(BaseModel):
    """One /proc/pressure line's rolling averages, as percentages of wall time.

    ``avg10`` is the number to look at during an incident; ``avg300`` is the
    one that separates a burst from a condition.
    """

    avg10: float | None = None
    avg60: float | None = None
    avg300: float | None = None


class PSIStats(BaseModel):
    """``some`` / ``full`` stall shares for one resource (#983 Phase 2).

    ``some`` — at least one task was stalled waiting for the resource.
    ``full`` — every runnable task was. At node level the kernel reports CPU
    ``full`` as 0, so a CPU verdict has to read ``some``.

    The whole object is null when the kubelet did not report PSI (pre-1.36,
    or the feature off). Null is UNRECORDED, never "no pressure" — the two
    are opposite facts and a panel that conflates them is worse than one that
    shows nothing.
    """

    some: PSIWindow | None = None
    full: PSIWindow | None = None


class KubeletTransport(BaseModel):
    """Which transport served the kubelet Summary API, per node (#983 Phase 2).

    ``direct`` = straight to the kubelet on :10250, authorized by
    ``nodes/stats``. ``proxy`` = through the apiserver, authorized by
    ``nodes/proxy``, which grants read access to EVERY kubelet endpoint and is
    the grant this exists to retire.

    Per node rather than a single value, because a mixed cluster is the
    dangerous case: one value would report whichever node was processed last,
    and "direct" while another node fell back is precisely the wrong answer to
    "can I drop the broad grant?".

    ``all_direct`` is that decision, and it is False when nothing was probed —
    measuring nothing must never read as safe.

    Reported by whichever api replica served the request. Each replica probes
    every node within that request, so the map is complete; only the
    retry-backoff cache is per-replica.
    """

    by_node: dict[str, str] = {}
    direct_nodes: int = 0
    proxy_nodes: int = 0
    all_direct: bool = False
    blocked_reasons: dict[str, str] = {}


class NodeVitals(BaseModel):
    name: str
    ready: bool
    roles: list[str]
    schedulable: bool
    kubelet_version: str | None = None
    os_image: str | None = None
    kernel: str | None = None
    container_runtime: str | None = None
    architecture: str | None = None
    internal_ip: str | None = None
    age_seconds: int | None = None
    memory_pressure: bool = False
    disk_pressure: bool = False
    pid_pressure: bool = False
    cpu_capacity_cores: float | None = None
    memory_capacity_bytes: int | None = None
    pods_capacity: int | None = None
    pods_running: int = 0
    cpu_usage_cores: float | None = None
    memory_working_set_bytes: int | None = None
    memory_available_bytes: int | None = None
    fs_used_bytes: int | None = None
    fs_capacity_bytes: int | None = None
    # #983 Phase 2 — PSI. null means the kubelet did not report it.
    psi_cpu: PSIStats | None = None
    psi_memory: PSIStats | None = None
    psi_io: PSIStats | None = None
    # #402 — host partitions (root slot / var / ESP) from the supervisor.
    host_disk_partitions: list[HostPartition] = []
    # #999 Part A — md arrays + multipath maps from the supervisor.
    # ``None`` means the supervisor has not reported storage at all (too
    # old to collect it), which is UNKNOWN and must never render as a
    # green tick. An empty snapshot is a real "nothing here" reading.
    host_storage: NodeStorage | None = None


class PodSummary(BaseModel):
    name: str
    namespace: str
    component: str | None = None
    node: str | None = None
    phase: str
    state: str
    ready: str
    restarts: int
    age_seconds: int | None = None
    cpu_usage_cores: float | None = None
    memory_working_set_bytes: int | None = None


class WorkloadHealth(BaseModel):
    component: str
    kind: str | None = None
    ready: int
    total: int
    restarts: int
    # Job pods still running for this component (#1213) — e.g. a CNPG
    # replica join. Not counted in ready / total; while non-zero the
    # component reads "degraded" even at ready == total.
    jobs_running: int = 0
    status: str
    # #1387 — for the database row: "cnpg" when ready / total are the CNPG
    # Cluster's readyInstances / spec.instances, "pods" when it could not be
    # read and they are a pod count. None for every other component.
    source: str | None = None


class ClusterDnsProbe(BaseModel):
    """The resolve probe's verdict (#985).

    Separate from the replica counts on purpose: pods existing and the
    path working are different facts, and ``ready=2, spread_ok=true,
    probe failed`` is a real state that points at kube-proxy or the CNI
    rather than at CoreDNS.
    """

    ok: bool
    latency_ms: float | None = None
    error: str | None = None
    #: Which node's api replica ran the probe. On a multi-node control
    #: plane the request is served by whichever replica took it, so a
    #: pass here is a statement about one vantage, not the cluster.
    from_node: str | None = None


class ClusterDns(BaseModel):
    """Cluster DNS (CoreDNS) health (#985).

    Every count is nullable and ``None`` means UNKNOWN — a zero would
    read as "no replicas", which is a much more alarming claim than "we
    could not look".
    """

    available: bool
    detail: str | None = None
    #: The nameserver this api pod actually queries, read from its own
    #: ``/etc/resolv.conf`` rather than from the Service object.
    resolver_ip: str | None = None
    replicas_ready: int | None = None
    replicas_total: int | None = None
    #: ``ensure_coredns_ha``'s own target — ``min(nodes, 2)`` — not the
    #: Deployment's ``spec.replicas``, which would need a grant this
    #: snapshot does not hold.
    expected_replicas: int | None = None
    #: Nodes hosting a ready replica.
    nodes: list[str] = []
    spread_ok: bool | None = None
    resolve_probe: ClusterDnsProbe | None = None
    checked_at: str | None = None


class ClusterHealth(BaseModel):
    available: bool
    detail: str | None = None
    nodes_total: int
    nodes_ready: int
    pods_total: int
    pods_running: int
    pods_by_phase: dict[str, int]
    kubelet_version: str | None = None
    is_ha: bool
    control_plane_nodes: int
    metrics_available: bool
    kubelet_transport: KubeletTransport | None = None
    cluster_dns: ClusterDns | None = None
    cpu_usage_cores: float | None = None
    cpu_capacity_cores: float | None = None
    memory_working_set_bytes: int | None = None
    memory_capacity_bytes: int | None = None
    nodes: list[NodeVitals]
    workloads: list[WorkloadHealth]
    top_pods_cpu: list[PodSummary]
    top_pods_mem: list[PodSummary]


async def _merge_supervisor_host_state(db: AsyncSession, snap: dict[str, Any]) -> None:
    """Attach supervisor-reported host state to each node in ``snap``.

    The api pod is a container and can't see the host's disks — the
    supervisor statvfs's the partitions (#402) and reads md / multipath
    state out of the host's sysfs (#999 Part A), shipping both inside its
    ``cluster_health`` JSONB. We match by hostname == kube node name.
    Mutates ``snap`` in place.

    Storage is attached whenever the key is PRESENT, including when it
    reports no arrays: an empty snapshot is what clears a torn-down array
    off the screen, whereas a missing key means the supervisor is too old
    to have looked and the node's ``host_storage`` stays ``None``.
    """
    if not snap.get("available") or not snap.get("nodes"):
        return
    rows = (
        await db.execute(
            select(Appliance.hostname, Appliance.cluster_health).where(
                Appliance.state == APPLIANCE_STATE_APPROVED
            )
        )
    ).all()
    pmap: dict[str, list[dict[str, Any]]] = {}
    smap: dict[str, dict[str, Any]] = {}
    for hostname, ch in rows:
        if not hostname or not isinstance(ch, dict):
            continue
        parts = ch.get("host_disk_partitions")
        if isinstance(parts, list) and parts:
            pmap[hostname] = parts
        storage = ch.get("storage")
        if isinstance(storage, dict):
            smap[hostname] = storage
    for node in snap["nodes"]:
        if node["name"] in pmap:
            node["host_disk_partitions"] = pmap[node["name"]]
        if node["name"] in smap:
            storage = dict(smap[node["name"]])
            findings = evaluate_storage(storage)
            storage["findings"] = [
                {
                    "severity": f.severity,
                    "kind": f.kind,
                    "name": f.name,
                    "detail": f.detail,
                }
                for f in findings
            ]
            storage["worst_severity"] = worst_severity(findings)
            node["host_storage"] = storage


async def _merge_host_state_best_effort(db: AsyncSession, snap: dict[str, Any]) -> None:
    """Attach the supervisor's host state when the database answers; keep
    the kube snapshot when it does not.

    Everything in ``snap`` a caller polls for — ``nodes_ready``, the per-node
    Ready flags, the pod rollup — came from kubeapi; only the host disk / md /
    multipath decoration needs Postgres. During a CNPG failover (the primary's
    node partitioned or lost, #1083) that read raises for the 60-90 s the
    promotion takes, and letting it out of the handler turned a complete kube
    answer into a 500 for exactly the window in which a client watching
    ``nodes_ready`` needs a true one. Every node then keeps
    ``host_storage: None`` and ``host_disk_partitions: []``, which the model
    documents as "not reported" — never as "healthy".
    """
    try:
        await _merge_supervisor_host_state(db, snap)
    except Exception as exc:  # noqa: BLE001 — the decoration must never sink the snapshot
        logger.warning(
            "cluster_health_host_state_unavailable",
            error_class=type(exc).__name__,
            error=str(exc)[:200],
        )


@router.get(
    "/health",
    response_model=ClusterHealth,
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="Cluster health snapshot (nodes + pods + live usage)",
)
async def cluster_health(db: DB) -> ClusterHealth:
    try:
        # Off-loop: the gather is a handful of blocking stdlib kubeapi calls.
        snap = await anyio.to_thread.run_sync(get_cluster_health)
    except k8s.KubeapiUnavailableError as exc:
        # Generic client-facing detail; log the exception text server-side so
        # an internal error message can't reach the operator's browser
        # (CodeQL py/stack-trace-exposure).
        logger.info("cluster_health_kubeapi_unreachable", error=str(exc))
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "kubeapi unreachable from api; retry shortly.",
        ) from exc
    await _merge_host_state_best_effort(db, snap)
    return ClusterHealth(**snap)


@router.get(
    "/health/stream",
    # ``response_class`` REPLACES the documented application/json (#921);
    # a ``responses={200: {"content": ...}}`` entry merges with it instead,
    # leaving the route declaring a JSON body it never produces.
    response_class=EventStreamResponse,
    responses={200: {"description": "Server-sent event stream of cluster health"}},
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="Stream cluster health snapshots as SSE (~2s cadence)",
)
async def cluster_health_stream(request: Request) -> StreamingResponse:
    """Push a fresh cluster snapshot every ``_STREAM_INTERVAL_S`` seconds.

    Server-driven (no client polling): the browser opens one connection and
    animates each frame. A momentarily-unreachable kubeapi emits an
    ``available: false`` frame (with a reason) rather than dropping the
    stream, so the dashboard self-heals when the control plane settles.
    """

    async def event_source():
        while True:
            if await request.is_disconnected():
                break
            try:
                snap = await anyio.to_thread.run_sync(get_cluster_health)
                # Short-lived session per tick (don't hold a connection open
                # for the whole stream); cheap single-row-per-node lookup.
                # Best-effort for the same reason as the one-shot GET: a
                # database that is failing over must not turn a complete
                # kube frame into an "unavailable" one (#1083).
                async with AsyncSessionLocal() as db:
                    await _merge_host_state_best_effort(db, snap)
            except k8s.KubeapiUnavailableError as exc:
                # Log detail server-side; keep the client-facing reason generic
                # so an exception message can't leak internals to the browser
                # (CodeQL py/stack-trace-exposure).
                logger.info("cluster_health_stream_kubeapi_unreachable", error=str(exc))
                snap = cluster_unavailable("kubeapi unreachable; retrying")
            except Exception as exc:  # noqa: BLE001 — never let the stream die
                logger.warning("cluster_health_stream_gather_failed", error=str(exc))
                snap = cluster_unavailable("health gather failed; retrying")
            yield f"data: {json.dumps(snap)}\n\n"
            await asyncio.sleep(_STREAM_INTERVAL_S)

    # X-Accel-Buffering disables nginx buffering so each frame arrives ASAP —
    # same pattern as the container-log + AI-chat SSE surfaces.
    return StreamingResponse(
        event_source(),
        media_type="text/event-stream",
        headers={
            "X-Accel-Buffering": "no",
            "Cache-Control": "no-cache",
        },
    )
