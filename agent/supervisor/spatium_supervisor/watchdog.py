"""Service container watchdog (#170 Wave E, #183 Phase 7).

Bridges the gap between ``role_switch_state`` (set once when
``apply_role_assignment`` runs) and the *current* runtime state of
the supervisor-managed service pods. Without this watchdog, a pod
that crashed / got removed / had its image purged between heartbeats
would leave the supervisor reporting a stale ``role_switch_state=
ready`` indefinitely — ``apply_role_assignment`` no-ops on every
subsequent heartbeat because the chart-content hash hasn't moved.

Phase 7 retired the docker-compose path; this watchdog is k3s-only.
Pre-Phase-7 the module branched on ``detect_runtime()`` to choose
between a ``docker_api.list_running_containers()`` poll and a
``k8s_api.list_pods()`` poll. Now it's just the kubeapi path.

Algorithm:

1. Read the assigned profiles from the supervisor's
   ``role-compose.env`` (the file the supervisor itself writes on
   every role-assignment apply). Map profile → chart-component name
   (dhcp profile → dhcp-kea, etc.).
2. Probe kubeapi ``/readyz``. If kubeapi is wedged, mark every
   desired service ``missing`` so the Fleet UI shows the cluster-
   level fault loud + skip the rest of the probe.
3. Enumerate pods in ``spatium`` via the chart's
   ``app.kubernetes.io/part-of=spatiumddi`` selector. For each
   desired service, derive a ``status`` verdict from the matching
   Pod's phase + container statuses:
   * ``missing`` — no pod found.
   * ``starting`` — Pending or Running-but-not-ready.
   * ``unhealthy`` — CrashLoopBackOff / ErrImagePull / Failed.
   * ``healthy`` — Running + all containers ready.
4. Track first-observed timestamps per (service, status) in a
   process-local history map. ``since`` rides every heartbeat.
5. Optionally auto-heal: when one or more services are ``missing``,
   re-fire ``apply_role_assignment`` (PATCH the HelmChart CR). helm-
   controller diffs internally — present-and-healthy services
   no-op, missing ones come up.

   Never while the node is not approved (#2808). A revoked node's
   teardown deletes the role chart but keeps ``role-compose.env`` (a
   re-registration restores the roles from it, #2801), so the env still
   names the roles; healing from it started DNS and DHCP again on a node
   taken out of service. While held, a missing service is reported as
   ``held`` (down on purpose) rather than ``missing``, and nothing is
   applied.

Cadence: 5 min (5 heartbeats at the default 60 s interval). Steady-
state cost is one ``GET /api/v1/namespaces/spatium/pods`` + dict
bookkeeping; sub-100 ms.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog

from . import k8s_api
from .service_lifecycle import apply_role_assignment

log = structlog.get_logger(__name__)


# Compose-profile-name → chart-component name. ``COMPOSE_PROFILES``
# in role-compose.env carries profile values; pod labels carry the
# chart component. ``dhcp`` profile maps to ``dhcp-kea`` component;
# everything else is identity. ``looking-glass`` (#566) is identity,
# same as the DNS roles.
_PROFILE_TO_SERVICE: dict[str, str] = {
    "dns-bind9": "dns-bind9",
    "dns-powerdns": "dns-powerdns",
    "dns-technitium": "dns-technitium",
    "dhcp": "dhcp-kea",
    "looking-glass": "looking-glass",
}


@dataclass(frozen=True)
class ServiceHealth:
    """Per-service watchdog verdict.

    ``status`` ∈ {healthy, missing, unhealthy, starting, held}. The Fleet
    drilldown renders a green chip on healthy, amber on starting,
    rose on unhealthy / missing, neutral on held. ``since_ts`` is the unix-epoch
    seconds of the first observation in this status; the heartbeat
    serialises it as an ISO-8601 wall-clock string for the API.
    """

    service: str
    role: str
    status: str
    since_ts: float
    container_id: str | None


# Process-local history of (status, monotonic-first-seen,
# wall-first-seen). Wall timestamp is persisted alongside the
# monotonic anchor so a backward host-clock adjustment between two
# probes can't reconstruct a ``since`` that lands in the past
# relative to itself (issue #244). Survives heartbeat ticks within
# one supervisor process; resets on restart (acceptable — first
# watchdog tick after restart re-observes).
_status_history: dict[str, tuple[str, float, float]] = {}


def read_assigned_profiles(env_file: Path) -> list[str]:
    """Parse the ``COMPOSE_PROFILES`` value from role-compose.env.

    Returns ``[]`` on missing file, empty value, or read error. The
    supervisor writes this file on every heartbeat that returns a
    role_assignment, so a non-empty result means the supervisor has
    been told about roles + the operator hasn't cleared them.
    """
    if not env_file.exists():
        return []
    try:
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("COMPOSE_PROFILES="):
                val = line.split("=", 1)[1].strip()
                if not val:
                    return []
                return [p.strip() for p in val.split(",") if p.strip()]
    except OSError:
        pass
    return []


def _derive_pod_status(pod: k8s_api.PodStatus) -> str:
    """Translate a Pod's phase + containerStatuses into the four-
    value verdict the Fleet drilldown renders (healthy / starting /
    unhealthy / missing).
    """
    phase = pod.status
    if phase == "Pending":
        return "starting"
    if phase in ("Failed", "Succeeded"):
        # Succeeded for a long-running service container means the
        # process exited cleanly but the workload should be Running.
        return "unhealthy"
    if phase != "Running":
        return "starting"
    # Pod is Running — check each container's Ready bit. Any
    # not-ready (CrashLoopBackOff, ImagePullBackOff, etc) demotes
    # the whole verdict to unhealthy. Empty container list = pod
    # mid-init.
    if not pod.container_statuses:
        return "starting"
    for cs in pod.container_statuses:
        if not cs.get("ready"):
            waiting = cs.get("state", {}).get("waiting", {})
            reason = (waiting.get("reason") or "").lower() if waiting else ""
            if reason in ("crashloopbackoff", "errimagepull", "imagepullbackoff"):
                return "unhealthy"
            return "starting"
    return "healthy"


def _own_node_name() -> str | None:
    """This node's k8s Node name (downward-API ``spec.nodeName``), or None
    when the supervisor was not told it. k3s lowercases the hostname."""
    name = os.environ.get("NODE_NAME") or os.environ.get("APPLIANCE_HOSTNAME")
    return name.strip().rstrip(".").lower() if name and name.strip() else None


def _on_node(pod: k8s_api.PodStatus, node: str | None) -> bool:
    return node is not None and pod.node_name.strip().rstrip(".").lower() == node


def container_runtime(pod: k8s_api.PodStatus, service: str) -> dict[str, Any] | None:
    """The service container's restart history, as the kubelet reports it
    (#2018).

    The kubelet puts every container on the appliance in a cgroup with
    ``memory.oom.group`` set (cgroup v2, Kubernetes 1.28+), so a container
    that reaches its memory limit is killed WHOLE: the DNS daemon and the
    agent beside it die in the same instant, and the agent never gets to
    write its OOM record. The restarted agent cannot see it either: a
    restarted container is a new cgroup whose ``oom_kill`` counter starts at
    zero. The kubelet is the one party that saw it, in the container's
    ``lastState.terminated.reason`` (``OOMKilled``), which this carries to
    the control plane. ``running_since`` (None while the container is not
    running, e.g. in CrashLoopBackOff) lets the control plane tell a kill
    that is still current from one the daemon has since outlived.
    """
    statuses = pod.container_statuses or []
    cs = next((c for c in statuses if c.get("name") == service), None)
    if cs is None:
        if len(statuses) != 1:
            return None
        cs = statuses[0]
    state = cs.get("state") or {}
    running = state.get("running") or {}
    terminated = (cs.get("lastState") or {}).get("terminated") or None
    last: dict[str, Any] | None = None
    if isinstance(terminated, dict):
        last = {
            "reason": terminated.get("reason"),
            "exit_code": terminated.get("exitCode"),
            "finished_at": terminated.get("finishedAt"),
        }
    try:
        restarts = int(cs.get("restartCount") or 0)
    except (TypeError, ValueError):
        restarts = 0
    return {
        "restart_count": restarts,
        "running_since": running.get("startedAt") if running else None,
        "last_termination": last,
        "memory_limit": pod.memory_limits.get(str(cs.get("name") or service)),
    }


def _check_health_k3s(
    env_file: Path,
    desired_services: dict[str, str],
    *,
    auto_heal: bool,
    held_by: str | None = None,
) -> dict[str, dict[str, Any]]:
    """One k3s health-check pass.

    Probes ``/readyz`` first — if kubeapi itself is wedged, mark
    every desired service as ``missing`` so the Fleet UI carries a
    loud red banner and the operator knows the cluster (not the
    workload) is the problem. Then enumerates pods in the
    ``spatium`` namespace via the kubeapi label selector
    ``app.kubernetes.io/part-of=spatiumddi`` and matches against the
    ``app.kubernetes.io/component`` label.
    """
    out: dict[str, dict[str, Any]] = {}
    now_wall = time.time()
    now_mono = time.monotonic()

    # kubeapi reachability is the precondition — if it's down, every
    # service is effectively missing AND auto-heal can't do anything
    # useful (HelmChart PATCH would fail too). Surface this loud.
    if not k8s_api.check_kubeapi_ready():
        log.error("supervisor.watchdog.kubeapi_unreachable")
        down = "held" if held_by is not None else "missing"
        for svc, role in desired_services.items():
            prev = _status_history.get(svc)
            if prev is None or prev[0] != down:
                _status_history[svc] = (down, now_mono, now_wall)
                since_wall = now_wall
            else:
                since_wall = prev[2]
            out[svc] = {
                "role": role,
                "status": down,
                "since": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(since_wall)),
                "container_id": None,
            }
            if held_by is not None:
                out[svc]["held_by"] = held_by
        return out

    pods = k8s_api.list_pods(
        namespace="spatium",
        label_selector="app.kubernetes.io/part-of=spatiumddi",
    )
    # #2018 — prefer THIS node's pod. The role workloads are DaemonSets, so
    # on a multi-node cluster every node has a pod with the same component
    # label and the last one listed used to win, whichever node it ran on.
    own_node = _own_node_name()
    by_service: dict[str, k8s_api.PodStatus] = {}
    for pod in pods:
        component = pod.labels.get("app.kubernetes.io/component")
        if component not in desired_services:
            continue
        current = by_service.get(component)
        if (
            current is None
            or not _on_node(current, own_node)
            or _on_node(pod, own_node)
        ):
            by_service[component] = pod

    missing_services: list[str] = []
    for svc, role in desired_services.items():
        # Explicit Optional annotation so mypy can narrow correctly
        # in the if-branch below (issue #241).
        pod: k8s_api.PodStatus | None = by_service.get(svc)
        if pod is None:
            # #2808 — a role service a non-approved node does not run is down
            # on purpose, not missing: no red chip, no heal.
            status = "held" if held_by is not None else "missing"
            container_id = None
            missing_services.append(svc)
        else:
            status = _derive_pod_status(pod)
            container_id = (pod.name[:24]) or None

        prev = _status_history.get(svc)
        if prev is None or prev[0] != status:
            _status_history[svc] = (status, now_mono, now_wall)
            since_wall = now_wall
        else:
            since_wall = prev[2]

        entry: dict[str, Any] = {
            "role": role,
            "status": status,
            "since": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(since_wall)),
            "container_id": container_id,
        }
        if held_by is not None:
            entry["held_by"] = held_by
        # #2018 — only a pod known to be this node's: another node's OOM
        # kill must not be reported as this appliance's.
        if pod is not None and (own_node is None or _on_node(pod, own_node)):
            runtime = container_runtime(pod, svc)
            if runtime is not None:
                entry["container"] = runtime
        out[svc] = entry

    if held_by is not None:
        if missing_services:
            # #2808 — the role chart is down because the node is not
            # approved (the revoked teardown deleted it). Re-applying it here
            # started DNS and DHCP on a node taken out of service. The first
            # accepted heartbeat after approval applies the roles again.
            log.info(
                "supervisor.watchdog.heal_skipped_not_approved",
                approval_state=held_by,
                held=missing_services,
            )
    elif auto_heal and missing_services:
        log.warning(
            "supervisor.watchdog.missing_services",
            missing=missing_services,
        )
        # Re-applying the HelmChart CR is cheap (helm-controller
        # short-circuits when nothing changed) but lets the
        # supervisor re-assert desired state when a pod's been
        # ``kubectl delete``'d out from under us.
        result = apply_role_assignment(list(desired_services.values()), env_file)
        log.info(
            "supervisor.watchdog.heal_attempted",
            state=result.state,
            reason=result.reason,
            started=list(result.started),
        )

    return out


def check_health(
    env_file: Path,
    *,
    auto_heal: bool = True,
    held_by: str | None = None,
) -> dict[str, dict[str, Any]]:
    """One watchdog pass.

    Returns a JSON-serialisable ``role_health`` dict keyed by service
    name. Empty dict when no roles are assigned (idle appliance —
    nothing to watch). ``auto_heal=False`` lets tests drive the
    watcher without re-firing the apply path.

    ``held_by`` is the approval state holding the role services down
    (``approval_state.role_services_hold``), or ``None`` when the node is
    approved. When set, nothing is healed and a missing service reports
    ``held`` (#2808).

    Phase 7: k3s-only. The pre-Phase-7 runtime branch (compose vs
    k3s) is gone with the rest of docker.
    """
    profiles = read_assigned_profiles(env_file)
    desired_services: dict[str, str] = {}  # service → role(profile)
    for p in profiles:
        svc = _PROFILE_TO_SERVICE.get(p)
        if svc is not None:
            desired_services[svc] = p

    if not desired_services:
        # Garbage-collect history so a later role-assign starts fresh.
        _status_history.clear()
        return {}

    out = _check_health_k3s(env_file, desired_services, auto_heal=auto_heal, held_by=held_by)

    # Garbage-collect stale entries (operator switched roles).
    for stale in list(_status_history):
        if stale not in desired_services:
            del _status_history[stale]

    return out


__all__ = [
    "ServiceHealth",
    "check_health",
    "read_assigned_profiles",
]
