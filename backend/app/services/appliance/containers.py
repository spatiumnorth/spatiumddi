"""Pod listing + control + log tailing for the appliance Fleet UI.

Phase 11 wave 4 (#183) rewrite. Pre-Phase-11 this talked to the
docker socket via the docker SDK; appliance mode is now k3s-only
(see Phase 7 docker-strip), so we go through kubeapi instead via
the api pod's mounted ServiceAccount token.

The endpoints in ``app/api/v1/appliance/containers.py`` wrap
these helpers + add permission gates + audit-log rows. The public
exception name + dataclass shape are unchanged so callers don't
have to follow the rewrite.

The appliance's Cluster -> Pods surface is gated on ``settings.appliance_mode``
+ the ServiceAccount actually being mounted (``services/appliance/k8s.get_config()``). On docker-
compose / non-k8s deployments the gate fails fast + the endpoints
log + 503 — same shape the docker path used. Platform Insights >
Containers (#3761) reuses the log helpers on any Kubernetes install via
``release_pods`` / ``find_release_pod``, gated on the ServiceAccount only.
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import anyio
import structlog

from app.config import settings
from app.services.appliance import k8s

logger = structlog.get_logger(__name__)


class DockerUnavailableError(RuntimeError):
    """Raised when kubeapi can't be reached or the ServiceAccount
    isn't mounted.

    Name kept for backwards compat with the router which translates
    this to 503 Service Unavailable. The error message body
    distinguishes the real cause for the operator's log.
    """


@dataclass
class ContainerSummary:
    """Pod summary in a docker-shape (name/image/state/status/
    health/short_id/started_at/is_spatium) for the existing
    ``/appliance/containers`` API surface.

    ``short_id`` is the pod's metadata.uid truncated to 12 chars
    (matches docker short_id length). ``health`` reflects the
    pod-level readiness summary (healthy / unhealthy / starting)
    derived from container statuses + waiting reasons — same
    vocabulary the docker container model used.
    """

    name: str
    image: str
    state: str  # running / pending / succeeded / failed / unknown
    status: str  # human-readable e.g. "Running (5m, healthy)"
    health: str | None  # healthy / unhealthy / starting / None
    short_id: str
    started_at: datetime | None
    is_spatium: bool
    component: str  # workload label (api/worker/frontend/…) — #416 log picker


def _pod_component(pod: dict[str, Any]) -> str:
    """Workload component for a pod — the ``app.kubernetes.io/component``
    label, else the chart-prefix-stripped pod name. Mirrors
    ``cluster_health._pod_component`` (kept local to avoid an import cycle)."""
    labels = (pod.get("metadata") or {}).get("labels") or {}
    comp = labels.get("app.kubernetes.io/component")
    if comp:
        return comp
    name = (pod.get("metadata") or {}).get("name") or "?"
    for pre in ("spatium-control-spatiumddi-", "spatium-bootstrap-", "spatium-"):
        if name.startswith(pre):
            name = name[len(pre) :]
            break
    parts = name.rsplit("-", 2)
    return parts[0] if len(parts) == 3 else name


def _parse_pod_to_summary(pod: dict[str, Any]) -> ContainerSummary:
    """Flatten a kubeapi Pod object to ContainerSummary."""
    meta = pod.get("metadata") or {}
    spec = pod.get("spec") or {}
    status_obj = pod.get("status") or {}
    name = meta.get("name") or ""
    labels = meta.get("labels") or {}
    # "Spatium" pod detection — both chart conventions count:
    #   * umbrella (charts/spatiumddi/): ``app.kubernetes.io/name=
    #     spatiumddi``
    #   * appliance (charts/spatiumddi-appliance/):
    #     ``app.kubernetes.io/part-of=spatiumddi`` (plus the same
    #     ``name`` on some templates)
    is_spatium = (
        labels.get("app.kubernetes.io/part-of") == "spatiumddi"
        or labels.get("app.kubernetes.io/name") == "spatiumddi"
    )

    containers = spec.get("containers") or []
    first_image = containers[0].get("image", "") if containers else ""

    phase = status_obj.get("phase") or "Unknown"
    # Health derived from container readiness + waiting reasons.
    container_statuses = status_obj.get("containerStatuses") or []
    health: str | None = None
    waiting_reason = ""
    if phase == "Running" and container_statuses:
        all_ready = all(cs.get("ready") for cs in container_statuses)
        if all_ready:
            health = "healthy"
        else:
            for cs in container_statuses:
                waiting = (cs.get("state") or {}).get("waiting") or {}
                r = waiting.get("reason") or ""
                if r:
                    waiting_reason = r
                    break
            if waiting_reason.lower() in (
                "crashloopbackoff",
                "errimagepull",
                "imagepullbackoff",
            ):
                health = "unhealthy"
            else:
                health = "starting"
    elif phase == "Pending":
        health = "starting"
    elif phase in ("Failed", "Unknown"):
        health = "unhealthy"

    # State mirrors the docker vocabulary roughly:
    #   Running   → running
    #   Pending   → starting (no docker analog; closest is "created")
    #   Succeeded → exited
    #   Failed    → exited
    #   Unknown   → unknown
    state = {
        "Running": "running",
        "Pending": "starting",
        "Succeeded": "exited",
        "Failed": "exited",
    }.get(phase, "unknown")

    # Human-readable status combining phase + age + health hint.
    # Same shape ``docker ps`` produces:  "Up 5 minutes (healthy)".
    start_time = status_obj.get("startTime")
    started_at: datetime | None = None
    if start_time:
        try:
            started_at = datetime.fromisoformat(start_time.rstrip("Z") + "+00:00")
        except ValueError:
            started_at = None
    if waiting_reason:
        status_str = f"{phase} ({waiting_reason})"
    elif health:
        status_str = f"{phase} ({health})"
    else:
        status_str = phase

    return ContainerSummary(
        name=name,
        image=first_image,
        state=state,
        status=status_str,
        health=health,
        short_id=(meta.get("uid") or "")[:12],
        started_at=started_at,
        is_spatium=is_spatium,
        component=_pod_component(pod),
    )


def release_pods() -> list[dict[str, Any]]:
    """SpatiumDDI's own pods in the api pod's namespace -- the inventory the
    Platform Insights Containers tab lists AND the allowlist its log routes
    resolve a pod name against (#3761).

    Scope is the namespace of the mounted ServiceAccount, narrowed to pods
    labelled as ours (same rule as ``service_control.kube``) and, when the api
    pod's own release label resolves (``HOSTNAME`` is the pod name, read off
    the same listing), to that release, so a second SpatiumDDI install in the
    namespace is not offered. Always a fresh listing: a pod name is never
    trusted from the caller.
    """
    try:
        pods = k8s.list_pods()
    except k8s.KubeapiUnavailableError as exc:
        raise DockerUnavailableError(str(exc)) from exc
    ours = [p for p in pods if _parse_pod_to_summary(p).is_spatium]
    own_name = os.environ.get("HOSTNAME", "")
    release = None
    for p in pods:
        meta = p.get("metadata") or {}
        if own_name and meta.get("name") == own_name:
            release = (meta.get("labels") or {}).get("app.kubernetes.io/instance")
            break
    if release:
        ours = [
            p
            for p in ours
            if ((p.get("metadata") or {}).get("labels") or {}).get("app.kubernetes.io/instance")
            == release
        ]
    return ours


def list_release_containers() -> list[ContainerSummary]:
    out = [_parse_pod_to_summary(p) for p in release_pods()]
    out.sort(key=lambda c: (c.component, c.name))
    return out


def find_release_pod(name: str) -> tuple[ContainerSummary, str | None] | None:
    """``(summary, default log container)`` for a current release pod, or None
    when ``name`` is not one of them (the caller answers 404)."""
    for p in release_pods():
        if (p.get("metadata") or {}).get("name") == name:
            return _parse_pod_to_summary(p), _pick_log_container(p)
    return None


def list_containers(*, appliance_only: bool = True) -> list[ContainerSummary]:
    """``appliance_only`` keeps the appliance's own Cluster -> Pods behaviour
    (empty off the appliance). Platform Insights uses ``release_pods()``."""
    if appliance_only and not settings.appliance_mode:
        return []
    try:
        pods = k8s.list_pods()
    except k8s.KubeapiUnavailableError as exc:
        raise DockerUnavailableError(str(exc)) from exc
    out = [_parse_pod_to_summary(p) for p in pods]
    # Spatium pods first, then alphabetical within each group.
    out.sort(key=lambda c: (not c.is_spatium, c.name))
    return out


# Container names that are never the workload's "main" log source — skip
# them when a multi-container pod has no component-matching or default
# container (e.g. the redis pod ships a render-config sidecar).
_LOG_SIDECAR_NAMES = frozenset({"render-config"})


def _pick_log_container(pod: dict[str, Any], prefer: str | None = None) -> str | None:
    """Which container's logs to tail for a (possibly multi-container) pod.

    kubeapi 400s a logs request on a multi-container pod unless a container
    is named (#416 follow-up: the redis pod is render-config + redis +
    sentinel). Returns None for a single-container pod — kubeapi defaults to
    the only one. Otherwise prefer the component-matching container (redis →
    redis), then the ``kubectl.kubernetes.io/default-container`` annotation,
    then the first non-sidecar, then the first."""
    names = [
        c.get("name") for c in (pod.get("spec") or {}).get("containers") or [] if c.get("name")
    ]
    if len(names) <= 1:
        return None
    if prefer and prefer in names:
        return prefer
    ann = (pod.get("metadata") or {}).get("annotations") or {}
    default_c = ann.get("kubectl.kubernetes.io/default-container")
    if default_c in names:
        return default_c
    for n in names:
        if n not in _LOG_SIDECAR_NAMES:
            return n
    return names[0]


def _default_log_container(name: str) -> str | None:
    """Default log container for a bare pod name (the Pods-tab path), so a
    multi-container pod doesn't 400. None if the pod isn't found / single."""
    try:
        pods = k8s.list_pods()
    except k8s.KubeapiUnavailableError:
        return None
    for p in pods:
        if (p.get("metadata") or {}).get("name") == name:
            return _pick_log_container(p)
    return None


def resolve_workload_pod(component: str) -> tuple[str, str | None] | None:
    """Resolve a workload component (api/worker/frontend/…) to ``(pod_name,
    container)`` for its current running SpatiumDDI pod — the newest, so a
    just-rolled Deployment resolves to the fresh pod, and the right container
    on a multi-container pod (e.g. redis). Lets the log surface tail a stable
    workload instead of a churny pod name (#416). None if nothing matches."""
    if not settings.appliance_mode:
        return None
    try:
        pods = k8s.list_pods()
    except k8s.KubeapiUnavailableError as exc:
        raise DockerUnavailableError(str(exc)) from exc
    matches: list[tuple[ContainerSummary, dict[str, Any]]] = []
    for p in pods:
        summary = _parse_pod_to_summary(p)
        if summary.is_spatium and summary.state == "running" and summary.component == component:
            matches.append((summary, p))
    if not matches:
        return None
    matches.sort(
        key=lambda sp: sp[0].started_at or datetime.min.replace(tzinfo=UTC),
        reverse=True,
    )
    summary, pod = matches[0]
    return summary.name, _pick_log_container(pod, prefer=component)


def container_action(name: str, action: str) -> None:
    """Apply ``start`` / ``stop`` / ``restart`` to the named pod.

    K8s vocabulary:
      * ``restart`` → delete the pod; the owning Deployment /
        DaemonSet recreates it on the next reconcile.
      * ``start`` / ``stop`` → not directly supported on a single
        pod (you'd scale the owning Deployment). For the appliance
        Fleet UI's purposes ``restart`` is the only meaningful
        action; ``start`` / ``stop`` raise ValueError (was a
        wishlist UX in the docker era).
    """
    if action == "restart":
        ok, err = k8s.delete_pod(name)
        if not ok:
            raise DockerUnavailableError(err or f"failed to delete pod {name}")
        logger.info("appliance_pod_restart", name=name)
        return
    if action in ("start", "stop"):
        raise ValueError(
            f"pod action {action!r} requires scaling the owning Deployment; "
            "use kubectl scale for now (UI exposure pending)"
        )
    raise ValueError(f"unknown pod action: {action!r}")


def get_container_logs(
    name: str,
    tail: int = 200,
    since_seconds: int | None = None,
    container: str | None = None,
) -> str:
    """Return the last ``tail`` log lines (or lines since N seconds ago).

    Decoded UTF-8 with replacement for binary fragments. Truncated at
    ``tail`` lines server-side so response is bounded.
    """
    try:
        body = k8s.get_pod_logs(name, tail=tail, since_seconds=since_seconds, container=container)
    except k8s.KubeapiUnavailableError as exc:
        raise DockerUnavailableError(str(exc)) from exc
    return body


async def stream_container_logs(
    name: str, tail: int = 100, container: str | None = None
) -> AsyncGenerator[str, None]:
    """Yield log lines from the named pod as they arrive.

    Wraps ``k8s.stream_pod_logs`` (a sync generator) with
    ``anyio.to_thread.run_sync`` so the FastAPI event loop isn't
    blocked. Each yielded chunk is a UTF-8 string with the
    trailing newline stripped; the router formats them as SSE
    ``data:`` frames.

    Cancellation: when the SSE client disconnects, FastAPI cancels
    this generator; the underlying http.client connection in the
    worker thread is closed via the generator's GeneratorExit
    propagation through the iter wrapper below.
    """
    if container is None:
        # A bare pod name (the Pods tab) on a multi-container pod (e.g. redis:
        # render-config / redis / sentinel) makes kubeapi 400 "a container
        # name must be specified". Resolve a default from the pod's spec.
        container = _default_log_container(name)
    try:
        gen = k8s.stream_pod_logs(name, tail=tail, container=container)
    except k8s.KubeapiUnavailableError as exc:
        raise DockerUnavailableError(str(exc)) from exc

    def _next() -> str | None:
        try:
            return next(gen)
        except StopIteration:
            return None

    try:
        while True:
            line = await anyio.to_thread.run_sync(_next)
            if line is None:
                break
            yield line
    finally:
        close = getattr(gen, "close", None)
        if callable(close):
            try:
                close()
            except Exception:  # noqa: BLE001
                pass


__all__ = [
    "ContainerSummary",
    "DockerUnavailableError",
    "container_action",
    "get_container_logs",
    "find_release_pod",
    "list_containers",
    "list_release_containers",
    "release_pods",
    "stream_container_logs",
]


_ = UTC  # silence "imported but unused" — kept for stable import line
