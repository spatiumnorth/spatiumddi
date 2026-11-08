"""Container resource stats — self-monitoring of the spatiumddi stack.

Polls the local Docker daemon over the UDS that the operator mounts on
the api container. Returns CPU% / memory / network / block-IO for each
container. Default filter is the ``spatiumddi-*`` prefix so we surface
only our own stack and not whatever else is running on the host; pass
``?prefix=`` (empty string) to drop the filter.

If ``/var/run/docker.sock`` isn't mounted (the default — operator
opt-in via the same compose toggle the Docker integration uses), the
endpoint reports ``available=false`` with a one-line hint instead of
500ing. No fallback to the per-host Docker integration: that's for
mirroring data INTO IPAM, this is for monitoring our own runtime.

#3761: the same screen also reports a Kubernetes backend. ``GET
/containers/backends`` says which of Docker / Kubernetes / the appliance this
deployment can see (and, for each one that cannot, which toggle enables it);
``/containers/pods`` + the two ``/pods/{name}/logs`` routes list the release's
pods and read their logs through ``services/appliance/containers`` and the
support-bundle redactor. The pod inventory is the allowlist: a pod name that
is not in a fresh listing is a 404.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import anyio
import httpx
import structlog
from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel

from app.api.deps import DB, SuperAdmin
from app.api.v1.appliance.containers import _sse_log_response
from app.config import settings
from app.core.exc_text import describe_exc
from app.models.audit import AuditLog
from app.services.appliance import containers as pod_svc
from app.services.appliance import k8s
from app.services.support_bundle.scrub import LOG_CONTEXT_LINES, redact_log_tail

logger = structlog.get_logger(__name__)
router = APIRouter()

DOCKER_SOCKET = "/var/run/docker.sock"


class ContainerStat(BaseModel):
    id: str  # short id
    name: str
    image: str
    state: str  # running / exited / paused / ...
    started_at: str | None
    cpu_percent: float | None  # 0..N (where N = cpus * 100)
    memory_bytes: int | None
    memory_limit_bytes: int | None
    memory_percent: float | None
    network_rx_bytes: int | None
    network_tx_bytes: int | None
    block_read_bytes: int | None
    block_write_bytes: int | None


class ContainerStatsResponse(BaseModel):
    available: bool
    hint: str | None = None
    rows: list[ContainerStat] = []


def _socket_available() -> bool:
    try:
        return Path(DOCKER_SOCKET).is_socket()
    except OSError:
        return False


def _short_name(raw_names: list[str]) -> str:
    """Docker prefixes container names with ``/`` and may list aliases."""
    if not raw_names:
        return ""
    return raw_names[0].lstrip("/")


def _compute_cpu_percent(stats: dict[str, Any]) -> float | None:
    """Compute CPU% the same way ``docker stats`` does.

    delta_cpu = container_total_usage - precpu_total_usage
    delta_sys = system_cpu_usage - precpu_system_cpu_usage
    pct = (delta_cpu / delta_sys) * online_cpus * 100
    """
    try:
        cpu = stats["cpu_stats"]
        precpu = stats["precpu_stats"]
        cur_cpu = int(cpu["cpu_usage"]["total_usage"])
        prev_cpu = int(precpu.get("cpu_usage", {}).get("total_usage", 0))
        cur_sys = int(cpu.get("system_cpu_usage", 0))
        prev_sys = int(precpu.get("system_cpu_usage", 0))
        online = int(cpu.get("online_cpus", 0)) or len(
            cpu.get("cpu_usage", {}).get("percpu_usage") or []
        )
        d_cpu = cur_cpu - prev_cpu
        d_sys = cur_sys - prev_sys
        if d_sys <= 0 or online <= 0:
            return None
        return round((d_cpu / d_sys) * online * 100.0, 2)
    except (KeyError, TypeError, ValueError):
        return None


def _sum_network(stats: dict[str, Any]) -> tuple[int | None, int | None]:
    nets = stats.get("networks") or {}
    if not nets:
        return None, None
    rx = sum(int(n.get("rx_bytes", 0) or 0) for n in nets.values())
    tx = sum(int(n.get("tx_bytes", 0) or 0) for n in nets.values())
    return rx, tx


def _sum_blkio(stats: dict[str, Any]) -> tuple[int | None, int | None]:
    """Sum block-io read/write bytes across every device the container touched."""
    blk = (stats.get("blkio_stats") or {}).get("io_service_bytes_recursive") or []
    if not blk:
        return None, None
    read = sum(int(e.get("value", 0) or 0) for e in blk if str(e.get("op", "")).lower() == "read")
    write = sum(int(e.get("value", 0) or 0) for e in blk if str(e.get("op", "")).lower() == "write")
    return read, write


@router.get("/containers/stats", response_model=ContainerStatsResponse)
async def container_stats(
    _: SuperAdmin,
    prefix: str = Query(
        "spatiumddi-",
        description=(
            "Substring filter on container name. Default scopes to "
            "the spatiumddi-* stack. Pass an empty string to see all "
            "containers on the host."
        ),
    ),
    include_stopped: bool = Query(False),
) -> ContainerStatsResponse:
    """Per-container CPU/memory/network/IO from the local Docker daemon.

    Requires ``/var/run/docker.sock`` to be mounted into the api
    container. The dev compose has commented-out lines for this; the
    operator uncomments them + sets ``DOCKER_GID``.
    """

    if not _socket_available():
        return ContainerStatsResponse(
            available=False,
            hint=(
                f"{DOCKER_SOCKET} is not mounted into the api container. "
                "Uncomment the docker.sock volume + group_add in your "
                "docker-compose file (or grant access on Kubernetes via "
                "a hostPath mount + matching supplemental group)."
            ),
        )

    transport = httpx.AsyncHTTPTransport(uds=DOCKER_SOCKET)
    async with httpx.AsyncClient(
        base_url="http://docker", transport=transport, timeout=10.0
    ) as client:
        try:
            params: dict[str, Any] = {}
            if include_stopped:
                params["all"] = "true"
            list_resp = await client.get("/containers/json", params=params)
            list_resp.raise_for_status()
            containers: list[dict[str, Any]] = list_resp.json()
        except httpx.HTTPError as exc:
            logger.warning("container_stats_list_failed", error=str(exc))
            return ContainerStatsResponse(
                available=False,
                # ``describe_exc``, not ``describe_http_exc``: the request URL
                # here is the placeholder ``http://docker``, so naming its
                # "host:port" would point the operator at an address that
                # does not exist; the socket path above is the real one.
                hint=f"Couldn't list containers via {DOCKER_SOCKET}: {describe_exc(exc)}",
            )

        rows: list[ContainerStat] = []
        for c in containers:
            name = _short_name(c.get("Names") or [])
            if prefix and prefix not in name:
                continue

            cid = c.get("Id", "")[:12]
            state = c.get("State", "unknown")
            image = c.get("Image", "")

            # Stopped containers have no live stats — surface the row but
            # with all stat fields nulled.
            if state != "running":
                rows.append(
                    ContainerStat(
                        id=cid,
                        name=name,
                        image=image,
                        state=state,
                        started_at=None,
                        cpu_percent=None,
                        memory_bytes=None,
                        memory_limit_bytes=None,
                        memory_percent=None,
                        network_rx_bytes=None,
                        network_tx_bytes=None,
                        block_read_bytes=None,
                        block_write_bytes=None,
                    )
                )
                continue

            try:
                stats_resp = await client.get(
                    f"/containers/{c['Id']}/stats", params={"stream": "false"}
                )
                stats_resp.raise_for_status()
                s = stats_resp.json()
            except httpx.HTTPError as exc:
                logger.debug("container_stats_one_failed", name=name, error=str(exc))
                continue

            mem_stats = s.get("memory_stats") or {}
            mem_used = int(mem_stats.get("usage", 0) or 0)
            # cgroupv2 reports 'inactive_file' under stats; subtract for
            # closer parity with `docker stats`.
            inactive = int((mem_stats.get("stats") or {}).get("inactive_file") or 0)
            mem_used = max(mem_used - inactive, 0)
            mem_limit = int(mem_stats.get("limit", 0) or 0)
            mem_pct: float | None = None
            if mem_limit > 0:
                mem_pct = round((mem_used / mem_limit) * 100.0, 2)

            rx, tx = _sum_network(s)
            br, bw = _sum_blkio(s)

            rows.append(
                ContainerStat(
                    id=cid,
                    name=name,
                    image=image,
                    state=state,
                    started_at=s.get("read"),  # ISO timestamp of the stats sample
                    cpu_percent=_compute_cpu_percent(s),
                    memory_bytes=mem_used,
                    memory_limit_bytes=mem_limit or None,
                    memory_percent=mem_pct,
                    network_rx_bytes=rx,
                    network_tx_bytes=tx,
                    block_read_bytes=br,
                    block_write_bytes=bw,
                )
            )

        rows.sort(key=lambda r: r.name)
        return ContainerStatsResponse(available=True, rows=rows)


# ── Backends + Kubernetes pods (#3761) ─────────────────────────────────

_SA_REASON = (
    "The api has no usable Kubernetes ServiceAccount. Set api.serviceAccount.enabled=true "
    "in the Helm values (it grants read on pods and pods/log in the release namespace)."
)


class BackendStatus(BaseModel):
    available: bool
    reason: str | None = None
    detail: str | None = None  # namespace for kubernetes


class ContainerBackendsResponse(BaseModel):
    docker: BackendStatus
    kubernetes: BackendStatus
    appliance: bool


class PodRow(BaseModel):
    name: str
    component: str
    image: str
    state: str
    status: str
    health: str | None
    started_at: str | None
    containers: list[str]


class PodListResponse(BaseModel):
    available: bool
    reason: str | None = None
    rows: list[PodRow] = []


def _kube_probe() -> tuple[bool, str | None]:
    """Can the api list pods in its own namespace right now?"""
    if k8s.get_config() is None:
        return False, _SA_REASON
    try:
        pod_svc.release_pods()
    except pod_svc.DockerUnavailableError as exc:
        text = str(exc)
        if "403" in text:
            return False, (
                "kubeapi refused to list pods; the api ServiceAccount lacks the pod "
                "read Role. Set api.serviceAccount.enabled=true in the Helm values."
            )
        return False, f"kubeapi unreachable: {text}"
    return True, None


@router.get("/containers/backends", response_model=ContainerBackendsResponse)
async def container_backends(_: SuperAdmin) -> ContainerBackendsResponse:
    """Which runtimes this deployment can show, and why not for the others."""
    docker_ok = _socket_available()
    kube_ok, kube_reason = await anyio.to_thread.run_sync(_kube_probe)
    cfg = k8s.get_config()
    return ContainerBackendsResponse(
        docker=BackendStatus(
            available=docker_ok,
            reason=None if docker_ok else f"{DOCKER_SOCKET} is not mounted into the api container.",
        ),
        kubernetes=BackendStatus(
            available=kube_ok,
            reason=kube_reason,
            detail=cfg.namespace if (kube_ok and cfg) else None,
        ),
        appliance=bool(settings.appliance_mode),
    )


@router.get("/containers/pods", response_model=PodListResponse)
async def container_pods(_: SuperAdmin) -> PodListResponse:
    if k8s.get_config() is None:
        return PodListResponse(available=False, reason=_SA_REASON)
    try:
        pods = await anyio.to_thread.run_sync(pod_svc.release_pods)
    except pod_svc.DockerUnavailableError as exc:
        return PodListResponse(available=False, reason=f"kubeapi: {exc}")
    rows = []
    for p in pods:
        s = pod_svc._parse_pod_to_summary(p)  # noqa: SLF001
        rows.append(
            PodRow(
                name=s.name,
                component=s.component,
                image=s.image,
                state=s.state,
                status=s.status,
                health=s.health,
                started_at=s.started_at.isoformat() if s.started_at else None,
                containers=[
                    c["name"]
                    for c in (p.get("spec") or {}).get("containers") or []
                    if c.get("name")
                ],
            )
        )
    rows.sort(key=lambda r: (r.component, r.name))
    return PodListResponse(available=True, rows=rows)


async def _resolve_pod(name: str) -> str | None:
    """Fresh-listing allowlist: 404 for any name that is not a release pod.
    Returns the default log container."""
    if k8s.get_config() is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, _SA_REASON)
    try:
        found = await anyio.to_thread.run_sync(pod_svc.find_release_pod, name)
    except pod_svc.DockerUnavailableError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    if found is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"no such pod {name!r}")
    return found[1]


def _audit_log_read(db: DB, user: Any, name: str, how: str) -> None:
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="container_logs_read",
            resource_type="container",
            resource_id=f"pod/{name}",
            resource_display=name,
            result="success",
            new_value={"mode": how},
        )
    )


@router.get("/containers/pods/{name}/logs")
async def pod_logs(
    name: str,
    user: SuperAdmin,
    db: DB,
    tail: int = Query(200, ge=1, le=5000),
) -> dict[str, str]:
    default_container = await _resolve_pod(name)
    requested = tail + LOG_CONTEXT_LINES
    try:
        text = await anyio.to_thread.run_sync(
            lambda: pod_svc.get_container_logs(name, tail=requested, container=default_container)
        )
    except pod_svc.DockerUnavailableError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    _audit_log_read(db, user, name, "tail")
    await db.commit()
    return {"name": name, "tail": redact_log_tail(text, tail, requested=requested)}


@router.get("/containers/pods/{name}/logs/stream")
async def pod_logs_stream(
    name: str,
    request: Request,
    user: SuperAdmin,
    db: DB,
    tail: int = Query(100, ge=1, le=5000),
):
    default_container = await _resolve_pod(name)
    _audit_log_read(db, user, name, "stream")
    await db.commit()
    gen = pod_svc.stream_container_logs(name, tail=tail, container=default_container)
    return _sse_log_response(gen, request)
