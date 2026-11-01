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
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import structlog
from fastapi import APIRouter, Query
from pydantic import BaseModel

from app.api.deps import SuperAdmin
from app.core.exc_text import describe_http_exc

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
                hint=f"Couldn't list containers via {DOCKER_SOCKET}: {describe_http_exc(exc)}",
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
