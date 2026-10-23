"""Container management endpoints — Phase 4d.

Mounted at ``/api/v1/appliance/containers``:

    GET    /                          list all containers + spatium-only first
    POST   /{name}/{action}           start / stop / restart
    GET    /{name}/logs               tail (non-streaming)
    GET    /{name}/logs/stream        SSE — follow=true tail (close to disconnect)
"""

from __future__ import annotations

import json
from datetime import datetime

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.api.deps import DB, CurrentUser
from app.api.stream_auth import StreamAuthGuard
from app.core.permissions import require_permission
from app.models.audit import AuditLog
from app.services.appliance.containers import (
    DockerUnavailableError,
    container_action,
    get_container_logs,
    resolve_workload_pod,
    stream_container_logs,
)
from app.services.appliance.containers import (
    list_containers as svc_list_containers,
)

logger = structlog.get_logger(__name__)

router = APIRouter()


class ContainerInfo(BaseModel):
    name: str
    image: str
    state: str
    status: str
    health: str | None
    short_id: str
    started_at: datetime | None
    is_spatium: bool


_ALLOWED_ACTIONS = ("start", "stop", "restart")


@router.get(
    "",
    response_model=list[ContainerInfo],
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="List Docker containers visible to the api",
)
async def list_containers() -> list[ContainerInfo]:
    try:
        rows = svc_list_containers()
    except DockerUnavailableError as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"docker daemon unreachable from api: {exc}",
        )
    return [ContainerInfo(**c.__dict__) for c in rows]


@router.post(
    "/{name}/{action}",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Run start / stop / restart on a container",
)
async def post_container_action(
    name: str,
    action: str,
    db: DB,
    user: CurrentUser,
) -> dict[str, str]:
    if action not in _ALLOWED_ACTIONS:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"action must be one of {_ALLOWED_ACTIONS}",
        )
    try:
        container_action(name, action)
    except DockerUnavailableError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action=f"container_{action}",
            resource_type="appliance",
            resource_id=f"container/{name}",
            resource_display=name,
            result="success",
        )
    )
    await db.commit()
    return {"name": name, "action": action, "status": "accepted"}


@router.get(
    "/{name}/logs",
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="Tail recent log lines (non-streaming)",
)
async def get_logs(name: str, tail: int = 200) -> dict[str, str]:
    if tail < 1 or tail > 5000:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "tail must be between 1 and 5000")
    try:
        text = get_container_logs(name, tail=tail)
    except DockerUnavailableError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    return {"name": name, "tail": text}


def _sse_log_response(gen, request: Request) -> StreamingResponse:
    """Wrap a log-chunk generator as an SSE response.

    Chunks are JSON-encoded ``{"line": "..."}`` so embedded newlines /
    quotes round-trip cleanly through the SSE wire format.
    ``X-Accel-Buffering: no`` disables nginx response buffering so each
    line reaches the browser ASAP (same pattern as the AI-chat stream).
    The caller is re-validated on a bounded cadence before each chunk is
    sent (``StreamAuthGuard``); the stream ends once that fails.
    """
    guard = StreamAuthGuard(request, permission=("read", "appliance"))

    async def event_source():
        try:
            async for chunk in gen:
                if not await guard.still_authorized():
                    return
                for line in chunk.splitlines():
                    yield f"data: {json.dumps({'line': line})}\n\n"
        finally:
            await gen.aclose()

    return StreamingResponse(
        event_source(),
        media_type="text/event-stream",
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
    )


@router.get(
    "/{name}/logs/stream",
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="Stream a single pod's logs as SSE (follow=true)",
)
async def stream_logs(name: str, request: Request, tail: int = 100):
    """Stream one pod's logs by exact pod name; closes on client disconnect."""
    try:
        gen = stream_container_logs(name, tail=tail)
    except DockerUnavailableError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    return _sse_log_response(gen, request)


@router.get(
    "/workloads/{component}/logs/stream",
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="Stream a workload's logs as SSE — resolves component → current pod",
)
async def stream_workload_logs(component: str, request: Request, tail: int = 100):
    """Tail a workload (deployment / daemonset) by its component label
    (api / worker / frontend / …) instead of a churny pod name (#416).

    Resolves the component to its current running pod server-side, so the
    operator picks a stable workload and a pod roll just means the next
    (re)connect lands on the fresh pod.
    """
    try:
        resolved = resolve_workload_pod(component)
    except DockerUnavailableError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    if resolved is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"no running pod for workload {component!r}",
        )
    pod, container = resolved
    try:
        gen = stream_container_logs(pod, tail=tail, container=container)
    except DockerUnavailableError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    return _sse_log_response(gen, request)
