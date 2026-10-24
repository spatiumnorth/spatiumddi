"""Packet capture (tcpdump) on-demand API — issue #59.

Mounted at ``/api/v1/pcap`` (module-gated by ``tools.pcap``). Mirrors the
nmap surface but the deliverable is a binary ``.pcap`` download, not a
searchable text/XML blob, so there is **no SSE stream** — the UI polls
``GET /captures/{id}`` for live ``bytes_captured`` + status, and the
finished capture is fetched via ``GET /captures/{id}/download``.

Endpoints (all gate on the ``manage_packet_capture`` permission):

* ``POST /captures`` — start a capture (server vantage in Phase 1),
  202 + queued row + Celery dispatch.
* ``GET /captures`` — paginated list, filter by status / vantage /
  appliance.
* ``GET /captures/{id}`` — full record (incl. live progress while
  running).
* ``DELETE /captures/{id}`` — cancel a running capture or hard-delete a
  terminal one (unlinks the ``.pcap``).
* ``POST /captures/bulk-delete`` — cancel + delete up to 500.
* ``GET /interfaces`` — capturable interfaces for a vantage (+ an honest
  note about what it can see).
* ``GET /captures/{id}/download`` — stream the ``.pcap`` (Bearer auth,
  audited; 404 — never 500 — when the artifact is gone).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import DB, CurrentUser
from app.api.pagination import MAX_PAGE
from app.core.celery_dispatch import dispatch
from app.core.permissions import require_permission
from app.core.responses import PcapResponse
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.audit import AuditLog
from app.models.pcap import PacketCapture
from app.services.pcap import (
    PcapArgError,
    build_pcap_argv,
    clamp_caps,
    enumerate_interfaces,
    validate_bpf_filter,
    validate_interface,
)

from .schemas import (
    PcapBulkDeleteRequest,
    PcapCaptureCreate,
    PcapCaptureListResponse,
    PcapCaptureRead,
    PcapInterfacesResponse,
)

logger = structlog.get_logger(__name__)

PERMISSION = "manage_packet_capture"

router = APIRouter(tags=["pcap"])


# ── Helpers ──────────────────────────────────────────────────────────

# A capture is downloadable once it has a real on-disk artifact — true for
# a normally-completed capture AND for one the operator Stopped early
# (#59 follow-up): tcpdump flushes the savefile on SIGTERM, so the packets
# captured before Stop are a valid, downloadable ``.pcap``. A failed
# capture never exposes a partial (its bytes are unreliable).
_DOWNLOADABLE_STATUSES = ("completed", "cancelled")


def _has_artifact(row: PacketCapture) -> bool:
    return bool(
        row.status in _DOWNLOADABLE_STATUSES
        and row.pcap_path
        and not row.artifact_missing
        and (row.pcap_size_bytes or 0) > 0
    )


def _to_read(row: PacketCapture) -> PcapCaptureRead:
    return PcapCaptureRead(
        id=row.id,
        vantage_kind=row.vantage_kind,
        appliance_id=row.appliance_id,
        vantage_label=row.vantage_label,
        interface=row.interface,
        bpf_filter=row.bpf_filter,
        snaplen=row.snaplen,
        promiscuous=row.promiscuous,
        max_packets=row.max_packets,
        max_duration_s=row.max_duration_s,
        max_bytes=row.max_bytes,
        status=row.status,
        started_at=row.started_at,
        finished_at=row.finished_at,
        duration_seconds=row.duration_seconds,
        exit_code=row.exit_code,
        command_line=row.command_line,
        error_message=row.error_message,
        packets_captured=row.packets_captured,
        bytes_captured=row.bytes_captured,
        pcap_size_bytes=row.pcap_size_bytes,
        pcap_sha256=row.pcap_sha256,
        has_artifact=_has_artifact(row),
        metadata_json=row.metadata_json,
        created_by_user_id=row.created_by_user_id,
        created_at=row.created_at,
        modified_at=row.modified_at,
    )


async def _audit(
    db: AsyncSession,
    *,
    user: Any,
    action: str,
    capture_id: uuid.UUID,
    label: str,
    new_value: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            user_display_name=user.display_name if user else "system",
            auth_source=getattr(user, "auth_source", "local") or "local",
            action=action,
            resource_type="packet_capture",
            resource_id=str(capture_id),
            resource_display=f"pcap:{label}",
            new_value=new_value,
        )
    )


# ── Interfaces ───────────────────────────────────────────────────────


@router.get(
    "/interfaces",
    response_model=PcapInterfacesResponse,
    dependencies=[Depends(require_permission("read", PERMISSION))],
)
async def list_interfaces(
    db: DB,
    current_user: CurrentUser,  # noqa: ARG001 — gate handled by dep
    vantage: str = Query("server"),
    appliance_id: uuid.UUID | None = Query(None),
) -> PcapInterfacesResponse:
    if vantage == "server":
        return PcapInterfacesResponse(
            interfaces=enumerate_interfaces(),
            note=(
                "Control-plane container network (inter-pod / bridge traffic "
                "only — NOT the host's physical NICs)."
            ),
        )
    if vantage == "appliance":
        # The supervisor enumerates the host's real NICs from
        # /run/udev/data and reports them on every heartbeat; we surface
        # that list so the operator picks (not guesses) the capture NIC.
        if appliance_id is None:
            return PcapInterfacesResponse(
                interfaces=[],
                note="Select an appliance to list its host network interfaces.",
            )
        appliance = await db.get(Appliance, appliance_id)
        if appliance is None:
            raise HTTPException(status_code=422, detail="appliance_id not found")
        ifaces = [i for i in (appliance.host_interfaces or []) if i]
        if ifaces:
            if "any" not in ifaces:
                ifaces = ["any", *ifaces]
            note = (
                "The appliance host's real NICs (reported by the supervisor). "
                'Pick the LAN NIC to capture subnet traffic; "any" spans all '
                "host interfaces."
            )
        else:
            note = (
                "No interfaces reported yet — the supervisor enumerates them on "
                'its heartbeat (~30 s). Type a NIC name (e.g. eth0) or "any" '
                "meanwhile."
            )
        return PcapInterfacesResponse(interfaces=ifaces, note=note)
    raise HTTPException(status_code=422, detail=f"unknown vantage: {vantage!r}")


# ── CRUD ─────────────────────────────────────────────────────────────


@router.post(
    "/captures",
    response_model=PcapCaptureRead,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_permission("write", PERMISSION))],
)
async def create_capture(
    body: PcapCaptureCreate, db: DB, current_user: CurrentUser
) -> PcapCaptureRead:
    if body.vantage_kind not in ("server", "appliance"):
        raise HTTPException(status_code=422, detail=f"unknown vantage: {body.vantage_kind!r}")

    appliance_label = "control plane"
    appliance_id = body.appliance_id
    # Server vantage enumerates the worker's own NICs; appliance vantage
    # can't (different host), so the host runner does the membership check.
    require_avail = True
    if body.vantage_kind == "appliance":
        if appliance_id is None:
            raise HTTPException(
                status_code=422,
                detail="appliance_id is required for appliance-host capture",
            )
        appliance = await db.get(Appliance, appliance_id)
        if appliance is None:
            raise HTTPException(status_code=422, detail="appliance_id not found")
        if appliance.state != APPLIANCE_STATE_APPROVED:
            raise HTTPException(
                status_code=422,
                detail=f"appliance is {appliance.state!r}, not approved — can't dispatch a capture",
            )
        appliance_label = appliance.hostname or str(appliance_id)
        require_avail = False
    else:
        # server vantage carries no appliance binding.
        appliance_id = None

    # Pre-validate (surfaces PcapArgError before persisting a doomed row).
    try:
        interface = validate_interface(body.interface, require_available=require_avail)
        bpf = validate_bpf_filter(body.bpf_filter)
        mp, md, mb, sl = clamp_caps(
            max_packets=body.max_packets,
            max_duration_s=body.max_duration_s,
            max_bytes=body.max_bytes,
            snaplen=body.snaplen,
        )
        # Build once to surface any argv error now.
        build_pcap_argv(
            interface=interface,
            bpf_filter=bpf,
            snaplen=sl,
            promiscuous=body.promiscuous,
            max_packets=mp,
            output_path="/dev/null",
        )
    except PcapArgError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    cap = PacketCapture(
        vantage_kind=body.vantage_kind,
        appliance_id=appliance_id,
        vantage_label=appliance_label,
        interface=interface,
        bpf_filter=bpf,
        snaplen=sl,
        promiscuous=body.promiscuous,
        max_packets=mp,
        max_duration_s=md,
        max_bytes=mb,
        status="queued",
        created_by_user_id=current_user.id,
    )
    db.add(cap)
    await db.flush()
    await _audit(
        db,
        user=current_user,
        action="create",
        capture_id=cap.id,
        label=f"{appliance_label}:{interface}",
        new_value={
            "vantage_kind": body.vantage_kind,
            "appliance_id": str(appliance_id) if appliance_id else None,
            "interface": interface,
            "bpf_filter": bpf,
            "snaplen": sl,
            "max_packets": mp,
            "max_duration_s": md,
            "max_bytes": mb,
        },
    )
    await db.commit()
    await db.refresh(cap)

    # Server vantage runs in the worker via Celery. Appliance vantage is
    # NOT dispatched here — the supervisor's pcap_proxy long-polls
    # /supervisor/pcap/poll and claims the queued row itself.
    if body.vantage_kind == "server":
        try:
            from app.tasks.pcap import run_capture_task  # noqa: PLC0415

            await dispatch(run_capture_task, str(cap.id))
        except Exception as exc:  # noqa: BLE001 — broker down
            logger.warning("pcap_dispatch_failed", capture_id=str(cap.id), error=str(exc))

    return _to_read(cap)


@router.get(
    "/captures",
    response_model=PcapCaptureListResponse,
    dependencies=[Depends(require_permission("read", PERMISSION))],
)
async def list_captures(
    db: DB,
    current_user: CurrentUser,  # noqa: ARG001
    status_filter: str | None = Query(None, alias="status"),
    vantage: str | None = Query(None),
    appliance_id: uuid.UUID | None = Query(None),
    page: int = Query(1, ge=1, le=MAX_PAGE),
    page_size: int = Query(50, ge=1, le=500),
) -> PcapCaptureListResponse:
    base = select(PacketCapture)
    if status_filter:
        base = base.where(PacketCapture.status == status_filter)
    if vantage:
        base = base.where(PacketCapture.vantage_kind == vantage)
    if appliance_id is not None:
        base = base.where(PacketCapture.appliance_id == appliance_id)

    total = int((await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one())
    stmt = (
        base.order_by(PacketCapture.created_at.desc())
        .limit(page_size)
        .offset((page - 1) * page_size)
    )
    rows = list((await db.execute(stmt)).scalars().all())
    return PcapCaptureListResponse(
        items=[_to_read(r) for r in rows], total=total, page=page, page_size=page_size
    )


@router.get(
    "/captures/{capture_id}",
    response_model=PcapCaptureRead,
    dependencies=[Depends(require_permission("read", PERMISSION))],
)
async def get_capture(
    capture_id: uuid.UUID, db: DB, current_user: CurrentUser  # noqa: ARG001
) -> PcapCaptureRead:
    row = await db.get(PacketCapture, capture_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    return _to_read(row)


@router.delete(
    "/captures/{capture_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission("delete", PERMISSION))],
)
async def cancel_or_delete_capture(
    capture_id: uuid.UUID, db: DB, current_user: CurrentUser
) -> None:
    """Cancel an in-flight capture or hard-delete a terminal one.

    queued/running → ``cancelled`` (the runner self-terminates on its
    next ~1 s poll). Terminal → row removed + ``.pcap`` unlinked.
    """
    row = await db.get(PacketCapture, capture_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    label = row.vantage_label or row.vantage_kind

    if row.status in ("queued", "running"):
        row.status = "cancelled"
        if row.finished_at is None:
            row.finished_at = datetime.now(UTC)
        await _audit(db, user=current_user, action="cancel", capture_id=row.id, label=label)
        await db.commit()
        return

    if row.pcap_path:
        from contextlib import suppress

        with suppress(OSError):
            Path(row.pcap_path).unlink()
    await _audit(db, user=current_user, action="delete", capture_id=row.id, label=label)
    await db.delete(row)
    await db.commit()


@router.post(
    "/captures/bulk-delete",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_permission("delete", PERMISSION))],
)
async def bulk_delete_captures(
    body: PcapBulkDeleteRequest, db: DB, current_user: CurrentUser
) -> dict[str, int]:
    """Bulk-cancel + delete up to 500 captures (same per-row policy)."""
    from contextlib import suppress

    cancelled = 0
    deleted = 0
    now = datetime.now(UTC)
    for cid in body.capture_ids:
        row = await db.get(PacketCapture, cid)
        if row is None:
            continue
        label = row.vantage_label or row.vantage_kind
        if row.status in ("queued", "running"):
            row.status = "cancelled"
            if row.finished_at is None:
                row.finished_at = now
            await _audit(db, user=current_user, action="cancel", capture_id=row.id, label=label)
            cancelled += 1
        else:
            if row.pcap_path:
                with suppress(OSError):
                    Path(row.pcap_path).unlink()
            await _audit(db, user=current_user, action="delete", capture_id=row.id, label=label)
            await db.delete(row)
            deleted += 1
    await db.commit()
    return {"deleted": deleted, "cancelled": cancelled}


# ── Download ─────────────────────────────────────────────────────────


@router.get(
    "/captures/{capture_id}/download",
    # ``response_class`` REPLACES the documented application/json (#921);
    # a ``responses={200: {"content": ...}}`` entry merges with it instead,
    # leaving the route declaring a JSON body it never produces.
    response_class=PcapResponse,
    responses={200: {"description": "The capture file"}},
    dependencies=[Depends(require_permission("read", PERMISSION))],
)
async def download_capture(
    capture_id: uuid.UUID, db: DB, current_user: CurrentUser
) -> FileResponse:
    """Stream the finished ``.pcap``.

    Auth is the standard ``Authorization: Bearer`` (the frontend fetches a
    blob — no ``?token=`` fallback, unlike the nmap SSE stream). The
    download is audited (the moment sensitive bytes leave the system).
    Guards return 404 — never 500 — when the artifact is gone (pruned /
    restore drift), with a structured detail.
    """
    row = await db.get(PacketCapture, capture_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    if not _has_artifact(row):
        raise HTTPException(status_code=404, detail="Capture has no downloadable artifact yet")
    if not row.pcap_path or not Path(row.pcap_path).exists():
        raise HTTPException(
            status_code=404,
            detail="capture artifact no longer on disk (pruned or volume drift)",
        )

    ts = (row.finished_at or row.created_at).strftime("%Y%m%d-%H%M%S")
    iface = (row.interface or "any").replace("/", "_")
    filename = f"capture-{row.vantage_kind}-{iface}-{ts}.pcap"

    await _audit(
        db,
        user=current_user,
        action="download",
        capture_id=row.id,
        label=row.vantage_label or row.vantage_kind,
        new_value={"filename": filename, "bytes": row.pcap_size_bytes},
    )
    await db.commit()

    return FileResponse(
        row.pcap_path,
        media_type="application/vnd.tcpdump.pcap",
        filename=filename,
        headers={"Referrer-Policy": "no-referrer"},
    )


__all__ = ["router"]
