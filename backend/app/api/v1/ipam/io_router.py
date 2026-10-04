"""IPAM import / export endpoints — thin wrappers around ``app.services.ipam_io``."""

from __future__ import annotations

import ipaddress
import uuid
from typing import Literal

import structlog
from fastapi import APIRouter, Body, File, Form, HTTPException, Query, UploadFile, status
from fastapi.responses import Response

from app.api.deps import DB, CurrentUser
from app.core.content_disposition import content_disposition
from app.core.permissions import user_has_permission
from app.core.responses import PdfResponse
from app.services.ipam.address_set_gate import (
    load_writable_set_ranges,
    user_can_write_ip,
)
from app.services.ipam_io import (
    commit_address_import,
    commit_import,
    export_subtree,
    parse_payload,
    preview_address_import,
    preview_import,
)

logger = structlog.get_logger(__name__)
router = APIRouter()


# Upload size guard: 25 MB is plenty for IPAM imports.
_MAX_UPLOAD_BYTES = 25 * 1024 * 1024


async def _read_upload(file: UploadFile) -> bytes:
    data = await file.read()
    if len(data) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Upload exceeds {_MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit",
        )
    return data


@router.post("/import/preview")
async def import_preview(
    current_user: CurrentUser,
    db: DB,
    file: UploadFile = File(...),
    space_id: uuid.UUID | None = Form(default=None),
    space_name: str | None = Form(default=None),
    strategy: Literal["skip", "overwrite", "fail"] = Form(default="fail"),
) -> dict:
    """Dry-run an import and return the would-create / would-update / conflict diff."""
    data = await _read_upload(file)
    payload = parse_payload(data, file.filename or "", file.content_type)
    preview = await preview_import(
        db,
        payload,
        space_id=space_id,
        space_name=space_name,
        strategy=strategy,
    )
    logger.info(
        "ipam_import_preview",
        space_id=preview.space_id,
        creates=len(preview.creates),
        updates=len(preview.updates),
        conflicts=len(preview.conflicts),
        errors=len(preview.errors),
        user=current_user.display_name,
    )
    return preview.as_dict()


@router.post("/import/commit")
async def import_commit(
    current_user: CurrentUser,
    db: DB,
    file: UploadFile = File(...),
    space_id: uuid.UUID | None = Form(default=None),
    space_name: str | None = Form(default=None),
    strategy: Literal["skip", "overwrite", "fail"] = Form(default="fail"),
) -> dict:
    """Commit the import in a single transaction. Writes audit entries per mutation."""
    # The import creates / updates blocks and subnets, so the coarse router
    # gate (which also admits any address_set grant) is not enough.
    for rtype in ("ip_block", "subnet"):
        if not user_has_permission(current_user, "write", rtype):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: need 'write' on '{rtype}'",
            )
    data = await _read_upload(file)
    payload = parse_payload(data, file.filename or "", file.content_type)
    result = await commit_import(
        db,
        payload,
        current_user=current_user,
        space_id=space_id,
        space_name=space_name,
        strategy=strategy,
    )
    await db.commit()
    return result.as_dict()


@router.post("/import/preview-json")
async def import_preview_json(
    current_user: CurrentUser,
    db: DB,
    body: dict = Body(...),
) -> dict:
    """JSON-body variant of preview — useful for programmatic clients that do not
    want to send multipart/form-data.

    Body shape::

        {
          "space_id": "…" | null,
          "space_name": "…" | null,
          "strategy": "skip" | "overwrite" | "fail",
          "payload": { "subnets": [...] }   // or { "spaces": [...], ... }
        }
    """
    from app.services.ipam_io.parser import ParsedPayload

    raw = body.get("payload")
    if not isinstance(raw, dict):
        raise HTTPException(status_code=422, detail="Missing 'payload' object")
    parsed = ParsedPayload(
        spaces=list(raw.get("spaces") or []),
        blocks=list(raw.get("blocks") or []),
        subnets=list(raw.get("subnets") or []),
        addresses=list(raw.get("addresses") or []),
    )
    space_id = body.get("space_id")
    preview = await preview_import(
        db,
        parsed,
        space_id=uuid.UUID(space_id) if space_id else None,
        space_name=body.get("space_name"),
        strategy=body.get("strategy", "fail"),
    )
    return preview.as_dict()


@router.post("/import/addresses/preview")
async def import_addresses_preview(
    current_user: CurrentUser,
    db: DB,
    file: UploadFile = File(...),
    subnet_id: uuid.UUID = Form(...),
    strategy: Literal["skip", "overwrite", "fail"] = Form(default="fail"),
) -> dict:
    """Dry-run a subnet-scoped IP address import.

    Accepts CSV / JSON / XLSX with an ``address`` (or ``ip``) column plus
    any of ``hostname``, ``mac_address``, ``description``, ``status``,
    ``tags``, ``custom_fields``. Any unrecognised columns become
    ``custom_fields`` entries so migrations from other DDI tools don't
    need column renaming.
    """
    data = await _read_upload(file)
    payload = parse_payload(data, file.filename or "", file.content_type)
    preview = await preview_address_import(
        db,
        payload,
        subnet_id=subnet_id,
        strategy=strategy,
    )
    logger.info(
        "ipam_address_import_preview",
        subnet_id=str(subnet_id),
        creates=len(preview.creates),
        updates=len(preview.updates),
        conflicts=len(preview.conflicts),
        errors=len(preview.errors),
        user=current_user.display_name,
    )
    return preview.as_dict()


@router.post("/import/addresses/commit")
async def import_addresses_commit(
    current_user: CurrentUser,
    db: DB,
    file: UploadFile = File(...),
    subnet_id: uuid.UUID = Form(...),
    strategy: Literal["skip", "overwrite", "fail"] = Form(default="fail"),
) -> dict:
    """Commit a subnet-scoped IP address import. Same transaction as the
    audit trail it writes — a DNS-sync failure on a single row surfaces
    as a non-fatal error in the response, not a rolled-back import.
    """
    data = await _read_upload(file)
    payload = parse_payload(data, file.filename or "", file.content_type)

    # Address-set write delegation (#103): resolve the caller's writable
    # ranges once and refuse the whole import if they hold neither subnet-wide
    # write nor any address set on this subnet. Otherwise pass a per-IP gate
    # closure so rows outside the writable ranges are skipped + reported. The
    # gate helpers are imported at module level from the shared module (#12).
    subnet_writable = user_has_permission(current_user, "write", "subnet", subnet_id)
    set_ranges = await load_writable_set_ranges(db, current_user, subnet_id)
    if not subnet_writable and not set_ranges:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No write permission on subnet or any address set on it.",
        )

    def _can_write(addr: str) -> bool:
        try:
            ip_int = int(ipaddress.ip_address(addr))
        except ValueError:
            return False
        return user_can_write_ip(current_user, ip_int, subnet_writable, set_ranges)

    result = await commit_address_import(
        db,
        payload,
        current_user=current_user,
        subnet_id=subnet_id,
        strategy=strategy,
        can_write_ip=None if subnet_writable else _can_write,
    )
    await db.commit()
    return result.as_dict()


@router.get(
    "/export.pdf",
    # Declared media type, not just the wire header: FastAPI documents a bare
    # `-> Response` as application/json, so the (correctly sent)
    # application/pdf was undocumented and schema-conformance clients flagged
    # every response (schemathesis UndefinedContentType, 13/13 runs).
    # ``response_class`` rather than a ``responses={200: {"content": ...}}``
    # entry (#921): that entry MERGES with the inferred application/json, so
    # the route still declared a JSON body it never produces.
    response_class=PdfResponse,
    responses={200: {"description": "PDF IPAM report"}},
)
async def export_pdf_endpoint(
    current_user: CurrentUser,
    db: DB,
    space_id: uuid.UUID | None = Query(default=None),
    block_id: uuid.UUID | None = Query(default=None),
    subnet_id: uuid.UUID | None = Query(default=None),
    include_addresses: bool = Query(default=False),
) -> Response:
    """Print-ready PDF of an IPAM subtree (#82) — the handover / auditor
    deliverable, as opposed to ``/export``'s machine-readable formats.

    Same scope selector: exactly one of space_id / block_id / subnet_id.
    A subnet scope renders the detail report (facts + address table);
    a space or block scope renders the tree report. A subnet report
    always includes its addresses — it exists to show them — so
    ``include_addresses`` is only meaningful on the tree shape, where it
    appends a scope-wide address table. Read-gated by the IPAM
    router-level permission dependency, same as every other route here.
    """
    from app.services.ipam_io.pdf import generate_ipam_pdf  # noqa: PLC0415

    data, filename = await generate_ipam_pdf(
        db,
        space_id=space_id,
        block_id=block_id,
        subnet_id=subnet_id,
        include_addresses=include_addresses,
    )
    logger.info(
        "ipam_export_pdf",
        space_id=str(space_id) if space_id else None,
        block_id=str(block_id) if block_id else None,
        subnet_id=str(subnet_id) if subnet_id else None,
        bytes=len(data),
        user=current_user.display_name,
    )
    return Response(
        content=data,
        media_type="application/pdf",
        headers={"Content-Disposition": content_disposition(filename)},
    )


@router.get("/export")
async def export_endpoint(
    current_user: CurrentUser,
    db: DB,
    space_id: uuid.UUID | None = Query(default=None),
    block_id: uuid.UUID | None = Query(default=None),
    subnet_id: uuid.UUID | None = Query(default=None),
    format: Literal["csv", "json", "xlsx"] = Query(default="csv"),
    include_addresses: bool = Query(default=False),
) -> Response:
    """Export a subtree. Exactly one of space_id/block_id/subnet_id must be set."""
    data, content_type, filename = await export_subtree(
        db,
        space_id=space_id,
        block_id=block_id,
        subnet_id=subnet_id,
        format=format,
        include_addresses=include_addresses,
    )
    logger.info(
        "ipam_export",
        space_id=str(space_id) if space_id else None,
        block_id=str(block_id) if block_id else None,
        subnet_id=str(subnet_id) if subnet_id else None,
        format=format,
        bytes=len(data),
        user=current_user.display_name,
    )
    return Response(
        content=data,
        media_type=content_type,
        headers={"Content-Disposition": content_disposition(filename)},
    )
