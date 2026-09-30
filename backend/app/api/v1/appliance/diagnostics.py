"""Logs + self-test + diagnostic bundle endpoints (Phase 4e).

Mounted at ``/api/v1/appliance/diagnostics``:

    GET   /logs                       — list available log files
    GET   /logs/{name}                — tail a specific log file
    POST  /self-test                  — run the self-test battery
    GET   /bundle                     — download the diagnostic zip
"""

from __future__ import annotations

from datetime import UTC

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse

from app.api.deps import DB, CurrentUser
from app.core.content_disposition import content_disposition
from app.core.permissions import require_permission
from app.core.responses import ZipResponse
from app.models.audit import AuditLog
from app.services.appliance.diagnostics import (
    generate_diagnostic_bundle,
    list_log_sources,
    read_log_tail,
    run_self_test,
    self_test_report_to_dict,
)

logger = structlog.get_logger(__name__)

router = APIRouter()


@router.get(
    "/logs",
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="List host log files visible to the appliance",
)
async def list_logs() -> dict[str, list[str]]:
    return {"sources": list_log_sources()}


@router.get(
    "/logs/{name}",
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="Tail a specific log file",
)
async def get_log(name: str, lines: int = 500) -> dict[str, str | int]:
    if lines < 1 or lines > 5000:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "lines must be between 1 and 5000")
    try:
        text = read_log_tail(name, lines=lines)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    if not text:
        # File missing OR empty — return 404 so the UI distinguishes
        # "operator typo'd the name" from "log just hasn't seen activity".
        # Empty-but-existent file isn't really a useful state to show.
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"log '{name}' not found or empty",
        )
    return {"name": name, "lines": lines, "tail": text}


@router.post(
    "/self-test",
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="Run the appliance self-test battery",
)
async def post_self_test() -> dict:
    report = run_self_test()
    return self_test_report_to_dict(report)


@router.get(
    "/bundle",
    # ``response_class`` REPLACES the documented application/json (#921);
    # a ``responses={200: {"content": ...}}`` entry merges with it instead,
    # leaving the route declaring a JSON body it never produces.
    response_class=ZipResponse,
    responses={200: {"description": "Diagnostics archive"}},
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Download a diagnostic bundle (zip)",
)
async def get_bundle(db: DB, user: CurrentUser):
    """Returns a zip with logs, container output, system info, and
    redacted config. Admin permission required because the bundle
    surfaces internal log content + env keys (values redacted but
    keys are visible)."""
    blob = generate_diagnostic_bundle()
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="diagnostic_bundle",
            resource_type="appliance",
            resource_id="diagnostics",
            resource_display="bundle",
            new_value={"size_bytes": len(blob)},
            result="success",
        )
    )
    await db.commit()
    logger.info(
        "appliance_diagnostic_bundle_generated",
        size_bytes=len(blob),
        user=user.username,
    )
    from datetime import datetime

    stamp = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S")
    filename = f"spatium-diagnostic-{stamp}.zip"
    return StreamingResponse(
        iter([blob]),
        media_type="application/zip",
        headers={
            "Content-Disposition": content_disposition(filename),
            "Content-Length": str(len(blob)),
        },
    )
