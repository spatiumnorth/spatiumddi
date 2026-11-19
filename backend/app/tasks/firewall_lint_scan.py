"""One-time advisory lint of existing ``firewall_extra`` values (#285 Phase 5).

The 3d write-path lint only checks the DELTA — a value that predates the
grammar is grandfathered and never re-linted. This task closes that gap with a
ONE-TIME advisory sweep: every appliance's stored ``firewall_extra`` is run
through ``lint_firewall_extra`` and any findings are recorded as audit rows
(``firewall_extra_lint_advisory``) so operators can clean up legacy values.
Advisory only — it never rejects or mutates anything; ``nft -c -f`` on the host
remains the authority.

Run-once is gated on the **audit log itself** (no schema/watermark column): a
single ``firewall_extra_lint_scan_complete`` marker row is written at the end,
and the task short-circuits on every subsequent tick once it sees that row. The
beat entry fires every 30 min but the scan body runs exactly once per install.
"""

from __future__ import annotations

import structlog
from sqlalchemy import exists, select

from app.celery_app import celery_app
from app.db import task_session
from app.models.appliance import Appliance
from app.models.audit import AuditLog
from app.services.appliance.firewall_lint import lint_firewall_extra
from app.task_runtime import run_task

logger = structlog.get_logger(__name__)

_MARKER_ACTION = "firewall_extra_lint_scan_complete"
_ADVISORY_ACTION = "firewall_extra_lint_advisory"


async def scan_firewall_extra(db) -> dict[str, int | bool]:  # type: ignore[no-untyped-def]
    """Advisory-lint every stored firewall_extra once. Returns a summary."""
    already = (await db.execute(select(exists().where(AuditLog.action == _MARKER_ACTION)))).scalar()
    if already:
        return {"ran": False, "appliances": 0, "with_findings": 0}

    rows = list(
        (await db.execute(select(Appliance).where(Appliance.firewall_extra.isnot(None))))
        .scalars()
        .all()
    )
    with_findings = 0
    for row in rows:
        findings = lint_firewall_extra(row.firewall_extra)
        if not findings:
            continue
        with_findings += 1
        db.add(
            AuditLog(
                action=_ADVISORY_ACTION,
                resource_type="appliance",
                resource_id=str(row.id),
                resource_display=row.hostname,
                user_display_name="system",
                result="success",
                new_value={
                    "findings": [
                        {"line": f.line, "severity": f.severity, "message": f.message}
                        for f in findings
                    ]
                },
            )
        )
    # Watermark — written even when nothing had findings, so the scan is
    # genuinely one-shot.
    db.add(
        AuditLog(
            action=_MARKER_ACTION,
            resource_type="platform",
            resource_id="firewall_extra_lint",
            resource_display="firewall_extra advisory scan",
            user_display_name="system",
            result="success",
            new_value={"appliances_scanned": len(rows), "with_findings": with_findings},
        )
    )
    await db.commit()
    return {"ran": True, "appliances": len(rows), "with_findings": with_findings}


@celery_app.task(name="app.tasks.firewall_lint_scan.scan_firewall_extra")
def scan_firewall_extra_task() -> dict[str, int | bool]:
    result = run_task(_run())
    logger.info("firewall_extra_lint_scan", **result)
    return result


async def _run() -> dict[str, int | bool]:
    async with task_session() as db:
        return await scan_firewall_extra(db)
