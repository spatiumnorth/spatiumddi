"""Operator Copilot tools for the on-demand nmap scanner.

Three tools split read vs. write:

* ``list_nmap_scans``       — paginated history, filterable by IP /
                              status / preset / time window.
* ``get_nmap_scan_results`` — full results for one scan ID, including
                              alive flag, open ports + services, OS
                              guess, and (truncated) raw stdout.
* ``propose_run_nmap_scan`` — gated write: model proposes a scan,
                              operator clicks Apply before nmap
                              actually runs. Touching the network is
                              never silent.

The propose tool delegates to a registered ``run_nmap_scan``
operation in :mod:`app.services.ai.operations` so the same preview /
apply contract used for IPAM allocations applies here.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.nmap.schemas import NmapPreset
from app.models.auth import User
from app.models.nmap import NmapScan
from app.services.ai.tools.base import register_tool

# Cap the raw_stdout snippet returned by ``get_nmap_scan_results`` so
# the model isn't blown out of context by a verbose scan. Operators
# wanting the full output open the scan in the UI.
_STDOUT_TAIL_CHARS = 2000


# ── list_nmap_scans ───────────────────────────────────────────────────


class ListNmapScansArgs(BaseModel):
    target_ip: str | None = Field(
        default=None,
        description=(
            "Filter by exact target IP / hostname. Substring not "
            "supported — pass the full address."
        ),
    )
    ip_address_id: str | None = Field(
        default=None,
        description="Filter by IPAM IPAddress UUID.",
    )
    status: Literal["queued", "running", "completed", "failed", "cancelled"] | None = Field(
        default=None,
        description="Filter by scan run state.",
    )
    preset: NmapPreset | None = Field(
        default=None,
        description="Filter by nmap preset (quick, service_version, …).",
    )
    since: datetime | None = Field(
        default=None,
        description=(
            "Return scans started at or after this UTC timestamp "
            "(ISO 8601). Omit for the full history."
        ),
    )
    limit: int = Field(default=20, ge=1, le=100)


@register_tool(
    name="list_nmap_scans",
    module="tools.nmap",
    description=(
        "List nmap scans from the on-demand scanner history. Filter "
        "by target IP, IPAM address UUID, status, preset, or a "
        "since-timestamp. Each row includes ``status``, ``preset``, "
        "``started_at`` / ``finished_at``, and a short summary "
        "(open-port count, host_state) when complete. For full "
        "results — open ports, OS guess, raw stdout — call "
        "``get_nmap_scan_results`` with the scan id."
    ),
    args_model=ListNmapScansArgs,
    category="network",
)
async def list_nmap_scans(
    db: AsyncSession, user: User, args: ListNmapScansArgs
) -> list[dict[str, Any]] | dict[str, Any]:
    stmt = select(NmapScan)
    if args.target_ip:
        stmt = stmt.where(NmapScan.target_ip == args.target_ip.strip())
    if args.ip_address_id:
        try:
            stmt = stmt.where(NmapScan.ip_address_id == uuid.UUID(args.ip_address_id))
        except ValueError:
            return {
                "error": f"ip_address_id must be a UUID, got {args.ip_address_id!r}.",
                "hint": "Call find_ip with the IP first to resolve the UUID.",
            }
    if args.status:
        stmt = stmt.where(NmapScan.status == args.status)
    if args.preset:
        stmt = stmt.where(NmapScan.preset == args.preset)
    if args.since:
        stmt = stmt.where(NmapScan.started_at >= args.since)
    stmt = stmt.order_by(NmapScan.started_at.desc().nullslast()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()

    out: list[dict[str, Any]] = []
    for r in rows:
        summary = r.summary_json or {}
        ports = summary.get("ports") or []
        out.append(
            {
                "id": str(r.id),
                "target_ip": r.target_ip,
                "ip_address_id": str(r.ip_address_id) if r.ip_address_id else None,
                "preset": r.preset,
                "status": r.status,
                "host_state": summary.get("host_state"),
                "open_port_count": sum(1 for p in ports if p.get("state") == "open"),
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                "duration_seconds": r.duration_seconds,
                "exit_code": r.exit_code,
                "error_message": r.error_message,
            }
        )
    return out


# ── get_nmap_scan_results ─────────────────────────────────────────────


class GetNmapScanResultsArgs(BaseModel):
    scan_id: str = Field(
        description="The nmap scan UUID returned by list_nmap_scans.",
    )


@register_tool(
    name="get_nmap_scan_results",
    module="tools.nmap",
    description=(
        "Return full results for one nmap scan: alive / down state, "
        "every port + state + service / version, OS guess + accuracy, "
        "and a tail of the raw stdout. Use this after "
        "``list_nmap_scans`` finds a scan id, or after a "
        "``propose_run_nmap_scan`` proposal has been applied and "
        "completed (poll until ``status == 'completed'``)."
    ),
    args_model=GetNmapScanResultsArgs,
    category="network",
)
async def get_nmap_scan_results(
    db: AsyncSession, user: User, args: GetNmapScanResultsArgs
) -> dict[str, Any]:
    try:
        scan_uuid = uuid.UUID(args.scan_id)
    except ValueError:
        return {
            "error": f"scan_id must be a UUID, got {args.scan_id!r}.",
        }
    row = await db.get(NmapScan, scan_uuid)
    if row is None:
        return {"error": f"No nmap scan with id {args.scan_id}."}

    summary = row.summary_json or {}
    stdout = row.raw_stdout or ""
    return {
        "id": str(row.id),
        "target_ip": row.target_ip,
        "ip_address_id": str(row.ip_address_id) if row.ip_address_id else None,
        "preset": row.preset,
        "port_spec": row.port_spec,
        "status": row.status,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "finished_at": row.finished_at.isoformat() if row.finished_at else None,
        "duration_seconds": row.duration_seconds,
        "exit_code": row.exit_code,
        "command_line": row.command_line,
        "error_message": row.error_message,
        "host_state": summary.get("host_state"),
        "ports": summary.get("ports") or [],
        "os": summary.get("os"),
        "hosts": summary.get("hosts"),  # populated for CIDR scans
        "stdout_tail": stdout[-_STDOUT_TAIL_CHARS:] if stdout else None,
        "stdout_truncated": len(stdout) > _STDOUT_TAIL_CHARS,
    }


__all__ = ["list_nmap_scans", "get_nmap_scan_results"]
