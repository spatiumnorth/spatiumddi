"""Operator Copilot tools for the packet-capture surface (issue #59).

Read-only, ``module="tools.pcap"`` so disabling the feature module hides
them. They return capture **metadata only** — never the captured bytes
(those are sensitive + binary; the operator downloads the ``.pcap`` from
the UI under the audited download endpoint).

* ``find_packet_captures``  — paginated history, filter by status /
                              vantage / appliance / since.
* ``count_packet_captures`` — count by the same filters.
* ``get_packet_capture``    — one capture's full metadata (incl. live
                              byte progress + the parsed summary).

The matching write — ``propose_run_packet_capture`` — is a gated
propose→apply Operation registered in
:mod:`app.services.ai.operations` (model proposes, operator clicks
Apply; capturing traffic is never silent).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.pcap import PacketCapture
from app.services.ai.tools.base import register_tool

_MODULE = "tools.pcap"
_PcapStatus = Literal["queued", "running", "completed", "failed", "cancelled"]


def _row_summary(r: PacketCapture) -> dict[str, Any]:
    return {
        "id": str(r.id),
        "vantage_kind": r.vantage_kind,
        "vantage_label": r.vantage_label,
        "interface": r.interface,
        "bpf_filter": r.bpf_filter,
        "status": r.status,
        "packets_captured": r.packets_captured,
        "bytes_captured": r.bytes_captured,
        "pcap_size_bytes": r.pcap_size_bytes,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
        "duration_seconds": r.duration_seconds,
        "error_message": r.error_message,
        "has_artifact": bool(
            r.status == "completed" and r.pcap_path and (r.pcap_size_bytes or 0) > 0
        ),
    }


# ── find_packet_captures ───────────────────────────────────────────────


class FindPacketCapturesArgs(BaseModel):
    status: _PcapStatus | None = Field(default=None, description="Filter by run state.")
    vantage_kind: Literal["server", "appliance"] | None = Field(
        default=None, description="Filter by capture vantage."
    )
    appliance_id: str | None = Field(default=None, description="Filter by appliance UUID.")
    since: datetime | None = Field(
        default=None, description="Captures created at/after this UTC timestamp (ISO 8601)."
    )
    limit: int = Field(default=20, ge=1, le=100)


@register_tool(
    name="find_packet_captures",
    permission=("read", "manage_packet_capture"),
    module=_MODULE,
    description=(
        "List packet captures (tcpdump) from the on-demand capture "
        "history. Filter by status, vantage (server / appliance), "
        "appliance UUID, or a since-timestamp. Returns metadata only "
        "(interface, BPF filter, status, packet/byte counts, whether a "
        "downloadable .pcap exists) — never the captured bytes."
    ),
    args_model=FindPacketCapturesArgs,
    category="network",
)
async def find_packet_captures(
    db: AsyncSession, user: User, args: FindPacketCapturesArgs
) -> list[dict[str, Any]] | dict[str, Any]:
    stmt = select(PacketCapture)
    if args.status:
        stmt = stmt.where(PacketCapture.status == args.status)
    if args.vantage_kind:
        stmt = stmt.where(PacketCapture.vantage_kind == args.vantage_kind)
    if args.appliance_id:
        try:
            stmt = stmt.where(PacketCapture.appliance_id == uuid.UUID(args.appliance_id))
        except ValueError:
            return {"error": f"appliance_id must be a UUID, got {args.appliance_id!r}."}
    if args.since:
        stmt = stmt.where(PacketCapture.created_at >= args.since)
    stmt = stmt.order_by(desc(PacketCapture.created_at)).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [_row_summary(r) for r in rows]


# ── count_packet_captures ──────────────────────────────────────────────


class CountPacketCapturesArgs(BaseModel):
    status: _PcapStatus | None = Field(default=None, description="Filter by run state.")
    vantage_kind: Literal["server", "appliance"] | None = Field(default=None)


@register_tool(
    name="count_packet_captures",
    permission=("read", "manage_packet_capture"),
    module=_MODULE,
    description="Count packet captures, optionally filtered by status and/or vantage.",
    args_model=CountPacketCapturesArgs,
    category="network",
)
async def count_packet_captures(
    db: AsyncSession, user: User, args: CountPacketCapturesArgs
) -> dict[str, Any]:
    stmt = select(func.count()).select_from(PacketCapture)
    if args.status:
        stmt = stmt.where(PacketCapture.status == args.status)
    if args.vantage_kind:
        stmt = stmt.where(PacketCapture.vantage_kind == args.vantage_kind)
    total = int((await db.execute(stmt)).scalar_one())
    return {"count": total}


# ── get_packet_capture ─────────────────────────────────────────────────


class GetPacketCaptureArgs(BaseModel):
    capture_id: str = Field(description="The capture UUID from find_packet_captures.")


@register_tool(
    name="get_packet_capture",
    permission=("read", "manage_packet_capture"),
    module=_MODULE,
    description=(
        "Return full metadata for one packet capture: vantage, "
        "interface, BPF filter, caps, live byte/packet progress, the "
        "stop-reason summary, and whether a downloadable .pcap exists. "
        "Never returns the captured bytes — direct the operator to the "
        "UI download for the actual .pcap."
    ),
    args_model=GetPacketCaptureArgs,
    category="network",
)
async def get_packet_capture(
    db: AsyncSession, user: User, args: GetPacketCaptureArgs
) -> dict[str, Any]:
    try:
        cap_uuid = uuid.UUID(args.capture_id)
    except ValueError:
        return {"error": f"capture_id must be a UUID, got {args.capture_id!r}."}
    row = await db.get(PacketCapture, cap_uuid)
    if row is None:
        return {"error": f"No packet capture with id {args.capture_id}."}
    out = _row_summary(row)
    out.update(
        {
            "snaplen": row.snaplen,
            "promiscuous": row.promiscuous,
            "max_packets": row.max_packets,
            "max_duration_s": row.max_duration_s,
            "max_bytes": row.max_bytes,
            "command_line": row.command_line,
            "pcap_sha256": row.pcap_sha256,
            "metadata": row.metadata_json,
        }
    )
    return out


__all__ = ["find_packet_captures", "count_packet_captures", "get_packet_capture"]
