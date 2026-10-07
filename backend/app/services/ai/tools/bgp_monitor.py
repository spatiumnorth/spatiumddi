"""Operator Copilot tools — BGP prefix-hijack monitoring (issue #527).

Read-only surface over the ``bgp_tracked_prefix`` + ``bgp_hijack_detection``
tables the periodic poll (``app.tasks.bgp_hijack_poll``) maintains, plus
one ``propose_*`` write to allowlist an expected additional origin. All
tagged ``module="network.asn"`` so they disappear when the ASN feature
module is off. Reads default-enabled (operators should be able to ask
"any hijacks right now?"); the write proposal defaults OFF like the
other ``propose_*`` tools.
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asn import ASN
from app.models.auth import User
from app.models.bgp_monitor import BGPHijackDetection, BGPTrackedPrefix
from app.services.ai.tools.base import register_tool


def _detection_dict(row: BGPHijackDetection) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "tracked_prefix": str(row.tracked_prefix),
        "observed_prefix": str(row.observed_prefix),
        "expected_origin_asn": int(row.expected_origin_asn),
        "observed_origin_asn": int(row.observed_origin_asn),
        "detection_kind": row.detection_kind,
        "rpki_status": row.rpki_status,
        "severity": row.severity,
        "source": row.source,
        "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
        "resolved_at": row.resolved_at.isoformat() if row.resolved_at else None,
        "acknowledged": row.acknowledged,
    }


# ── find_bgp_hijacks ──────────────────────────────────────────────────


class FindBgpHijacksArgs(BaseModel):
    asn: int | None = Field(default=None, description="Filter to this AS number.")
    detection_kind: str | None = Field(
        default=None,
        description="'prefix_hijack' (exact) or 'more_specific' (sub-prefix).",
    )
    active_only: bool = Field(default=True, description="Only unresolved detections (default).")
    limit: int = Field(default=50, ge=1, le=500)


@register_tool(
    name="find_bgp_hijacks",
    permission=("read", "manage_asns"),
    description=(
        "List observed BGP prefix-hijack detections — cases where an "
        "unexpected origin AS was seen announcing a tracked prefix (or a "
        "more-specific sub-prefix) on the public routing table. Each row "
        "carries the tracked prefix, the observed prefix + origin, the "
        "RPKI status (invalid = a ROA contradicts the announcement, "
        "unknown = no ROA coverage), severity, and first/last-seen "
        "timestamps. Use for 'is anyone hijacking our prefixes?' or "
        "'show active more-specific hijacks'."
    ),
    args_model=FindBgpHijacksArgs,
    category="network",
    module="network.asn",
    default_enabled=True,
)
async def find_bgp_hijacks(
    db: AsyncSession, user: User, args: FindBgpHijacksArgs
) -> dict[str, Any]:
    stmt = select(BGPHijackDetection)
    if args.asn is not None:
        asn_row = await db.scalar(select(ASN).where(ASN.number == args.asn))
        if asn_row is None:
            return {"detections": [], "note": f"no tracked ASN AS{args.asn}"}
        stmt = stmt.where(BGPHijackDetection.asn_id == asn_row.id)
    if args.detection_kind:
        stmt = stmt.where(BGPHijackDetection.detection_kind == args.detection_kind)
    if args.active_only:
        stmt = stmt.where(BGPHijackDetection.resolved_at.is_(None))
    stmt = stmt.order_by(BGPHijackDetection.last_seen_at.desc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return {"detections": [_detection_dict(r) for r in rows], "count": len(rows)}


# ── count_bgp_hijacks ─────────────────────────────────────────────────


class CountBgpHijacksArgs(BaseModel):
    active_only: bool = Field(default=True)


@register_tool(
    name="count_bgp_hijacks",
    permission=("read", "manage_asns"),
    description=(
        "Count BGP prefix-hijack detections, broken down by RPKI status "
        "(invalid / unknown) and detection kind. Use for 'how many "
        "hijacks are active?' as a quick health check."
    ),
    args_model=CountBgpHijacksArgs,
    category="network",
    module="network.asn",
    default_enabled=True,
)
async def count_bgp_hijacks(
    db: AsyncSession, user: User, args: CountBgpHijacksArgs
) -> dict[str, Any]:
    stmt = select(
        BGPHijackDetection.detection_kind,
        BGPHijackDetection.rpki_status,
        func.count(),
    ).group_by(BGPHijackDetection.detection_kind, BGPHijackDetection.rpki_status)
    if args.active_only:
        stmt = stmt.where(BGPHijackDetection.resolved_at.is_(None))
    rows = (await db.execute(stmt)).all()
    total = 0
    by_kind: dict[str, int] = {}
    by_rpki: dict[str, int] = {}
    for kind, rpki, count in rows:
        total += count
        by_kind[kind] = by_kind.get(kind, 0) + count
        by_rpki[rpki] = by_rpki.get(rpki, 0) + count
    return {"total": total, "by_kind": by_kind, "by_rpki_status": by_rpki}


# ── find_tracked_prefixes ─────────────────────────────────────────────


class FindTrackedPrefixesArgs(BaseModel):
    asn: int | None = Field(default=None, description="Filter to this AS number.")
    limit: int = Field(default=100, ge=1, le=1000)


@register_tool(
    name="find_tracked_prefixes",
    permission=("read", "manage_asns"),
    description=(
        "List the prefixes SpatiumDDI monitors for BGP hijacks, with the "
        "expected origin AS, the source (roa / announced / both / "
        "manual), and any operator-allowlisted additional origins. Use "
        "for 'which prefixes are we watching?' or to confirm a prefix is "
        "under monitoring."
    ),
    args_model=FindTrackedPrefixesArgs,
    category="network",
    module="network.asn",
    default_enabled=True,
)
async def find_tracked_prefixes(
    db: AsyncSession, user: User, args: FindTrackedPrefixesArgs
) -> dict[str, Any]:
    stmt = select(BGPTrackedPrefix)
    if args.asn is not None:
        asn_row = await db.scalar(select(ASN).where(ASN.number == args.asn))
        if asn_row is None:
            return {"prefixes": [], "note": f"no tracked ASN AS{args.asn}"}
        stmt = stmt.where(BGPTrackedPrefix.asn_id == asn_row.id)
    stmt = stmt.order_by(BGPTrackedPrefix.prefix).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return {
        "prefixes": [
            {
                "id": str(r.id),
                "prefix": str(r.prefix),
                "expected_origin_asn": int(r.expected_origin_asn),
                "source": r.source,
                "enabled": r.enabled,
                "allowed_origins": [int(o) for o in (r.allowed_origins or [])],
                "last_seen_origins": r.last_seen_origins,
            }
            for r in rows
        ],
        "count": len(rows),
    }


# ── propose_allowlist_bgp_origin ──────────────────────────────────────


class AllowlistBgpOriginArgs(BaseModel):
    detection_id: uuid.UUID = Field(
        ..., description="The bgp_hijack_detection id to allowlist + acknowledge."
    )


@register_tool(
    name="propose_allowlist_bgp_origin",
    permission=("write", "manage_asns"),
    description=(
        "Propose marking the observed origin AS of a BGP hijack "
        "detection as an EXPECTED additional origin for the tracked "
        "prefix (intentional multi-origin / anycast / DDoS-scrubbing). "
        "On apply, the origin is appended to the tracked prefix's "
        "allowlist (suppressing future detections from it) and this "
        "detection is acknowledged. Returns a preview the operator must "
        "explicitly apply."
    ),
    args_model=AllowlistBgpOriginArgs,
    writes=True,
    category="network",
    module="network.asn",
    default_enabled=False,
)
async def propose_allowlist_bgp_origin(
    db: AsyncSession, user: User, args: AllowlistBgpOriginArgs
) -> dict[str, Any]:
    from app.services.ai.tools.proposals import _propose_via  # noqa: PLC0415

    return await _propose_via(db=db, user=user, operation_name="allowlist_bgp_origin", args=args)
