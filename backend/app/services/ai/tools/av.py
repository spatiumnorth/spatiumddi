"""Operator-Copilot tools for AV / Audio-Video-over-IP awareness (#540).

Read-only tools over the AV descriptors layered on the multicast
registry — Dante / AES67 / SMPTE 2110 / NDI flows and the reserved
ranges an operator has declared for each protocol. All gated on the
``network.av`` feature module so they leave the registry in lock-step
with the feature surface.

No ``propose_*`` write tools. Every write on this surface is plain CRUD
an operator performs in the UI, and shipping write proposals for a
brand-new table before anyone has used it would be speculative — the
proposal shells can be added once real usage shows which mutations an
operator actually wants to delegate.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.av import AV_PROTOCOLS, AVFlowProfile, AVReservedRange
from app.models.multicast import MulticastGroup
from app.services.ai.tools.base import register_tool

_MODULE = "network.av"


class FindAVFlowsArgs(BaseModel):
    av_protocol: str | None = Field(
        default=None,
        description=(
            "Filter to one AV protocol: dante / aes67 / smpte2110_video / "
            "smpte2110_audio / smpte2110_anc / ndi / ravenna / other."
        ),
    )
    ptp_domain: int | None = Field(
        default=None, ge=0, le=255, description="Filter to one PTP clock domain (0-255)."
    )
    space_id: UUID | None = Field(default=None, description="Restrict to one IPSpace.")
    q: str | None = Field(
        default=None,
        description="Case-insensitive substring match on the AV flow label or group name.",
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_av_flows",
    permission=("read", "av_flow"),
    description=(
        "List AV-over-IP flows (Dante / AES67 / SMPTE 2110 / NDI) with their "
        "multicast address, protocol, human flow label and PTP clock domain. "
        "Use this to answer 'what is on this multicast address', 'which flows "
        "are on PTP domain N', or to find a flow by its AV-side name."
    ),
    args_model=FindAVFlowsArgs,
    category="network",
    module=_MODULE,
    # Read-only inventory of operator-entered metadata; no secrets.
    default_enabled=True,
)
async def find_av_flows(
    db: AsyncSession, user: User, args: FindAVFlowsArgs
) -> list[dict[str, Any]]:
    _ = user
    if args.av_protocol is not None and args.av_protocol not in AV_PROTOCOLS:
        return [
            {
                "error": (
                    f"Unknown av_protocol {args.av_protocol!r}. "
                    f"Valid: {', '.join(sorted(AV_PROTOCOLS))}."
                )
            }
        ]

    stmt = select(AVFlowProfile, MulticastGroup).join(
        MulticastGroup, MulticastGroup.id == AVFlowProfile.group_id
    )
    if args.av_protocol is not None:
        stmt = stmt.where(AVFlowProfile.av_protocol == args.av_protocol)
    if args.ptp_domain is not None:
        stmt = stmt.where(AVFlowProfile.ptp_domain == args.ptp_domain)
    if args.space_id is not None:
        stmt = stmt.where(MulticastGroup.space_id == args.space_id)
    if args.q:
        needle = f"%{args.q}%"
        stmt = stmt.where(
            AVFlowProfile.av_flow_label.ilike(needle) | MulticastGroup.name.ilike(needle)
        )
    stmt = stmt.limit(args.limit)

    return [
        {
            "group_id": str(group.id),
            "address": str(group.address),
            "group_name": group.name,
            "av_protocol": profile.av_protocol,
            "av_flow_label": profile.av_flow_label,
            "ptp_domain": profile.ptp_domain,
            "seen_via": profile.seen_via,
            "space_id": str(group.space_id),
            "vlan_id": str(group.vlan_id) if group.vlan_id else None,
        }
        for profile, group in (await db.execute(stmt)).all()
    ]


class CountAVFlowsArgs(BaseModel):
    space_id: UUID | None = Field(default=None, description="Restrict to one IPSpace.")


@register_tool(
    name="count_av_flows",
    permission=("read", "av_flow"),
    description=(
        "Count AV-over-IP flows grouped by protocol, with how many are missing "
        "a PTP clock domain. Use for a quick 'how much AV do we have and is it "
        "documented' rollup."
    ),
    args_model=CountAVFlowsArgs,
    category="network",
    module=_MODULE,
    default_enabled=True,
)
async def count_av_flows(db: AsyncSession, user: User, args: CountAVFlowsArgs) -> dict[str, Any]:
    _ = user
    stmt = select(
        AVFlowProfile.av_protocol,
        func.count(AVFlowProfile.id),
        func.count(AVFlowProfile.id).filter(AVFlowProfile.ptp_domain.is_(None)),
    ).group_by(AVFlowProfile.av_protocol)
    if args.space_id is not None:
        stmt = stmt.join(MulticastGroup, MulticastGroup.id == AVFlowProfile.group_id).where(
            MulticastGroup.space_id == args.space_id
        )

    rows = (await db.execute(stmt)).all()
    by_protocol = {
        proto: {"total": int(total), "missing_ptp_domain": int(no_ptp)}
        for proto, total, no_ptp in rows
    }
    return {
        "total": sum(v["total"] for v in by_protocol.values()),
        "missing_ptp_domain": sum(v["missing_ptp_domain"] for v in by_protocol.values()),
        "by_protocol": by_protocol,
    }


class FindAVReservedRangesArgs(BaseModel):
    av_protocol: str | None = Field(default=None, description="Filter to one AV protocol.")
    space_id: UUID | None = Field(default=None, description="Restrict to one IPSpace.")
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_av_reserved_ranges",
    permission=("read", "av_flow"),
    description=(
        "List the multicast ranges an operator has declared for each AV "
        "protocol (e.g. the Dante 239.69.0.0/16 pool). These are what the "
        "av_flow_outside_reserved_range conformity check evaluates against."
    ),
    args_model=FindAVReservedRangesArgs,
    category="network",
    module=_MODULE,
    default_enabled=True,
)
async def find_av_reserved_ranges(
    db: AsyncSession, user: User, args: FindAVReservedRangesArgs
) -> list[dict[str, Any]]:
    _ = user
    if args.av_protocol is not None and args.av_protocol not in AV_PROTOCOLS:
        return [
            {
                "error": (
                    f"Unknown av_protocol {args.av_protocol!r}. "
                    f"Valid: {', '.join(sorted(AV_PROTOCOLS))}."
                )
            }
        ]
    stmt = select(AVReservedRange)
    if args.av_protocol is not None:
        stmt = stmt.where(AVReservedRange.av_protocol == args.av_protocol)
    if args.space_id is not None:
        stmt = stmt.where(AVReservedRange.space_id == args.space_id)
    stmt = stmt.limit(args.limit)

    return [
        {
            "id": str(r.id),
            "cidr": str(r.cidr),
            "av_protocol": r.av_protocol,
            "name": r.name,
            "description": r.description,
            "exclusive": r.exclusive,
            "space_id": str(r.space_id),
            "vlan_id": str(r.vlan_id) if r.vlan_id else None,
        }
        for r in (await db.execute(stmt)).scalars().all()
    ]
