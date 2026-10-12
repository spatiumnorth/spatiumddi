"""Read-only multicast tools for the Operator Copilot — issue #126 Phase 4.

Surfaces the multicast registry to the chat surface so an operator
can ask "which groups does 10.0.0.99 consume?" or "how many groups
run in the studio-A VRF?" without leaving the drawer.

Five tools:

* ``find_multicast_group`` — search by name / address / space
* ``find_multicast_membership`` — search by ip_address_id /
  group_id / role / seen_via
* ``find_multicast_domain`` — search by name / pim_mode
* ``count_multicast_groups_by_vrf`` — fan-out summary keyed on the
  PIM domain's VRF binding
* (the ``propose_create_multicast_group`` write proposal lives in
  ``tools/proposals.py`` next to the other ``propose_*`` shells)

All gated on ``module="network.multicast"`` — the tool registry
filters them out when the operator turns the multicast feature
module off.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.multicast import (
    MEMBERSHIP_ROLES,
    MEMBERSHIP_SOURCES,
    MulticastDomain,
    MulticastGroup,
    MulticastMembership,
)
from app.models.vrf import VRF
from app.services.ai.tools.base import register_tool

# ── find_multicast_group ────────────────────────────────────────────


class FindMulticastGroupArgs(BaseModel):
    space_id: str | None = Field(default=None, description="Filter by parent IPSpace UUID.")
    domain_id: str | None = Field(default=None, description="Filter by PIM domain UUID.")
    address: str | None = Field(
        default=None,
        description=(
            "Exact-match filter on the multicast address (e.g. "
            "``239.5.7.42``). Use ``search`` for substrings."
        ),
    )
    search: str | None = Field(
        default=None,
        description=(
            "Substring match on group name / application / address " "host-form (case-insensitive)."
        ),
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_multicast_group",
    permission=("read", "multicast"),
    description=(
        "Search the multicast group registry. Each result includes "
        "address, name, application, parent IPSpace, optional VLAN / "
        "customer / domain bindings, and the bandwidth estimate. Use "
        "for 'list groups in studio space' or 'find the SMPTE 2110 "
        "stream' style asks. Read-only."
    ),
    args_model=FindMulticastGroupArgs,
    category="multicast",
    module="network.multicast",
)
async def find_multicast_group(
    db: AsyncSession, user: User, args: FindMulticastGroupArgs
) -> list[dict[str, Any]]:
    stmt = select(MulticastGroup)
    if args.space_id:
        stmt = stmt.where(MulticastGroup.space_id == args.space_id)
    if args.domain_id:
        stmt = stmt.where(MulticastGroup.domain_id == args.domain_id)
    if args.address:
        stmt = stmt.where(MulticastGroup.address == args.address)
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            (func.lower(MulticastGroup.name).like(like))
            | (func.lower(MulticastGroup.application).like(like))
            | (func.host(MulticastGroup.address).like(like))
        )
    stmt = stmt.order_by(MulticastGroup.address.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(g.id),
            "address": str(g.address),
            "name": g.name,
            "application": g.application,
            "rtp_payload_type": g.rtp_payload_type,
            "bandwidth_mbps_estimate": (
                str(g.bandwidth_mbps_estimate) if g.bandwidth_mbps_estimate is not None else None
            ),
            "space_id": str(g.space_id),
            "vlan_id": str(g.vlan_id) if g.vlan_id else None,
            "customer_id": str(g.customer_id) if g.customer_id else None,
            "service_id": str(g.service_id) if g.service_id else None,
            "domain_id": str(g.domain_id) if g.domain_id else None,
        }
        for g in rows
    ]


# ── find_multicast_membership ──────────────────────────────────────


class FindMulticastMembershipArgs(BaseModel):
    group_id: str | None = Field(
        default=None,
        description=(
            "Filter to memberships of one group (UUID). Common ask: "
            "'who consumes 239.5.7.42' — caller resolves the address "
            "to a group_id via find_multicast_group first."
        ),
    )
    ip_address_id: str | None = Field(
        default=None,
        description=(
            "Filter to memberships involving this IPAM IP. Common ask: "
            "'what streams does 10.0.0.99 listen to'."
        ),
    )
    role: str | None = Field(
        default=None,
        description=(
            "Filter by role — ``producer``, ``consumer``, or "
            "``rendezvous_point``. RP is for PIM ASM groups."
        ),
    )
    seen_via: str | None = Field(
        default=None,
        description=(
            "Filter by source — ``manual`` (operator-typed), "
            "``igmp_snooping`` (SNMP populator), or ``sap_announce``. "
            "Discovered rows tagged anything other than ``manual`` "
            "indicate live observation."
        ),
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_multicast_membership",
    permission=("read", "multicast"),
    description=(
        "Search multicast group memberships — the producer / consumer "
        "/ RP rows that bind an IP to a group. Includes seen_via "
        "(manual / igmp_snooping / sap_announce) so the LLM can tell "
        "discovered rows apart from operator-curated ones, plus "
        "last_seen_at for staleness detection. Read-only."
    ),
    args_model=FindMulticastMembershipArgs,
    category="multicast",
    module="network.multicast",
)
async def find_multicast_membership(
    db: AsyncSession, user: User, args: FindMulticastMembershipArgs
) -> list[dict[str, Any]]:
    if args.role and args.role not in MEMBERSHIP_ROLES:
        return [
            {
                "error": (
                    f"Invalid role {args.role!r} — must be one of " f"{sorted(MEMBERSHIP_ROLES)}"
                )
            }
        ]
    if args.seen_via and args.seen_via not in MEMBERSHIP_SOURCES:
        return [
            {
                "error": (
                    f"Invalid seen_via {args.seen_via!r} — must be one of "
                    f"{sorted(MEMBERSHIP_SOURCES)}"
                )
            }
        ]

    stmt = select(MulticastMembership)
    if args.group_id:
        stmt = stmt.where(MulticastMembership.group_id == args.group_id)
    if args.ip_address_id:
        stmt = stmt.where(MulticastMembership.ip_address_id == args.ip_address_id)
    if args.role:
        stmt = stmt.where(MulticastMembership.role == args.role)
    if args.seen_via:
        stmt = stmt.where(MulticastMembership.seen_via == args.seen_via)
    stmt = stmt.order_by(MulticastMembership.id.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(m.id),
            "group_id": str(m.group_id),
            "ip_address_id": str(m.ip_address_id),
            "role": m.role,
            "seen_via": m.seen_via,
            "last_seen_at": (m.last_seen_at.isoformat() if m.last_seen_at else None),
            "notes": m.notes,
        }
        for m in rows
    ]


# ── find_multicast_domain ──────────────────────────────────────────


class FindMulticastDomainArgs(BaseModel):
    pim_mode: str | None = Field(
        default=None,
        description=(
            "Filter by PIM mode — ``sparse``, ``dense``, ``ssm``, "
            "``bidir``, or ``none``. Sparse + bidir are the RP-driven "
            "shapes; SSM is source-specific (no RP)."
        ),
    )
    vrf_id: str | None = Field(default=None, description="Filter by bound VRF UUID.")
    search: str | None = Field(
        default=None,
        description="Substring match on domain name (case-insensitive).",
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_multicast_domain",
    permission=("read", "multicast"),
    description=(
        "Search PIM (multicast routing) domains. Each result includes "
        "name, pim_mode, optional VRF binding, rendezvous-point "
        "address (sparse / bidir), and SSM range (ssm). Use for 'what "
        "PIM domains do we have' or 'show me the studio-A RP'."
    ),
    args_model=FindMulticastDomainArgs,
    category="multicast",
    module="network.multicast",
)
async def find_multicast_domain(
    db: AsyncSession, user: User, args: FindMulticastDomainArgs
) -> list[dict[str, Any]]:
    stmt = select(MulticastDomain)
    if args.pim_mode:
        stmt = stmt.where(MulticastDomain.pim_mode == args.pim_mode)
    if args.vrf_id:
        stmt = stmt.where(MulticastDomain.vrf_id == args.vrf_id)
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(func.lower(MulticastDomain.name).like(like))
    stmt = stmt.order_by(MulticastDomain.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(d.id),
            "name": d.name,
            "pim_mode": d.pim_mode,
            "vrf_id": str(d.vrf_id) if d.vrf_id else None,
            "rendezvous_point_device_id": (
                str(d.rendezvous_point_device_id) if d.rendezvous_point_device_id else None
            ),
            "rendezvous_point_address": d.rendezvous_point_address,
            "ssm_range": d.ssm_range,
        }
        for d in rows
    ]


# ── count_multicast_groups_by_vrf ──────────────────────────────────


class CountGroupsByVRFArgs(BaseModel):
    """No filters — operators looking at this aggregate want every
    VRF + a catch-all bucket for un-domained groups."""

    pass


@register_tool(
    name="count_multicast_groups_by_vrf",
    permission=("read", "multicast"),
    description=(
        "Count multicast groups bucketed by their PIM domain's VRF "
        "binding. Returns one row per VRF (with name + ID) plus a "
        "``no_domain`` bucket for groups that don't yet sit inside a "
        "PIM domain. Use for capacity-planning asks like 'how many "
        "streams run in the studio VRF'."
    ),
    args_model=CountGroupsByVRFArgs,
    category="multicast",
    module="network.multicast",
)
async def count_multicast_groups_by_vrf(
    db: AsyncSession, user: User, args: CountGroupsByVRFArgs
) -> list[dict[str, Any]]:
    # Left join groups → domain → vrf so groups without a domain (or
    # a domain without a VRF) bucket under ``no_domain`` rather than
    # vanishing from the count.
    stmt = (
        select(
            MulticastDomain.vrf_id.label("vrf_id"),
            VRF.name.label("vrf_name"),
            func.count(MulticastGroup.id).label("group_count"),
        )
        .select_from(MulticastGroup)
        .outerjoin(MulticastDomain, MulticastDomain.id == MulticastGroup.domain_id)
        .outerjoin(VRF, VRF.id == MulticastDomain.vrf_id)
        .group_by(MulticastDomain.vrf_id, VRF.name)
        .order_by(func.count(MulticastGroup.id).desc())
    )
    rows = (await db.execute(stmt)).all()
    out: list[dict[str, Any]] = []
    for vrf_id, vrf_name, count in rows:
        if vrf_id is None:
            out.append({"vrf_id": None, "vrf_name": "no_domain", "group_count": int(count)})
        else:
            out.append(
                {
                    "vrf_id": str(vrf_id),
                    "vrf_name": vrf_name or "(unnamed VRF)",
                    "group_count": int(count),
                }
            )
    return out
