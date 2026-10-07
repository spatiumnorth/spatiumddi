"""Operator-Copilot tools for IPv6 Router Advertisements + rogue-RA (#524).

Read tools for RA-enabled scopes and observed/rogue RA routers, plus a
``propose_*`` write to add a router to a group's expected-RA allowlist. All are
gated on the ``ipv6.router_advertisements`` feature module so they vanish from
the registry in lock-step with the feature surface.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.dhcp import DHCPScope, RAObservedRouter
from app.models.ipam import Subnet
from app.services.ai import operations
from app.services.ai.operations import AllowlistRARouterArgs
from app.services.ai.tools.base import register_tool
from app.services.ai.tools.proposals import _persist_proposal, _proposal_result
from app.services.dhcp.radvd import build_ra_config

_MODULE = "ipv6.router_advertisements"


class FindRASubnetsArgs(BaseModel):
    group_id: UUID | None = Field(default=None, description="Restrict to one DHCP server group")
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_ra_subnets",
    permission=("read", "dhcp_server"),
    description=(
        "List IPv6 subnets/scopes with Router Advertisements enabled, showing the "
        "resolved M/O flags, prefix + router lifetimes, and RDNSS/DNSSL the DHCP "
        "agent's radvd will advertise."
    ),
    args_model=FindRASubnetsArgs,
    category="dhcp",
    module=_MODULE,
    default_enabled=True,
)
async def find_ra_subnets(
    db: AsyncSession, user: User, args: FindRASubnetsArgs
) -> list[dict[str, Any]]:
    stmt = select(DHCPScope).where(DHCPScope.ra_enabled.is_(True))
    if args.group_id is not None:
        stmt = stmt.where(DHCPScope.group_id == args.group_id)
    stmt = stmt.limit(args.limit)
    scopes = list((await db.execute(stmt)).scalars().all())
    subnet_ids = [s.subnet_id for s in scopes]
    subnet_map: dict[UUID, Subnet] = {}
    if subnet_ids:
        for s in (
            (await db.execute(select(Subnet).where(Subnet.id.in_(subnet_ids)))).scalars().all()
        ):
            subnet_map[s.id] = s
    out: list[dict[str, Any]] = []
    for sc in scopes:
        subnet = subnet_map.get(sc.subnet_id)
        if subnet is None:
            continue
        ra = build_ra_config(sc, subnet)
        if ra is None:
            continue
        out.append(
            {
                "scope_id": str(sc.id),
                "group_id": str(sc.group_id),
                "subnet_cidr": ra.subnet_cidr,
                "interface": ra.interface or "(agent default)",
                "managed_flag": ra.managed_flag,
                "other_flag": ra.other_flag,
                "router_lifetime": ra.router_lifetime,
                "prefix_valid_lifetime": ra.prefix_valid_lifetime,
                "prefix_preferred_lifetime": ra.prefix_preferred_lifetime,
                "rdnss": list(ra.rdnss),
                "dnssl": list(ra.dnssl),
            }
        )
    return out


class FindObservedRAArgs(BaseModel):
    group_id: UUID | None = Field(default=None, description="Restrict to one DHCP server group")
    classification: str | None = Field(
        default=None, description="Filter: expected | acknowledged | rogue"
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_observed_ra_routers",
    permission=("read", "dhcp_server"),
    description=(
        "List IPv6 routers the DHCP agent's passive RA sniffer has observed, with "
        "their advertised prefixes, M/O flags, and rogue/expected/acknowledged "
        "classification."
    ),
    args_model=FindObservedRAArgs,
    category="dhcp",
    module=_MODULE,
    default_enabled=True,
)
async def find_observed_ra_routers(
    db: AsyncSession, user: User, args: FindObservedRAArgs
) -> list[dict[str, Any]]:
    stmt = select(RAObservedRouter)
    if args.group_id is not None:
        stmt = stmt.where(RAObservedRouter.group_id == args.group_id)
    if args.classification:
        stmt = stmt.where(RAObservedRouter.classification == args.classification)
    stmt = stmt.order_by(RAObservedRouter.last_seen_at.desc()).limit(args.limit)
    rows = list((await db.execute(stmt)).scalars().all())
    return [
        {
            "id": str(r.id),
            "group_id": str(r.group_id),
            "source_ip": str(r.source_ip),
            "source_mac": str(r.source_mac) if r.source_mac else None,
            "prefixes": list(r.prefixes or []),
            "managed_flag": r.managed_flag,
            "other_flag": r.other_flag,
            "router_lifetime": r.router_lifetime,
            "classification": r.classification,
            "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
        }
        for r in rows
    ]


class CountRogueRAArgs(BaseModel):
    since_days: int = Field(default=1, ge=1, le=90)


@register_tool(
    name="count_rogue_ra_routers",
    permission=("read", "dhcp_server"),
    description="Count IPv6 routers currently classified as rogue RAs within the recency window.",
    args_model=CountRogueRAArgs,
    category="dhcp",
    module=_MODULE,
    default_enabled=True,
)
async def count_rogue_ra_routers(
    db: AsyncSession, user: User, args: CountRogueRAArgs
) -> dict[str, Any]:
    cutoff = datetime.now(UTC) - timedelta(days=args.since_days)
    total = (
        await db.execute(
            select(func.count())
            .select_from(RAObservedRouter)
            .where(
                RAObservedRouter.classification == "rogue",
                RAObservedRouter.last_seen_at >= cutoff,
            )
        )
    ).scalar_one()
    return {"rogue_ra_count": int(total), "since_days": args.since_days}


@register_tool(
    name="propose_allowlist_ra_router",
    permission=("write", "dhcp_server"),
    description=(
        "Prepare a proposal to add an IPv6 router (by source IP or MAC) to a DHCP "
        "group's expected-RA-router allowlist so it stops classifying as a rogue "
        "RA. The operator must click Apply to commit. Returns a kind='proposal' "
        "payload — surface the preview and wait for their decision."
    ),
    args_model=AllowlistRARouterArgs,
    writes=False,  # propose is read-only; the apply endpoint is the write.
    category="dhcp",
    module=_MODULE,
    default_enabled=True,
)
async def propose_allowlist_ra_router(
    db: AsyncSession, user: User, args: AllowlistRARouterArgs
) -> dict[str, Any]:
    op = operations.get_operation("allowlist_ra_router")
    if op is None:
        return {"error": "Operation 'allowlist_ra_router' is not registered"}
    preview = await op.preview(db, user, args)
    if not preview.ok:
        return {
            "kind": "proposal_rejected",
            "operation": "allowlist_ra_router",
            "detail": preview.detail,
        }
    proposal = await _persist_proposal(
        db,
        user=user,
        operation="allowlist_ra_router",
        args=args.model_dump(mode="json"),
        preview_text=preview.preview_text,
    )
    return _proposal_result(proposal, preview_text=preview.preview_text)
