"""Operator Copilot tools for DNSBL / RBL reputation monitoring (#528).

Read tools (all default-enabled, ``module="security.dnsbl"`` so disabling
the feature module strips them — NN #14):

* ``find_blocklisted_ips`` — public-facing IPs currently listed on ≥1
  enabled blocklist, with the lists + return codes + delist reason.
* ``count_blocklisted_ips`` — rollup of how many IPs are listed, by list
  and by candidate source.
* ``find_dnsbl_lists`` — the curated blocklist catalog + per-list enable
  + registration / QPS policy note.

Write tool (default-DISABLED — it mutates state):

* ``propose_pin_ip_for_dnsbl`` — proposal to pin an IP for monitoring.
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import String, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.dnsbl import DNSBLList, DNSBLListing
from app.services.ai import operations
from app.services.ai.tools.base import register_tool

_MODULE = "security.dnsbl"


# ── find_blocklisted_ips ───────────────────────────────────────────


class FindBlocklistedIPsArgs(BaseModel):
    ip: str | None = Field(default=None, description="Substring match on the IP.")
    list_id: str | None = Field(default=None, description="Filter to one blocklist (UUID).")
    source: str | None = Field(
        default=None,
        description="Candidate source: ipam / internet_facing / nat_egress / pinned.",
    )
    limit: int = Field(default=50, ge=1, le=200)


@register_tool(
    name="find_blocklisted_ips",
    permission=("read", "dnsbl"),
    description=(
        "List public-facing IPs currently on one or more enabled DNS "
        "blocklists (Spamhaus, Barracuda, SpamCop, SORBS, …). Each row "
        "carries the IP, the list name, return codes, the TXT delist "
        "reason, when it was first listed, and how the IP was surfaced "
        "(ipam / internet_facing / nat_egress / pinned). Use for 'is any "
        "of our mail IPs blacklisted?'. Read-only."
    ),
    args_model=FindBlocklistedIPsArgs,
    category="security",
    default_enabled=True,
    module=_MODULE,
)
async def find_blocklisted_ips(
    db: AsyncSession, user: User, args: FindBlocklistedIPsArgs
) -> dict[str, Any]:
    stmt = (
        select(DNSBLListing, DNSBLList.name)
        .join(DNSBLList, DNSBLList.id == DNSBLListing.list_id)
        .where(DNSBLListing.listed.is_(True))
    )
    if args.ip:
        stmt = stmt.where(cast(DNSBLListing.ip, String).ilike(f"%{args.ip.strip()}%"))
    if args.list_id:
        try:
            stmt = stmt.where(DNSBLListing.list_id == uuid.UUID(args.list_id))
        except ValueError:
            return {"error": f"invalid list_id {args.list_id!r}"}
    if args.source:
        stmt = stmt.where(DNSBLListing.source == args.source)
    stmt = stmt.order_by(DNSBLListing.first_listed_at.desc().nullslast()).limit(args.limit)
    rows = (await db.execute(stmt)).all()
    return {
        "listings": [
            {
                "ip": str(listing.ip),
                "list": list_name,
                "source": listing.source,
                "return_codes": list(listing.return_codes or []),
                "reason": listing.txt_reason,
                "first_listed_at": (
                    listing.first_listed_at.isoformat() if listing.first_listed_at else None
                ),
                "last_checked_at": (
                    listing.last_checked_at.isoformat() if listing.last_checked_at else None
                ),
            }
            for listing, list_name in rows
        ],
        "count": len(rows),
    }


# ── count_blocklisted_ips ──────────────────────────────────────────


class CountBlocklistedIPsArgs(BaseModel):
    pass


@register_tool(
    name="count_blocklisted_ips",
    permission=("read", "dnsbl"),
    description=(
        "Count how many public-facing IPs are currently blocklisted, "
        "broken down by list and by candidate source. Use for 'how bad is "
        "our reputation exposure right now?'. Read-only."
    ),
    args_model=CountBlocklistedIPsArgs,
    category="security",
    default_enabled=True,
    module=_MODULE,
)
async def count_blocklisted_ips(
    db: AsyncSession, user: User, args: CountBlocklistedIPsArgs
) -> dict[str, Any]:
    distinct_ips = await db.scalar(
        select(func.count(func.distinct(DNSBLListing.ip))).where(DNSBLListing.listed.is_(True))
    )
    by_list_rows = (
        await db.execute(
            select(DNSBLList.name, func.count())
            .join(DNSBLListing, DNSBLListing.list_id == DNSBLList.id)
            .where(DNSBLListing.listed.is_(True))
            .group_by(DNSBLList.name)
        )
    ).all()
    by_source_rows = (
        await db.execute(
            select(DNSBLListing.source, func.count())
            .where(DNSBLListing.listed.is_(True))
            .group_by(DNSBLListing.source)
        )
    ).all()
    return {
        "distinct_listed_ips": distinct_ips or 0,
        "by_list": {name: count for name, count in by_list_rows},
        "by_source": {source: count for source, count in by_source_rows},
    }


# ── find_dnsbl_lists ───────────────────────────────────────────────


class FindDNSBLListsArgs(BaseModel):
    enabled_only: bool = Field(default=False)


@register_tool(
    name="find_dnsbl_lists",
    permission=("read", "dnsbl"),
    description=(
        "List the curated DNS blocklist catalog: name, DNS zone suffix, "
        "category, whether it's enabled, whether it requires registration, "
        "and its query-rate policy note. Use to answer 'which blocklists "
        "are we checking against?' or 'why is Spamhaus returning query "
        "blocked?'. Read-only."
    ),
    args_model=FindDNSBLListsArgs,
    category="security",
    default_enabled=True,
    module=_MODULE,
)
async def find_dnsbl_lists(
    db: AsyncSession, user: User, args: FindDNSBLListsArgs
) -> dict[str, Any]:
    stmt = select(DNSBLList)
    if args.enabled_only:
        stmt = stmt.where(DNSBLList.enabled.is_(True))
    stmt = stmt.order_by(DNSBLList.name.asc())
    rows = list((await db.execute(stmt)).scalars().all())
    return {
        "lists": [
            {
                "id": str(r.id),
                "name": r.name,
                "zone_suffix": r.zone_suffix,
                "category": r.category,
                "enabled": r.enabled,
                "requires_registration": r.requires_registration,
                "qps_note": r.qps_note,
                "is_builtin": r.is_builtin,
            }
            for r in rows
        ],
        "count": len(rows),
    }


# ── propose_pin_ip_for_dnsbl (gated write, default-disabled) ────────


@register_tool(
    name="propose_pin_ip_for_dnsbl",
    permission=("write", "dnsbl"),
    description=(
        "Prepare a proposal to pin an IP for DNSBL / RBL reputation "
        "monitoring. The operator must click Apply for the pin to be "
        "created. Returns kind='proposal'; surface the preview and wait "
        "for the operator's decision."
    ),
    args_model=operations.PinIPForDNSBLArgs,
    writes=False,  # the propose tool is read-only; apply is the write
    category="security",
    default_enabled=False,
    module=_MODULE,
)
async def propose_pin_ip_for_dnsbl(
    db: AsyncSession, user: User, args: operations.PinIPForDNSBLArgs
) -> dict[str, Any]:
    from app.services.ai.tools.proposals import _persist_proposal, _proposal_result  # noqa: PLC0415

    op = operations.get_operation("pin_ip_for_dnsbl")
    if op is None:
        return {"error": "Operation 'pin_ip_for_dnsbl' is not registered"}
    preview = await op.preview(db, user, args)
    if not preview.ok:
        return {
            "kind": "proposal_rejected",
            "operation": "pin_ip_for_dnsbl",
            "detail": preview.detail,
        }
    proposal = await _persist_proposal(
        db,
        user=user,
        operation="pin_ip_for_dnsbl",
        args=args.model_dump(),
        preview_text=preview.preview_text,
    )
    return _proposal_result(proposal, preview_text=preview.preview_text)
