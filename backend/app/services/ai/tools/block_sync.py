"""Operator Copilot tools for active block sync (#601).

All carry ``module="security.block_sync"`` so disabling the (default-off)
feature module strips them from the AI surface (NN #14).

Reads (default-enabled) — answer "what's blocked?" / "how many blocks are
pushed vs errored?":

* ``find_network_blocks`` — list SpatiumDDI-owned IP/MAC blocks + per-target
  push status.
* ``count_network_blocks`` — counts by kind + enabled state.

Propose write (default-DISABLED per NN #13 — broad blast radius + an
off-prem firewall/gateway write): the model surfaces a create as a
propose→Apply card; the tool itself only persists a proposal. The real
mutation lands only when a human clicks Apply, which routes through the
same ``create_network_block`` operation the REST endpoint uses (and its
two-person approval gate when armed).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.block_sync import NetworkBlock, NetworkBlockPush
from app.services.ai import operations
from app.services.ai.operations_risky import CreateNetworkBlockArgs
from app.services.ai.tools.base import register_tool

MODULE = "security.block_sync"


# ── find_network_blocks ──────────────────────────────────────────────


class FindNetworkBlocksArgs(BaseModel):
    kind: str | None = Field(
        default=None, description="Filter to one kind: 'ip' or 'mac'. Omit for both."
    )
    enabled_only: bool = Field(
        default=False, description="When true, only currently-enforced (enabled) blocks."
    )
    value_contains: str | None = Field(
        default=None, description="Substring match on the blocked IP/MAC value."
    )
    limit: int = Field(default=50, ge=1, le=200)


@register_tool(
    name="find_network_blocks",
    permission=("read", "manage_block_sync"),
    description=(
        "List SpatiumDDI-owned active network blocks (blocked IPs / MACs) "
        "and where each has been pushed — the enforcement half of the "
        "detect→block loop (#601). Each row carries kind, value, reason, "
        "source (manual / new_device / rogue_dhcp), enabled state, optional "
        "expiry, and the per-target push status (pushed / pending / error) "
        "on each armed OPNsense firewall / UniFi controller. Use for 'what's "
        "blocked upstream?' or 'did the block for aa:bb:… land?'. Read-only."
    ),
    args_model=FindNetworkBlocksArgs,
    category="read",
    default_enabled=True,
    module=MODULE,
)
async def find_network_blocks(
    db: AsyncSession, user: User, args: FindNetworkBlocksArgs
) -> dict[str, Any]:
    stmt = select(NetworkBlock)
    if args.kind is not None:
        stmt = stmt.where(NetworkBlock.kind == args.kind)
    if args.enabled_only:
        stmt = stmt.where(NetworkBlock.enabled.is_(True))
    if args.value_contains:
        stmt = stmt.where(NetworkBlock.value.ilike(f"%{args.value_contains}%"))
    stmt = stmt.order_by(NetworkBlock.created_at.desc()).limit(args.limit)
    blocks = list((await db.execute(stmt)).scalars().all())

    pushes: dict[Any, list[NetworkBlockPush]] = {}
    if blocks:
        rows = (
            (
                await db.execute(
                    select(NetworkBlockPush).where(
                        NetworkBlockPush.block_id.in_([b.id for b in blocks])
                    )
                )
            )
            .scalars()
            .all()
        )
        for p in rows:
            pushes.setdefault(p.block_id, []).append(p)

    return {
        "network_blocks": [
            {
                "id": str(b.id),
                "kind": b.kind,
                "value": b.value,
                "reason": b.reason,
                "description": b.description,
                "source": b.source,
                "enabled": b.enabled,
                "expires_at": b.expires_at.isoformat() if b.expires_at else None,
                "pushes": [
                    {
                        "target_kind": p.target_kind,
                        "target_id": str(p.target_id),
                        "push_status": p.push_status,
                        "last_error": p.last_error,
                    }
                    for p in pushes.get(b.id, [])
                ],
            }
            for b in blocks
        ],
        "count": len(blocks),
    }


# ── count_network_blocks ─────────────────────────────────────────────


class CountNetworkBlocksArgs(BaseModel):
    pass


@register_tool(
    name="count_network_blocks",
    permission=("read", "manage_block_sync"),
    description=(
        "Count active network blocks (#601) grouped by kind (ip / mac) and "
        "enabled state, plus push-status totals across all armed targets. "
        "Use to size the enforcement set. Read-only."
    ),
    args_model=CountNetworkBlocksArgs,
    category="read",
    default_enabled=True,
    module=MODULE,
)
async def count_network_blocks(
    db: AsyncSession, user: User, args: CountNetworkBlocksArgs
) -> dict[str, Any]:
    by_kind: dict[str, int] = {}
    for kind, n in (
        await db.execute(
            select(NetworkBlock.kind, func.count(NetworkBlock.id)).group_by(NetworkBlock.kind)
        )
    ).all():
        by_kind[kind] = int(n)
    enabled = (
        await db.execute(select(func.count(NetworkBlock.id)).where(NetworkBlock.enabled.is_(True)))
    ).scalar_one()
    by_push: dict[str, int] = {}
    for st, n in (
        await db.execute(
            select(NetworkBlockPush.push_status, func.count(NetworkBlockPush.id)).group_by(
                NetworkBlockPush.push_status
            )
        )
    ).all():
        by_push[st] = int(n)
    return {
        "total": sum(by_kind.values()),
        "enabled": int(enabled),
        "by_kind": by_kind,
        "by_push_status": by_push,
    }


# ── propose_create_network_block (default-DISABLED) ──────────────────


@register_tool(
    name="propose_create_network_block",
    permission=("admin", "manage_block_sync"),
    description=(
        "Prepare a proposal to create/arm an active network block (#601) — a "
        "blocked IP (pushed to armed OPNsense firewall aliases) or MAC "
        "(pushed as an L2 quarantine on armed UniFi controllers). Pass "
        "kind ('ip'|'mac'), value, and optional reason / description / "
        "source. The proposal must be applied by a human operator clicking "
        "Apply; the real write routes through the create_network_block "
        "operation (including its two-person approval gate when a policy "
        "matches). Default-disabled: enabling it lets the copilot stage "
        "firewall/gateway blocks (broad blast radius + off-prem write). "
        "Returns a kind='proposal' card."
    ),
    args_model=CreateNetworkBlockArgs,
    writes=False,  # The propose tool is read-only; Apply performs the write.
    category="ops",
    default_enabled=False,
    module=MODULE,
)
async def propose_create_network_block(
    db: AsyncSession, user: User, args: CreateNetworkBlockArgs
) -> dict[str, Any]:
    from app.services.ai.tools.proposals import (  # noqa: PLC0415
        _persist_proposal,
        _proposal_result,
    )

    op = operations.get_operation("create_network_block")
    if op is None:  # pragma: no cover — registered at import
        return {"error": "Operation 'create_network_block' is not registered"}
    preview = await op.preview(db, user, args)
    if not preview.ok:
        return {
            "kind": "proposal_rejected",
            "operation": "create_network_block",
            "detail": preview.detail,
        }
    proposal = await _persist_proposal(
        db,
        user=user,
        operation="create_network_block",
        args=args.model_dump(mode="json"),
        preview_text=preview.preview_text,
    )
    return _proposal_result(proposal, preview_text=preview.preview_text)


__all__ = [
    "count_network_blocks",
    "find_network_blocks",
    "propose_create_network_block",
]
