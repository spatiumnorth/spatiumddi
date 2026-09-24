"""Risky-operation registry for the two-person approval workflow (#62).

Each delete handler covered by the approval gate has its mutation body
factored verbatim into an :class:`Operation` ``apply()`` here, with a
``preview()`` that re-runs the same 404 / 409 / synthesised-zone guards
the original handler did inline. The REST handler delegates to
``apply()`` on the inline (no-approval) path AND the approve endpoint
replays the same ``apply()`` under the approver's identity after a
fresh ``preview()`` stale-state check — one mutation path, two callers.

THE INLINE-FIDELITY CONTRACT — ``apply()`` must be byte-identical to the
pre-#62 handler when the module is off:

* The ``apply()`` body is the original handler body, unchanged. Every
  side effect (soft-delete batch + per-row audit, permanent cascade of
  DHCP scopes / DNS records / zones, agent bundle rebuilds, ``collect_wake``
  / ``publish_wake`` of the affected channel, ``_update_block_utilization``)
  is preserved in the same order.
* ``apply()`` / ``preview()`` raise the original handler's HTTP statuses —
  ``HTTPException(404)`` for not-found, ``HTTPException(409)`` for
  not-empty / conflict, ``HTTPException(403)`` for superadmin-required —
  CONSISTENTLY across all six ops. (A bare ``ValueError`` here would
  surface as a 500 to the inline caller — fixed.)
* ``apply()`` does NOT call ``enforce_operation_permission``: the inline
  handler is already authorized by the router's permission gate, and the
  two callers that bypass that gate — the approve endpoint + the AI
  propose→apply path — enforce the permission themselves *before*
  dispatching ``apply()``. Re-checking inside ``apply()`` would 403 a
  delegate whose scoped grant the router admitted (#103 address-set
  delegate) — fidelity break.
* Superadmin parity with the ORIGINAL ROUTE (so the approve path, which
  bypasses the delete route's dependencies, enforces identically):
  subnet / block / space require superadmin only on the ``permanent``
  branch; ``delete_zone`` / ``delete_scope`` / ``delete_group`` were
  fully ``SuperAdmin``-gated at the route, so their ``apply()`` requires
  superadmin ALWAYS. A failed check raises ``HTTPException(403)``.
* The ``permanent`` / ``force`` flags are frozen into the args model so
  the approved replay takes the *identical* branch the requester intended.
* Audit ``action`` strings stay exactly as today (``soft_delete`` on the
  default path, ``delete`` on the permanent path) — never collapsed.
* The not-found / not-empty validation is factored into one shared helper
  used by both ``preview()`` and ``apply()`` so the two never drift.

CLAUDE.md non-negotiables honoured: #2 (async throughout), #3 (server-side
permission enforcement — by the router gate inline, by the approve / AI
dispatch sites for the bypass callers), #4 (every mutation writes its audit
row before the commit inside ``apply()``).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any
from uuid import UUID

import structlog
from fastapi import HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.services.ai.operations import (
    Operation,
    PreviewResult,
    get_operation,
    register,
)

logger = structlog.get_logger(__name__)


# ── Blast-radius preview helper (#3a) ──────────────────────────────────────
#
# The approve path re-runs preview() and compares its preview_text against the
# frozen request-time preview_text; any drift refuses execution (#3b). For
# that drift check to actually catch a cascade that GREW between request and
# approval, every delete op's preview_text must embed the CURRENT blast radius
# (counts that move when the cascade changes), not just a static label.


async def _soft_delete_cascade_summary(db: AsyncSession, root: Any) -> str:
    """Render the soft-delete cascade blast radius for ``root`` as a stable,
    count-bearing string (#3a).

    Uses the SAME ``collect_soft_delete_batch`` walk ``apply()`` will use, so
    the preview reflects exactly what would be soft-deleted right now. Counts
    are grouped by resource type and rendered in a fixed order so the string is
    deterministic for a given set of rows (the approve-time drift compare is a
    plain string equality, so ordering must not jitter). The root row itself is
    excluded from the cascade counts (it's the target, not collateral)."""
    # Local import — keep the soft_delete dependency off module load.
    from app.services.soft_delete import (  # noqa: PLC0415
        _resource_type,
        collect_soft_delete_batch,
    )

    batch = await collect_soft_delete_batch(db, root)
    root_id = getattr(root, "id", None)
    root_rt = _resource_type(root)
    counts: dict[str, int] = {}
    for row in batch.rows:
        if getattr(row.obj, "id", None) == root_id and row.resource_type == root_rt:
            continue
        counts[row.resource_type] = counts.get(row.resource_type, 0) + 1
    labels = {
        "ip_block": "child block",
        "subnet": "subnet",
        "dhcp_scope": "DHCP scope",
        "dhcp_pool": "DHCP pool",
        "dhcp_static_assignment": "DHCP reservation",
        "dns_record": "DNS record",
    }
    order = [
        "ip_block",
        "subnet",
        "dhcp_scope",
        "dhcp_pool",
        "dhcp_static_assignment",
        "dns_record",
    ]
    parts = []
    for rt in order:
        n = counts.get(rt, 0)
        if n:
            noun = labels[rt]
            parts.append(f"{n} {noun}" + ("s" if n != 1 else ""))
    # Include the leftover types deterministically (sorted) in case the walk
    # grows to cover a type not in ``order`` — never silently drop a count.
    for rt in sorted(counts):
        if rt not in order and counts[rt]:
            parts.append(f"{counts[rt]} {rt}")
    if not parts:
        return "cascades nothing (empty)"
    return "cascades " + ", ".join(parts)


async def _push_agentless_scope_deletes(db: AsyncSession, batch: Any) -> set[UUID]:
    """Remove every DHCP scope in a soft-delete batch from its agentless members.

    Soft-delete means "stop serving", and that has to hold on every backend.
    Agent-based (Kea) members converge on their own — a stamped scope drops
    straight out of the rendered ConfigBundle — but agentless members (Windows
    DHCP today, and any future agentless driver) only converge on an explicit
    push (#616).

    EVERY delete whose cascade can reach a DHCPScope owes this call: scope,
    subnet, block, and space. Driving it off the batch rather than a hand-rolled
    per-handler query is deliberate — the batch is the one thing that already
    knows exactly which scopes are being trashed, so a new ancestor type added to
    ``_collect_descendants`` cannot silently skip the write-through.

    ORDER IS LOAD-BEARING: call this BEFORE ``apply_soft_delete``. The push
    resolves each scope's CIDR through ``db.get(Subnet, ...)``; once the subnet
    row is stamped, the global soft-delete filter hides it and the push would
    raise ``WindowsPushError("subnet is missing from IPAM")``.

    Returns the group ids whose agents should be woken after the commit.
    """
    from app.models.dhcp import DHCPScope  # noqa: PLC0415
    from app.services.dhcp.windows_writethrough import push_scope_delete  # noqa: PLC0415

    group_ids: set[UUID] = set()
    for row in batch.rows:
        if isinstance(row.obj, DHCPScope):
            await push_scope_delete(db, row.obj)
            group_ids.add(row.obj.group_id)
    return group_ids


async def _purge_leases_for_scope_batch(db: AsyncSession, batch: Any) -> None:
    """Tear down each batched scope's DHCP-derived rows before the soft-delete stamp.

    A scope owns two kinds of derived row that the soft-delete batch does NOT
    cover: dynamic ``DHCPLease`` rows (only a nullable ``ON DELETE SET NULL``
    backlink to the scope, so they'd survive) and their + the reservations'
    IPAM mirror ``ip_address`` rows (``status="dhcp"`` / ``static_dhcp``), which
    otherwise linger visibly in the subnet table and keep counting toward
    utilization after the scope is gone. Delete both here.

    MUST run BEFORE ``apply_soft_delete`` (same constraint as
    ``_push_agentless_scope_deletes``): once the scope/subnet is stamped the
    global filter hides it and the lease-subnet resolver / DDNS lookups see
    nothing. Drives off ``batch.rows`` so every ancestor whose cascade reaches a
    scope — scope, subnet, block, space — is covered from one place.
    """
    from app.models.dhcp import DHCPScope  # noqa: PLC0415
    from app.services.dhcp.lease_cleanup import delete_leases_for_scope  # noqa: PLC0415
    from app.services.dhcp.static_ipam import remove_ipam_for_scope_statics  # noqa: PLC0415

    for row in batch.rows:
        if isinstance(row.obj, DHCPScope):
            await delete_leases_for_scope(db, row.obj.id)
            await remove_ipam_for_scope_statics(db, row.obj.id)


# ── delete_subnet ──────────────────────────────────────────────────────────


class DeleteSubnetArgs(BaseModel):
    subnet_id: UUID
    force: bool = False
    permanent: bool = False


async def _subnet_not_empty_detail(db: AsyncSession, subnet_id: UUID) -> str | None:
    """Shared non-empty check for subnet permanent-delete (#17).

    Returns the 409 detail string when the subnet still holds user IPs or
    DHCP scopes, else ``None``. Both ``preview()`` and ``apply()`` call this
    so the two can never drift. Mirrors the inline handler's count query.
    """
    from app.models.dhcp import DHCPScope
    from app.models.ipam import IPAddress

    user_ip_count = (
        await db.execute(
            select(func.count(IPAddress.id)).where(
                IPAddress.subnet_id == subnet_id,
                IPAddress.status.notin_(["network", "broadcast", "orphan"]),
                IPAddress.auto_from_lease.is_(False),
            )
        )
    ).scalar_one()
    scope_count = (
        await db.execute(select(func.count(DHCPScope.id)).where(DHCPScope.subnet_id == subnet_id))
    ).scalar_one()
    if not (user_ip_count or scope_count):
        return None
    parts = []
    if user_ip_count:
        parts.append(f"{user_ip_count} allocated IP address" + ("es" if user_ip_count != 1 else ""))
    if scope_count:
        parts.append(f"{scope_count} DHCP scope" + ("s" if scope_count != 1 else ""))
    return (
        f"Subnet is not empty: {', '.join(parts)}. "
        "Delete the contents first, or retry with force=true to cascade."
    )


async def _preview_delete_subnet(
    db: AsyncSession, user: User, args: DeleteSubnetArgs
) -> PreviewResult:
    from app.api.v1.ipam.router import _enforce_subnet_token_scope
    from app.models.dhcp import DHCPScope
    from app.models.ipam import IPAddress, Subnet

    subnet = await db.get(Subnet, args.subnet_id)
    if subnet is None:
        return PreviewResult(ok=False, detail="Subnet not found")
    # Per-row API-token binding — mirrors the inline handler.
    _enforce_subnet_token_scope(user, args.subnet_id)

    if args.permanent and not args.force:
        # Re-run the non-empty 409 the inline permanent path raises.
        detail = await _subnet_not_empty_detail(db, args.subnet_id)
        if detail is not None:
            return PreviewResult(ok=False, detail=detail)

    mode = "Permanently delete" if args.permanent else "Soft-delete"
    parts = [f"{mode} subnet `{subnet.network}`" + (f" ({subnet.name})" if subnet.name else "")]
    if args.permanent:
        # #3a: counts move as the cascade grows → the approve-time drift check
        # catches a subnet that gained IPs/scopes since it was requested.
        scope_count = (
            await db.execute(
                select(func.count(DHCPScope.id)).where(DHCPScope.subnet_id == args.subnet_id)
            )
        ).scalar_one()
        ip_count = (
            await db.execute(
                select(func.count(IPAddress.id)).where(IPAddress.subnet_id == args.subnet_id)
            )
        ).scalar_one()
        parts.append(
            f"cascades {scope_count} DHCP scope(s) + {ip_count} IP row(s) + auto DNS cleanup"
        )
        if args.force:
            parts.append("force=true (skip non-empty check)")
    else:
        # #3a: the soft-delete cascade summary embeds the current blast radius
        # (DHCP scopes the subnet holds) so a grown cascade is detectable.
        parts.append(await _soft_delete_cascade_summary(db, subnet))
        parts.append("restorable from /admin/trash")
    return PreviewResult(ok=True, detail="ready", preview_text="; ".join(parts))


async def _apply_delete_subnet(
    db: AsyncSession, user: User, args: DeleteSubnetArgs
) -> dict[str, Any]:
    """Body factored verbatim from ipam/router.py:delete_subnet."""

    from app.api.deps import require_superadmin
    from app.api.v1.ipam.router import (
        _audit,
        _enforce_subnet_token_scope,
        _revoke_subnet_lease_mirrors,
        _update_block_utilization,
    )
    from app.drivers.dhcp import is_agentless
    from app.models.dhcp import DHCPConfigOp, DHCPScope, DHCPServer
    from app.models.ipam import Subnet
    from app.services.dhcp.config_bundle import build_config_bundle
    from app.services.dhcp.lease_cleanup import delete_leases_for_scope
    from app.services.dhcp.windows_writethrough import push_scope_delete
    from app.services.soft_delete import apply_soft_delete, collect_soft_delete_batch

    subnet = await db.get(Subnet, args.subnet_id)
    if subnet is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Subnet not found")
    _enforce_subnet_token_scope(user, args.subnet_id)

    if not args.permanent:
        await _revoke_subnet_lease_mirrors(db, subnet)

        # Wake DHCP agents for groups whose scopes are being trashed: soft-delete
        # stamps the scopes deleted, changing rendered Kea config, but without a
        # wake convergence waits for the 12s safety tick (#512). The push +
        # group-id capture both run BEFORE apply_soft_delete stamps the batch —
        # see _push_agentless_scope_deletes.
        from app.core.agent_wake import (  # noqa: PLC0415
            collect_wake,
            dhcp_group_channel,
            dns_group_channel,
        )
        from app.services.dns.reverse_zone import retire_auto_reverse_zones  # noqa: PLC0415

        batch = await collect_soft_delete_batch(db, subnet)
        # spatiumddi#1066 — the reverse zone this subnet auto-created rides
        # the same batch (restore brings both back) unless a sibling subnet
        # still lives in it, in which case it is re-linked and stays.
        _retired, _relinked, dns_wake_group_ids = await retire_auto_reverse_zones(
            db, subnet, batch=batch
        )
        wake_group_ids = await _push_agentless_scope_deletes(db, batch)
        await _purge_leases_for_scope_batch(db, batch)
        apply_soft_delete(batch, user.id)
        for row in batch.rows:
            db.add(
                _audit(
                    user,
                    "soft_delete",
                    row.resource_type,
                    str(row.obj.id),
                    row.display,
                    old_value={"deletion_batch_id": str(batch.batch_id)},
                )
            )
        await db.commit()
        for gid in wake_group_ids:
            collect_wake(dhcp_group_channel(gid))
        for gid in dns_wake_group_ids:
            collect_wake(dns_group_channel(gid))
        return {"subnet_id": str(args.subnet_id), "mode": "soft_delete"}

    require_superadmin(user)

    if not args.force:
        detail = await _subnet_not_empty_detail(db, args.subnet_id)
        if detail is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)

    block_id = subnet.block_id

    scope_rows = (
        (await db.execute(select(DHCPScope).where(DHCPScope.subnet_id == args.subnet_id)))
        .scalars()
        .all()
    )
    agent_servers_to_refresh: dict[uuid.UUID, DHCPServer] = {}
    for scope in scope_rows:
        await push_scope_delete(db, scope)
        # Leases have a nullable ON DELETE SET NULL backlink to the scope, so the
        # subnet cascade would leave them scopeless survivors — purge them (and
        # their mirrors + DDNS) here, before db.delete(subnet). Static mirrors go
        # with the subnet's ip_address cascade below.
        await delete_leases_for_scope(db, scope.id)
        group_servers = (
            (
                await db.execute(
                    select(DHCPServer).where(DHCPServer.server_group_id == scope.group_id)
                )
            )
            .scalars()
            .all()
        )
        for srv in group_servers:
            if not is_agentless(srv.driver):
                agent_servers_to_refresh[srv.id] = srv

    # Withdraw the DNS records IPAM published for the subnet's addresses BEFORE
    # the cascade drops the addresses — dns_record.ip_address_id is SET NULL, so
    # a record left to the database stays served, ownerless. Through the
    # record-ops chokepoint: an agentless (Windows DNS) primary is only
    # retracted by an explicit op (#512), and in a no-views group neither is an
    # agent. spatiumddi#1151: every auto-generated record of every address — this
    # used to take only the primary A ``ip.dns_record_id`` names, leaving PTRs
    # in a hand-made or shared reverse zone, extra-zone A / AAAA and aliases.
    from app.services.dns.record_ops import retract_address_records  # noqa: PLC0415

    _records_retracted, dns_wake_group_ids = await retract_address_records(db, [subnet.id])

    # spatiumddi#1066 — the subnet's auto-created reverse zone: re-linked to
    # a sibling that still lives in it, else deleted the way the zone-delete
    # operation does it (agentless servers told, queued ops swept, records
    # deleted set-based, the group woken) instead of a bare row DELETE.
    from app.core.agent_wake import collect_wake, dns_group_channel  # noqa: PLC0415
    from app.services.dns.reverse_zone import retire_auto_reverse_zones  # noqa: PLC0415

    _retired, _relinked, zone_wake_group_ids = await retire_auto_reverse_zones(db, subnet)
    dns_wake_group_ids |= zone_wake_group_ids

    db.add(
        _audit(
            user,
            "delete",
            "subnet",
            str(subnet.id),
            f"{subnet.network} ({subnet.name})",
            old_value={"network": str(subnet.network), "name": subnet.name},
        )
    )
    await db.delete(subnet)
    await db.flush()
    await _update_block_utilization(db, block_id)

    for server in agent_servers_to_refresh.values():
        bundle = await build_config_bundle(db, server)
        server.config_etag = bundle.etag
        existing = (
            await db.execute(
                select(DHCPConfigOp).where(
                    DHCPConfigOp.server_id == server.id,
                    DHCPConfigOp.op_type == "apply_config",
                    DHCPConfigOp.status == "pending",
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            db.add(
                DHCPConfigOp(
                    server_id=server.id,
                    op_type="apply_config",
                    payload={"etag": bundle.etag},
                    status="pending",
                )
            )

    await db.commit()
    for gid in dns_wake_group_ids:
        collect_wake(dns_group_channel(gid))
    return {"subnet_id": str(args.subnet_id), "mode": "delete"}


_OP_DELETE_SUBNET = Operation(
    name="delete_subnet",
    description="Delete a subnet (soft-delete batch, or permanent cascade of DHCP scopes + auto DNS).",
    args_model=DeleteSubnetArgs,
    preview=_preview_delete_subnet,
    apply=_apply_delete_subnet,
    category="ipam",
    required_permission=("delete", "subnet"),
)
register(_OP_DELETE_SUBNET)


# ── delete_block ───────────────────────────────────────────────────────────


class DeleteBlockArgs(BaseModel):
    block_id: UUID
    permanent: bool = False


async def _block_not_empty_detail(db: AsyncSession, block_id: UUID, network: Any) -> str | None:
    """Shared non-empty check for block permanent-delete (#17)."""
    from app.models.ipam import IPBlock, Subnet

    subnet_count = (
        await db.execute(
            select(func.count()).select_from(Subnet).where(Subnet.block_id == block_id)
        )
    ).scalar_one()
    child_block_count = (
        await db.execute(
            select(func.count()).select_from(IPBlock).where(IPBlock.parent_block_id == block_id)
        )
    ).scalar_one()
    if not (subnet_count or child_block_count):
        return None
    parts = []
    if child_block_count:
        parts.append(f"{child_block_count} child block(s)")
    if subnet_count:
        parts.append(f"{subnet_count} subnet(s)")
    return (
        f"Block {network} still contains {' and '.join(parts)}. "
        "Delete or move them before deleting the block."
    )


async def _preview_delete_block(
    db: AsyncSession, user: User, args: DeleteBlockArgs
) -> PreviewResult:
    from app.models.ipam import IPBlock

    block = await db.get(IPBlock, args.block_id)
    if block is None:
        return PreviewResult(ok=False, detail="IP block not found")

    if args.permanent:
        detail = await _block_not_empty_detail(db, args.block_id, block.network)
        if detail is not None:
            return PreviewResult(ok=False, detail=detail)
        return PreviewResult(
            ok=True,
            detail="ready",
            preview_text=f"Permanently delete empty block `{block.network}` ({block.name})",
        )

    # #3a: embed the current cascade counts so the approve-time drift check
    # catches new child blocks / subnets added since the request.
    return PreviewResult(
        ok=True,
        detail="ready",
        preview_text=(
            f"Soft-delete block `{block.network}` ({block.name}) — "
            f"{await _soft_delete_cascade_summary(db, block)}; "
            "restorable from /admin/trash"
        ),
    )


async def _apply_delete_block(
    db: AsyncSession, user: User, args: DeleteBlockArgs
) -> dict[str, Any]:
    """Body factored verbatim from ipam/router.py:delete_block."""
    from app.api.deps import require_superadmin
    from app.api.v1.ipam.router import _audit
    from app.models.ipam import IPBlock
    from app.services.soft_delete import apply_soft_delete, collect_soft_delete_batch

    block = await db.get(IPBlock, args.block_id)
    if block is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IP block not found")

    if args.permanent:
        require_superadmin(user)
        detail = await _block_not_empty_detail(db, args.block_id, block.network)
        if detail is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)

        db.add(
            _audit(
                user,
                "delete",
                "ip_block",
                str(block.id),
                f"{block.network} ({block.name})",
                old_value={"network": str(block.network)},
            )
        )
        await db.delete(block)
        await db.commit()
        return {"block_id": str(args.block_id), "mode": "delete"}

    from app.core.agent_wake import collect_wake, dhcp_group_channel  # noqa: PLC0415

    batch = await collect_soft_delete_batch(db, block)
    # A block cascade reaches DHCP scopes (via its subnets), so it owes the same
    # agentless write-through the scope + subnet paths do (#616). Before the stamp.
    wake_group_ids = await _push_agentless_scope_deletes(db, batch)
    await _purge_leases_for_scope_batch(db, batch)
    apply_soft_delete(batch, user.id)
    for row in batch.rows:
        db.add(
            _audit(
                user,
                "soft_delete",
                row.resource_type,
                str(row.obj.id),
                row.display,
                old_value={"deletion_batch_id": str(batch.batch_id)},
            )
        )
    await db.commit()
    for gid in wake_group_ids:
        collect_wake(dhcp_group_channel(gid))
    return {"block_id": str(args.block_id), "mode": "soft_delete"}


_OP_DELETE_BLOCK = Operation(
    name="delete_block",
    description="Delete an IP block (soft-delete cascade, or permanent if empty).",
    args_model=DeleteBlockArgs,
    preview=_preview_delete_block,
    apply=_apply_delete_block,
    category="ipam",
    required_permission=("delete", "ip_block"),
)
register(_OP_DELETE_BLOCK)


# ── delete_space ───────────────────────────────────────────────────────────


class DeleteSpaceArgs(BaseModel):
    space_id: UUID
    permanent: bool = False


async def _space_not_empty_detail(db: AsyncSession, space_id: UUID, name: str) -> str | None:
    """Shared non-empty check for space permanent-delete (#17)."""
    from app.models.ipam import IPBlock, Subnet

    subnet_count = (
        await db.execute(
            select(func.count()).select_from(Subnet).where(Subnet.space_id == space_id)
        )
    ).scalar_one()
    block_count = (
        await db.execute(
            select(func.count()).select_from(IPBlock).where(IPBlock.space_id == space_id)
        )
    ).scalar_one()
    if not (subnet_count or block_count):
        return None
    parts = []
    if block_count:
        parts.append(f"{block_count} block(s)")
    if subnet_count:
        parts.append(f"{subnet_count} subnet(s)")
    return (
        f"IP space {name!r} still contains {' and '.join(parts)}. "
        "Delete or move them before deleting the space."
    )


async def _preview_delete_space(
    db: AsyncSession, user: User, args: DeleteSpaceArgs
) -> PreviewResult:
    from app.models.ipam import IPSpace

    space = await db.get(IPSpace, args.space_id)
    if space is None:
        return PreviewResult(ok=False, detail="IP space not found")

    if args.permanent:
        detail = await _space_not_empty_detail(db, args.space_id, space.name)
        if detail is not None:
            return PreviewResult(ok=False, detail=detail)
        return PreviewResult(
            ok=True,
            detail="ready",
            preview_text=f"Permanently delete empty IP space `{space.name}`",
        )

    # #3a: embed the current cascade counts so the approve-time drift check
    # catches new blocks / subnets / scopes added since the request.
    return PreviewResult(
        ok=True,
        detail="ready",
        preview_text=(
            f"Soft-delete IP space `{space.name}` — "
            f"{await _soft_delete_cascade_summary(db, space)}; "
            "restorable from /admin/trash"
        ),
    )


async def _apply_delete_space(
    db: AsyncSession, user: User, args: DeleteSpaceArgs
) -> dict[str, Any]:
    """Body factored verbatim from ipam/router.py:delete_space."""
    from app.api.deps import require_superadmin
    from app.api.v1.ipam.router import _audit
    from app.models.ipam import IPSpace
    from app.services.soft_delete import apply_soft_delete, collect_soft_delete_batch

    space = await db.get(IPSpace, args.space_id)
    if space is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IP space not found")

    if args.permanent:
        require_superadmin(user)
        detail = await _space_not_empty_detail(db, args.space_id, space.name)
        if detail is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)

        db.add(
            _audit(
                user,
                "delete",
                "ip_space",
                str(space.id),
                space.name,
                old_value={"name": space.name},
            )
        )
        await db.delete(space)
        await db.commit()
        return {"space_id": str(args.space_id), "mode": "delete"}

    from app.core.agent_wake import collect_wake, dhcp_group_channel  # noqa: PLC0415

    batch = await collect_soft_delete_batch(db, space)
    # A space cascade reaches DHCP scopes (via its subnets), so it owes the same
    # agentless write-through the scope + subnet paths do (#616). Before the stamp.
    wake_group_ids = await _push_agentless_scope_deletes(db, batch)
    await _purge_leases_for_scope_batch(db, batch)
    apply_soft_delete(batch, user.id)
    for row in batch.rows:
        db.add(
            _audit(
                user,
                "soft_delete",
                row.resource_type,
                str(row.obj.id),
                row.display,
                old_value={"deletion_batch_id": str(batch.batch_id)},
            )
        )
    await db.commit()
    for gid in wake_group_ids:
        collect_wake(dhcp_group_channel(gid))
    return {"space_id": str(args.space_id), "mode": "soft_delete"}


_OP_DELETE_SPACE = Operation(
    name="delete_space",
    description="Delete an IP space (soft-delete subtree, or permanent if empty).",
    args_model=DeleteSpaceArgs,
    preview=_preview_delete_space,
    apply=_apply_delete_space,
    category="ipam",
    required_permission=("delete", "ip_space"),
)
register(_OP_DELETE_SPACE)


# ── delete_zone ────────────────────────────────────────────────────────────


class DeleteZoneArgs(BaseModel):
    group_id: UUID
    zone_id: UUID
    permanent: bool = False


async def _preview_delete_zone(db: AsyncSession, user: User, args: DeleteZoneArgs) -> PreviewResult:
    from app.api.v1.dns.router import _reject_if_synthesised_zone, _require_zone

    try:
        zone = await _require_zone(args.group_id, args.zone_id, db)
        _reject_if_synthesised_zone(zone, "delete")
    except HTTPException as exc:
        return PreviewResult(ok=False, detail=str(exc.detail))

    mode = "Permanently delete" if args.permanent else "Soft-delete"
    if args.permanent:
        # #3a: count the records this zone holds so a permanent delete of a
        # zone that grew records since request is caught by the drift check.
        from app.models.dns import DNSRecord  # noqa: PLC0415

        rec_count = (
            await db.execute(
                select(func.count(DNSRecord.id)).where(DNSRecord.zone_id == args.zone_id)
            )
        ).scalar_one()
        suffix = (
            f" — cascades {rec_count} DNS record(s)"
            " (pushes a remove-zone write-through to agentless servers first)"
        )
    else:
        # #3a: the soft-delete cascade summary embeds the current record count.
        suffix = (
            f" — {await _soft_delete_cascade_summary(db, zone)};"
            " the zone + its records are restorable from /admin/trash"
        )
    return PreviewResult(
        ok=True, detail="ready", preview_text=f"{mode} DNS zone `{zone.name}`{suffix}"
    )


async def _apply_delete_zone(db: AsyncSession, user: User, args: DeleteZoneArgs) -> dict[str, Any]:
    """Body factored verbatim from dns/router.py:delete_zone."""
    from app.api.deps import require_superadmin
    from app.api.v1.dns.router import (
        _push_zone_to_agentless_servers,
        _reject_if_synthesised_zone,
        _require_zone,
    )
    from app.core.agent_wake import collect_wake, dns_group_channel
    from app.models.audit import AuditLog
    from app.services.soft_delete import apply_soft_delete, collect_soft_delete_batch

    # The original DELETE route was fully SuperAdmin-gated — replicate here so
    # the approve path (which bypasses the route's SuperAdmin dependency)
    # enforces identically (#8). require_superadmin raises HTTPException(403).
    require_superadmin(user)

    zone = await _require_zone(args.group_id, args.zone_id, db)  # raises 404 if absent
    _reject_if_synthesised_zone(zone, "delete")

    if not args.permanent:
        # Soft-delete is the moment the zone leaves the bundle, so it is the
        # moment its queued ops become unapplyable: left behind, each one is
        # shipped up to five times against a zone the agent no longer serves,
        # then parks as ``failed`` forever (review of #964). Sweep here — the
        # trash purge and permanent-delete-from-trash only ever see rows that
        # came through this path.
        from app.services.dns.record_ops import sweep_zone_ops  # noqa: PLC0415

        await sweep_zone_ops(db, zone, zone.group_id)
        batch = await collect_soft_delete_batch(db, zone)
        apply_soft_delete(batch, user.id)
        for row in batch.rows:
            db.add(
                AuditLog(
                    user_id=user.id,
                    user_display_name=user.display_name,
                    auth_source=user.auth_source,
                    action="soft_delete",
                    resource_type=row.resource_type,
                    resource_id=str(row.obj.id),
                    resource_display=row.display,
                    old_value={"deletion_batch_id": str(batch.batch_id)},
                    result="success",
                )
            )
        collect_wake(dns_group_channel(args.group_id))
        await db.commit()
        return {"zone_id": str(args.zone_id), "mode": "soft_delete"}

    await _push_zone_to_agentless_servers(db, zone, "delete")
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="delete",
            resource_type="dns_zone",
            resource_id=str(zone.id),
            resource_display=zone.name,
            result="success",
        )
    )
    collect_wake(dns_group_channel(args.group_id))
    # Set-based first, ORM second. ``db.delete(zone)`` alone cascades through
    # the ORM: every record row is loaded, tracked and DELETEd one by one
    # inside the request. On a 250k-1M record zone that is minutes of a
    # single transaction on the request loop — the api's liveness probes
    # timed out and the pod was killed mid-delete (appliance sizing
    # campaign, 2026-09-02). ``dns_record.zone_id`` already cascades at the
    # FK, so delete the records in one statement and let the ORM cascade
    # find nothing left to load. The zone's queued record ops go with it
    # (``sweep_zone_ops``, shared with zone_move): a ``pending``/``in_flight``
    # op for a zone that no longer exists would only fail on the agent and
    # surface as a zombie on the next resync.
    from sqlalchemy import delete as sa_delete

    from app.models.dns import DNSRecord
    from app.services.dns.record_ops import sweep_zone_ops

    await sweep_zone_ops(db, zone, zone.group_id)
    await db.execute(sa_delete(DNSRecord).where(DNSRecord.zone_id == zone.id))
    await db.delete(zone)
    await db.commit()
    return {"zone_id": str(args.zone_id), "mode": "delete"}


_OP_DELETE_ZONE = Operation(
    name="delete_zone",
    description="Delete a DNS zone (soft-delete batch, or permanent with agentless write-through).",
    args_model=DeleteZoneArgs,
    preview=_preview_delete_zone,
    apply=_apply_delete_zone,
    category="dns",
    required_permission=("delete", "dns_zone"),
)
register(_OP_DELETE_ZONE)


# ── delete_scope ───────────────────────────────────────────────────────────


class DeleteScopeArgs(BaseModel):
    scope_id: UUID
    permanent: bool = False


async def _preview_delete_scope(
    db: AsyncSession, user: User, args: DeleteScopeArgs
) -> PreviewResult:
    from app.models.dhcp import DHCPLease, DHCPScope

    scope = await db.get(DHCPScope, args.scope_id)
    if scope is None:
        return PreviewResult(ok=False, detail="Scope not found")
    mode = "Permanently delete" if args.permanent else "Soft-delete"
    # A scope carries its pools + reservations into the batch (#617), so both
    # modes report a real blast radius. This used to claim a scope was a cascade
    # leaf, which made the approval preview read as "nothing else affected" for
    # a scope holding hundreds of reservations.
    cascade = await _soft_delete_cascade_summary(db, scope)
    # Dynamic leases aren't in the soft-delete batch (they're server-owned), but
    # scope deletion now clears them too (#623) — surface the count so the
    # preview / approval doesn't under-report the blast radius.
    lease_count = (
        await db.execute(
            select(func.count()).select_from(DHCPLease).where(DHCPLease.scope_id == scope.id)
        )
    ).scalar_one()
    if lease_count:
        cascade += f" + {lease_count} dynamic lease" + ("s" if lease_count != 1 else "")
    if args.permanent:
        suffix = (
            f" — {cascade} (unrecoverable; pushes a remove-scope write-through "
            "to Windows members first)"
        )
    else:
        suffix = f" — {cascade}; restorable from /admin/trash"
    return PreviewResult(
        ok=True, detail="ready", preview_text=f"{mode} DHCP scope `{scope.id}`{suffix}"
    )


async def _apply_delete_scope(
    db: AsyncSession, user: User, args: DeleteScopeArgs
) -> dict[str, Any]:
    """Body factored verbatim from dhcp/scopes.py:delete_scope."""
    from app.api.deps import require_superadmin
    from app.api.v1.dhcp._audit import write_audit
    from app.core.agent_wake import collect_wake, dhcp_group_channel
    from app.models.dhcp import DHCPScope
    from app.services.dhcp.lease_cleanup import delete_leases_for_scope
    from app.services.dhcp.static_ipam import remove_ipam_for_scope_statics
    from app.services.dhcp.windows_writethrough import push_scope_delete
    from app.services.soft_delete import apply_soft_delete, collect_soft_delete_batch

    # The original DELETE route was fully SuperAdmin-gated (#8).
    require_superadmin(user)

    scope = await db.get(DHCPScope, args.scope_id)
    if scope is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scope not found")
    collect_wake(dhcp_group_channel(scope.group_id))

    # Deleted means deleted on every backend (#616). Agent-based (Kea) members
    # converge by themselves — the soft-deleted scope drops straight out of the
    # rendered ConfigBundle — but agentless members (Windows DHCP today, and any
    # future agentless driver) only converge on an explicit push. This used to
    # fire on the permanent path only, and since the UI never sends
    # ``permanent=true``, a scope deleted from the UI stayed live on the Windows
    # box forever: not removed by the trash permanent-delete (which skips the
    # write-through hooks) nor by the purge sweep (a Core DELETE that runs no
    # Python). Fire it on both paths.
    await push_scope_delete(db, scope)

    # Tear down the scope's DHCP-derived rows that the soft-delete batch / FK
    # CASCADE do NOT cover: dynamic leases (only a nullable ON DELETE SET NULL
    # backlink, so they'd survive) + their and the reservations' IPAM mirror
    # rows (which otherwise linger visibly in the subnet table and keep counting
    # toward utilization). Delete both — leases are ephemeral polled state
    # (re-populated from the next poll on restore), and freeing the IPs to a
    # deleted row folds them back into free gaps. Runs on BOTH paths, before the
    # stamp / CASCADE so the scope + subnet are still resolvable.
    leases_removed, lease_mirrors = await delete_leases_for_scope(db, scope.id)
    statics_released = await remove_ipam_for_scope_statics(db, scope.id)
    cleanup_audit = {
        "leases_removed": leases_removed,
        "lease_mirrors_removed": lease_mirrors,
        "static_mirrors_removed": statics_released,
    }

    if not args.permanent:
        batch = await collect_soft_delete_batch(db, scope)
        apply_soft_delete(batch, user.id)
        for row in batch.rows:
            write_audit(
                db,
                user=user,
                action="soft_delete",
                resource_type=row.resource_type,
                resource_id=str(row.obj.id),
                resource_display=row.display,
                old_value={"deletion_batch_id": str(batch.batch_id), **cleanup_audit},
            )
        await db.commit()
        return {"scope_id": str(args.scope_id), "mode": "soft_delete"}

    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="dhcp_scope",
        resource_id=str(scope.id),
        resource_display=str(scope.id),
        old_value=cleanup_audit,
    )
    await db.delete(scope)
    await db.commit()
    return {"scope_id": str(args.scope_id), "mode": "delete"}


_OP_DELETE_SCOPE = Operation(
    name="delete_scope",
    description="Delete a DHCP scope (soft-delete, or permanent with Windows write-through).",
    args_model=DeleteScopeArgs,
    preview=_preview_delete_scope,
    apply=_apply_delete_scope,
    category="dhcp",
    required_permission=("delete", "dhcp_scope"),
)
register(_OP_DELETE_SCOPE)


# ── delete_group ───────────────────────────────────────────────────────────


class DeleteGroupArgs(BaseModel):
    group_id: UUID


async def _preview_delete_group(
    db: AsyncSession, user: User, args: DeleteGroupArgs
) -> PreviewResult:
    from app.models.dhcp import DHCPServer, DHCPServerGroup

    g = await db.get(DHCPServerGroup, args.group_id)
    if g is None:
        return PreviewResult(ok=False, detail="Server group not found")
    server_count = (
        await db.execute(
            select(func.count())
            .select_from(DHCPServer)
            .where(DHCPServer.server_group_id == args.group_id)
        )
    ).scalar_one()
    if server_count:
        return PreviewResult(
            ok=False,
            detail=(
                f"DHCP server group {g.name!r} still contains "
                f"{server_count} server(s). Move them to another group "
                "(or standalone) before deleting the group."
            ),
        )
    return PreviewResult(
        ok=True, detail="ready", preview_text=f"Delete empty DHCP server group `{g.name}`"
    )


async def _apply_delete_group(
    db: AsyncSession, user: User, args: DeleteGroupArgs
) -> dict[str, Any]:
    """Body factored verbatim from dhcp/server_groups.py:delete_group."""
    from app.api.deps import require_superadmin
    from app.api.v1.dhcp._audit import write_audit
    from app.models.dhcp import DHCPServer, DHCPServerGroup

    # The original DELETE route was fully SuperAdmin-gated (#8).
    require_superadmin(user)

    g = await db.get(DHCPServerGroup, args.group_id)
    if g is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Server group not found")

    server_count = (
        await db.execute(
            select(func.count())
            .select_from(DHCPServer)
            .where(DHCPServer.server_group_id == args.group_id)
        )
    ).scalar_one()
    if server_count:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"DHCP server group {g.name!r} still contains "
                f"{server_count} server(s). Move them to another group "
                "(or standalone) before deleting the group."
            ),
        )

    # Deleting the group hard-deletes its scopes, and the FK CASCADE takes their
    # reservations with them — no Python runs, so nothing would release the IPAM
    # mirrors and the addresses would be stranded at ``status="static_dhcp"``
    # pointing at rows Postgres has dropped (#618). Delete the mirror rows (not
    # just free them) so the IPs fold back into free gaps. The scopes' dynamic
    # leases (nullable ON DELETE SET NULL backlink) would otherwise survive the
    # group delete, so tear those + their mirrors down too.
    from app.models.dhcp import DHCPScope  # noqa: PLC0415
    from app.services.dhcp.lease_cleanup import delete_leases_for_scope  # noqa: PLC0415
    from app.services.dhcp.static_ipam import remove_ipam_for_scope_statics  # noqa: PLC0415

    group_scopes = (
        (
            await db.execute(
                select(DHCPScope)
                .where(DHCPScope.group_id == args.group_id)
                .execution_options(include_deleted=True)
            )
        )
        .scalars()
        .all()
    )
    released = 0
    for sc in group_scopes:
        released += await remove_ipam_for_scope_statics(db, sc.id)
        await delete_leases_for_scope(db, sc.id)

    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="dhcp_server_group",
        resource_id=str(g.id),
        resource_display=g.name,
        old_value={"ipam_mirrors_released": released},
    )
    await db.delete(g)
    await db.commit()
    return {"group_id": str(args.group_id), "mode": "delete"}


_OP_DELETE_GROUP = Operation(
    name="delete_group",
    description="Delete a DHCP server group (refused if it still holds servers).",
    args_model=DeleteGroupArgs,
    preview=_preview_delete_group,
    apply=_apply_delete_group,
    category="dhcp",
    # The REST route is SuperAdmin-only; this declares the granular backstop
    # the approver is checked against (a superadmin approver passes via {*,*}).
    required_permission=("delete", "dhcp_server_group"),
)
register(_OP_DELETE_GROUP)


# ── create_network_block (active block sync #601) ───────────────────────────
#
# Unlike the six deletes, this is a *create* — but it is a genuine risky op:
# a network block, once armed, pushes a real firewall/gateway block that can
# lock a device (or the operator) out of the network. Gating it through the
# same two-person workflow is the issue's explicit guardrail #6. The op body
# does the network_block upsert + audit + immediate reconcile-enqueue; the
# router delegates to it on the inline path and the approve endpoint replays
# it under the approver's identity.


class CreateNetworkBlockArgs(BaseModel):
    kind: str
    value: str
    reason: str = "quarantine"
    description: str = ""
    source: str = "manual"
    source_ref: str | None = None
    expires_at: datetime | None = None


async def _preview_create_network_block(
    db: AsyncSession, user: User, args: CreateNetworkBlockArgs
) -> PreviewResult:
    from app.models.block_sync import BLOCK_KINDS, BLOCK_SOURCES
    from app.services.block_sync.reconcile import (
        applicable_targets_for_kind,
        normalize_block_value,
    )

    if args.kind not in BLOCK_KINDS:
        return PreviewResult(ok=False, detail=f"kind must be one of {BLOCK_KINDS}")
    if args.source not in BLOCK_SOURCES:
        return PreviewResult(ok=False, detail=f"source must be one of {BLOCK_SOURCES}")
    try:
        value = normalize_block_value(args.kind, args.value)
    except ValueError as exc:
        return PreviewResult(ok=False, detail=str(exc))
    targets = await applicable_targets_for_kind(db, args.kind)
    names = ", ".join(f"{tk}:{tid}" for tk, tid in targets) or "no armed targets"
    return PreviewResult(
        ok=True,
        detail="ready",
        preview_text=(
            f"Block {args.kind} `{value}` and push to {len(targets)} armed " f"target(s) ({names})"
        ),
    )


async def _apply_create_network_block(
    db: AsyncSession, user: User, args: CreateNetworkBlockArgs
) -> dict[str, Any]:
    from app.models.audit import AuditLog
    from app.models.block_sync import NetworkBlock
    from app.services.block_sync.reconcile import (
        applicable_targets_for_kind,
        normalize_block_value,
    )

    value = normalize_block_value(args.kind, args.value)
    existing = (
        await db.execute(
            select(NetworkBlock).where(NetworkBlock.kind == args.kind, NetworkBlock.value == value)
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.enabled = True
        existing.reason = args.reason
        existing.description = args.description
        existing.source = args.source
        existing.source_ref = args.source_ref
        existing.expires_at = args.expires_at
        existing.updated_by_user_id = user.id
        block = existing
        action = "update"
    else:
        block = NetworkBlock(
            kind=args.kind,
            value=value,
            reason=args.reason,
            description=args.description,
            source=args.source,
            source_ref=args.source_ref,
            enabled=True,
            expires_at=args.expires_at,
            created_by_user_id=user.id,
            updated_by_user_id=user.id,
        )
        db.add(block)
        action = "create"
    await db.flush()

    targets = await applicable_targets_for_kind(db, args.kind)
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action=action,
            resource_type="network_block",
            resource_id=str(block.id),
            resource_display=f"{args.kind}:{value}",
            new_value={
                "kind": args.kind,
                "value": value,
                "reason": args.reason,
                "source": args.source,
                "targets": len(targets),
            },
        )
    )
    await db.commit()

    # Immediate converge on each armed target (broker-down → 60 s sweep).
    try:
        from app.tasks.block_sync import reconcile_target_now  # noqa: PLC0415

        for target_kind, target_id in targets:
            try:
                reconcile_target_now.delay(target_kind, str(target_id))
            except Exception:  # noqa: BLE001 — broker unavailable; the 60 s
                pass  # sweep converges this target, so a lost enqueue is safe
    except Exception:  # noqa: BLE001 — task import/broker issues never fail the write
        pass

    return {"block_id": str(block.id), "kind": args.kind, "value": value, "mode": action}


_OP_CREATE_NETWORK_BLOCK = Operation(
    name="create_network_block",
    description="Create/arm a network block (IP or MAC) and push it to armed OPNsense/UniFi targets.",
    args_model=CreateNetworkBlockArgs,
    preview=_preview_create_network_block,
    apply=_apply_create_network_block,
    category="security",
    required_permission=("admin", "manage_block_sync"),
)
register(_OP_CREATE_NETWORK_BLOCK)


# Registry-completeness anchor for the startup assertion (sibling slice):
# every operation name the seeded policies reference must exist here.
RISKY_OPERATION_NAMES: frozenset[str] = frozenset(
    {
        "delete_subnet",
        "delete_block",
        "delete_space",
        "delete_zone",
        "delete_scope",
        "delete_group",
        "create_network_block",
    }
)


def _assert_registered() -> None:
    """Defensive: prove all six names registered at import (catches a
    rename that desyncs the seeded policies from the registry)."""
    missing = [n for n in RISKY_OPERATION_NAMES if get_operation(n) is None]
    if missing:  # pragma: no cover — import-time invariant
        raise RuntimeError(f"risky operations not registered: {missing}")


_assert_registered()
