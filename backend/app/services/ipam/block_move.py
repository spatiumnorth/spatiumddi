"""Block-move — relocate an ``IPBlock`` and everything under it into a
different ``IPSpace`` (issue #27).

Mirrors the resize service's preview / commit shape:

* ``preview_move`` — pure read; assembles a ``MovePlan`` describing
  every row that will move + every integration-blocker that would
  refuse the commit. UI renders this for typed-CIDR confirmation.
* ``commit_move`` — single-transaction rewrite. Takes a per-block
  advisory xact-lock to serialise concurrent move attempts on the
  same block, re-runs the plan-assembly to catch races (overlap
  appeared, integration row appeared between preview and commit),
  then rewrites ``space_id`` on the moved block + all descendant
  blocks + all descendant subnets in one go.

Why a separate service module instead of folding into
``services.ipam.resize``? Resize and move share infra (advisory
lock + descendant walk) but the operator-facing semantics are
different. Keeping them separate keeps each module's contract
narrow and lets the audit-log surface a clean ``block.moved``
action distinct from ``block.resized``.
"""

from __future__ import annotations

import ipaddress
import uuid
import zlib
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPBlock, IPSpace, Subnet

# Advisory-lock namespace for block-move. Distinct from the resize
# namespaces so a move and a resize on the *same* block don't
# accidentally serialise against each other (they target different
# columns; either should serialise against itself but they're
# disjoint).
_LOCK_NS_BLOCK_MOVE = 0x49504D33  # "IPM3"


class BlockMoveError(Exception):
    """Service-layer exception with an HTTP status code attached."""

    def __init__(self, message: str, *, status_code: int = 422) -> None:
        super().__init__(message)
        self.status_code = status_code


# ── Plan dataclasses ────────────────────────────────────────────────────────


@dataclass
class IntegrationBlocker:
    """A descendant row that the reconciler would re-create after a move,
    so the move would be a silent no-op or a desync. Surface in preview;
    refuse on commit."""

    kind: str  # "block" | "subnet" | "ip_address"
    resource_id: str  # uuid as str
    network: str  # CIDR or IP for human display
    integration: str  # "kubernetes" | "docker" | "proxmox" | "tailscale"


@dataclass
class MovePlan:
    block_id: str
    block_network: str
    source_space_id: str
    target_space_id: str
    target_parent_id: str | None
    descendant_block_ids: list[str]
    descendant_subnet_ids: list[str]
    descendant_ip_count: int
    reparent_chain_block_ids: list[str] = field(default_factory=list)
    integration_blockers: list[IntegrationBlocker] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class MoveResult:
    block_id: str
    source_space_id: str
    target_space_id: str
    target_parent_id: str | None
    blocks_moved: int  # incl. the moved block itself
    subnets_moved: int
    addresses_in_moved_subtree: int
    reparented_block_ids: list[str]


# ── Helpers ─────────────────────────────────────────────────────────────────


def _advisory_lock_key(resource_id: uuid.UUID) -> tuple[int, int]:
    key = zlib.crc32(str(resource_id).encode("utf-8"))
    if key >= 2**31:
        key -= 2**32
    return (_LOCK_NS_BLOCK_MOVE, key)


async def _try_advisory_lock(db: AsyncSession, resource_id: uuid.UUID) -> bool:
    ns, key = _advisory_lock_key(resource_id)
    row: bool = (
        await db.execute(
            text("SELECT pg_try_advisory_xact_lock(:ns, :key)"),
            {"ns": ns, "key": key},
        )
    ).scalar_one()
    return bool(row)


async def _collect_descendants(
    db: AsyncSession, root_block_id: uuid.UUID
) -> tuple[list[str], list[str], int]:
    """Return ``(descendant_block_ids, descendant_subnet_ids,
    address_count)`` rooted at ``root_block_id`` (exclusive of the
    root). Descendant subnet IDs cover every subnet under any
    descendant block; address count is a SUM across those subnets.
    """
    blocks = (
        await db.execute(
            text("""
                WITH RECURSIVE descendants AS (
                    SELECT id FROM ip_block WHERE parent_block_id = CAST(:root AS uuid)
                    UNION ALL
                    SELECT b.id FROM ip_block b
                    INNER JOIN descendants d ON b.parent_block_id = d.id
                )
                SELECT id FROM descendants
                """),
            {"root": str(root_block_id)},
        )
    ).fetchall()
    descendant_block_ids = [str(r[0]) for r in blocks]
    # Subnets are direct children of blocks (block_id FK); collect
    # under the moved block AND every descendant block.
    block_filter = [str(root_block_id), *descendant_block_ids]
    subnets = (
        await db.execute(
            text(
                "SELECT id FROM subnet "
                "WHERE block_id = ANY(CAST(:ids AS uuid[])) "
                "AND deleted_at IS NULL"
            ),
            {"ids": block_filter},
        )
    ).fetchall()
    descendant_subnet_ids = [str(r[0]) for r in subnets]
    address_count = 0
    if descendant_subnet_ids:
        address_count = int(
            (
                await db.execute(
                    text(
                        "SELECT COUNT(*) FROM ip_address "
                        "WHERE subnet_id = ANY(CAST(:ids AS uuid[]))"
                    ),
                    {"ids": descendant_subnet_ids},
                )
            ).scalar_one()
        )
    return descendant_block_ids, descendant_subnet_ids, address_count


async def _collect_integration_blockers(
    db: AsyncSession,
    moved_block_id: uuid.UUID,
    descendant_block_ids: list[str],
    descendant_subnet_ids: list[str],
) -> list[IntegrationBlocker]:
    """Find every block / subnet / IP under the moved subtree that's
    owned by an integration reconciler. Moving such rows would cause
    the reconciler to immediately re-create them in the original
    space on its next sweep, leaving the move as a silent no-op
    that desynchronises provenance. Refuse the commit instead.

    The reconciler-owned rows are detected by the four integration
    FKs that exist on every IPAM table:
      * kubernetes_cluster_id
      * docker_host_id
      * proxmox_node_id
      * tailscale_tenant_id
    """
    block_ids = [str(moved_block_id), *descendant_block_ids]
    blockers: list[IntegrationBlocker] = []

    for kind, sql, params in (
        (
            "block",
            """
            SELECT id, network::text,
                   kubernetes_cluster_id, docker_host_id,
                   proxmox_node_id, tailscale_tenant_id
            FROM ip_block
            WHERE id = ANY(CAST(:ids AS uuid[]))
              AND (kubernetes_cluster_id IS NOT NULL
                OR docker_host_id IS NOT NULL
                OR proxmox_node_id IS NOT NULL
                OR tailscale_tenant_id IS NOT NULL)
            """,
            {"ids": block_ids},
        ),
        (
            "subnet",
            """
            SELECT id, network::text,
                   kubernetes_cluster_id, docker_host_id,
                   proxmox_node_id, tailscale_tenant_id
            FROM subnet
            WHERE id = ANY(CAST(:ids AS uuid[]))
              AND (kubernetes_cluster_id IS NOT NULL
                OR docker_host_id IS NOT NULL
                OR proxmox_node_id IS NOT NULL
                OR tailscale_tenant_id IS NOT NULL)
            """,
            {"ids": descendant_subnet_ids},
        ),
    ):
        if not params["ids"]:
            continue
        rows = (await db.execute(text(sql), params)).fetchall()
        for row in rows:
            integration = (
                "kubernetes"
                if row[2]
                else "docker" if row[3] else "proxmox" if row[4] else "tailscale"
            )
            blockers.append(
                IntegrationBlocker(
                    kind=kind,
                    resource_id=str(row[0]),
                    network=str(row[1]),
                    integration=integration,
                )
            )

    # Also surface integration-owned IPAddress rows under the moved
    # subtree. Same blast radius — IP rows owned by an integration
    # would get re-created in the source space on the next sweep.
    if descendant_subnet_ids:
        rows = (
            await db.execute(
                text("""
                    SELECT id, address::text,
                           kubernetes_cluster_id, docker_host_id,
                           proxmox_node_id, tailscale_tenant_id
                    FROM ip_address
                    WHERE subnet_id = ANY(CAST(:ids AS uuid[]))
                      AND (kubernetes_cluster_id IS NOT NULL
                        OR docker_host_id IS NOT NULL
                        OR proxmox_node_id IS NOT NULL
                        OR tailscale_tenant_id IS NOT NULL)
                    LIMIT 50
                    """),
                {"ids": descendant_subnet_ids},
            )
        ).fetchall()
        for row in rows:
            integration = (
                "kubernetes"
                if row[2]
                else "docker" if row[3] else "proxmox" if row[4] else "tailscale"
            )
            blockers.append(
                IntegrationBlocker(
                    kind="ip_address",
                    resource_id=str(row[0]),
                    network=str(row[1]),
                    integration=integration,
                )
            )

    return blockers


async def _check_overlap_in_target(
    db: AsyncSession,
    moved_block: IPBlock,
    target_space_id: uuid.UUID,
    target_parent_id: uuid.UUID | None,
) -> list[str]:
    """Re-run the same overlap rule ``create_block`` uses, against the
    target space's blocks at the destination level. Returns the list
    of block IDs that the moved block will SUPERNET (those reparent
    under it at commit). Raises ``BlockMoveError`` on any partial
    overlap or strict-subset where the target parent isn't already
    set right.
    """
    moved_net = ipaddress.ip_network(str(moved_block.network), strict=False)

    if target_parent_id is None:
        sql = (
            "SELECT id, network::text FROM ip_block "
            "WHERE space_id = CAST(:space AS uuid) "
            "AND parent_block_id IS NULL "
            "AND network && CAST(:net AS cidr) "
            "AND id != CAST(:self AS uuid)"
        )
        params: dict[str, Any] = {
            "space": str(target_space_id),
            "net": str(moved_net),
            "self": str(moved_block.id),
        }
    else:
        sql = (
            "SELECT id, network::text FROM ip_block "
            "WHERE space_id = CAST(:space AS uuid) "
            "AND parent_block_id = CAST(:parent AS uuid) "
            "AND network && CAST(:net AS cidr) "
            "AND id != CAST(:self AS uuid)"
        )
        params = {
            "space": str(target_space_id),
            "parent": str(target_parent_id),
            "net": str(moved_net),
            "self": str(moved_block.id),
        }

    rows = (await db.execute(text(sql), params)).fetchall()
    reparent: list[str] = []
    for row in rows:
        sibling_id = str(row[0])
        sibling_net = ipaddress.ip_network(str(row[1]), strict=False)
        if sibling_net == moved_net:
            raise BlockMoveError(
                f"Target space already has a block {moved_net} at this level",
                status_code=409,
            )
        if sibling_net.subnet_of(moved_net):  # type: ignore[arg-type]
            reparent.append(sibling_id)
            continue
        if moved_net.subnet_of(sibling_net):  # type: ignore[arg-type]
            raise BlockMoveError(
                f"Target space contains an existing block {sibling_net} that "
                f"would supernet the moved block {moved_net}; pick that block "
                f"as the target parent instead.",
                status_code=409,
            )
        raise BlockMoveError(
            f"Block {moved_net} overlaps with an existing block {sibling_net} "
            f"in the target space.",
            status_code=409,
        )
    return reparent


async def _validate_target_parent(
    db: AsyncSession,
    moved_block: IPBlock,
    target_space_id: uuid.UUID,
    target_parent_id: uuid.UUID,
) -> None:
    parent = await db.get(IPBlock, target_parent_id)
    if parent is None:
        raise BlockMoveError("Target parent block not found", status_code=404)
    if parent.space_id != target_space_id:
        raise BlockMoveError(
            "Target parent block does not belong to the target space",
            status_code=422,
        )
    if parent.id == moved_block.id:
        raise BlockMoveError("Target parent cannot be the moved block itself", status_code=422)
    parent_net = ipaddress.ip_network(str(parent.network), strict=False)
    moved_net = ipaddress.ip_network(str(moved_block.network), strict=False)
    if not moved_net.subnet_of(parent_net):  # type: ignore[arg-type]
        raise BlockMoveError(
            f"Moved block {moved_net} is not contained in target parent {parent_net}",
            status_code=422,
        )
    if moved_net == parent_net:
        raise BlockMoveError(
            "Moved block and target parent are the same CIDR; pick the parent's "
            "parent or remove the target_parent_id to land at top level.",
            status_code=422,
        )


# ── Plan assembly ───────────────────────────────────────────────────────────


async def assemble_move_plan(
    db: AsyncSession,
    moved_block: IPBlock,
    target_space_id: uuid.UUID,
    target_parent_id: uuid.UUID | None,
) -> MovePlan:
    """Pure read — gather everything the operator needs to see in
    preview, plus everything the commit path needs to verify before
    writes. Both ``preview_move`` and ``commit_move`` call this; the
    commit path re-runs it under an advisory lock to detect races.
    """
    target_space = await db.get(IPSpace, target_space_id)
    if target_space is None:
        raise BlockMoveError("Target IP space not found", status_code=404)
    if target_space.id == moved_block.space_id and target_parent_id is None:
        raise BlockMoveError(
            "Block is already at top level of this space — nothing to do.",
            status_code=422,
        )

    if target_parent_id is not None:
        await _validate_target_parent(db, moved_block, target_space_id, target_parent_id)

    descendant_block_ids, descendant_subnet_ids, ip_count = await _collect_descendants(
        db, moved_block.id
    )

    blockers = await _collect_integration_blockers(
        db, moved_block.id, descendant_block_ids, descendant_subnet_ids
    )

    reparent_chain = await _check_overlap_in_target(
        db, moved_block, target_space_id, target_parent_id
    )

    # Soft warnings — non-blocking, surfaced in preview.
    warnings: list[str] = []
    src_space = await db.get(IPSpace, moved_block.space_id)
    if (
        src_space
        and target_space
        and src_space.vrf_id is not None
        and target_space.vrf_id is not None
        and src_space.vrf_id != target_space.vrf_id
    ):
        warnings.append(
            "Source and target spaces have different VRFs — moved block will "
            "inherit the target space's VRF unless it overrides via vrf_id."
        )
    if (
        moved_block.kubernetes_cluster_id
        or moved_block.docker_host_id
        or moved_block.proxmox_node_id
        or moved_block.tailscale_tenant_id
    ):
        # Caught by integration-blocker collection above too; this
        # warning is the heads-up version surfaced even when the
        # operator hasn't drilled into the blocker list.
        warnings.append(
            "The moved block itself is owned by an integration reconciler — "
            "the move will be refused unless the integration is detached first."
        )

    return MovePlan(
        block_id=str(moved_block.id),
        block_network=str(moved_block.network),
        source_space_id=str(moved_block.space_id),
        target_space_id=str(target_space_id),
        target_parent_id=str(target_parent_id) if target_parent_id else None,
        descendant_block_ids=descendant_block_ids,
        descendant_subnet_ids=descendant_subnet_ids,
        descendant_ip_count=ip_count,
        reparent_chain_block_ids=reparent_chain,
        integration_blockers=blockers,
        warnings=warnings,
    )


# ── Public API ──────────────────────────────────────────────────────────────


async def preview_move(
    db: AsyncSession,
    moved_block: IPBlock,
    target_space_id: uuid.UUID,
    target_parent_id: uuid.UUID | None,
) -> MovePlan:
    return await assemble_move_plan(db, moved_block, target_space_id, target_parent_id)


async def commit_move(
    db: AsyncSession,
    moved_block: IPBlock,
    target_space_id: uuid.UUID,
    target_parent_id: uuid.UUID | None,
    confirmation_cidr: str,
) -> MoveResult:
    """Commit the move under an advisory xact-lock. Re-runs the full
    plan inside the lock to catch concurrent overlap insertions,
    integration row creation, etc.

    The caller is responsible for committing the transaction — we
    only ``flush`` so the audit-log row written by the router lands
    in the same transaction.
    """
    if confirmation_cidr.strip() != str(moved_block.network):
        raise BlockMoveError(
            f"Confirmation CIDR '{confirmation_cidr}' does not match block "
            f"network '{moved_block.network}'.",
            status_code=422,
        )

    if not await _try_advisory_lock(db, moved_block.id):
        raise BlockMoveError(
            "Another move is in progress for this block. Try again shortly.",
            status_code=423,
        )

    plan = await assemble_move_plan(db, moved_block, target_space_id, target_parent_id)

    if plan.integration_blockers:
        # Race-window catch: someone added an integration-owned row
        # between preview and commit. Refuse.
        raise BlockMoveError(
            f"{len(plan.integration_blockers)} integration-owned descendant "
            f"row(s) found — refuse to move. Detach the integration first.",
            status_code=409,
        )

    # ── Apply the rewrite ──────────────────────────────────────────────────
    # 1. Moved block itself.
    moved_block.space_id = uuid.UUID(plan.target_space_id)
    moved_block.parent_block_id = (
        uuid.UUID(plan.target_parent_id) if plan.target_parent_id else None
    )

    # 2. Descendant blocks — keep parent FKs intact, just bump space_id.
    if plan.descendant_block_ids:
        await db.execute(
            update(IPBlock)
            .where(IPBlock.id.in_([uuid.UUID(b) for b in plan.descendant_block_ids]))
            .values(space_id=uuid.UUID(plan.target_space_id))
        )

    # 3. Descendant subnets — Subnet has its own space_id column.
    if plan.descendant_subnet_ids:
        await db.execute(
            update(Subnet)
            .where(Subnet.id.in_([uuid.UUID(s) for s in plan.descendant_subnet_ids]))
            .values(space_id=uuid.UUID(plan.target_space_id))
        )

    # 4. IPAddress rows live under Subnet (no space_id column) — nothing
    # to rewrite here. ``ip_count`` in the plan is a reporting field.

    # 5. Reparent-chain — top-level target-space siblings that the moved
    # block now supernets get rehomed under it.
    if plan.reparent_chain_block_ids:
        await db.execute(
            update(IPBlock)
            .where(IPBlock.id.in_([uuid.UUID(b) for b in plan.reparent_chain_block_ids]))
            .values(parent_block_id=moved_block.id)
        )

    await db.flush()

    return MoveResult(
        block_id=plan.block_id,
        source_space_id=plan.source_space_id,
        target_space_id=plan.target_space_id,
        target_parent_id=plan.target_parent_id,
        blocks_moved=1 + len(plan.descendant_block_ids),
        subnets_moved=len(plan.descendant_subnet_ids),
        addresses_in_moved_subtree=plan.descendant_ip_count,
        reparented_block_ids=list(plan.reparent_chain_block_ids),
    )


__all__ = [
    "BlockMoveError",
    "IntegrationBlocker",
    "MovePlan",
    "MoveResult",
    "preview_move",
    "commit_move",
    "assemble_move_plan",
]
