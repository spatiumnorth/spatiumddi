"""Periodic IPAM utilization recount sweep (issue #521).

Recomputes ``Subnet.allocated_ips`` + ``utilization_percent`` for every
non-deleted subnet, and the recursive ``allocated_ips`` / ``total_ips`` /
``utilization_percent`` rollups on ``IPBlock``, correcting any drift that
crept into the cached counters. Drift accumulates from the handful of code
paths that adjust a counter by an estimated delta rather than a fresh count
— the CSV/XLSX address importer bumps ``subnet.allocated_ips`` by a
computed delta, bulk integration reconcilers insert rows in bulk, and any
partial-failure path that mutates a row but not the cache leaves the two
out of step.

Idempotent + cheap by design:

  * ONE grouped ``COUNT(*) WHERE status != 'available'`` over
    ``ip_address`` (grouped by subnet_id) — NOT a per-subnet ORM loop, so
    it scales to 10k+ subnets on a single round-trip.
  * A single in-memory pass over the block tree for the recursive rollup
    (mirrors ``_update_block_utilization`` in the IPAM router — full-CIDR
    denominator, BIGINT-clamped ``total_ips``, ``deleted_at IS NULL``
    guards on both blocks and subnets).
  * Only rows whose cached value actually drifted are written, so a
    converged install commits nothing and writes no audit row.

Always safe to run — it never touches semantic state, only derived
counters — so there's no platform-settings gate; the beat entry fires it
hourly.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.celery_app import celery_app
from app.config import settings
from app.db import task_session
from app.models.audit import AuditLog
from app.services.ipam.utilization import COUNTS_TOWARD_UTILIZATION_SQL

logger = structlog.get_logger(__name__)

_SINGLETON_ID = 1
# Mirror of ``_BIGINT_MAX`` in the IPAM router — the ``total_ips`` columns
# are BIGINT, so a huge IPv6 block (e.g. a /48) is clamped rather than
# overflowing.
_BIGINT_MAX = 2**63 - 1


def _num_addresses(network: Any) -> int:
    """Full CIDR size for a block/subnet network value (asyncpg returns an
    ``ip_network`` object for CIDR columns; ``str()`` handles both that and
    a plain string)."""
    return int(ipaddress.ip_network(str(network), strict=False).num_addresses)


async def _recount_subnets(db: AsyncSession) -> int:
    """Recompute per-subnet ``allocated_ips`` + ``utilization_percent``.

    Returns the number of subnet rows whose cached values drifted and were
    corrected. Writes only the changed rows.
    """
    # One grouped count over the whole address table (ip_address has no
    # soft-delete column, so every row counts; the subnet-side deleted_at
    # guard is applied when we select the target rows below).
    counts: dict[str, int] = {}
    for sid, cnt in (
        await db.execute(
            text(
                "SELECT subnet_id, COUNT(*) FROM ip_address "
                f"WHERE {COUNTS_TOWARD_UTILIZATION_SQL} GROUP BY subnet_id"
            )
        )
    ).all():
        counts[str(sid)] = int(cnt)

    changes: list[dict[str, Any]] = []
    for sid, total_ips, allocated_ips, util in (
        await db.execute(
            text(
                "SELECT id, total_ips, allocated_ips, utilization_percent "
                "FROM subnet WHERE deleted_at IS NULL"
            )
        )
    ).all():
        new_alloc = counts.get(str(sid), 0)
        new_util = round(new_alloc / total_ips * 100, 2) if total_ips and total_ips > 0 else 0.0
        if new_alloc != int(allocated_ips) or abs(new_util - float(util)) > 0.001:
            changes.append({"id": str(sid), "a": new_alloc, "u": new_util})

    if changes:
        await db.execute(
            text(
                "UPDATE subnet SET allocated_ips = :a, utilization_percent = :u "
                "WHERE id = CAST(:id AS uuid)"
            ),
            changes,
        )
    return len(changes)


async def _recount_blocks(db: AsyncSession) -> int:
    """Recompute the recursive ``allocated_ips`` / ``total_ips`` /
    ``utilization_percent`` rollups on every non-deleted block.

    Reads the (already-corrected) per-subnet ``allocated_ips`` and rolls it
    up the block tree in a single in-memory pass. Returns the number of
    block rows corrected.
    """
    block_rows = (
        await db.execute(
            text(
                "SELECT id, parent_block_id, network, allocated_ips, total_ips, "
                "utilization_percent FROM ip_block WHERE deleted_at IS NULL"
            )
        )
    ).all()
    if not block_rows:
        return 0

    parent: dict[str, str | None] = {}
    current: dict[str, tuple[int, int, float]] = {}
    networks: dict[str, Any] = {}
    for bid, pbid, network, allocated_ips, total_ips, util in block_rows:
        key = str(bid)
        parent[key] = str(pbid) if pbid is not None else None
        current[key] = (int(allocated_ips), int(total_ips), float(util))
        networks[key] = network

    # Direct allocation per block = sum of its own subnets' allocated_ips
    # (non-deleted subnets only), matching the router's recursive CTE which
    # guards ``s.deleted_at IS NULL``.
    subtree: dict[str, int] = {key: 0 for key in current}
    for bid, direct in (
        await db.execute(
            text(
                "SELECT block_id, COALESCE(SUM(allocated_ips), 0) FROM subnet "
                "WHERE deleted_at IS NULL GROUP BY block_id"
            )
        )
    ).all():
        key = str(bid)
        if key in subtree:  # a subnet under a soft-deleted block is ignored
            subtree[key] = int(direct)

    # Roll child sums up into parents. Process deepest-first so each block's
    # subtree is fully accumulated before it contributes to its parent. A
    # block whose parent is soft-deleted (parent not in the map) stops
    # there — the router's CTE likewise never crosses a deleted ancestor.
    def _depth(key: str) -> int:
        d = 0
        cur = parent.get(key)
        guard = 0
        while cur is not None and cur in subtree and guard < 100000:
            d += 1
            cur = parent.get(cur)
            guard += 1
        return d

    for key in sorted(subtree, key=_depth, reverse=True):
        pkey = parent.get(key)
        if pkey is not None and pkey in subtree:
            subtree[pkey] += subtree[key]

    changes: list[dict[str, Any]] = []
    for key, (old_alloc, old_total, old_util) in current.items():
        alloc = subtree[key]
        block_total = _num_addresses(networks[key])
        new_total = min(block_total, _BIGINT_MAX)
        new_util = round(alloc / block_total * 100, 2) if block_total > 0 else 0.0
        if alloc != old_alloc or new_total != old_total or abs(new_util - old_util) > 0.001:
            changes.append({"id": key, "a": alloc, "t": new_total, "u": new_util})

    if changes:
        await db.execute(
            text(
                "UPDATE ip_block SET allocated_ips = :a, total_ips = :t, "
                "utilization_percent = :u WHERE id = CAST(:id AS uuid)"
            ),
            changes,
        )
    return len(changes)


async def recount_utilization(db: AsyncSession) -> dict[str, int]:
    """Core recount pass against an open session. Subnets first (blocks read
    the corrected per-subnet counts), then the block rollup, then a single
    audit row when anything drifted. Does NOT commit — the caller owns the
    transaction boundary."""
    subnets_corrected = await _recount_subnets(db)
    blocks_corrected = await _recount_blocks(db)

    if subnets_corrected or blocks_corrected:
        db.add(
            AuditLog(
                user_display_name="<system>",
                auth_source="system",
                action="ipam-utilization-recount",
                resource_type="platform",
                resource_id=str(_SINGLETON_ID),
                resource_display="utilization-recount",
                result="success",
                new_value={
                    "subnets_corrected": subnets_corrected,
                    "blocks_corrected": blocks_corrected,
                },
            )
        )
    return {"subnets_corrected": subnets_corrected, "blocks_corrected": blocks_corrected}


async def _run_recount() -> dict[str, int]:
    async with task_session(command_timeout=settings.task_db_long_command_timeout) as db:
        result = await recount_utilization(db)
        await db.commit()
        return result


@celery_app.task(name="app.tasks.ipam_utilization_recount.recount_ipam_utilization")
def recount_ipam_utilization() -> dict[str, int]:
    """Celery beat entrypoint — fires hourly. Idempotent: corrects cached
    subnet/block utilization counters that drifted from the live row counts,
    writing (and auditing) only what changed."""
    result = asyncio.run(_run_recount())
    logger.info(
        "ipam_utilization_recount_completed",
        subnets_corrected=result["subnets_corrected"],
        blocks_corrected=result["blocks_corrected"],
    )
    return result
