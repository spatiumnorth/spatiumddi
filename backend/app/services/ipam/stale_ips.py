"""Stale-IP report — allocated IPs nothing has seen in a while (issue #45).

The IP-discovery sweep (#23) stamps ``last_seen_at`` / ``last_seen_method``
on every IPAddress it can prove is alive (ping / ARP / DHCP / nmap / SNMP).
This module reads that signal from the *other* direction: which IPs are
still marked ``allocated`` but haven't been seen on the wire in N days?
Those are the address-space-hygiene candidates — hosts decommissioned
without anyone freeing the IPAM row.

Read side (``build_stale_ip_report``) powers ``GET /ipam/reports/stale-ips``
and the ``find_stale_ips`` MCP tool. ``select_stale_ip_ids`` resolves the
full matching set for the "deprecate all matching" one-click action.
``count_stale_per_subnet`` powers the ``stale_ip_count`` alert rule.

Semantics:
* candidate status = ``allocated`` only. ``reserved`` / ``static_dhcp``
  are deliberately held; ``deprecated`` is already deprecated;
  integration-owned statuses churn on their own reconciler cadence.
* ``auto_from_lease`` rows are always excluded — a DHCP lease mirror is
  owned by the DHCP server and naturally comes and goes.
* a row counts as stale when ``last_seen_at`` is older than the cutoff.
  Rows *never* seen (``last_seen_at IS NULL``) are a separate concern —
  many live in subnets where discovery was never enabled, so they'd be
  false positives. They're included only when the caller opts in via
  ``include_never_seen``.
"""

from __future__ import annotations

import uuid
from collections.abc import Collection
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.selectable import Select

from app.models.ipam import IPAddress, Subnet

# Operator-tunable default — the issue's stated 90-day window.
STALE_IP_DEFAULT_DAYS = 90

# Only ``allocated`` rows are hygiene candidates. Kept as a frozenset so
# the semantics are obvious and the set is easy to widen later.
STALE_CANDIDATE_STATUSES: frozenset[str] = frozenset({"allocated"})

# Hard cap on the "deprecate all matching" path so one click can't issue
# an unbounded write. The report itself paginates; this guards the
# server-side resolve-then-mutate flow.
MAX_BULK_DEPRECATE = 5000


def _recency_clause(stale_cutoff: datetime, include_never_seen: bool) -> Any:
    """WHERE fragment selecting rows whose last-seen signal is stale."""
    older = and_(IPAddress.last_seen_at.is_not(None), IPAddress.last_seen_at < stale_cutoff)
    if include_never_seen:
        return or_(IPAddress.last_seen_at.is_(None), older)
    return older


def _stale_stmt(
    stale_cutoff: datetime,
    include_never_seen: bool,
    *,
    space_id: uuid.UUID | None,
    block_id: uuid.UUID | None,
    subnet_id: uuid.UUID | None,
    subnet_ids: Collection[uuid.UUID] | None = None,
) -> Select[Any]:
    """Base SELECT over stale IPAddress rows, scope filters applied.

    Joins Subnet so callers can scope by space / block and so soft-deleted
    subnets drop out of the report. ``subnet_ids`` limits the rows to those
    subnets (a caller bound to specific subnets); ``None`` applies no limit.
    """
    stmt = (
        select(IPAddress)
        .join(Subnet, IPAddress.subnet_id == Subnet.id)
        .where(
            Subnet.deleted_at.is_(None),
            IPAddress.status.in_(STALE_CANDIDATE_STATUSES),
            IPAddress.auto_from_lease.is_(False),
            _recency_clause(stale_cutoff, include_never_seen),
        )
    )
    if subnet_id is not None:
        stmt = stmt.where(IPAddress.subnet_id == subnet_id)
    if subnet_ids is not None:
        stmt = stmt.where(IPAddress.subnet_id.in_(list(subnet_ids)))
    if block_id is not None:
        stmt = stmt.where(Subnet.block_id == block_id)
    if space_id is not None:
        stmt = stmt.where(Subnet.space_id == space_id)
    return stmt


def _days_stale(last_seen_at: datetime | None, now: datetime) -> int | None:
    if last_seen_at is None:
        return None
    return max(0, (now - last_seen_at).days)


async def build_stale_ip_report(
    db: AsyncSession,
    *,
    stale_days: int = STALE_IP_DEFAULT_DAYS,
    include_never_seen: bool = False,
    space_id: uuid.UUID | None = None,
    block_id: uuid.UUID | None = None,
    subnet_id: uuid.UUID | None = None,
    subnet_ids: Collection[uuid.UUID] | None = None,
    limit: int = 200,
    offset: int = 0,
) -> dict[str, Any]:
    """Paginated stale-IP report across all (or a scoped set of) subnets.

    Stalest rows first — NULL ``last_seen_at`` sorts before any timestamp
    (PostgreSQL ``NULLS FIRST`` on ascending), so never-seen rows lead when
    ``include_never_seen`` is on, then oldest-seen, then by address.
    """
    now = datetime.now(UTC)
    stale_cutoff = now - timedelta(days=max(1, stale_days))

    base = _stale_stmt(
        stale_cutoff,
        include_never_seen,
        space_id=space_id,
        block_id=block_id,
        subnet_id=subnet_id,
        subnet_ids=subnet_ids,
    )

    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one()

    rows = list(
        (
            await db.execute(
                base.order_by(
                    IPAddress.last_seen_at.asc().nullsfirst(),
                    IPAddress.address.asc(),
                )
                .limit(max(1, min(limit, 1000)))
                .offset(max(0, offset))
            )
        )
        .scalars()
        .all()
    )

    # One bulk lookup keeps the subnet display columns cheap even on a
    # 1000-row page spanning many subnets.
    subnet_ids = {r.subnet_id for r in rows}
    subnets: dict[uuid.UUID, Subnet] = {}
    if subnet_ids:
        for s in (
            (await db.execute(select(Subnet).where(Subnet.id.in_(subnet_ids)))).scalars().all()
        ):
            subnets[s.id] = s

    entries: list[dict[str, Any]] = []
    for r in rows:
        s = subnets.get(r.subnet_id)
        entries.append(
            {
                "id": str(r.id),
                "address": str(r.address),
                "status": r.status,
                "hostname": r.hostname,
                "mac_address": str(r.mac_address) if r.mac_address else None,
                "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
                "last_seen_method": r.last_seen_method,
                "days_stale": _days_stale(r.last_seen_at, now),
                "subnet_id": str(r.subnet_id),
                "subnet_network": str(s.network) if s else None,
                "subnet_name": s.name if s else None,
            }
        )

    return {
        "generated_at": now.isoformat(),
        "stale_days": stale_days,
        "include_never_seen": include_never_seen,
        "total": int(total),
        "limit": max(1, min(limit, 1000)),
        "offset": max(0, offset),
        "entries": entries,
    }


async def select_stale_ip_ids(
    db: AsyncSession,
    *,
    stale_days: int = STALE_IP_DEFAULT_DAYS,
    include_never_seen: bool = False,
    space_id: uuid.UUID | None = None,
    block_id: uuid.UUID | None = None,
    subnet_id: uuid.UUID | None = None,
    subnet_ids: Collection[uuid.UUID] | None = None,
    cap: int = MAX_BULK_DEPRECATE,
) -> list[uuid.UUID]:
    """Resolve the full set of stale IP ids matching the filter (capped).

    Powers the "deprecate all matching" one-click action — the caller
    re-uses the same filter the operator saw in the report so the action
    is exactly what's on screen.
    """
    now = datetime.now(UTC)
    stale_cutoff = now - timedelta(days=max(1, stale_days))
    base = _stale_stmt(
        stale_cutoff,
        include_never_seen,
        space_id=space_id,
        block_id=block_id,
        subnet_id=subnet_id,
        subnet_ids=subnet_ids,
    )
    rows = (await db.execute(base.with_only_columns(IPAddress.id).limit(max(1, cap)))).all()
    return [row[0] for row in rows]


async def count_stale_per_subnet(
    db: AsyncSession,
    *,
    stale_days: int = STALE_IP_DEFAULT_DAYS,
    include_never_seen: bool = False,
) -> dict[uuid.UUID, int]:
    """Map of subnet_id → stale allocated-IP count. Powers the
    ``stale_ip_count`` alert rule. Only subnets with ≥ 1 stale IP appear.
    """
    now = datetime.now(UTC)
    stale_cutoff = now - timedelta(days=max(1, stale_days))
    stmt = (
        select(IPAddress.subnet_id, func.count().label("n"))
        .join(Subnet, IPAddress.subnet_id == Subnet.id)
        .where(
            Subnet.deleted_at.is_(None),
            IPAddress.status.in_(STALE_CANDIDATE_STATUSES),
            IPAddress.auto_from_lease.is_(False),
            _recency_clause(stale_cutoff, include_never_seen),
        )
        .group_by(IPAddress.subnet_id)
    )
    return {row[0]: int(row[1]) for row in (await db.execute(stmt)).all()}


__all__ = [
    "MAX_BULK_DEPRECATE",
    "STALE_CANDIDATE_STATUSES",
    "STALE_IP_DEFAULT_DAYS",
    "build_stale_ip_report",
    "count_stale_per_subnet",
    "select_stale_ip_ids",
]
