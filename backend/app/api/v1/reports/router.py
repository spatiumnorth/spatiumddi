"""Top-N report endpoints (issue #47).

Each endpoint returns at most :data:`TOP_N` rows, ranked, with a
``generated_at`` server clock so the front end can render a
"fresh as of …" hint. The aggregation lives in module-level
``compute_*`` helpers so the matching Operator-Copilot MCP tools
(``app.services.ai.tools.reports``) can reuse the exact same query
without going through the HTTP layer.

Permission gates (CLAUDE.md non-negotiable #3) are per-endpoint, keyed
to the dominant resource type each report draws from:

* top-subnets       → ``read`` on ``subnet``
* top-owners        → ``read`` on ``customer`` (the payload IS the
  customer roster — customer_id + customer_name for the top owners —
  so it must gate on the same resource type the canonical customers
  surface does, not on the ``ip_address`` rows we happen to count)
* top-modified      → ``read`` on ``audit_log``
* top-dns-clients   → ``read`` on ``server`` OR ``dns_group`` (the DNS
  query-log surface in the Logs router gates on ``server``; we accept
  the DNS family root too)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import DB
from app.core.permissions import require_any_permission, require_permission
from app.models.audit import AuditLog
from app.models.ipam import IPAddress, Subnet
from app.models.logs import DNSQueryLogEntry
from app.models.ownership import Customer
from app.services.logs.partitions import DEFAULT_RETENTION_HOURS

router = APIRouter()


# Top-N cap shared by every report. The reports surface is a heads-up
# rollup, not a paginated table — operators drill into the canonical
# admin page for the full set.
TOP_N = 10

# Trailing window for the most-modified-resources report. Mirrors the
# security dashboard's permission-change window so the two surfaces
# read consistently.
MODIFIED_WINDOW_DAYS = 7

# Label for the synthetic "no customer" bucket in the owner report.
UNOWNED_LABEL = "Unowned"


# ── Schemas ─────────────────────────────────────────────────────────


class TopSubnetRow(BaseModel):
    id: str
    name: str
    network: str
    utilization_percent: float
    allocated_ips: int
    total_ips: int


class TopOwnerRow(BaseModel):
    # ``customer_id`` is None for the synthetic "Unowned" bucket.
    customer_id: str | None
    customer_name: str
    ip_count: int


class TopModifiedResourceRow(BaseModel):
    resource_type: str
    resource_id: str
    resource_display: str
    change_count: int


class TopDNSClientRow(BaseModel):
    client_ip: str
    query_count: int


class TopSubnetsReport(BaseModel):
    generated_at: datetime
    rows: list[TopSubnetRow]


class TopOwnersReport(BaseModel):
    generated_at: datetime
    rows: list[TopOwnerRow]


class TopModifiedResourcesReport(BaseModel):
    generated_at: datetime
    window_days: int
    rows: list[TopModifiedResourceRow]


class TopDNSClientsReport(BaseModel):
    generated_at: datetime
    rows: list[TopDNSClientRow]


# ── Aggregation helpers (shared with the MCP tools) ─────────────────


async def compute_top_subnets(db: AsyncSession, *, limit: int = TOP_N) -> list[TopSubnetRow]:
    """Subnets ranked by ``utilization_percent`` descending.

    Soft-deleted subnets are excluded. Ties break on allocated count so
    the busier subnet wins a tie at the same percentage.
    """
    stmt = (
        select(Subnet)
        .where(Subnet.deleted_at.is_(None))
        .order_by(desc(Subnet.utilization_percent), desc(Subnet.allocated_ips))
        .limit(limit)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [
        TopSubnetRow(
            id=str(s.id),
            name=s.name or str(s.network),
            network=str(s.network),
            utilization_percent=round(float(s.utilization_percent), 1),
            allocated_ips=int(s.allocated_ips),
            total_ips=int(s.total_ips),
        )
        for s in rows
    ]


async def compute_top_owners(db: AsyncSession, *, limit: int = TOP_N) -> list[TopOwnerRow]:
    """Customers ranked by the count of IPs whose subnet they own.

    ``IPAddress`` has no direct owner FK — ownership lives on
    ``Subnet.customer_id``. We join IP → Subnet, group by the owning
    Customer, and bucket every IP whose subnet has no customer into a
    single synthetic "Unowned" row. Soft-deleted subnets / customers
    are excluded; their IPs fall into "Unowned".
    """
    # Owned counts: IP → Subnet → Customer, grouped by customer.
    owned_stmt = (
        select(
            Customer.id.label("customer_id"),
            Customer.name.label("customer_name"),
            func.count(IPAddress.id).label("ip_count"),
        )
        .select_from(IPAddress)
        .join(Subnet, IPAddress.subnet_id == Subnet.id)
        .join(Customer, Subnet.customer_id == Customer.id)
        .where(Subnet.deleted_at.is_(None))
        .where(Customer.deleted_at.is_(None))
        .group_by(Customer.id, Customer.name)
    )
    owned = (await db.execute(owned_stmt)).all()

    # Unowned count: IPs whose subnet has no live customer link. Covers
    # both NULL customer_id and customer_id pointing at a soft-deleted
    # customer (the inner join above drops those, so re-count by the
    # absence of a live join here).
    unowned_stmt = (
        select(func.count(IPAddress.id))
        .select_from(IPAddress)
        .join(Subnet, IPAddress.subnet_id == Subnet.id)
        .outerjoin(
            Customer,
            (Subnet.customer_id == Customer.id) & (Customer.deleted_at.is_(None)),
        )
        .where(Subnet.deleted_at.is_(None))
        .where(Customer.id.is_(None))
    )
    unowned_count = int((await db.execute(unowned_stmt)).scalar_one() or 0)

    rows: list[TopOwnerRow] = [
        TopOwnerRow(
            customer_id=str(r.customer_id),
            customer_name=r.customer_name,
            ip_count=int(r.ip_count),
        )
        for r in owned
    ]
    if unowned_count > 0:
        rows.append(
            TopOwnerRow(customer_id=None, customer_name=UNOWNED_LABEL, ip_count=unowned_count)
        )
    rows.sort(key=lambda r: r.ip_count, reverse=True)
    return rows[:limit]


async def compute_top_modified_resources(
    db: AsyncSession, *, limit: int = TOP_N, window_days: int = MODIFIED_WINDOW_DAYS
) -> list[TopModifiedResourceRow]:
    """Audit-log rows grouped by resource over the trailing window.

    Counts create / update / delete mutations per
    ``(resource_type, resource_id)``. ``resource_display`` is taken from
    the *most-recent* row for that resource (highest ``timestamp``) so
    the label reflects the current name even if it was renamed
    mid-window. A correlated subquery selects that latest display per
    grouped resource — ``func.max(resource_display)`` would instead
    return the lexicographically-largest string, which is not the same
    thing the moment a resource is renamed.
    """
    since = datetime.now(UTC) - timedelta(days=window_days)
    # Correlated subquery: the display string from the newest audit row
    # for this (resource_type, resource_id). Ordering by timestamp DESC,
    # seq DESC breaks same-timestamp ties deterministically on the
    # later-inserted row (``seq`` is a strictly-increasing insertion
    # sequence, unlike the UUID ``id``).
    inner = AuditLog.__table__.alias("recent_disp")
    latest_display = (
        select(inner.c.resource_display)
        .where(
            and_(
                inner.c.resource_type == AuditLog.resource_type,
                inner.c.resource_id == AuditLog.resource_id,
            )
        )
        .order_by(desc(inner.c.timestamp), desc(inner.c.seq))
        .limit(1)
        .correlate(AuditLog.__table__)
        .scalar_subquery()
    )
    stmt = (
        select(
            AuditLog.resource_type.label("resource_type"),
            AuditLog.resource_id.label("resource_id"),
            func.count().label("change_count"),
            latest_display.label("resource_display"),
        )
        .where(AuditLog.timestamp >= since)
        .where(AuditLog.action.in_(("create", "update", "delete")))
        .group_by(AuditLog.resource_type, AuditLog.resource_id)
        .order_by(desc(func.count()))
        .limit(limit)
    )
    rows = (await db.execute(stmt)).all()
    return [
        TopModifiedResourceRow(
            resource_type=r.resource_type,
            resource_id=r.resource_id,
            resource_display=r.resource_display or "",
            change_count=int(r.change_count),
        )
        for r in rows
    ]


async def compute_top_dns_clients(db: AsyncSession, *, limit: int = TOP_N) -> list[TopDNSClientRow]:
    """DNS query-log clients ranked by query volume over the last 24 h.

    Groups the parsed BIND9 query-log rows by ``client_ip``, bounded to
    the trailing :data:`app.services.logs.partitions.DEFAULT_RETENTION_HOURS` (24 h)
    window. The prune sweep only runs nightly, so between sweeps the
    table can hold ~48 h of rows — without the time predicate this would
    over-count *and* full-table-scan past the ``ix_dns_query_log_ts``
    index. Reusing the retention constant keeps the report window and
    the prune window aligned. An empty table returns ``[]``.
    """
    since = datetime.now(UTC) - timedelta(hours=DEFAULT_RETENTION_HOURS)
    stmt = (
        select(
            DNSQueryLogEntry.client_ip.label("client_ip"),
            func.count().label("query_count"),
        )
        .where(DNSQueryLogEntry.ts >= since)
        .where(DNSQueryLogEntry.client_ip.is_not(None))
        .group_by(DNSQueryLogEntry.client_ip)
        .order_by(desc(func.count()))
        .limit(limit)
    )
    rows = (await db.execute(stmt)).all()
    return [
        TopDNSClientRow(client_ip=str(r.client_ip), query_count=int(r.query_count)) for r in rows
    ]


# ── Routes ──────────────────────────────────────────────────────────


@router.get(
    "/top-subnets-by-utilization",
    response_model=TopSubnetsReport,
    dependencies=[Depends(require_permission("read", "subnet"))],
)
async def top_subnets_by_utilization(db: DB) -> TopSubnetsReport:
    """Top 10 subnets by utilization percentage."""
    return TopSubnetsReport(
        generated_at=datetime.now(UTC),
        rows=await compute_top_subnets(db),
    )


@router.get(
    "/top-owners-by-ip-count",
    response_model=TopOwnersReport,
    dependencies=[Depends(require_permission("read", "customer"))],
)
async def top_owners_by_ip_count(db: DB) -> TopOwnersReport:
    """Top 10 owners (Customers) by allocated-IP count, with an
    "Unowned" bucket for IPs whose subnet has no customer."""
    return TopOwnersReport(
        generated_at=datetime.now(UTC),
        rows=await compute_top_owners(db),
    )


@router.get(
    "/top-modified-resources",
    response_model=TopModifiedResourcesReport,
    dependencies=[Depends(require_permission("read", "audit_log"))],
)
async def top_modified_resources(db: DB) -> TopModifiedResourcesReport:
    """Top 10 most-modified resources over the trailing 7 days."""
    return TopModifiedResourcesReport(
        generated_at=datetime.now(UTC),
        window_days=MODIFIED_WINDOW_DAYS,
        rows=await compute_top_modified_resources(db),
    )


@router.get(
    "/top-dns-clients",
    response_model=TopDNSClientsReport,
    dependencies=[Depends(require_any_permission(("read", "server"), ("read", "dns_group")))],
)
async def top_dns_clients(db: DB) -> TopDNSClientsReport:
    """Top 10 noisiest DNS query-log clients (24 h retention window)."""
    return TopDNSClientsReport(
        generated_at=datetime.now(UTC),
        rows=await compute_top_dns_clients(db),
    )
