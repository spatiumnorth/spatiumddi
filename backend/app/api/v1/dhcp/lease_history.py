"""DHCP lease history — read-only endpoint.

History rows are written by ``services/dhcp/lease_history.py`` from
the lease-pull and time-based-cleanup paths. This endpoint exposes
them with a typical operator query pattern: server-scoped, time-range
filterable, paginated, ordered by most-recent-expiry first.

Retention is governed by
``PlatformSettings.dhcp_lease_history_retention_days`` (default 90;
``0`` = keep forever); the daily prune task lives in
``tasks.dhcp_lease_history_prune``.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator
from sqlalchemy import String, cast, func, select
from sqlalchemy.sql import Select

from app.api.deps import DB, CurrentUser
from app.api.pagination import MAX_PAGE
from app.core.permissions import require_resource_permission
from app.models.dhcp import DHCPLeaseHistory, DHCPServer

router = APIRouter(
    prefix="/servers",
    tags=["dhcp"],
    dependencies=[Depends(require_resource_permission("dhcp_server"))],
)


#: Terminal lease states a history row can carry. Exported because the
#: fleet-wide route in ``leases.py`` validates against the same set — two
#: copies would let one route accept a state the other rejects (#917).
VALID_LEASE_HISTORY_STATES = frozenset({"expired", "released", "removed", "superseded"})


class LeaseHistoryRow(BaseModel):
    id: uuid.UUID
    server_id: uuid.UUID
    scope_id: uuid.UUID | None
    ip_address: str
    # NULL for a DHCPv6 lease identified by DUID only (#1141).
    mac_address: str | None
    duid: str | None = None
    iaid: int | None = None
    hostname: str | None
    client_id: str | None
    started_at: datetime | None
    expired_at: datetime
    lease_state: str
    created_at: datetime

    model_config = {"from_attributes": True}

    @field_validator("ip_address", "mac_address", mode="before")
    @classmethod
    def _coerce(cls, v: Any) -> Any:
        return str(v) if v is not None else v


class LeaseHistoryPage(BaseModel):
    total: int
    page: int
    per_page: int
    items: list[LeaseHistoryRow]


def apply_lease_history_filters(
    base: Select[Any],
    *,
    mac: str | None,
    ip: str | None,
    hostname: str | None,
    lease_state: str | None,
) -> Select[Any]:
    """The mac / ip / hostname / state filters, shared with the fleet-wide
    route in ``leases.py`` (#917) so the two cannot diverge on what a filter
    means."""
    if mac:
        # MACADDR → text for substring match. Postgres canonicalises to
        # ``aa:bb:cc:dd:ee:ff`` so we lowercase the input first.
        base = base.where(cast(DHCPLeaseHistory.mac_address, String).ilike(f"%{mac.lower()}%"))
    if ip:
        # Try CIDR-containment first; if the operator typed a bare host,
        # fall back to exact match. The INET column supports the
        # ``<<=`` (subnet-or-equal) operator natively in postgres.
        try:
            net = ipaddress.ip_network(ip, strict=False)
            base = base.where(DHCPLeaseHistory.ip_address.op("<<=")(str(net)))
        except (ValueError, TypeError):
            base = base.where(DHCPLeaseHistory.ip_address == ip)
    if hostname:
        base = base.where(DHCPLeaseHistory.hostname.ilike(f"%{hostname}%"))
    if lease_state:
        base = base.where(DHCPLeaseHistory.lease_state == lease_state)
    return base


@router.get("/{server_id}/lease-history", response_model=LeaseHistoryPage)
async def list_lease_history(
    server_id: uuid.UUID,
    db: DB,
    _: CurrentUser,
    since: datetime | None = Query(None, description="ISO 8601 lower bound on expired_at"),
    until: datetime | None = Query(None, description="ISO 8601 upper bound on expired_at"),
    mac: str | None = Query(None, description="Substring match on MAC"),
    ip: str | None = Query(None, description="IP or CIDR — exact / containment match"),
    hostname: str | None = Query(None, description="Hostname substring match"),
    lease_state: str | None = Query(None, description="Filter by lease_state"),
    page: int = Query(1, ge=1, le=MAX_PAGE),
    per_page: int = Query(50, ge=1, le=500),
) -> LeaseHistoryPage:
    server = await db.get(DHCPServer, server_id)
    if server is None:
        raise HTTPException(status_code=404, detail="Server not found")

    if since is None:
        since = datetime.now(UTC) - timedelta(days=90)
    if until is None:
        until = datetime.now(UTC)
    if lease_state is not None and lease_state not in VALID_LEASE_HISTORY_STATES:
        raise HTTPException(
            status_code=422,
            detail=f"lease_state must be one of {sorted(VALID_LEASE_HISTORY_STATES)}",
        )

    base = select(DHCPLeaseHistory).where(DHCPLeaseHistory.server_id == server_id)
    base = base.where(DHCPLeaseHistory.expired_at >= since)
    base = base.where(DHCPLeaseHistory.expired_at <= until)

    base = apply_lease_history_filters(
        base, mac=mac, ip=ip, hostname=hostname, lease_state=lease_state
    )

    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
    rows = (
        (
            await db.execute(
                base.order_by(DHCPLeaseHistory.expired_at.desc())
                .offset((page - 1) * per_page)
                .limit(per_page)
            )
        )
        .scalars()
        .all()
    )

    return LeaseHistoryPage(
        total=int(total or 0),
        page=page,
        per_page=per_page,
        items=[LeaseHistoryRow.model_validate(r) for r in rows],
    )
