"""Fleet-wide DHCP lease search (issue #917).

The per-server routes in ``servers.py`` answer "what is this server handing
out". They cannot answer the question a technician actually starts from —
**"does this MAC have a lease anywhere?"** — without one call per DHCP server
and a client-side merge, and that merge is order-sensitive: page 1 of server A
and page 1 of server B are not the newest rows overall.

The MCP tool ``find_dhcp_leases`` has searched the whole fleet since it was
written, so the capability existed and was reachable only from the copilot.
That asymmetry is what #917 catalogued: non-negotiable #13 guarantees every
REST surface gets a tool, and nothing guarantees the converse.

Both routes here reuse the per-server row shape and enrichment verbatim (see
``_leases.py``) so a client can use one or the other without reshaping.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import cast, func, select

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.api.pagination import DEFAULT_PAGE_SIZE, MAX_PAGE, MAX_PAGE_SIZE, Page, paginate
from app.api.v1.dhcp._leases import LeaseResponse, apply_lease_filters, enrich_leases
from app.api.v1.dhcp.lease_history import (
    VALID_LEASE_HISTORY_STATES,
    LeaseHistoryPage,
    LeaseHistoryRow,
    apply_lease_history_filters,
)
from app.core.permissions import require_resource_permission
from app.models.dhcp import DHCPLease, DHCPLeaseHistory, DHCPServer, DHCPServerGroup
from app.services.dhcp.reprovision import (
    ReprovisionError,
    commit_reprovision,
    preview_reprovision,
)

router = APIRouter(
    tags=["dhcp"],
    dependencies=[Depends(require_resource_permission("dhcp_server"))],
)


async def _server_ids_for_group(db: DB, group_id: uuid.UUID) -> list[uuid.UUID]:
    """Every server in a group, for the ``group_id`` filter.

    Leases carry ``server_id``, not a group — the group lives on the server
    row as ``server_group_id`` — so the filter resolves to an ``IN`` rather
    than a join, which keeps the ordering index on ``last_seen_at`` usable.

    404s an unknown group, and returns an EMPTY LIST for a real group that
    happens to have no servers. Those are genuinely different answers — one is
    the caller's mistake, the other is a true statement about the fleet — and
    an earlier cut collapsed them into a 404, so a freshly-created group looked
    like a typo.
    """
    if not await db.get(DHCPServerGroup, group_id):
        raise HTTPException(status_code=404, detail="Server group not found")
    return list(
        (await db.execute(select(DHCPServer.id).where(DHCPServer.server_group_id == group_id)))
        .scalars()
        .all()
    )


def _restrict_to_servers(query: Any, column: Any, server_ids: list[uuid.UUID]) -> Any:
    """Apply the group filter, including the empty case.

    ``in_([])`` is valid SQL that matches nothing, which is exactly right for a
    group with no servers — spelled out because the obvious ``if server_ids``
    guard silently turns it into "no filter at all".
    """
    return query.where(column.in_(server_ids))


def _exact_ip(column: Any, value: str) -> Any:
    """Host-equality on an INET column, family-agnostic.

    ``func.host()`` on both sides so ``10.0.0.5`` matches a row stored as
    ``10.0.0.5/32`` — the shape the Kea pull writes for a v6 lease. A plain
    ``==`` misses those, which reads as "this MAC has no lease" and is the
    single worst wrong answer this endpoint can give.
    """
    return func.host(column) == func.host(cast(value, column.type))


@router.get("/leases", response_model=Page[LeaseResponse])
async def list_all_leases(
    db: DB,
    _: CurrentUser,
    search: str | None = Query(None, description="substring over ip / mac / hostname"),
    mac: str | None = Query(None, description="exact MAC match (any common separator form)"),
    ip: str | None = Query(None, description="exact IP match"),
    state: str | None = Query(None, description="exact lease state filter"),
    device_class: str | None = Query(None, description="fingerbank device class"),
    server_id: uuid.UUID | None = Query(None, description="restrict to one DHCP server"),
    group_id: uuid.UUID | None = Query(None, description="restrict to one DHCP server group"),
    scope_id: uuid.UUID | None = Query(None, description="restrict to one scope"),
    page: int = Query(1, ge=1, le=MAX_PAGE),
    page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
) -> Page[LeaseResponse]:
    """Active leases across every DHCP server, newest-seen first.

    ``search`` is the substring form the UI grid uses; ``mac`` and ``ip`` are
    exact-match filters for the "look up this device" flow, where a substring
    match on a MAC would also return a different device whose address happens
    to contain the same bytes.

    Rows carry the same OUI vendor + fingerbank device fields the per-server
    route returns.
    """
    q = apply_lease_filters(
        select(DHCPLease), search=search, state=state, device_class=device_class
    )
    if server_id is not None:
        q = q.where(DHCPLease.server_id == server_id)
    if group_id is not None:
        q = _restrict_to_servers(q, DHCPLease.server_id, await _server_ids_for_group(db, group_id))
    if scope_id is not None:
        q = q.where(DHCPLease.scope_id == scope_id)
    if mac:
        # Compared as MACADDR, NOT cast to text: a ``cast(col, String) == …``
        # is non-sargable and defeats ``ix_dhcp_lease_server_mac`` on this
        # endpoint's flagship query. The bind parameter is normalised first so
        # Postgres's own MACADDR parsing never sees a form it would reject.
        q = q.where(DHCPLease.mac_address == _normalized_mac(mac))
    if ip:
        q = q.where(_exact_ip(DHCPLease.ip_address, _validated_ip(ip)))

    q = q.order_by(DHCPLease.last_seen_at.desc())
    rows, total = await paginate(db, q, page=page, page_size=page_size)
    await enrich_leases(db, rows)
    return Page[LeaseResponse](
        items=[LeaseResponse.model_validate(lease) for lease in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/lease-history", response_model=LeaseHistoryPage)
async def list_all_lease_history(
    db: DB,
    _: CurrentUser,
    since: datetime | None = Query(None, description="ISO 8601 lower bound on expired_at"),
    until: datetime | None = Query(None, description="ISO 8601 upper bound on expired_at"),
    mac: str | None = Query(None, description="Substring match on MAC"),
    ip: str | None = Query(None, description="IP or CIDR — exact / containment match"),
    hostname: str | None = Query(None, description="Hostname substring match"),
    lease_state: str | None = Query(None, description="Filter by lease_state"),
    server_id: uuid.UUID | None = Query(None, description="restrict to one DHCP server"),
    group_id: uuid.UUID | None = Query(None, description="restrict to one DHCP server group"),
    page: int = Query(1, ge=1, le=MAX_PAGE),
    per_page: int = Query(50, ge=1, le=500),
) -> LeaseHistoryPage:
    """Expired / released leases across every server — "has this MAC ever
    had a lease here?".

    Same filters and row shape as the per-server route, with the server
    restriction moved from the path to an optional query parameter. The
    default window is the trailing 90 days, matching the per-server route (and
    the retention default it is bounded by).
    """
    if since is None:
        since = datetime.now(UTC) - timedelta(days=90)
    if until is None:
        until = datetime.now(UTC)
    if lease_state is not None and lease_state not in VALID_LEASE_HISTORY_STATES:
        raise HTTPException(
            status_code=422,
            detail=f"lease_state must be one of {sorted(VALID_LEASE_HISTORY_STATES)}",
        )

    base = select(DHCPLeaseHistory).where(
        DHCPLeaseHistory.expired_at >= since, DHCPLeaseHistory.expired_at <= until
    )
    if server_id is not None:
        base = base.where(DHCPLeaseHistory.server_id == server_id)
    if group_id is not None:
        base = _restrict_to_servers(
            base, DHCPLeaseHistory.server_id, await _server_ids_for_group(db, group_id)
        )
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


class ReprovisionPlanOut(BaseModel):
    """A re-provision plan (#1287); the commit adds the two ids it created."""

    lease_id: str
    scope_id: str
    subnet: str
    mac_address: str
    old_ip: str
    old_hostname: str
    target_ip: str
    target_source: str = Field(description="requested | reserved_pool | outside_dynamic_pools")
    target_reason: str
    hostname: str
    fqdn: str | None
    dns_create: list[str]
    dns_remove: list[str]
    ipam_remove: list[str]
    ipam_create: str
    old_lease: str = Field(description="kept_until_moved | removed_now")
    servers: list[str]
    expected_move: str
    t1_at: datetime | None
    warnings: list[str]
    static_assignment_id: str | None = None
    ip_address_id: str | None = None


class ReprovisionCommit(BaseModel):
    """Commit body: the target from the preview, and the name it showed."""

    target_ip: str = Field(description="Static address to move the device to (from the preview).")
    hostname: str | None = Field(
        default=None, description="New host name (single label); default: the lease's."
    )


@router.get("/leases/{lease_id}/reprovision/preview", response_model=ReprovisionPlanOut)
async def preview_lease_reprovision(
    lease_id: uuid.UUID,
    db: DB,
    _: CurrentUser,
    target_ip: str | None = Query(None, description="override the picked static address"),
    hostname: str | None = Query(None, description="new host name; default: the lease's"),
) -> dict[str, Any]:
    """What re-provisioning this lease onto a static address would do (#1287).

    Read-only. Picks the first free address in the scope's reserved pools (or,
    without one, outside every dynamic pool), and lists the reservation, the
    DNS records created and removed, and when the device is expected to move.
    """
    try:
        plan = await preview_reprovision(db, lease_id, target_ip=target_ip, hostname=hostname)
    except ReprovisionError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    return plan.as_dict()


@router.post("/leases/{lease_id}/reprovision", response_model=ReprovisionPlanOut)
async def commit_lease_reprovision(
    lease_id: uuid.UUID, body: ReprovisionCommit, db: DB, user: SuperAdmin
) -> dict[str, Any]:
    """Move a leased device to a static address: reservation + DNS, lease gone.

    Re-validates everything the preview checked. Superadmin, like the two
    steps it replaces (creating a reservation, deleting a lease).
    """
    try:
        return await commit_reprovision(
            db, user, lease_id, target_ip=body.target_ip, hostname=body.hostname
        )
    except ReprovisionError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


def _normalized_mac(value: str) -> str:
    """Canonicalise a MAC to the ``aa:bb:cc:dd:ee:ff`` form Postgres stores.

    Operators paste MACs in whichever form their last tool printed —
    ``AA-BB-CC-DD-EE-FF``, ``aabb.ccdd.eeff``, bare hex. Comparing the raw
    string against a MACADDR cast would silently miss every one of those, and
    a lookup that answers "no lease" for a device that has one is worse than
    an error.
    """
    from app.services.oui import normalize_mac_key  # noqa: PLC0415

    key = normalize_mac_key(value)
    if not key or len(key) != 12:
        raise HTTPException(status_code=422, detail=f"{value!r} is not a MAC address")
    return ":".join(key[i : i + 2] for i in range(0, 12, 2))


def _validated_ip(value: str) -> str:
    """Reject anything that is not a bare IP before it reaches an INET cast.

    An unparseable literal raises a ``DBAPIError`` from the driver rather than
    a 422, which surfaces to the client as a 500 on its own bad input.
    """
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"{value!r} is not an IP address") from exc
