"""DHCP pool CRUD under /scopes/{scope_id}/pools."""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.api.v1.dhcp._audit import write_audit
from app.api.v1.dhcp.scopes import validate_dhcp_options
from app.core.agent_wake import collect_wake, dhcp_group_channel
from app.core.permissions import require_resource_permission
from app.core.update_nulls import resolve_update_changes
from app.models.dhcp import DHCPClientClass, DHCPLease, DHCPPool, DHCPScope, DHCPServerGroup
from app.models.ipam import IPAddress, Subnet
from app.services.dhcp.option_validation import normalize_options
from app.services.dhcp.pool_occupancy import (
    PoolOccupancy,
    compute_pool_occupancy_batch,
)
from app.services.dhcp.windows_writethrough import push_pool_change

router = APIRouter(tags=["dhcp"], dependencies=[Depends(require_resource_permission("dhcp_pool"))])

# ``pd`` = DHCPv6 prefix-delegation pool (issue #368). For a pd pool the
# start_ip/end_ip range is ignored — the delegation is described by
# pd_prefix / delegated_length / excluded_prefix instead.
VALID_POOL_TYPES = {"dynamic", "excluded", "reserved", "pd"}


class PoolCreate(BaseModel):
    name: str = ""
    # Optional for pd pools (derived from pd_prefix); required for v4 ranges.
    start_ip: str | None = None
    end_ip: str | None = None
    pool_type: str = "dynamic"
    class_restriction: str | None = None
    lease_time_override: int | None = None
    options_override: dict[str, Any] | None = None
    # DHCPv6 prefix delegation (issue #368) — only for pool_type == "pd".
    pd_prefix: str | None = None
    delegated_length: int | None = None
    excluded_prefix: str | None = None

    @field_validator("pool_type")
    @classmethod
    def _p(cls, v: str) -> str:
        if v not in VALID_POOL_TYPES:
            raise ValueError(f"pool_type must be one of {sorted(VALID_POOL_TYPES)}")
        return v


class PoolUpdate(BaseModel):
    name: str | None = None
    start_ip: str | None = None
    end_ip: str | None = None
    pool_type: str | None = None
    class_restriction: str | None = None
    lease_time_override: int | None = None
    options_override: dict[str, Any] | None = None
    pd_prefix: str | None = None
    delegated_length: int | None = None
    excluded_prefix: str | None = None


class PoolResponse(BaseModel):
    id: uuid.UUID
    scope_id: uuid.UUID
    name: str
    start_ip: str
    end_ip: str
    pool_type: str
    class_restriction: str | None
    lease_time_override: int | None
    options_override: dict[str, Any] | None
    pd_prefix: str | None = None
    delegated_length: int | None = None
    excluded_prefix: str | None = None
    existing_ips_in_range: list[dict[str, str]] | None = None
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}

    @field_validator("start_ip", "end_ip", mode="before")
    @classmethod
    def _inet_to_str(cls, v: Any) -> Any:
        return str(v) if v is not None else v


def _ip_int(ip_str: str) -> int:
    # Family-agnostic so a v6 (address or pd) pool in the scope doesn't blow up
    # the overlap scan with an IPv4Address ValueError (#368).
    return int(ipaddress.ip_address(ip_str))


def _validate_pd(
    pd_prefix: str | None, delegated_length: int | None, excluded_prefix: str | None
) -> tuple[ipaddress.IPv6Network, str]:
    """Validate a DHCPv6 prefix-delegation pool (issue #368). Returns the
    parsed prefix network. 422 on any malformed input. Shared by create + update."""
    if not pd_prefix or not delegated_length:
        raise HTTPException(
            status_code=422,
            detail="pd pools require pd_prefix and delegated_length",
        )
    try:
        net = ipaddress.ip_network(pd_prefix, strict=False)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"invalid pd_prefix: {exc}") from exc
    if not isinstance(net, ipaddress.IPv6Network):
        raise HTTPException(status_code=422, detail="pd_prefix must be an IPv6 prefix")
    dl = int(delegated_length)
    if dl < net.prefixlen or dl > 128:
        raise HTTPException(
            status_code=422,
            detail=(
                f"delegated_length {dl} must be between the pd_prefix length "
                f"{net.prefixlen} and 128"
            ),
        )
    if excluded_prefix:
        try:
            ex = ipaddress.ip_network(excluded_prefix, strict=False)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"invalid excluded_prefix: {exc}") from exc
        if not isinstance(ex, ipaddress.IPv6Network) or not ex.subnet_of(net):
            raise HTTPException(
                status_code=422,
                detail="excluded_prefix must be an IPv6 sub-prefix of pd_prefix",
            )
        # RFC 6603: the excluded prefix is carved out of each delegated prefix,
        # so it must be strictly longer than the delegated length — Kea rejects
        # the config otherwise (#368 review).
        if ex.prefixlen <= dl:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"excluded_prefix length {ex.prefixlen} must be greater than "
                    f"delegated_length {dl}"
                ),
            )
    return net, str(net.network_address)


async def _check_class_family(db: AsyncSession, scope: DHCPScope, name: str | None) -> None:
    """422 when a pool restricts to an operator client class its daemon does
    not define (#1229). Kea accepts the reference, so the pool would silently
    match no one. A name that is not an operator class (a generated PXE /
    phone / device-policy class, or Kea's built-in ``KNOWN``) is not checked."""
    if not name:
        return
    cc = (
        await db.execute(
            select(DHCPClientClass).where(
                DHCPClientClass.group_id == scope.group_id, DHCPClientClass.name == name
            )
        )
    ).scalar_one_or_none()
    family = scope.address_family or "ipv4"
    if cc is not None and cc.address_family not in (family, "dual"):
        raise HTTPException(
            status_code=422,
            detail=(
                f"Client class '{name}' is {cc.address_family}-only, so it is not "
                f"defined in this {family} scope's daemon and the pool would match "
                "no client. Change the class's address family first."
            ),
        )


async def _check_pool_overlap(
    db: AsyncSession,
    scope_id: uuid.UUID,
    start: str,
    end: str,
    exclude_id: uuid.UUID | None = None,
) -> str | None:
    """Return an error message if the given range overlaps any existing pool in the scope."""
    new_start, new_end = _ip_int(start), _ip_int(end)
    if new_start > new_end:
        return f"start_ip ({start}) must be <= end_ip ({end})"
    res = await db.execute(select(DHCPPool).where(DHCPPool.scope_id == scope_id))
    for p in res.scalars().all():
        if exclude_id and p.id == exclude_id:
            continue
        # pd pools (#368) carry a prefix network address in start/end_ip as a
        # NOT-NULL placeholder, not an address range — they never overlap an
        # address pool, so skip them (also avoids comparing across families).
        if p.pool_type == "pd":
            continue
        ps, pe = _ip_int(str(p.start_ip)), _ip_int(str(p.end_ip))
        if new_start <= pe and new_end >= ps:
            return (
                f"Range {start}–{end} overlaps existing pool "
                f"'{p.name or p.id}' ({p.start_ip}–{p.end_ip})"
            )
    return None


async def _existing_ips_in_range(
    db: AsyncSession, subnet_id: uuid.UUID, start: str, end: str
) -> list[dict[str, str]]:
    """Return IPAM addresses that fall inside the given range and aren't 'available'."""
    res = await db.execute(select(IPAddress).where(IPAddress.subnet_id == subnet_id))
    s, e = _ip_int(start), _ip_int(end)
    hits: list[dict[str, str]] = []
    for ip in res.scalars().all():
        v = _ip_int(str(ip.address))
        if s <= v <= e and ip.status not in ("available", "network", "broadcast"):
            hits.append(
                {
                    "address": str(ip.address),
                    "status": ip.status,
                    "hostname": ip.hostname or "",
                }
            )
    return hits


@router.get("/scopes/{scope_id}/pools", response_model=list[PoolResponse])
async def list_pools(scope_id: uuid.UUID, db: DB, _: CurrentUser) -> list[DHCPPool]:
    res = await db.execute(select(DHCPPool).where(DHCPPool.scope_id == scope_id))
    return list(res.scalars().all())


@router.post(
    "/scopes/{scope_id}/pools",
    response_model=PoolResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_pool(
    scope_id: uuid.UUID, body: PoolCreate, db: DB, user: SuperAdmin
) -> PoolResponse:
    scope = await db.get(DHCPScope, scope_id)
    if scope is None:
        raise HTTPException(status_code=404, detail="Scope not found")
    if body.options_override:
        body.options_override = normalize_options(body.options_override)
        await validate_dhcp_options(
            db,
            body.options_override,
            group_id=None,  # rendered by Kea / FortiGate only (#1296)
            address_family=scope.address_family or "ipv4",
        )
    await _check_class_family(db, scope, body.class_restriction)

    if body.pool_type == "pd":
        # DHCPv6 prefix-delegation pool (issue #368). No v4 range / overlap
        # logic — validate the prefix + delegated length, then store the
        # prefix network address in start_ip/end_ip (NOT NULL placeholders).
        net, _start = _validate_pd(body.pd_prefix, body.delegated_length, body.excluded_prefix)
        values = body.model_dump()
        values["start_ip"] = str(net.network_address)
        values["end_ip"] = str(net.network_address)
        pool = DHCPPool(scope_id=scope_id, **values)
        db.add(pool)
        await db.flush()
        collect_wake(dhcp_group_channel(scope.group_id))
        write_audit(
            db,
            user=user,
            action="create",
            resource_type="dhcp_pool",
            resource_id=str(pool.id),
            resource_display=f"pd {body.pd_prefix} /{body.delegated_length}",
            new_value=body.model_dump(mode="json"),
        )
        await db.commit()
        await db.refresh(pool)
        return PoolResponse.model_validate(pool, from_attributes=True)

    if not body.start_ip or not body.end_ip:
        raise HTTPException(status_code=422, detail="start_ip and end_ip are required")
    overlap = await _check_pool_overlap(db, scope_id, body.start_ip, body.end_ip)
    if overlap:
        raise HTTPException(status_code=409, detail=overlap)
    pool = DHCPPool(scope_id=scope_id, **body.model_dump())
    db.add(pool)
    await db.flush()
    await push_pool_change(db, pool, action="create")
    collect_wake(dhcp_group_channel(scope.group_id))
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="dhcp_pool",
        resource_id=str(pool.id),
        resource_display=f"{body.start_ip}-{body.end_ip}",
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(pool)
    existing = await _existing_ips_in_range(db, scope.subnet_id, body.start_ip, body.end_ip)
    resp = PoolResponse.model_validate(pool, from_attributes=True)
    resp.existing_ips_in_range = existing or None
    return resp


@router.put("/pools/{pool_id}", response_model=PoolResponse)
async def update_pool(pool_id: uuid.UUID, body: PoolUpdate, db: DB, user: SuperAdmin) -> DHCPPool:
    pool = await db.get(DHCPPool, pool_id)
    if pool is None:
        raise HTTPException(status_code=404, detail="Pool not found")
    # Snapshot the old range BEFORE mutating, so we can remove the old
    # exclusion from Windows if it shifted.
    prev_start = str(pool.start_ip)
    prev_end = str(pool.end_ip)
    new_start = body.start_ip or prev_start
    new_end = body.end_ip or prev_end
    effective_type = body.pool_type if body.pool_type is not None else pool.pool_type
    if effective_type == "pd":
        # Re-validate the (merged) pd fields so a bad edit can't silently make a
        # working pd pool unrenderable (#368). Re-sync start/end placeholders to
        # the (possibly new) prefix network address.
        net, net_addr = _validate_pd(
            body.pd_prefix if body.pd_prefix is not None else pool.pd_prefix,
            body.delegated_length if body.delegated_length is not None else pool.delegated_length,
            body.excluded_prefix if body.excluded_prefix is not None else pool.excluded_prefix,
        )
        pool.start_ip = net_addr  # type: ignore[assignment]
        pool.end_ip = net_addr  # type: ignore[assignment]
    elif body.start_ip or body.end_ip:
        overlap = await _check_pool_overlap(
            db, pool.scope_id, new_start, new_end, exclude_id=pool.id
        )
        if overlap:
            raise HTTPException(status_code=409, detail=overlap)
    # #1563 — explicit null CLEARS the nullable pool fields (the UI's
    # "none" for class_restriction / PD fields sent null and the old
    # exclude_none silently kept the old value); null for a NOT NULL
    # pool column is a 422 instead.
    changes = resolve_update_changes(
        body,
        clearable={
            "class_restriction",
            "lease_time_override",
            "options_override",
            "pd_prefix",
            "delegated_length",
            "excluded_prefix",
        },
        non_nullable={"name", "start_ip", "end_ip", "pool_type"},
    )
    scope = await db.get(DHCPScope, pool.scope_id)
    if scope is not None and changes.get("class_restriction") not in (None, pool.class_restriction):
        await _check_class_family(db, scope, changes["class_restriction"])
    if changes.get("options_override"):
        changes["options_override"] = normalize_options(changes["options_override"])
        await validate_dhcp_options(
            db,
            changes["options_override"],
            group_id=None,  # rendered by Kea / FortiGate only (#1296)
            address_family=(scope.address_family if scope else None) or "ipv4",
            previous=pool.options_override or {},
        )
    for k, v in changes.items():
        setattr(pool, k, v)
    await db.flush()
    await push_pool_change(db, pool, action="update", prev_start=prev_start, prev_end=prev_end)
    if scope is not None:
        collect_wake(dhcp_group_channel(scope.group_id))
    write_audit(
        db,
        user=user,
        action="update",
        resource_type="dhcp_pool",
        resource_id=str(pool.id),
        resource_display=f"{pool.start_ip}-{pool.end_ip}",
        changed_fields=list(changes.keys()),
        new_value=body.model_dump(mode="json", exclude_unset=True),
    )
    await db.commit()
    await db.refresh(pool)
    return pool


@router.delete("/pools/{pool_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_pool(pool_id: uuid.UUID, db: DB, user: SuperAdmin) -> None:
    pool = await db.get(DHCPPool, pool_id)
    if pool is None:
        raise HTTPException(status_code=404, detail="Pool not found")
    scope = await db.get(DHCPScope, pool.scope_id)
    if scope is not None:
        collect_wake(dhcp_group_channel(scope.group_id))
    await push_pool_change(db, pool, action="delete")
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="dhcp_pool",
        resource_id=str(pool.id),
        resource_display=f"{pool.start_ip}-{pool.end_ip}",
    )
    await db.delete(pool)
    await db.commit()


# ── Occupancy (issue #913) ───────────────────────────────────────────
#
# ``services/dhcp/pool_occupancy.py`` has computed this since #339, but
# nothing HTTP called it — it was reachable only from the
# ``find_dhcp_pool_occupancy`` MCP tool and the ``dhcp_pool_exhaustion``
# alert evaluator. So "is this pool full?", which is the first question
# asked when a client cannot get an address, could only be answered by a
# caller that fetched pools + leases + reservations and redid the range
# arithmetic itself — three round trips and an easy thing to get subtly
# wrong, and a wrong "the pool is fine" sends the technician to the
# wrong place.


class PoolOccupancyResponse(BaseModel):
    """Live occupancy of one address-range pool.

    ``assigned`` unions active leases with in-pool static reservations, so
    a reserved-but-offline address counts as unavailable (#631) and a
    reserved-and-currently-leased one is not double-counted.
    """

    pool_id: uuid.UUID
    scope_id: uuid.UUID
    pool_name: str
    start_ip: str
    end_ip: str
    pool_type: str
    total: int
    assigned: int
    free: int
    percent: float
    #: Occupancy is derived at request time from mirrored lease rows, whose
    #: freshness depends on the last lease pull — so the caller is told
    #: when the number was computed rather than being left to assume it is
    #: instantaneous.
    computed_at: datetime


#: Occupancy is a *dynamic-allocation* question — "can a client still get
#: an address from here" — so it is answered for dynamic pools only, which
#: is also what the ``dhcp_pool_exhaustion`` alert evaluator and the
#: ``find_dhcp_pool_occupancy`` MCP tool already filter to. Reporting it
#: for the other types would disagree with both:
#:
#: * an ``excluded`` range is one DHCP will never offer, so a percentage
#:   full is not a fact about it at all;
#: * a ``reserved`` range is held for static assignments, so a correctly
#:   configured one is *supposed* to approach 100% and would render as a
#:   red exhaustion bar for doing its job;
#: * a ``pd`` pool (#368) stores its prefix's network address in both
#:   ``start_ip`` and ``end_ip`` as NOT NULL placeholders rather than a
#:   range, so the arithmetic yields a one-address pool at 0% — a number
#:   that looks like an answer and is not one.
_OCCUPANCY_POOL_TYPE = "dynamic"


def _not_applicable(pool_type: str) -> str:
    if pool_type == "pd":
        return (
            "Prefix-delegation pools have no address-range occupancy — "
            "start_ip/end_ip are placeholders for the delegated prefix, not a range."
        )
    return (
        f"Occupancy is only meaningful for dynamic pools; this one is "
        f"{pool_type!r}. An excluded range is never offered to a client, and a "
        f"reserved range is supposed to fill up."
    )


def _occupancy_row(
    pool: DHCPPool, occ: PoolOccupancy, computed_at: datetime
) -> PoolOccupancyResponse:
    return PoolOccupancyResponse(
        pool_id=pool.id,
        scope_id=pool.scope_id,
        pool_name=pool.name or "",
        start_ip=str(pool.start_ip),
        end_ip=str(pool.end_ip),
        pool_type=pool.pool_type,
        total=occ.total,
        assigned=occ.assigned,
        free=occ.free,
        percent=round(occ.percent, 2),
        computed_at=computed_at,
    )


@router.get("/pools/{pool_id}/occupancy", response_model=PoolOccupancyResponse)
async def pool_occupancy(pool_id: uuid.UUID, db: DB, _: CurrentUser) -> PoolOccupancyResponse:
    """Live occupancy of one pool — assigned / total / free / percent."""
    pool = await db.get(DHCPPool, pool_id)
    if pool is None:
        raise HTTPException(status_code=404, detail="Pool not found")
    if pool.pool_type != _OCCUPANCY_POOL_TYPE:
        raise HTTPException(status_code=422, detail=_not_applicable(pool.pool_type))
    occ = (await compute_pool_occupancy_batch(db, [pool]))[pool.id]
    return _occupancy_row(pool, occ, datetime.now(UTC))


# ── Fleet-wide occupancy (issue #942) ────────────────────────────────
#
# The dashboard's DHCP tab needs "which pools are fullest, across every
# scope" and must not answer it by fanning out one call per scope. The
# filters here are deliberately IDENTICAL to the per-scope endpoint and
# to the ``dhcp_pool_exhaustion`` alert evaluator: dynamic pools only,
# and no ``is_active`` filter on the parent scope. That last one is a
# choice, not an oversight — the evaluator does not filter on it either,
# and a surface that quietly dropped rows the alerting still fires on is
# precisely how an operator ends up reading "the pool is fine" about a
# pool that is paging someone. Inactive scopes are flagged in the row
# instead, so the UI can annotate without the API deciding for it.


class FleetPoolOccupancyRow(PoolOccupancyResponse):
    """One pool, plus the context needed to identify it without a
    follow-up call — a pool name alone is frequently empty, and a
    ``pool_id`` is not something an operator can act on."""

    scope_name: str
    scope_is_active: bool
    subnet_network: str | None
    group_id: uuid.UUID
    group_name: str


class FleetPoolOccupancyResponse(BaseModel):
    computed_at: datetime
    #: Every dynamic pool considered, not just the returned slice — so a
    #: caller can say "3 of 47" rather than implying the top-N is all of
    #: them.
    pool_count: int
    pools_warning: int
    pools_critical: int
    #: Distinct ``(scope, address)`` pairs in an active lease, fleet-wide.
    #: DISTINCT, not COUNT(*): ``dhcp_lease`` is per-server and a Kea HA
    #: pair mirrors every lease twice, so a row count reports 2x on
    #: exactly the deployments where the number matters — and would
    #: disagree with both ``pool_occupancy.py`` and the #889 InfluxDB
    #: exporter, which dedupe for the same reason. Pairing with the scope
    #: keeps this equal to the sum of that exporter's per-scope series.
    active_lease_count: int
    pools: list[FleetPoolOccupancyRow]


#: Occupancy bands for the fleet rollup. Same numbers the subnet
#: utilization heatmap uses, so "amber" means the same thing wherever an
#: operator sees it on this dashboard.
_POOL_WARNING_PERCENT = 80.0
_POOL_CRITICAL_PERCENT = 95.0


@router.get("/pools/occupancy", response_model=FleetPoolOccupancyResponse)
async def fleet_pool_occupancy(
    db: DB,
    _: CurrentUser,
    limit: int = Query(10, ge=1, le=200),
) -> FleetPoolOccupancyResponse:
    """Dynamic pools across every scope, fullest first.

    Answers the DHCP dashboard's headline question — "can clients still
    get an address anywhere" — in one round trip and a fixed number of
    queries: the pool fetch, one batched lease + reservation pass, the
    lease count, and name resolution for the returned slice only.

    Fixed query *count*, not fixed *work*: the batched pass reads every
    active lease and reservation in the scopes that own a dynamic pool,
    so it scales with the lease table rather than with ``limit``, which
    bounds only the rendered slice. That is deliberate — it is the same
    scan ``compute_pool_occupancy_batch`` already performs for the
    per-scope endpoint and for the ``dhcp_pool_exhaustion`` evaluator on
    its own tick, and re-deriving occupancy in SQL here would be a
    fourth implementation of the range arithmetic that could disagree
    with the other three. If this becomes hot, push the range containment
    into the shared helper so every caller benefits.
    """
    pools = list(
        (await db.execute(select(DHCPPool).where(DHCPPool.pool_type == _OCCUPANCY_POOL_TYPE)))
        .scalars()
        .all()
    )
    computed_at = datetime.now(UTC)
    occ_by_pool = await compute_pool_occupancy_batch(db, pools)

    # A zero-size pool (malformed or inverted range) reports 0/0 at 0%.
    # It is counted in ``pool_count`` — it exists and is misconfigured —
    # but must never outrank a genuinely full pool in the ranking.
    ranked = sorted(
        pools,
        key=lambda p: (occ_by_pool[p.id].percent, occ_by_pool[p.id].assigned),
        reverse=True,
    )
    pools_warning = sum(1 for p in pools if occ_by_pool[p.id].percent >= _POOL_WARNING_PERCENT)
    pools_critical = sum(1 for p in pools if occ_by_pool[p.id].percent >= _POOL_CRITICAL_PERCENT)

    lease_pairs = (
        select(DHCPLease.scope_id, DHCPLease.ip_address)
        .where(DHCPLease.scope_id.is_not(None), DHCPLease.state == "active")
        .distinct()
        .subquery()
    )
    active_lease_count = (
        await db.execute(select(func.count()).select_from(lease_pairs))
    ).scalar_one()

    top = ranked[:limit]
    # Resolve display context for the returned slice only — three
    # queries, independent of how many pools the fleet has.
    scope_ids = {p.scope_id for p in top}
    scopes: dict[uuid.UUID, DHCPScope] = {}
    if scope_ids:
        scopes = {
            s.id: s
            for s in (await db.execute(select(DHCPScope).where(DHCPScope.id.in_(scope_ids))))
            .scalars()
            .all()
        }
    subnet_ids = {s.subnet_id for s in scopes.values()}
    networks: dict[uuid.UUID, str] = {}
    if subnet_ids:
        networks = {
            row[0]: str(row[1])
            for row in (
                await db.execute(select(Subnet.id, Subnet.network).where(Subnet.id.in_(subnet_ids)))
            ).all()
        }
    group_ids = {s.group_id for s in scopes.values()}
    group_names: dict[uuid.UUID, str] = {}
    if group_ids:
        group_names = {
            row[0]: row[1]
            for row in (
                await db.execute(
                    select(DHCPServerGroup.id, DHCPServerGroup.name).where(
                        DHCPServerGroup.id.in_(group_ids)
                    )
                )
            ).all()
        }

    rows: list[FleetPoolOccupancyRow] = []
    for pool in top:
        scope = scopes.get(pool.scope_id)
        base = _occupancy_row(pool, occ_by_pool[pool.id], computed_at)
        rows.append(
            FleetPoolOccupancyRow(
                **base.model_dump(),
                scope_name=(scope.name if scope else "") or "",
                scope_is_active=scope.is_active if scope else False,
                subnet_network=networks.get(scope.subnet_id) if scope else None,
                # A pool always has a scope (FK, CASCADE) and a scope always
                # has a group. The fallbacks exist only so a row mid-delete
                # degrades instead of 500-ing the whole panel.
                group_id=scope.group_id if scope else uuid.UUID(int=0),
                group_name=(group_names.get(scope.group_id, "") if scope else "") or "",
            )
        )

    return FleetPoolOccupancyResponse(
        computed_at=computed_at,
        pool_count=len(pools),
        pools_warning=pools_warning,
        pools_critical=pools_critical,
        active_lease_count=int(active_lease_count),
        pools=rows,
    )


@router.get("/scopes/{scope_id}/pools/occupancy", response_model=list[PoolOccupancyResponse])
async def scope_pool_occupancy(
    scope_id: uuid.UUID, db: DB, _: CurrentUser
) -> list[PoolOccupancyResponse]:
    """Live occupancy of every dynamic pool in a scope, in one call.

    The scope-level shape is the one that matters operationally: a scope
    with several pools is exactly where a call-per-pool is wasteful, and
    also where "the scope looks fine" hides one exhausted class-restricted
    pool. Non-dynamic pools are omitted rather than reported at a number
    that is not a fact about them — see :data:`_OCCUPANCY_POOL_TYPE`.
    """
    scope = await db.get(DHCPScope, scope_id)
    if scope is None:
        raise HTTPException(status_code=404, detail="Scope not found")
    res = await db.execute(
        select(DHCPPool)
        .where(DHCPPool.scope_id == scope_id)
        .where(DHCPPool.pool_type == _OCCUPANCY_POOL_TYPE)
        .order_by(DHCPPool.start_ip)
    )
    pools = list(res.scalars().all())
    # One batched lease + reservation query for every pool, not one per
    # pool — the whole point of answering at the scope level.
    occ_by_pool = await compute_pool_occupancy_batch(db, pools)
    computed_at = datetime.now(UTC)
    return [_occupancy_row(p, occ_by_pool[p.id], computed_at) for p in pools]
