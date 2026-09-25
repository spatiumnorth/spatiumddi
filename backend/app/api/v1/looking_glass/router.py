"""BGP Looking Glass — operator CRUD + read surface (issue #566).

Mounted at ``/looking-glass`` (NOT ``/bgp`` — that's the #527 public-table
hijack monitor router, gated on the ``network.asn`` module). This router is
gated on its own ``network.looking_glass`` feature module by the top-level
``app.api.v1.router`` include (not wired here — see that file).

Endpoints:

* ``/collectors`` — list/get/rename/enable/disable/delete. Registration is
  agent-side (``POST /looking-glass/agents/register`` in ``agents.py``);
  operators never create a collector row directly. Deleting a collector
  cascades its peers (``bgp_lg_peer.collector_id`` FK ``ON DELETE CASCADE``)
  and, transitively, their routes (``bgp_lg_route.peer_id`` FK
  ``ON DELETE CASCADE``) — no manual cleanup needed here.
* ``/peers`` — full CRUD on a configured BGP session. The MD5 password is
  Fernet-encrypted on write and never returned in plaintext; responses carry
  ``md5_password_set: bool`` instead. Every mutation collects a wake on the
  owning collector's channel (post-commit flush is the caller's
  ``wake_publishing`` router dependency, wired by the integrator) so the
  collector's ConfigBundle long-poll re-fetches its peer set promptly
  instead of waiting for the 12s safety tick.
* ``/sessions`` — read-only per-peer runtime-state rollup (collector +
  peer joined), the Sessions-tab feed.
* ``/routes`` — the learned RIB, server-paginated + filterable, including by
  the ``matched_{block,subnet,space,asn,vrf}_id`` linkage columns populated by
  ``app.services.looking_glass.ipam_link`` (issue #566 Phase 3). ``/routes``
  (list), ``/routes/by-prefix?prefix=`` (all paths for one exact prefix, the
  CIDR passed as a query param so its slash / IPv6 colons encode cleanly),
  ``/routes/detail?prefix=`` (the same all-paths set, enriched with peer/
  collector names + a server-computed summary/IPAM-context rollup — backs the
  Routes-tab detail modal), and ``/routes/for-ip?ip=`` (reverse
  LPM-by-single-address, Phase 3) are distinct URL shapes so there's no route
  collision.
* ``/dashboard-summary`` — single-shot peer/route rollup backing the main
  Dashboard's "Looking Glass health" card (issue #566 Phase 5). See
  ``LookingGlassDashboardSummary`` for why this is its own shape rather than
  the Integrations dashboard tab's ``IntegrationPanel``.
* ``/vrf-rt-matches/{vrf_id}`` — issue #566 Phase 6. Which of a VRF's own
  import/export route targets actually appear on a currently-active route
  matched to that VRF (``matched_vrf_id``, which the VPNv4/VPNv6
  Route-Target cross-check in ``app.services.looking_glass.vrf_match`` now
  populates ahead of the plain IPAM-effective match). Feeds the VRF detail
  page's "Learned VPN Routes" tab.
* ``/multicast-reachability`` — issue #566 Phase 6, read-only. Cross-checks
  PIM domain rendezvous-point addresses and multicast-group producer
  source subnets against the learned RIB. See
  ``app.services.looking_glass.reachability.multicast_bgp_reachability``.

Every write handler writes an ``AuditLog`` row before ``commit()`` per
CLAUDE.md non-negotiable #4.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import DB, CurrentUser
from app.core.agent_wake import collect_wake, looking_glass_collector_channel
from app.core.crypto import encrypt_str
from app.core.permissions import require_resource_permission
from app.models.alerts import AlertEvent, AlertRule
from app.models.asn import ASN
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.bgp_looking_glass import BGPLGPeer, BGPLGRoute, LookingGlassCollector
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.models.network import NetworkDevice
from app.models.vrf import VRF
from app.services.bgp.hijack_monitor import RPKI_INVALID
from app.services.looking_glass.as_path_query import as_path_regexp_clause
from app.services.looking_glass.reverse_lookup import best_route_for_ip
from app.services.looking_glass.vrf_match import normalize_rt

from .schemas import (
    CollectorRead,
    CollectorUpdate,
    DomainReachability,
    GroupSourceReachability,
    LookingGlassDashboardSummary,
    MulticastReachabilityResponse,
    PeerCreate,
    PeerDetailAlert,
    PeerDetailCollector,
    PeerDetailCommunityCount,
    PeerDetailMatchedAsn,
    PeerDetailOriginAsnCount,
    PeerDetailResponse,
    PeerDetailRouter,
    PeerDetailRouteStats,
    PeerDetailRpkiBreakdown,
    PeerRead,
    PeerUpdate,
    RouteDetailIpamContext,
    RouteDetailPath,
    RouteDetailResponse,
    RouteDetailSummary,
    RouteForIpResponse,
    RouteListResponse,
    RouteRead,
    SessionRead,
    VrfRtMatchRow,
    VrfRtMatchSummary,
)

router = APIRouter(
    tags=["looking-glass"],
    dependencies=[Depends(require_resource_permission("bgp_lg_peer"))],
)


# ── Audit helper (mirrors app.api.v1.dhcp._audit.write_audit) ──────────


def _write_audit(
    db: AsyncSession,
    *,
    user: User | None,
    action: str,
    resource_type: str,
    resource_id: uuid.UUID,
    resource_display: str,
    changed_fields: list[str] | None = None,
    new_value: dict[str, Any] | None = None,
) -> None:
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            user_display_name=user.display_name if user else "system",
            auth_source=getattr(user, "auth_source", "local") or "local",
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id),
            resource_display=resource_display,
            changed_fields=changed_fields,
            new_value=new_value,
        )
    )


# ── Collectors ──────────────────────────────────────────────────────────


def _collector_to_read(c: LookingGlassCollector) -> CollectorRead:
    return CollectorRead.model_validate(c)


@router.get("/collectors", response_model=list[CollectorRead])
async def list_collectors(db: DB, _: CurrentUser) -> list[CollectorRead]:
    rows = (
        (await db.execute(select(LookingGlassCollector).order_by(LookingGlassCollector.name)))
        .scalars()
        .all()
    )
    return [_collector_to_read(c) for c in rows]


@router.get("/collectors/{collector_id}", response_model=CollectorRead)
async def get_collector(collector_id: uuid.UUID, db: DB, _: CurrentUser) -> CollectorRead:
    c = await db.get(LookingGlassCollector, collector_id)
    if c is None:
        raise HTTPException(status_code=404, detail="Collector not found")
    return _collector_to_read(c)


@router.patch("/collectors/{collector_id}", response_model=CollectorRead)
async def update_collector(
    collector_id: uuid.UUID, body: CollectorUpdate, db: DB, user: CurrentUser
) -> CollectorRead:
    c = await db.get(LookingGlassCollector, collector_id)
    if c is None:
        raise HTTPException(status_code=404, detail="Collector not found")

    changes = body.model_dump(exclude_unset=True)
    for k, v in changes.items():
        setattr(c, k, v)

    _write_audit(
        db,
        user=user,
        action="update",
        resource_type="looking_glass_collector",
        resource_id=c.id,
        resource_display=c.name,
        changed_fields=list(changes.keys()),
        new_value=changes,
    )
    await db.commit()
    await db.refresh(c)
    return _collector_to_read(c)


@router.delete(
    "/collectors/{collector_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None
)
async def delete_collector(collector_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    c = await db.get(LookingGlassCollector, collector_id)
    if c is None:
        raise HTTPException(status_code=404, detail="Collector not found")

    _write_audit(
        db,
        user=user,
        action="delete",
        resource_type="looking_glass_collector",
        resource_id=c.id,
        resource_display=c.name,
    )
    # FK CASCADE sweeps bgp_lg_peer rows (and, transitively, their
    # bgp_lg_route rows) — no manual cleanup needed.
    await db.delete(c)
    await db.commit()
    return None


# ── Peers ───────────────────────────────────────────────────────────────


def _peer_to_read(p: BGPLGPeer) -> PeerRead:
    return PeerRead(
        id=p.id,
        name=p.name,
        collector_id=p.collector_id,
        local_asn=p.local_asn,
        peer_asn=p.peer_asn,
        peer_address=p.peer_address,
        matched_asn_id=p.matched_asn_id,
        peer_router_id=p.peer_router_id,
        address_families=list(p.address_families or []),
        md5_password_set=bool(p.md5_password_encrypted),
        max_prefixes=p.max_prefixes,
        import_filter=p.import_filter or {"mode": "accept_all"},
        enabled=p.enabled,
        description=p.description,
        session_state=p.session_state,
        uptime_started_at=p.uptime_started_at,
        prefixes_received=p.prefixes_received,
        prefixes_accepted=p.prefixes_accepted,
        last_state_change=p.last_state_change,
        last_flap_at=p.last_flap_at,
        rpki_invalid_count=p.rpki_invalid_count,
        down_since=p.down_since,
        created_at=p.created_at,
        modified_at=p.modified_at,
    )


@router.get("/peers", response_model=list[PeerRead])
async def list_peers(
    db: DB, _: CurrentUser, collector_id: uuid.UUID | None = None
) -> list[PeerRead]:
    q = select(BGPLGPeer).order_by(BGPLGPeer.name)
    if collector_id is not None:
        q = q.where(BGPLGPeer.collector_id == collector_id)
    rows = (await db.execute(q)).scalars().all()
    return [_peer_to_read(p) for p in rows]


@router.post("/peers", response_model=PeerRead, status_code=status.HTTP_201_CREATED)
async def create_peer(body: PeerCreate, db: DB, user: CurrentUser) -> PeerRead:
    if (await db.get(LookingGlassCollector, body.collector_id)) is None:
        raise HTTPException(status_code=422, detail="collector_id not found")
    if body.matched_asn_id is not None and (await db.get(ASN, body.matched_asn_id)) is None:
        raise HTTPException(status_code=422, detail="matched_asn_id not found")
    if (
        body.peer_router_id is not None
        and (await db.get(NetworkDevice, body.peer_router_id)) is None
    ):
        raise HTTPException(status_code=422, detail="peer_router_id not found")

    payload = body.model_dump(exclude={"md5_password"})
    p = BGPLGPeer(**payload)
    if body.md5_password:
        p.md5_password_encrypted = encrypt_str(body.md5_password)
    db.add(p)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A peer for {body.peer_address} already exists on this collector.",
        ) from exc

    audit_payload = body.model_dump(mode="json", exclude={"md5_password"})
    audit_payload["md5_password_set"] = bool(body.md5_password)
    _write_audit(
        db,
        user=user,
        action="create",
        resource_type="bgp_lg_peer",
        resource_id=p.id,
        resource_display=p.name,
        new_value=audit_payload,
    )
    collect_wake(looking_glass_collector_channel(p.collector_id))
    await db.commit()
    await db.refresh(p)
    return _peer_to_read(p)


@router.get("/peers/{peer_id}", response_model=PeerRead)
async def get_peer(peer_id: uuid.UUID, db: DB, _: CurrentUser) -> PeerRead:
    p = await db.get(BGPLGPeer, peer_id)
    if p is None:
        raise HTTPException(status_code=404, detail="Peer not found")
    return _peer_to_read(p)


@router.get("/peers/{peer_id}/detail", response_model=PeerDetailResponse)
async def get_peer_detail(peer_id: uuid.UUID, db: DB, _: CurrentUser) -> PeerDetailResponse:
    """Rich rollup backing the Sessions-tab peer detail modal (issue #566).

    Composes the peer's own config + runtime state (``PeerRead`` already
    carries every session-state field) with its collector, its matched
    ASN/router links (when set), an aggregate view over its learned RIB
    (``bgp_lg_route`` rows for this peer), and any open ``bgp_lg_*`` alerts
    that reference it — either directly (``bgp_lg_session_down``, subject
    type ``bgp_lg_peer``) or via one of its routes (every other
    ``bgp_lg_*`` rule type, subject type ``bgp_lg_route``).
    """
    p = await db.get(BGPLGPeer, peer_id)
    if p is None:
        raise HTTPException(status_code=404, detail="Peer not found")

    collector = await db.get(LookingGlassCollector, p.collector_id)
    if collector is None:
        # FK is NOT NULL + CASCADE — a peer never outlives its collector.
        raise HTTPException(status_code=500, detail="Peer's collector is missing")

    matched_asn: PeerDetailMatchedAsn | None = None
    if p.matched_asn_id is not None:
        asn = await db.get(ASN, p.matched_asn_id)
        if asn is not None:
            matched_asn = PeerDetailMatchedAsn(id=asn.id, number=asn.number, name=asn.name)

    peer_router: PeerDetailRouter | None = None
    if p.peer_router_id is not None:
        device = await db.get(NetworkDevice, p.peer_router_id)
        if device is not None:
            peer_router = PeerDetailRouter(id=device.id, name=device.name)

    # ── Route-stats rollup ───────────────────────────────────────────
    active_where = (BGPLGRoute.peer_id == p.id, BGPLGRoute.withdrawn_at.is_(None))

    active_total = (
        await db.execute(select(func.count()).select_from(BGPLGRoute).where(*active_where))
    ).scalar_one()
    withdrawn_total = (
        await db.execute(
            select(func.count())
            .select_from(BGPLGRoute)
            .where(BGPLGRoute.peer_id == p.id, BGPLGRoute.withdrawn_at.is_not(None))
        )
    ).scalar_one()
    best_count = (
        await db.execute(
            select(func.count())
            .select_from(BGPLGRoute)
            .where(*active_where, BGPLGRoute.is_best.is_(True))
        )
    ).scalar_one()
    has_vpn_routes = (
        await db.execute(
            select(func.count())
            .select_from(BGPLGRoute)
            .where(*active_where, BGPLGRoute.route_distinguisher != "")
        )
    ).scalar_one() > 0

    rpki_rows = (
        await db.execute(
            select(BGPLGRoute.rpki_status, func.count())
            .where(*active_where)
            .group_by(BGPLGRoute.rpki_status)
        )
    ).all()
    rpki_counts = {status: n for status, n in rpki_rows}
    rpki = PeerDetailRpkiBreakdown(
        valid=rpki_counts.get("valid", 0),
        invalid=rpki_counts.get(RPKI_INVALID, 0),
        unknown=rpki_counts.get("unknown", 0),
    )

    origin_rows = (
        await db.execute(
            select(BGPLGRoute.origin_asn, func.count())
            .where(*active_where, BGPLGRoute.origin_asn.is_not(None))
            .group_by(BGPLGRoute.origin_asn)
            .order_by(func.count().desc())
            .limit(5)
        )
    ).all()
    top_origin_asns = [
        PeerDetailOriginAsnCount(asn=asn, count=n) for asn, n in origin_rows if asn is not None
    ]

    # Community counting done in Python over the fetched rows — this
    # peer's active RIB is small (per-peer scope, not the whole table), so
    # unnest-in-SQL would be needless ceremony for a correctness-equivalent
    # result.
    community_rows = (
        await db.execute(
            select(BGPLGRoute.communities, BGPLGRoute.large_communities).where(*active_where)
        )
    ).all()
    community_counter: Counter[str] = Counter()
    for communities, large_communities in community_rows:
        for c in communities or []:
            community_counter[str(c)] += 1
        for c in large_communities or []:
            community_counter[str(c)] += 1
    top_communities = [
        PeerDetailCommunityCount(value=v, count=n) for v, n in community_counter.most_common(8)
    ]

    sample_rows = (
        (
            await db.execute(
                select(BGPLGRoute).where(*active_where).order_by(BGPLGRoute.prefix).limit(8)
            )
        )
        .scalars()
        .all()
    )
    route_stats = PeerDetailRouteStats(
        active_total=active_total,
        withdrawn_total=withdrawn_total,
        best_count=best_count,
        rpki=rpki,
        top_origin_asns=top_origin_asns,
        top_communities=top_communities,
        has_vpn_routes=has_vpn_routes,
        sample_routes=[_route_to_read(r) for r in sample_rows],
    )

    # ── Active bgp_lg_* alerts referencing this peer or its routes ────
    route_ids = (
        (await db.execute(select(BGPLGRoute.id).where(BGPLGRoute.peer_id == p.id))).scalars().all()
    )
    subject_match = [
        and_(AlertEvent.subject_type == "bgp_lg_peer", AlertEvent.subject_id == str(p.id))
    ]
    if route_ids:
        route_id_strs = [str(rid) for rid in route_ids]
        subject_match.append(
            and_(
                AlertEvent.subject_type == "bgp_lg_route", AlertEvent.subject_id.in_(route_id_strs)
            )
        )

    alert_rows = (
        await db.execute(
            select(
                AlertEvent.severity, AlertEvent.message, AlertRule.rule_type, AlertEvent.fired_at
            )
            .join(AlertRule, AlertRule.id == AlertEvent.rule_id)
            .where(
                AlertEvent.resolved_at.is_(None),
                AlertRule.rule_type.like("bgp_lg_%"),
                or_(*subject_match),
            )
            .order_by(AlertEvent.fired_at.desc())
        )
    ).all()
    active_alerts = [
        PeerDetailAlert(severity=severity, message=message, rule_type=rule_type, fired_at=fired_at)
        for severity, message, rule_type, fired_at in alert_rows
    ]

    return PeerDetailResponse(
        peer=_peer_to_read(p),
        collector=PeerDetailCollector.model_validate(collector),
        matched_asn=matched_asn,
        peer_router=peer_router,
        route_stats=route_stats,
        active_alerts=active_alerts,
    )


@router.patch("/peers/{peer_id}", response_model=PeerRead)
async def update_peer(peer_id: uuid.UUID, body: PeerUpdate, db: DB, user: CurrentUser) -> PeerRead:
    p = await db.get(BGPLGPeer, peer_id)
    if p is None:
        raise HTTPException(status_code=404, detail="Peer not found")

    old_collector_id = p.collector_id
    was_enabled = p.enabled

    raw_changes = body.model_dump(exclude_unset=True)
    md5_password = raw_changes.pop("md5_password", None)
    changes = raw_changes

    if (
        "collector_id" in changes
        and (await db.get(LookingGlassCollector, changes["collector_id"])) is None
    ):
        raise HTTPException(status_code=422, detail="collector_id not found")
    if (
        changes.get("matched_asn_id") is not None
        and (await db.get(ASN, changes["matched_asn_id"])) is None
    ):
        raise HTTPException(status_code=422, detail="matched_asn_id not found")
    if (
        changes.get("peer_router_id") is not None
        and (await db.get(NetworkDevice, changes["peer_router_id"])) is None
    ):
        raise HTTPException(status_code=422, detail="peer_router_id not found")

    for k, v in changes.items():
        setattr(p, k, v)

    # md5_password: truthy -> rotate; "" -> clear; omitted/None -> keep
    # (mirrors NetworkDeviceUpdate's secret-rotation convention).
    changed_fields = list(changes.keys())
    if md5_password:
        p.md5_password_encrypted = encrypt_str(md5_password)
        changed_fields.append("md5_password_rotated")
    elif md5_password == "":
        p.md5_password_encrypted = None
        changed_fields.append("md5_password_cleared")

    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A peer for {p.peer_address} already exists on this collector.",
        ) from exc

    # Disabling a peer removes it from the config bundle, so the collector
    # stops pushing for it and absence-reconcile never runs — its learned
    # routes would otherwise stay "active" forever. Mark them withdrawn now.
    # (Deleting a peer instead sweeps its routes via FK CASCADE.)
    if was_enabled and not p.enabled:
        await db.execute(
            update(BGPLGRoute)
            .where(BGPLGRoute.peer_id == p.id, BGPLGRoute.withdrawn_at.is_(None))
            .values(withdrawn_at=datetime.now(UTC))
        )

    audit_payload = body.model_dump(mode="json", exclude_unset=True, exclude={"md5_password"})
    _write_audit(
        db,
        user=user,
        action="update",
        resource_type="bgp_lg_peer",
        resource_id=p.id,
        resource_display=p.name,
        changed_fields=changed_fields,
        new_value=audit_payload,
    )
    # Wake the (possibly new) owning collector; if the peer moved to a
    # different collector, also wake the old one so it drops the peer.
    collect_wake(looking_glass_collector_channel(p.collector_id))
    if p.collector_id != old_collector_id:
        collect_wake(looking_glass_collector_channel(old_collector_id))
    await db.commit()
    await db.refresh(p)
    return _peer_to_read(p)


@router.delete("/peers/{peer_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_peer(peer_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    p = await db.get(BGPLGPeer, peer_id)
    if p is None:
        raise HTTPException(status_code=404, detail="Peer not found")

    _write_audit(
        db,
        user=user,
        action="delete",
        resource_type="bgp_lg_peer",
        resource_id=p.id,
        resource_display=p.name,
    )
    collector_id = p.collector_id
    # FK CASCADE sweeps this peer's bgp_lg_route rows.
    await db.delete(p)
    collect_wake(looking_glass_collector_channel(collector_id))
    await db.commit()
    return None


# ── Sessions (read-only per-peer state rollup) ───────────────────────────


@router.get("/sessions", response_model=list[SessionRead])
async def list_sessions(
    db: DB, _: CurrentUser, collector_id: uuid.UUID | None = None
) -> list[SessionRead]:
    q = (
        select(BGPLGPeer, LookingGlassCollector)
        .join(LookingGlassCollector, LookingGlassCollector.id == BGPLGPeer.collector_id)
        .order_by(LookingGlassCollector.name, BGPLGPeer.name)
    )
    if collector_id is not None:
        q = q.where(BGPLGPeer.collector_id == collector_id)
    rows = (await db.execute(q)).all()
    return [
        SessionRead(
            peer_id=p.id,
            peer_name=p.name,
            collector_id=c.id,
            collector_name=c.name,
            collector_status=c.status,
            local_asn=p.local_asn,
            peer_asn=p.peer_asn,
            peer_address=p.peer_address,
            enabled=p.enabled,
            session_state=p.session_state,
            uptime_started_at=p.uptime_started_at,
            prefixes_received=p.prefixes_received,
            prefixes_accepted=p.prefixes_accepted,
            last_state_change=p.last_state_change,
            last_flap_at=p.last_flap_at,
            rpki_invalid_count=p.rpki_invalid_count,
            down_since=p.down_since,
        )
        for p, c in rows
    ]


# ── Routes (the learned RIB) ─────────────────────────────────────────────


def _route_to_read(r: BGPLGRoute) -> RouteRead:
    return RouteRead.model_validate(r)


def _parse_prefix(raw: str) -> str:
    try:
        return str(ipaddress.ip_network(raw, strict=False))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"invalid prefix: {raw!r}") from exc


@router.get("/routes", response_model=RouteListResponse)
async def list_routes(
    db: DB,
    _: CurrentUser,
    prefix: str | None = Query(None, description="contains-or-within CIDR match"),
    origin_asn: int | None = None,
    community: str | None = Query(None, description="matches communities or large_communities"),
    as_path_regexp: str | None = Query(
        None,
        max_length=128,
        description=(
            "AS-path regex (Cisco/Juniper '_' boundary convention), matched "
            "against the space-joined AS path — e.g. '_65001_' (anywhere) or "
            "'65001_$' (origin). See as_path_query.translate_as_path_regexp."
        ),
    ),
    rpki_status: str | None = None,
    peer_id: uuid.UUID | None = None,
    matched_block_id: uuid.UUID | None = None,
    matched_subnet_id: uuid.UUID | None = None,
    matched_space_id: uuid.UUID | None = None,
    matched_asn_id: uuid.UUID | None = None,
    matched_vrf_id: uuid.UUID | None = None,
    best_path_only: bool = False,
    withdrawn: bool = Query(False, description="include withdrawn routes (hidden by default)"),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> RouteListResponse:
    """Server-paginated, filterable view over the learned RIB.

    Mirrors ``GET /ipam/addresses/search``'s ``{items,total}`` envelope —
    the RIB is "low thousands" scoped per issue #566's v1 design, so
    server-side pagination (not client windowing) is the right shape.
    ``as_path_regexp`` (#566 Phase 4) matches the Cisco/Juniper ``_``
    boundary-token convention against the space-joined AS path — see
    ``app.services.looking_glass.as_path_query``.
    """
    q = select(BGPLGRoute)

    if prefix:
        net = _parse_prefix(prefix)
        # contains-or-within: match routes that are a supernet of, equal
        # to, or a subnet of the requested prefix.
        q = q.where(or_(BGPLGRoute.prefix.op(">>=")(net), BGPLGRoute.prefix.op("<<=")(net)))
    if origin_asn is not None:
        q = q.where(BGPLGRoute.origin_asn == origin_asn)
    if community:
        q = q.where(
            or_(
                BGPLGRoute.communities.contains([community]),
                BGPLGRoute.large_communities.contains([community]),
            )
        )
    if as_path_regexp:
        try:
            q = q.where(as_path_regexp_clause(as_path_regexp))
        except re.error as exc:
            raise HTTPException(status_code=422, detail=f"invalid as_path_regexp: {exc}") from exc
    if rpki_status:
        q = q.where(BGPLGRoute.rpki_status == rpki_status)
    if peer_id is not None:
        q = q.where(BGPLGRoute.peer_id == peer_id)
    if matched_block_id is not None:
        q = q.where(BGPLGRoute.matched_block_id == matched_block_id)
    if matched_subnet_id is not None:
        q = q.where(BGPLGRoute.matched_subnet_id == matched_subnet_id)
    if matched_space_id is not None:
        q = q.where(BGPLGRoute.matched_space_id == matched_space_id)
    if matched_asn_id is not None:
        q = q.where(BGPLGRoute.matched_asn_id == matched_asn_id)
    if matched_vrf_id is not None:
        q = q.where(BGPLGRoute.matched_vrf_id == matched_vrf_id)
    if best_path_only:
        q = q.where(BGPLGRoute.is_best.is_(True))
    if not withdrawn:
        q = q.where(BGPLGRoute.withdrawn_at.is_(None))

    total = (
        await db.execute(select(func.count()).select_from(q.order_by(None).subquery()))
    ).scalar_one()
    q = q.order_by(BGPLGRoute.prefix, BGPLGRoute.peer_id).offset(offset).limit(limit)
    rows = (await db.execute(q)).scalars().all()
    return RouteListResponse(
        items=[_route_to_read(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/routes/by-prefix", response_model=list[RouteRead])
async def get_route(
    db: DB,
    _: CurrentUser,
    prefix: str = Query(..., description="exact CIDR, e.g. 10.0.0.0/24 or 2001:db8::/32"),
    withdrawn: bool = Query(False, description="include withdrawn paths"),
) -> list[RouteRead]:
    """All paths for one exact prefix, across every peer.

    ``prefix`` is a query parameter (not a path segment) so the CIDR slash +
    IPv6 colons encode cleanly through proxies — a path-param ``{prefix:path}``
    would need raw slashes that some proxies / %2F-decoders mangle.

    Distinct from the ``prefix`` filter on ``GET /routes`` (which is a
    contains-or-within match): this is an exact-prefix lookup, feeding the
    "show ip bgp <prefix>" style detail view (and the future Query tab).
    """
    net = _parse_prefix(prefix)
    q = select(BGPLGRoute).where(BGPLGRoute.prefix == net)
    if not withdrawn:
        q = q.where(BGPLGRoute.withdrawn_at.is_(None))
    q = q.order_by(BGPLGRoute.peer_id)
    rows = (await db.execute(q)).scalars().all()
    return [_route_to_read(r) for r in rows]


def _pick_matched_id(paths: list[RouteDetailPath], attr: str) -> uuid.UUID | None:
    """Prefer the current best path's linkage; fall back to the first path
    carrying a non-NULL value for this ``matched_*_id`` attribute. See
    ``RouteDetailIpamContext``'s docstring for why paths can legitimately
    disagree (VPNv4/VPNv6 per-route Route-Target VRF matching)."""
    for path in paths:
        if path.is_best and getattr(path, attr) is not None:
            return getattr(path, attr)  # type: ignore[no-any-return]
    for path in paths:
        value = getattr(path, attr)
        if value is not None:
            return value  # type: ignore[no-any-return]
    return None


async def _build_route_ipam_context(
    db: AsyncSession, paths: list[RouteDetailPath]
) -> RouteDetailIpamContext:
    ctx = RouteDetailIpamContext(
        subnet_id=_pick_matched_id(paths, "matched_subnet_id"),
        block_id=_pick_matched_id(paths, "matched_block_id"),
        space_id=_pick_matched_id(paths, "matched_space_id"),
        asn_id=_pick_matched_id(paths, "matched_asn_id"),
        vrf_id=_pick_matched_id(paths, "matched_vrf_id"),
    )
    if ctx.subnet_id is not None:
        subnet = await db.get(Subnet, ctx.subnet_id)
        if subnet is not None:
            ctx.subnet_name = subnet.name or str(subnet.network)
    if ctx.block_id is not None:
        block = await db.get(IPBlock, ctx.block_id)
        if block is not None:
            ctx.block_name = block.name or str(block.network)
    if ctx.space_id is not None:
        space = await db.get(IPSpace, ctx.space_id)
        if space is not None:
            ctx.space_name = space.name
    if ctx.asn_id is not None:
        asn = await db.get(ASN, ctx.asn_id)
        if asn is not None:
            ctx.asn_number = asn.number
            ctx.asn_name = asn.name
    if ctx.vrf_id is not None:
        vrf = await db.get(VRF, ctx.vrf_id)
        if vrf is not None:
            ctx.vrf_name = vrf.name
    return ctx


@router.get("/routes/detail", response_model=RouteDetailResponse)
async def get_route_detail(
    db: DB,
    _: CurrentUser,
    prefix: str = Query(..., description="exact CIDR, e.g. 10.0.0.0/24 or 2001:db8::/32"),
    withdrawn: bool = Query(False, description="include withdrawn paths"),
) -> RouteDetailResponse:
    """The rich per-prefix rollup backing the Routes-tab detail modal
    (issue #566).

    Same exact-prefix scope as ``/routes/by-prefix`` — every path across
    every peer — but each path is enriched with its announcing peer +
    collector name (avoiding an N-round-trip client-side join against
    ``/peers``/``/collectors``), and a server-computed ``summary`` surfaces
    the two headline signals up front:

    * ``multi_origin`` — more than one *origin* ASN announcing this exact
      prefix. This is the hijack/route-leak signal regardless of how many
      peers/routers see it.
    * ``anycast_candidate`` — the same prefix learned from more than one
      router/peer. Combined with a single origin ASN this is the normal
      anycast/multi-homed shape; combined with ``multi_origin`` it's a
      stronger corroboration that this is either broad anycast or a
      widely-visible hijack.

    ``ipam`` carries the covering IPAM subnet/block/space plus the ASN/VRF
    a path resolved against, so the modal can deep-link straight into IPAM
    without a second lookup.
    """
    net = _parse_prefix(prefix)
    q = (
        select(BGPLGRoute, BGPLGPeer, LookingGlassCollector)
        .join(BGPLGPeer, BGPLGPeer.id == BGPLGRoute.peer_id)
        .join(LookingGlassCollector, LookingGlassCollector.id == BGPLGPeer.collector_id)
        .where(BGPLGRoute.prefix == net)
    )
    if not withdrawn:
        q = q.where(BGPLGRoute.withdrawn_at.is_(None))
    q = q.order_by(LookingGlassCollector.name, BGPLGPeer.name)
    rows = (await db.execute(q)).all()

    paths = [
        RouteDetailPath(
            route_id=r.id,
            peer_id=p.id,
            peer_name=p.name,
            collector_name=c.name,
            origin_asn=r.origin_asn,
            next_hop=str(r.next_hop),
            local_pref=r.local_pref,
            med=r.med,
            as_path=list(r.as_path or []),
            communities=list(r.communities or []),
            large_communities=list(r.large_communities or []),
            ext_communities=list(r.ext_communities or []),
            route_distinguisher=r.route_distinguisher,
            rpki_status=r.rpki_status,
            is_best=r.is_best,
            first_seen_at=r.first_seen_at,
            last_seen_at=r.last_seen_at,
            flap_count=r.flap_count,
            withdrawn_at=r.withdrawn_at,
            matched_subnet_id=r.matched_subnet_id,
            matched_block_id=r.matched_block_id,
            matched_space_id=r.matched_space_id,
            matched_asn_id=r.matched_asn_id,
            matched_vrf_id=r.matched_vrf_id,
        )
        for r, p, c in rows
    ]

    peer_count = len({path.peer_id for path in paths})
    distinct_origin_asns = sorted(
        {path.origin_asn for path in paths if path.origin_asn is not None}
    )

    rpki_counter: Counter[str] = Counter(path.rpki_status for path in paths)
    rpki = PeerDetailRpkiBreakdown(
        valid=rpki_counter.get("valid", 0),
        invalid=rpki_counter.get(RPKI_INVALID, 0),
        unknown=rpki_counter.get("unknown", 0),
    )

    origin_names: dict[int, str] = {}
    if distinct_origin_asns:
        asn_rows = (
            await db.execute(
                select(ASN.number, ASN.name).where(ASN.number.in_(distinct_origin_asns))
            )
        ).all()
        origin_names = {int(number): name for number, name in asn_rows}

    summary = RouteDetailSummary(
        path_count=len(paths),
        peer_count=peer_count,
        distinct_origin_asns=distinct_origin_asns,
        multi_origin=len(distinct_origin_asns) > 1,
        anycast_candidate=peer_count > 1,
        rpki=rpki,
        origin_names=origin_names,
    )

    ipam = await _build_route_ipam_context(db, paths)

    return RouteDetailResponse(prefix=net, paths=paths, summary=summary, ipam=ipam)


@router.get("/routes/for-ip", response_model=RouteForIpResponse)
async def get_route_for_ip(
    db: DB,
    _: CurrentUser,
    ip: str = Query(..., description="A single IP address, v4 or v6."),
) -> RouteForIpResponse:
    """Reverse longest-prefix-match: which active route covers this one IP
    address? Feeds the IP detail modal's "covering BGP route" section
    (issue #566 Phase 3). Shares its LPM implementation with the
    ``find_bgp_route_for_ip`` MCP tool via ``reverse_lookup.best_route_for_ip``
    so the two surfaces can't drift.
    """
    result = await best_route_for_ip(db, ip)
    if result is None:
        return RouteForIpResponse(ip=ip, found=False)
    route, alt_count = result
    return RouteForIpResponse(
        ip=ip, found=True, route=_route_to_read(route), alternate_paths_count=alt_count
    )


@router.get("/dashboard-summary", response_model=LookingGlassDashboardSummary)
async def dashboard_summary(db: DB, _: CurrentUser) -> LookingGlassDashboardSummary:
    """Single-shot rollup backing the Dashboard's Looking Glass health
    card. Peers/sessions are cheap to enumerate in full (bounded, like
    ``list_sessions``); route counts use ``func.count()`` so the
    "low-thousands" RIB is never pulled client-side just to compute a
    KPI number.
    """
    peers = (await db.execute(select(BGPLGPeer).where(BGPLGPeer.enabled.is_(True)))).scalars().all()
    peers_total = len(peers)
    peers_established = sum(1 for p in peers if p.session_state == "established")
    peers_down = peers_total - peers_established

    rpki_invalid = (
        await db.execute(
            select(func.count())
            .select_from(BGPLGRoute)
            .where(BGPLGRoute.rpki_status == RPKI_INVALID, BGPLGRoute.withdrawn_at.is_(None))
        )
    ).scalar_one()

    flapping = (
        await db.execute(
            select(func.count())
            .select_from(BGPLGRoute)
            .where(BGPLGRoute.flap_count >= 1, BGPLGRoute.withdrawn_at.is_(None))
        )
    ).scalar_one()

    return LookingGlassDashboardSummary(
        peers_total=peers_total,
        peers_established=peers_established,
        peers_down=peers_down,
        routes_rpki_invalid=rpki_invalid,
        routes_flapping=flapping,
    )


# ── VRF Route-Target cross-check (issue #566 Phase 6) ───────────────────


@router.get("/vrf-rt-matches/{vrf_id}", response_model=VrfRtMatchSummary)
async def get_vrf_rt_matches(vrf_id: uuid.UUID, db: DB, _: CurrentUser) -> VrfRtMatchSummary:
    """Which of a VRF's own import/export route targets actually show up on
    a currently-active learned route matched to that VRF. Feeds the VRF
    detail page's "Learned VPN Routes" tab RT cross-check — the routes
    themselves are already reachable via ``GET /looking-glass/routes
    ?matched_vrf_id=<vrf_id>`` (Phase 3); this endpoint answers "which RTs
    are actually being hit" without the caller having to walk every
    matched route's ``ext_communities`` client-side.
    """
    vrf = await db.get(VRF, vrf_id)
    if vrf is None:
        raise HTTPException(status_code=404, detail="VRF not found")

    import_set = set(vrf.import_targets or [])
    export_set = set(vrf.export_targets or [])

    # 2.1 types a select of a ``list`` column as untyped, so say what it is.
    rows: Sequence[list[Any]] = (
        (
            await db.execute(
                select(BGPLGRoute.ext_communities).where(
                    BGPLGRoute.matched_vrf_id == vrf.id,
                    BGPLGRoute.withdrawn_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )

    counts: dict[tuple[str, str], int] = {}
    for ext_communities in rows:
        hits: set[tuple[str, str]] = set()
        for raw in ext_communities or []:
            norm = normalize_rt(str(raw))
            if norm in import_set:
                hits.add((norm, "import"))
            if norm in export_set:
                hits.add((norm, "export"))
        for key in hits:
            counts[key] = counts.get(key, 0) + 1

    route_targets = [
        VrfRtMatchRow(route_target=rt, kind=kind, matched_route_count=n)
        for (rt, kind), n in sorted(counts.items())
    ]
    return VrfRtMatchSummary(
        vrf_id=vrf.id,
        vrf_name=vrf.name,
        matched_route_count=len(rows),
        route_targets=route_targets,
    )


# ── Multicast BGP reachability cross-reference (issue #566 Phase 6) ─────


@router.get("/multicast-reachability", response_model=MulticastReachabilityResponse)
async def get_multicast_reachability(db: DB, _: CurrentUser) -> MulticastReachabilityResponse:
    """Read-only cross-reference of multicast PIM RP addresses / producer
    source subnets against the learned RIB. See
    ``app.services.looking_glass.reachability.multicast_bgp_reachability``.

    Sits under this router's ``network.looking_glass`` module gate but does
    NOT also check ``network.multicast`` — reading multicast rows when that
    module is toggled off is harmless (module-off only hides a surface, it
    never deletes data, same as every other feature-module precedent in
    this codebase).
    """
    from app.services.looking_glass.reachability import multicast_bgp_reachability

    result = await multicast_bgp_reachability(db)
    return MulticastReachabilityResponse(
        domains=[
            DomainReachability(
                domain_id=d.domain_id,
                domain_name=d.domain_name,
                rp_address=d.rp_address,
                covering_route=_route_to_read(d.covering_route) if d.covering_route else None,
            )
            for d in result.domains
        ],
        groups=[
            GroupSourceReachability(
                group_id=g.group_id,
                group_name=g.group_name,
                group_address=g.group_address,
                source_subnet_id=g.source_subnet_id,
                source_subnet=g.source_subnet,
                covering_route=_route_to_read(g.covering_route) if g.covering_route else None,
            )
            for g in result.groups
        ],
    )
