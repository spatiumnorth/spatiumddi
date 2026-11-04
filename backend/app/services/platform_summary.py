"""One cheap, read-only snapshot of the whole install (issue #2143).

Built for external pollers (Home Assistant, a status page, Uptime Kuma, a
Grafana JSON source) that would otherwise make ~20 calls every minute and
couple themselves to the console's page shapes. ``GET /api/v1/summary`` and
the ``get_platform_summary`` Copilot tool both call :func:`build_summary`, so
the two cannot answer differently.

**Authorization is per section, and a section the caller may not read is
withheld, not leaked and not a 403 for the whole call.** A withheld section is
``null`` and ``withheld`` says why (``permission`` / ``token_scoped`` /
``module_disabled``), so a client can tell "not allowed" from "nothing there"
(#3449). Each section is gated on the permission its own list route needs
(DNS on ``dns_group``, DHCP on ``dhcp_server``, ...), so a count never
reveals what the role could not list: an IPAM-only Viewer learns nothing
about DNS, not even a zone-group count.

A resource-scoped API token (#374) only ever narrows its owner. This route
aggregates over the whole estate and cannot narrow a count to one subnet, so
a section is answered only when the token holds a type-wide grant for every
resource type it reads (``token_scoped_resource_ids`` is ``None``); a token
bound to specific instances of a type has that section withheld.

Cost: a constant number of queries however many groups, servers or pools
exist (every section is one or two grouped queries; pool occupancy is the
existing batched helper), and the computed snapshot is cached in-process for a
few seconds per access shape so many pollers cost one computation.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from time import monotonic
from typing import Any, Literal

import structlog
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.permissions import token_scoped_resource_ids, user_has_permission
from app.core.versions import canonical_version
from app.models.alerts import AlertEvent
from app.models.auth import User
from app.models.dhcp import DHCPLease, DHCPPool, DHCPScope, DHCPServer, DHCPServerGroup
from app.models.dns import (
    DNSBlockList,
    DNSServer,
    DNSServerGroup,
    dns_blocklist_group_assoc,
)
from app.models.dns_rpz_hit import DNSRPZHit
from app.models.ipam import IPSpace, Subnet
from app.models.metrics import DNSMetricSample
from app.models.settings import PlatformSettings
from app.services.dhcp.pool_occupancy import compute_pool_occupancy_batch
from app.services.feature_modules import get_enabled_modules
from app.services.ipam.new_device import new_device_counts

logger = structlog.get_logger(__name__)

WithheldReason = Literal["permission", "token_scoped", "module_disabled"]

#: Look-back for the DNS rate figures. Long enough to smooth the agents' 60 s
#: buckets, short enough that a sensor follows a real change.
DNS_WINDOW_MINUTES = 5
#: RPZ hits are rare; a 5 minute count is noise, so the blocked figure is a day.
RPZ_WINDOW_HOURS = 24
#: A DNS / DHCP server counts as online when the health sweep says ``active``.
ONLINE_STATUS = "active"
#: Config-apply verdicts that mean "the saved config is NOT what is running"
#: (#882). NULL (never reported) is UNKNOWN, deliberately not counted here.
CONFIG_FAILING = ("reverted", "revert_failed", "no_previous")
FULLEST_POOLS = 5
NEWEST_ALERTS = 10
MAX_TRACKED_SUBNETS = 100
MAX_BLOCKLISTS = 200
#: Subnets a poller pins for utilisation: tag key ``ha`` with value ``track``,
#: or the single key ``ha:track``.
TRACK_TAG_KEY = "ha"
TRACK_TAG_VALUE = "track"
CACHE_TTL_SECONDS = 5.0


# ── Response model ──────────────────────────────────────────────────────────


class PlatformSection(BaseModel):
    version: str
    #: ``ok`` / ``degraded`` (the ``/health/platform`` verdict), ``unknown``
    #: when the probe itself failed.
    health: str
    maintenance_mode: bool
    update_available: bool
    latest_version: str | None
    release_check_enabled: bool


class TrackedSubnet(BaseModel):
    id: uuid.UUID
    network: str
    name: str
    utilization_percent: float
    allocated_ips: int
    total_ips: int


class IPAMSection(BaseModel):
    spaces: int
    subnets: int
    #: Subnets tagged ``ha:track`` (see docs/API.md), at most 100.
    tracked_subnets: list[TrackedSubnet]


class NewDevicesSection(BaseModel):
    new: int
    new_randomized: int
    new_last_24h: int
    acknowledged: int
    known: int
    allowlist: int


class DNSGroupSummary(BaseModel):
    id: uuid.UUID
    name: str
    servers_total: int
    servers_online: int
    #: Servers whose agent reported a rejected config (#882).
    servers_config_failing: int
    queries_total: int
    queries_per_second: float
    #: Fractions of the window's queries (0..1); null when there were none.
    nxdomain_rate: float | None
    servfail_rate: float | None


class DNSBlocklistState(BaseModel):
    id: uuid.UUID
    name: str
    enabled: bool
    group_ids: list[uuid.UUID]


class DNSSection(BaseModel):
    window_minutes: int
    groups: list[DNSGroupSummary]
    #: Null with ``withheld["dns.blocklists"]`` when the caller may not read them.
    blocklists: list[DNSBlocklistState] | None
    #: Blocked (non-PASSTHRU) RPZ hits in the last 24 h; null with
    #: ``withheld["dns.rpz"]`` when the caller may not read them.
    rpz_blocked_24h: int | None


class DHCPGroupSummary(BaseModel):
    id: uuid.UUID
    name: str
    servers_total: int
    servers_online: int
    servers_config_failing: int
    #: Distinct addresses under an active lease (an HA pair mirrors each once).
    active_leases: int


class DHCPPoolSummary(BaseModel):
    pool_id: uuid.UUID
    name: str
    scope_id: uuid.UUID
    scope_name: str
    group_id: uuid.UUID
    assigned: int
    total: int
    occupancy_percent: float


class DHCPSection(BaseModel):
    groups: list[DHCPGroupSummary]
    #: Fullest dynamic pools, most-full first; null with
    #: ``withheld["dhcp.pools"]`` when the caller may not read pools.
    fullest_pools: list[DHCPPoolSummary] | None


class AlertRow(BaseModel):
    id: uuid.UUID
    severity: str
    subject_type: str
    subject_display: str
    message: str
    fired_at: datetime


class AlertsSection(BaseModel):
    open_total: int
    open_by_severity: dict[str, int]
    newest: list[AlertRow]


class PlatformSummary(BaseModel):
    generated_at: datetime
    platform: PlatformSection
    ipam: IPAMSection | None
    new_devices: NewDevicesSection | None
    dns: DNSSection | None
    dhcp: DHCPSection | None
    alerts: AlertsSection | None
    #: Why each ``null`` section (or sub-field, as ``section.field``) is
    #: absent. A key here means "not shown to you", never "nothing there".
    withheld: dict[str, WithheldReason]


# ── Access ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Access:
    """Which sections this caller gets, and why the others are withheld."""

    shown: frozenset[str]
    withheld: tuple[tuple[str, WithheldReason], ...]

    def has(self, key: str) -> bool:
        return key in self.shown


def _decide(
    user: User, types: tuple[str, ...], module: str | None, enabled: set[str]
) -> WithheldReason | None:
    """``None`` when the caller may read the whole of ``types``, else why not.

    Permission is judged before the module so a caller who may not read a
    section is never told whether its module is on.
    """
    for rtype in types:
        # A token bound to instances of a type (or to other types entirely)
        # cannot be answered with a whole-estate count; only a type-wide grant
        # (``None``) reads the section. Sessions and plain tokens carry none.
        if token_scoped_resource_ids(user, rtype) is not None:
            return "token_scoped"
    for rtype in types:
        if not user_has_permission(user, "read", rtype):
            return "permission"
    if module is not None and module not in enabled:
        return "module_disabled"
    return None


# (key, permission types, feature module, parent key it hangs off)
_SECTIONS: tuple[tuple[str, tuple[str, ...], str | None, str | None], ...] = (
    ("ipam", ("ip_space", "subnet"), None, None),
    ("new_devices", ("ip_address",), "security.new_device_watch", None),
    ("dns", ("dns_group",), "core.dns", None),
    ("dns.blocklists", ("dns_blocklist",), None, "dns"),
    ("dns.rpz", ("server",), "security.dns_threat", "dns"),
    ("dhcp", ("dhcp_server",), "core.dhcp", None),
    ("dhcp.pools", ("dhcp_pool",), None, "dhcp"),
    ("alerts", ("alert",), None, None),
)


def resolve_access(user: User, enabled: set[str]) -> Access:
    shown: set[str] = set()
    withheld: list[tuple[str, WithheldReason]] = []
    for key, types, module, parent in _SECTIONS:
        if parent is not None and parent not in shown:
            continue  # the parent's reason already covers it
        reason = _decide(user, types, module, enabled)
        if reason is None:
            shown.add(key)
        else:
            withheld.append((key, reason))
    return Access(frozenset(shown), tuple(withheld))


# ── Section builders (each a constant number of queries) ────────────────────


async def _health_verdict() -> str:
    """The ``/health/platform`` rollup, reusing that handler rather than a copy."""
    from app.api.health import platform_health

    try:
        # An anonymous call returns the rollup status and no component list,
        # which is all this needs.
        resp = await platform_health(None)
        status = json.loads(bytes(resp.body)).get("status")
    except Exception as exc:  # noqa: BLE001 — a failed probe must not fail the snapshot
        logger.warning("summary_health_probe_failed", error=str(exc))
        return "unknown"
    return status if isinstance(status, str) else "unknown"


async def _platform(db: AsyncSession) -> PlatformSection:
    ps = await db.get(PlatformSettings, 1)
    return PlatformSection(
        version=canonical_version(settings.version, settings.app_version),
        health=await _health_verdict(),
        maintenance_mode=bool(ps and ps.maintenance_mode_enabled),
        update_available=bool(ps and ps.update_available),
        latest_version=ps.latest_version if ps else None,
        release_check_enabled=ps.github_release_check_enabled if ps else True,
    )


async def _ipam(db: AsyncSession) -> IPAMSection:
    spaces = select(func.count()).select_from(IPSpace).scalar_subquery()
    subnets = select(func.count()).select_from(Subnet).scalar_subquery()
    n_spaces, n_subnets = (await db.execute(select(spaces, subnets))).one()
    tracked = (
        await db.execute(
            select(Subnet)
            .where(
                Subnet.tags.contains({TRACK_TAG_KEY: TRACK_TAG_VALUE})
                | Subnet.tags.has_key(f"{TRACK_TAG_KEY}:{TRACK_TAG_VALUE}")
            )
            .order_by(Subnet.network)
            .limit(MAX_TRACKED_SUBNETS)
        )
    ).scalars()
    return IPAMSection(
        spaces=int(n_spaces),
        subnets=int(n_subnets),
        tracked_subnets=[
            TrackedSubnet(
                id=s.id,
                network=str(s.network),
                name=s.name or "",
                utilization_percent=round(float(s.utilization_percent), 1),
                allocated_ips=int(s.allocated_ips or 0),
                total_ips=int(s.total_ips or 0),
            )
            for s in tracked
        ],
    )


def _server_counts(model: Any) -> Any:
    """Per-group ``(total, online, config_failing)`` over ``model``'s rows."""
    return (
        func.count(model.id),
        func.count(model.id).filter(model.status == ONLINE_STATUS),
        func.count(model.id).filter(model.config_apply_status.in_(CONFIG_FAILING)),
    )


async def _dns(db: AsyncSession, access: Access) -> DNSSection:
    since = datetime.now(UTC) - timedelta(minutes=DNS_WINDOW_MINUTES)
    total, online, failing = _server_counts(DNSServer)
    groups = (
        await db.execute(
            select(DNSServerGroup.id, DNSServerGroup.name, total, online, failing)
            .outerjoin(DNSServer, DNSServer.group_id == DNSServerGroup.id)
            .group_by(DNSServerGroup.id, DNSServerGroup.name)
            .order_by(DNSServerGroup.name)
        )
    ).all()
    metrics = {
        row.group_id: row
        for row in (
            await db.execute(
                select(
                    DNSServer.group_id,
                    func.coalesce(func.sum(DNSMetricSample.queries_total), 0).label("q"),
                    func.coalesce(func.sum(DNSMetricSample.nxdomain), 0).label("nx"),
                    func.coalesce(func.sum(DNSMetricSample.servfail), 0).label("sf"),
                )
                .join(DNSServer, DNSServer.id == DNSMetricSample.server_id)
                .where(DNSMetricSample.bucket_at >= since)
                .group_by(DNSServer.group_id)
            )
        ).all()
    }
    out: list[DNSGroupSummary] = []
    for gid, name, n_total, n_online, n_failing in groups:
        m = metrics.get(gid)
        q = int(m.q) if m else 0
        out.append(
            DNSGroupSummary(
                id=gid,
                name=name,
                servers_total=int(n_total),
                servers_online=int(n_online),
                servers_config_failing=int(n_failing),
                queries_total=q,
                queries_per_second=round(q / (DNS_WINDOW_MINUTES * 60), 3),
                nxdomain_rate=round(int(m.nx) / q, 4) if m and q else None,
                servfail_rate=round(int(m.sf) / q, 4) if m and q else None,
            )
        )

    blocklists: list[DNSBlocklistState] | None = None
    if access.has("dns.blocklists"):
        by_list: dict[uuid.UUID, DNSBlocklistState] = {}
        rows = await db.execute(
            select(
                DNSBlockList.id,
                DNSBlockList.name,
                DNSBlockList.enabled,
                dns_blocklist_group_assoc.c.group_id,
            )
            .outerjoin(
                dns_blocklist_group_assoc,
                dns_blocklist_group_assoc.c.blocklist_id == DNSBlockList.id,
            )
            .order_by(DNSBlockList.name)
        )
        for bid, bname, enabled, gid in rows.all():
            state = by_list.get(bid)
            if state is None:
                if len(by_list) >= MAX_BLOCKLISTS:
                    continue
                state = by_list[bid] = DNSBlocklistState(
                    id=bid, name=bname, enabled=bool(enabled), group_ids=[]
                )
            if gid is not None:
                state.group_ids.append(gid)
        blocklists = list(by_list.values())

    rpz: int | None = None
    if access.has("dns.rpz"):
        rpz = int(
            (
                await db.execute(
                    select(func.count())
                    .select_from(DNSRPZHit)
                    .where(DNSRPZHit.ts >= datetime.now(UTC) - timedelta(hours=RPZ_WINDOW_HOURS))
                    .where(DNSRPZHit.policy != "PASSTHRU")
                )
            ).scalar_one()
        )
    return DNSSection(
        window_minutes=DNS_WINDOW_MINUTES, groups=out, blocklists=blocklists, rpz_blocked_24h=rpz
    )


async def _dhcp(db: AsyncSession, access: Access) -> DHCPSection:
    total, online, failing = _server_counts(DHCPServer)
    groups = (
        await db.execute(
            select(DHCPServerGroup.id, DHCPServerGroup.name, total, online, failing)
            .outerjoin(DHCPServer, DHCPServer.server_group_id == DHCPServerGroup.id)
            .group_by(DHCPServerGroup.id, DHCPServerGroup.name)
            .order_by(DHCPServerGroup.name)
        )
    ).all()
    leases = dict(
        (
            await db.execute(
                select(
                    DHCPServer.server_group_id,
                    func.count(func.distinct(DHCPLease.ip_address)),
                )
                .join(DHCPServer, DHCPServer.id == DHCPLease.server_id)
                .where(DHCPLease.state == "active")
                .group_by(DHCPServer.server_group_id)
            )
        )
        .tuples()
        .all()
    )
    pools: list[DHCPPoolSummary] | None = None
    if access.has("dhcp.pools"):
        rows = (
            await db.execute(
                select(DHCPPool, DHCPScope)
                .join(DHCPScope, DHCPScope.id == DHCPPool.scope_id)
                .where(DHCPPool.pool_type == "dynamic")
            )
        ).all()
        occ = await compute_pool_occupancy_batch(db, [p for p, _ in rows])
        ranked = sorted(rows, key=lambda r: occ[r[0].id].percent, reverse=True)[:FULLEST_POOLS]
        pools = [
            DHCPPoolSummary(
                pool_id=p.id,
                name=p.name or "",
                scope_id=sc.id,
                scope_name=sc.name or "",
                group_id=sc.group_id,
                assigned=occ[p.id].assigned,
                total=occ[p.id].total,
                occupancy_percent=round(occ[p.id].percent, 1),
            )
            for p, sc in ranked
        ]
    return DHCPSection(
        groups=[
            DHCPGroupSummary(
                id=gid,
                name=name,
                servers_total=int(n_total),
                servers_online=int(n_online),
                servers_config_failing=int(n_failing),
                active_leases=int(leases.get(gid, 0)),
            )
            for gid, name, n_total, n_online, n_failing in groups
        ],
        fullest_pools=pools,
    )


async def _alerts(db: AsyncSession) -> AlertsSection:
    by_sev = {
        sev: int(n)
        for sev, n in (
            await db.execute(
                select(AlertEvent.severity, func.count())
                .where(AlertEvent.resolved_at.is_(None))
                .group_by(AlertEvent.severity)
            )
        ).all()
    }
    newest = (
        await db.execute(
            select(AlertEvent)
            .where(AlertEvent.resolved_at.is_(None))
            .order_by(AlertEvent.fired_at.desc())
            .limit(NEWEST_ALERTS)
        )
    ).scalars()
    return AlertsSection(
        open_total=sum(by_sev.values()),
        open_by_severity=by_sev,
        newest=[
            AlertRow(
                id=e.id,
                severity=e.severity,
                subject_type=e.subject_type,
                subject_display=e.subject_display,
                message=e.message,
                fired_at=e.fired_at,
            )
            for e in newest
        ],
    )


# ── Entry point ─────────────────────────────────────────────────────────────

_cache: dict[Access, tuple[float, PlatformSummary]] = {}


def invalidate_cache() -> None:
    _cache.clear()


async def build_summary(db: AsyncSession, user: User) -> PlatformSummary:
    """The snapshot ``user`` may see. See the module docstring for the rules."""
    access = resolve_access(user, await get_enabled_modules(db))
    hit = _cache.get(access)
    if hit is not None and monotonic() - hit[0] < CACHE_TTL_SECONDS:
        return hit[1]

    new_devices = None
    if access.has("new_devices"):
        new_devices = NewDevicesSection(**await new_device_counts(db))
    summary = PlatformSummary(
        generated_at=datetime.now(UTC),
        platform=await _platform(db),
        ipam=await _ipam(db) if access.has("ipam") else None,
        new_devices=new_devices,
        dns=await _dns(db, access) if access.has("dns") else None,
        dhcp=await _dhcp(db, access) if access.has("dhcp") else None,
        alerts=await _alerts(db) if access.has("alerts") else None,
        withheld=dict(access.withheld),
    )
    _cache[access] = (monotonic(), summary)
    return summary
