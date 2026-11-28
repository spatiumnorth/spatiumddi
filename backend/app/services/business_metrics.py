"""DNS / DHCP / IPAM business metrics for the Prometheus ``/metrics`` scrape (#2146).

Rendered at scrape time and cached for a few seconds, in **sections**. Each
section is gated on the read permission its own REST list routes need, the
way ``GET /summary`` gates its sections (#2143), so an API token can never
read more through ``/metrics`` than it could through the API:

=================  ==========================================  =================================
section            series                                      read permission (type-wide) on
=================  ==========================================  =================================
``ipam``           ``spatiumddi_subnet_*``                     ``ip_space`` + ``subnet``
``dhcp_scopes``    ``spatiumddi_dhcp_scope_*``                 ``dhcp_server`` + ``dhcp_scope``
``dhcp_pools``     ``spatiumddi_dhcp_pool_occupancy_ratio``    the above + ``dhcp_pool``
``dhcp_servers``   ``spatiumddi_dhcp_server_*``,               ``dhcp_server``
                   ``spatiumddi_dhcp_packets_dropped_5m``
``dns_servers``    ``spatiumddi_dns_server_*``,                ``dns_group``
                   ``spatiumddi_dns_queries_per_second``
``dns_rpz``        ``spatiumddi_dns_rpz_blocked_24h``          ``dns_group`` + ``server``
``alerts``         ``spatiumddi_alerts_open``                  ``alert``
=================  ==========================================  =================================

The configured scrape token (``PROMETHEUS_METRICS_TOKEN``) is an operator's
deliberate grant to a monitoring system and reads every section. A token
bound to resource instances (#374) is refused at ``/metrics`` before this
module runs; the type-wide check is made here as well so that, if that ever
changes, a bound token gets no section rather than the whole estate.

The subnet and scope sections come from the collectors the InfluxDB push
(#889) uses (``services/influxdb/collect.py``), so the two exporters cannot
disagree: utilization is the stored ``allocated_ips`` / ``total_ips``
counters, and the per-scope lease gauge counts DISTINCT addresses, so a Kea
HA pair's mirrored lease is counted once. Pool occupancy is
``services/dhcp/pool_occupancy.py``, the source of the exhaustion alert.
Server state, the 5-minute DNS query rate and the 24 h RPZ count use the
definitions ``/summary`` uses.

Traffic is published as **windowed gauges**, not ``_total`` counters: the
source is 60 s agent-bucket deltas with a retention window, and cumulating
them here would make a counter that goes backwards when the window is pruned
and resets on every api restart. Graph them directly; ``rate()`` is wrong on
them.

Cardinality: one series per subnet, scope, dynamic pool or server per family
(three per DNS server for the query rate), never per IP, lease or client, and
each family is capped at ``MAX_SERIES_PER_FAMILY``. A capped family is
reported by ``spatiumddi_business_metrics_truncated``.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import token_scoped_resource_ids, user_has_permission
from app.models.alerts import AlertEvent
from app.models.dhcp import DHCPPool, DHCPScope, DHCPServer, DHCPServerGroup
from app.models.dns import DNSServer, DNSServerGroup
from app.models.dns_rpz_hit import DNSRPZHit
from app.models.metrics import DHCPMetricSample, DNSMetricSample
from app.services.dhcp.pool_occupancy import compute_pool_occupancy_batch
from app.services.influxdb.collect import (
    MEASUREMENT_SCOPE_LEASES,
    MEASUREMENT_SUBNET,
    collect_dhcp_scope_lease_points,
    collect_subnet_utilization_points,
)

if TYPE_CHECKING:
    from app.models.auth import User

# Seconds a rendered block is reused.
CACHE_TTL_SECONDS = 15.0
# Per-family cap, so an enormous estate cannot make a scrape unbounded.
MAX_SERIES_PER_FAMILY = 10000
# Same windows and verdicts as ``GET /summary`` (#2143).
TRAFFIC_WINDOW_MINUTES = 5
RPZ_WINDOW_HOURS = 24
ONLINE_STATUS = "active"
CONFIG_FAILING = ("reverted", "revert_failed", "no_previous")
ALERT_SEVERITIES = ("info", "warning", "critical")

# Rendering order, and the read permissions each section needs.
SECTIONS: dict[str, tuple[str, ...]] = {
    "ipam": ("ip_space", "subnet"),
    "dhcp_scopes": ("dhcp_server", "dhcp_scope"),
    "dhcp_pools": ("dhcp_server", "dhcp_scope", "dhcp_pool"),
    "dhcp_servers": ("dhcp_server",),
    "dns_servers": ("dns_group",),
    "dns_rpz": ("dns_group", "server"),
    "alerts": ("alert",),
}
ALL_SECTIONS: frozenset[str] = frozenset(SECTIONS)


def sections_for_user(user: User) -> frozenset[str]:
    """The sections an API-token scrape by ``user`` may read.

    A section needs a TYPE-WIDE read grant on every resource type it shows:
    a role scoped to one subnet or one DNS group is not one, and a token
    bound to instances is not one either (the series cover the whole estate
    and cannot be narrowed to the bound rows).
    """
    allowed: set[str] = set()
    for key, types in SECTIONS.items():
        if any(token_scoped_resource_ids(user, t) is not None for t in types):
            continue
        if all(user_has_permission(user, "read", t) for t in types):
            allowed.add(key)
    return frozenset(allowed)


@dataclass(frozen=True)
class _Series:
    labels: Mapping[str, str]
    value: float | int | bool


@dataclass(frozen=True)
class _Section:
    text: str
    truncated: bool


_cache: tuple[float, dict[str, _Section]] | None = None
_lock = asyncio.Lock()


def clear_cache() -> None:
    global _cache
    _cache = None


def _escape(value: str) -> str:
    """A Prometheus text-format label value: backslash, newline and double
    quote are the only characters that need escaping."""
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _fmt(value: float | int | bool) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    return repr(float(value)) if isinstance(value, float) else str(int(value))


def _family(out: list[str], name: str, help_text: str, series: Iterable[_Series]) -> bool:
    """Append one gauge family; return True when it was truncated."""
    out.append(f"# HELP {name} {help_text}")
    out.append(f"# TYPE {name} gauge")
    for i, s in enumerate(series):
        if i >= MAX_SERIES_PER_FAMILY:
            return True
        lbl = ",".join(f'{k}="{_escape(str(v))}"' for k, v in s.labels.items())
        out.append(f"{name}{{{lbl}}} {_fmt(s.value)}" if lbl else f"{name} {_fmt(s.value)}")
    return False


def _section(families: Sequence[tuple[str, str, Iterable[_Series]]]) -> _Section:
    out: list[str] = []
    truncated = False
    for name, help_text, series in families:
        truncated |= _family(out, name, help_text, series)
    return _Section("\n".join(out) + "\n", truncated)


# ── Section builders (each a constant number of queries) ─────────────────────


async def _ipam(db: AsyncSession, now: datetime) -> _Section:
    points = [
        p
        for p in await collect_subnet_utilization_points(db, now)
        if p.measurement == MEASUREMENT_SUBNET
    ]

    def series(field: str) -> list[_Series]:
        return [
            _Series(
                {k: str(p.tags.get(k, "")) for k in ("subnet_id", "subnet", "space")},
                p.fields[field],  # type: ignore[arg-type]
            )
            for p in points
        ]

    return _section(
        [
            (
                "spatiumddi_subnet_allocated_ips",
                "Allocated addresses in the subnet (same counter as the IPAM grid)",
                series("allocated"),
            ),
            ("spatiumddi_subnet_total_ips", "Usable addresses in the subnet", series("total")),
            (
                "spatiumddi_subnet_utilization_percent",
                "Subnet utilization, allocated / total * 100",
                series("percent"),
            ),
        ]
    )


async def _dhcp_scopes(db: AsyncSession, now: datetime) -> _Section:
    points = [
        p
        for p in await collect_dhcp_scope_lease_points(db, now)
        if p.measurement == MEASUREMENT_SCOPE_LEASES
    ]

    def series(field: str) -> list[_Series]:
        return [
            _Series(
                {k: str(p.tags.get(k, "")) for k in ("scope_id", "scope", "group", "subnet")},
                p.fields[field],  # type: ignore[arg-type]
            )
            for p in points
        ]

    return _section(
        [
            (
                "spatiumddi_dhcp_scope_active_leases",
                "Distinct addresses under an active lease in the DHCP scope "
                "(an HA pair counts once)",
                series("active_leases"),
            ),
            (
                "spatiumddi_dhcp_scope_active",
                "1 when the DHCP scope is enabled, else 0",
                series("is_active"),
            ),
        ]
    )


async def _dhcp_pools(db: AsyncSession) -> _Section:
    # Dynamic pools only, as the exhaustion alert and the MCP tool count them:
    # an excluded / reserved / pd range is not a range a client draws from.
    # ``deleted_at`` is named on both models rather than left to the global
    # soft-delete listener, which cannot see every query shape (#3492).
    rows = (
        await db.execute(
            select(DHCPPool, DHCPScope.name, DHCPServerGroup.name)
            .join(DHCPScope, DHCPScope.id == DHCPPool.scope_id)
            .outerjoin(DHCPServerGroup, DHCPServerGroup.id == DHCPScope.group_id)
            .where(
                DHCPPool.pool_type == "dynamic",
                DHCPPool.deleted_at.is_(None),
                DHCPScope.deleted_at.is_(None),
            )
            .order_by(DHCPPool.id)
        )
    ).all()
    occ = await compute_pool_occupancy_batch(db, [r[0] for r in rows])
    series: list[_Series] = []
    for pool, scope_name, group_name in rows:
        series.append(
            _Series(
                {
                    "pool_id": str(pool.id),
                    "pool": pool.name or f"{pool.start_ip}-{pool.end_ip}",
                    "scope_id": str(pool.scope_id),
                    "scope": scope_name or "",
                    "group": group_name or "",
                },
                round(occ[pool.id].percent / 100.0, 6),
            )
        )
    return _section(
        [
            (
                "spatiumddi_dhcp_pool_occupancy_ratio",
                "Occupied share of a dynamic DHCP pool, 0..1 (active leases union "
                "in-pool reservations, distinct addresses)",
                series,
            )
        ]
    )


_ServerRow = tuple[str, str, str, str, str | None]


def _server_state_families(
    prefix: str, rows: Sequence[_ServerRow]
) -> list[tuple[str, str, Iterable[_Series]]]:
    up: list[_Series] = []
    apply_ok: list[_Series] = []
    for sid, name, group, status, apply_status in rows:
        labels = {"server_id": sid, "server": name, "group": group}
        up.append(_Series(labels, status == ONLINE_STATUS))
        # NULL is UNKNOWN (an agent that never reported, an agentless driver):
        # no series, rather than a 1 that would read as converged (#882).
        if apply_status == "ok":
            apply_ok.append(_Series(labels, True))
        elif apply_status in CONFIG_FAILING:
            apply_ok.append(_Series(labels, False))
    return [
        (
            f"spatiumddi_{prefix}_server_up",
            "1 when the health sweep reports the server active, else 0",
            up,
        ),
        (
            f"spatiumddi_{prefix}_server_config_apply_ok",
            "1 when the agent runs the saved config, 0 when it reverted or failed "
            "(absent when the server never reported)",
            apply_ok,
        ),
    ]


async def _dhcp_servers(db: AsyncSession, now: datetime) -> _Section:
    rows = (
        await db.execute(
            select(
                DHCPServer.id,
                DHCPServer.name,
                DHCPServerGroup.name,
                DHCPServer.status,
                DHCPServer.config_apply_status,
            )
            .outerjoin(DHCPServerGroup, DHCPServerGroup.id == DHCPServer.server_group_id)
            .order_by(DHCPServer.name)
        )
    ).all()
    state: list[_ServerRow] = [(str(i), n or "", g or "", s or "", a) for i, n, g, s, a in rows]
    names = {sid: (n, g) for sid, n, g, _, _ in state}
    # ``socket_drop`` NULL means the agent cannot measure it (#980): such a
    # server gets no series rather than a 0 that would read as "none dropped".
    drops = (
        await db.execute(
            select(DHCPMetricSample.server_id, func.sum(DHCPMetricSample.socket_drop))
            .where(DHCPMetricSample.bucket_at >= now - timedelta(minutes=TRAFFIC_WINDOW_MINUTES))
            .where(DHCPMetricSample.socket_drop.is_not(None))
            .group_by(DHCPMetricSample.server_id)
        )
    ).all()
    dropped = [
        _Series(
            {"server_id": str(sid), "server": names[str(sid)][0], "group": names[str(sid)][1]},
            int(n or 0),
        )
        for sid, n in drops
        if str(sid) in names
    ]
    return _section(
        [
            *_server_state_families("dhcp", state),
            (
                "spatiumddi_dhcp_packets_dropped_5m",
                "DHCP packets the kernel dropped on the server's socket in the last "
                f"{TRAFFIC_WINDOW_MINUTES} minutes (absent when the agent cannot measure it)",
                dropped,
            ),
        ]
    )


async def _dns_servers(db: AsyncSession, now: datetime) -> _Section:
    rows = (
        await db.execute(
            select(
                DNSServer.id,
                DNSServer.name,
                DNSServerGroup.name,
                DNSServer.status,
                DNSServer.config_apply_status,
            )
            .join(DNSServerGroup, DNSServerGroup.id == DNSServer.group_id)
            .order_by(DNSServerGroup.name, DNSServer.name)
        )
    ).all()
    state: list[_ServerRow] = [(str(i), n or "", g or "", s or "", a) for i, n, g, s, a in rows]
    names = {sid: (n, g) for sid, n, g, _, _ in state}
    window = TRAFFIC_WINDOW_MINUTES * 60
    traffic = (
        await db.execute(
            select(
                DNSMetricSample.server_id,
                func.coalesce(func.sum(DNSMetricSample.queries_total), 0),
                func.coalesce(func.sum(DNSMetricSample.nxdomain), 0),
                func.coalesce(func.sum(DNSMetricSample.servfail), 0),
            )
            .where(DNSMetricSample.bucket_at >= now - timedelta(seconds=window))
            .group_by(DNSMetricSample.server_id)
        )
    ).all()
    qps: list[_Series] = []
    for sid, total, nx, sf in traffic:
        if str(sid) not in names:
            continue
        name, group = names[str(sid)]
        for rcode, n in (("all", total), ("nxdomain", nx), ("servfail", sf)):
            qps.append(
                _Series(
                    {"server_id": str(sid), "server": name, "group": group, "rcode": rcode},
                    round(int(n) / window, 3),
                )
            )
    return _section(
        [
            *_server_state_families("dns", state),
            (
                "spatiumddi_dns_queries_per_second",
                f"Queries per second averaged over the last {TRAFFIC_WINDOW_MINUTES} minutes "
                '(rcode="all" is every query)',
                qps,
            ),
        ]
    )


async def _dns_rpz(db: AsyncSession, now: datetime) -> _Section:
    rows = (
        await db.execute(
            select(DNSServerGroup.name, func.count(DNSRPZHit.id))
            .join(DNSServer, DNSServer.id == DNSRPZHit.server_id)
            .join(DNSServerGroup, DNSServerGroup.id == DNSServer.group_id)
            .where(DNSRPZHit.ts >= now - timedelta(hours=RPZ_WINDOW_HOURS))
            .where(DNSRPZHit.policy != "PASSTHRU")
            .group_by(DNSServerGroup.name)
            .order_by(DNSServerGroup.name)
        )
    ).all()
    return _section(
        [
            (
                "spatiumddi_dns_rpz_blocked_24h",
                f"Lookups an RPZ policy rewrote in the last {RPZ_WINDOW_HOURS} hours "
                "(PASSTHRU excluded)",
                [_Series({"group": g or ""}, int(n)) for g, n in rows],
            )
        ]
    )


async def _alerts(db: AsyncSession) -> _Section:
    counts = dict.fromkeys(ALERT_SEVERITIES, 0)
    for sev, n in (
        await db.execute(
            select(AlertEvent.severity, func.count())
            .where(AlertEvent.resolved_at.is_(None))
            .group_by(AlertEvent.severity)
        )
    ).all():
        counts[str(sev)] = int(n)
    return _section(
        [
            (
                "spatiumddi_alerts_open",
                "Alert events not yet resolved, by severity",
                [_Series({"severity": s}, n) for s, n in counts.items()],
            )
        ]
    )


async def _render(db: AsyncSession) -> dict[str, _Section]:
    now = datetime.now(UTC)
    return {
        "ipam": await _ipam(db, now),
        "dhcp_scopes": await _dhcp_scopes(db, now),
        "dhcp_pools": await _dhcp_pools(db),
        "dhcp_servers": await _dhcp_servers(db, now),
        "dns_servers": await _dns_servers(db, now),
        "dns_rpz": await _dns_rpz(db, now),
        "alerts": await _alerts(db),
    }


async def business_metrics_text(db: AsyncSession, sections: Iterable[str] = ALL_SECTIONS) -> str:
    """Prometheus text exposition for the ``sections`` the caller may read.

    The cache holds every section and is estate-wide, never per caller; what
    a caller sees is selected from it afterwards, so a broad scrape's render
    is never served whole to a narrower one. No sections: an empty string,
    and no query is run.
    """
    global _cache
    allowed = set(sections)
    wanted = [s for s in SECTIONS if s in allowed]
    if not wanted:
        return ""
    async with _lock:
        if _cache is None or time.monotonic() - _cache[0] >= CACHE_TTL_SECONDS:
            _cache = (time.monotonic(), await _render(db))
        rendered = _cache[1]
    parts = [rendered[s] for s in wanted]
    truncated = any(p.truncated for p in parts)
    return (
        "".join(p.text for p in parts)
        + "# HELP spatiumddi_business_metrics_truncated "
        + f"1 when a business family in this scrape hit the {MAX_SERIES_PER_FAMILY}-series cap\n"
        + "# TYPE spatiumddi_business_metrics_truncated gauge\n"
        + f"spatiumddi_business_metrics_truncated {1 if truncated else 0}\n"
    )
