"""IPAM / DHCP business metrics for the Prometheus ``/metrics`` scrape (#2146).

Computed at scrape time from the same collectors the InfluxDB push (#889)
uses (``services/influxdb/collect.py``), so the two exporters cannot
disagree: utilization is the stored ``allocated_ips`` / ``total_ips``
counters, and the per-scope lease gauge counts DISTINCT addresses, so a Kea
HA pair's mirrored lease is counted once.

Cached for a few seconds: several Prometheus servers (or the appliance
console, which scrapes every ~13 s) share one computation instead of each
running three queries. One scrape runs a constant number of queries however many subnets
and scopes exist; the series count is capped (see ``MAX_SERIES_PER_FAMILY``).

Cardinality: one series per subnet for each of three families and one per
DHCP scope for two. Never per-IP, per-lease or per-client. The labels carry
subnet CIDRs and space / group / scope names, which is why the caller only
serves these on an authenticated scrape (see ``app.metrics``).

The DNS / DHCP *traffic* counters the InfluxDB export also carries are not
here: they are 60 s agent-bucket deltas with a retention window, and
cumulating them would make a Prometheus counter that goes backwards when the
window is pruned. Prometheus users get rates from the agents' own stats.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.influxdb.collect import (
    MEASUREMENT_SCOPE_LEASES,
    MEASUREMENT_SUBNET,
    collect_dhcp_scope_lease_points,
    collect_subnet_utilization_points,
)
from app.services.influxdb.line_protocol import Point

# Seconds a rendered block is reused.
CACHE_TTL_SECONDS = 15.0
# Per-family cap, so an enormous estate cannot make a scrape unbounded. A
# truncated family is reported by ``spatiumddi_business_metrics_truncated``.
MAX_SERIES_PER_FAMILY = 10000

_cache: tuple[float, str] | None = None
_lock = asyncio.Lock()


def clear_cache() -> None:
    global _cache
    _cache = None


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _fmt(value: float | int | bool | str) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    return repr(value) if isinstance(value, float) else str(value)


def _family(
    out: list[str],
    name: str,
    help_text: str,
    points: Iterable[Point],
    field: str,
    labels: tuple[str, ...],
) -> bool:
    """Append one gauge family; return True when it was truncated."""
    out.append(f"# HELP {name} {help_text}")
    out.append(f"# TYPE {name} gauge")
    truncated = False
    for i, p in enumerate(points):
        if i >= MAX_SERIES_PER_FAMILY:
            truncated = True
            break
        lbl = ",".join(f'{k}="{_escape(str(p.tags.get(k, "")))}"' for k in labels)
        out.append(f"{name}{{{lbl}}} {_fmt(p.fields[field])}")
    return truncated


async def _render(db: AsyncSession) -> str:
    now = datetime.now(UTC)
    subnets = [
        p
        for p in await collect_subnet_utilization_points(db, now)
        if p.measurement == MEASUREMENT_SUBNET
    ]
    scopes = [
        p
        for p in await collect_dhcp_scope_lease_points(db, now)
        if p.measurement == MEASUREMENT_SCOPE_LEASES
    ]
    sl = ("subnet_id", "subnet", "space")
    cl = ("scope_id", "scope", "group", "subnet")
    out: list[str] = []
    trunc = False
    trunc |= _family(
        out,
        "spatiumddi_subnet_allocated_ips",
        "Allocated addresses in the subnet (same counter as the IPAM grid)",
        subnets,
        "allocated",
        sl,
    )
    trunc |= _family(
        out, "spatiumddi_subnet_total_ips", "Usable addresses in the subnet", subnets, "total", sl
    )
    trunc |= _family(
        out,
        "spatiumddi_subnet_utilization_percent",
        "Subnet utilization, allocated / total * 100",
        subnets,
        "percent",
        sl,
    )
    trunc |= _family(
        out,
        "spatiumddi_dhcp_scope_active_leases",
        "Distinct addresses under an active lease in the DHCP scope (an HA pair counts once)",
        scopes,
        "active_leases",
        cl,
    )
    trunc |= _family(
        out,
        "spatiumddi_dhcp_scope_active",
        "1 when the DHCP scope is enabled, else 0",
        scopes,
        "is_active",
        cl,
    )
    out.append(
        "# HELP spatiumddi_business_metrics_truncated "
        f"1 when a business family hit the {MAX_SERIES_PER_FAMILY}-series cap"
    )
    out.append("# TYPE spatiumddi_business_metrics_truncated gauge")
    out.append(f"spatiumddi_business_metrics_truncated {1 if trunc else 0}")
    return "\n".join(out) + "\n"


async def business_metrics_text(db: AsyncSession) -> str:
    """Prometheus text exposition for the business series, cached briefly."""
    global _cache
    async with _lock:
        if _cache is not None and time.monotonic() - _cache[0] < CACHE_TTL_SECONDS:
            return _cache[1]
        text = await _render(db)
        _cache = (time.monotonic(), text)
        return text
