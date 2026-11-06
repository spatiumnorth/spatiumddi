"""Estimate a BIND9 group's named memory against its agents' limit (#3551).

Under split-horizon named loads zone data once per **view** that holds it.
#3551 made the BIND9 agent load an identical zone copy once and reference it
from the other views with ``in-view``, but BIND refuses a response-policy zone
defined that way, so every view that applies a blocklist still loads its own
copy of it. Adding a view to a group that subscribes to a large list can
therefore double named's memory and OOM-loop every agent in the group with
nothing in the product saying why.

This module estimates what named will hold and compares it with the memory
limit the group's agents report (their container's cgroup ``memory.max``, on
the heartbeat). It warns; it never refuses. The figures are measured on BIND
9.20.29 (``docs/features/DNS.md`` §2, "What a view costs in memory"):

* :data:`BASELINE_BYTES` — named and the agent at idle with one view, the
  ``DNS.md`` §8.0 rule of thumb;
* :data:`BYTES_PER_RECORD` — about 0.45 kB per record of each zone copy
  named loads (a copy shared through ``in-view`` counts once);
* :data:`BYTES_PER_RPZ_ENTRY` — about 1.4 kB per RPZ owner name, per view
  that loads the RPZ zone.

:func:`estimate_bytes` and :func:`assess` are pure; :func:`group_memory_estimate`
gathers their inputs from the database the way the bundle builder
(``services/dns/agent_config.py``) decides what each view loads.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from sqlalchemy import Text, bindparam, func, select, union
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import (
    DNSBlockList,
    DNSBlockListEntry,
    DNSRecord,
    DNSServer,
    DNSView,
    DNSZone,
)
from app.services.dns.pool_geo import (
    build_geo_steering,
    build_view_descriptors,
    places_zone_clause,
    views_rendering_zone,
)

MIB = 1024 * 1024

#: named and the agent at idle with one view (DNS.md §8.0's 400 MB).
BASELINE_BYTES = 400 * MIB
#: Per record of each zone copy named loads. Measured: a 200,000-record zone
#: costs about 86 MiB per copy.
BYTES_PER_RECORD = 450
#: Per RPZ owner name per view that loads the zone. Measured: a 100,000-entry
#: RPZ costs about 135 MiB per view.
BYTES_PER_RPZ_ENTRY = 1430
#: Warn when the estimate reaches this share of the limit.
WARN_FRACTION = 0.8
#: The DNS pod limit the shipped compose / chart / plain-k8s paths set (2Gi),
#: assumed when no agent of the group has reported one. The appliance sizes
#: its own from node RAM, and its agents report it.
DEFAULT_LIMIT_BYTES = 2 * 1024 * MIB

LimitSource = Literal["agent", "default"]


@dataclass(frozen=True)
class RpzLoad:
    """One RPZ zone as named loads it: in ``views`` (empty = no views), with
    ``entries`` owner names after the bundle's dedup and exceptions."""

    zone: str
    views: tuple[str, ...]
    entries: int

    @property
    def copies(self) -> int:
        return max(len(self.views), 1)

    @property
    def bytes(self) -> int:
        return self.entries * self.copies * BYTES_PER_RPZ_ENTRY


@dataclass(frozen=True)
class MemoryAssessment:
    estimated_bytes: int
    limit_bytes: int
    limit_source: LimitSource
    percent: float
    warn: bool


@dataclass(frozen=True)
class GroupMemoryEstimate:
    group_id: uuid.UUID
    views: tuple[str, ...]
    zone_records_loaded: int
    zone_bytes: int
    rpz: tuple[RpzLoad, ...]
    rpz_bytes: int
    baseline_bytes: int
    assessment: MemoryAssessment
    limit_server: str | None = None
    unknown_limit_servers: tuple[str, ...] = field(default_factory=tuple)

    @property
    def message(self) -> str | None:
        return warning_message(self) if self.assessment.warn else None


def estimate_bytes(zone_records_loaded: int, rpz: Iterable[RpzLoad]) -> int:
    """named + agent resident memory for this much loaded data."""
    return BASELINE_BYTES + zone_records_loaded * BYTES_PER_RECORD + sum(load.bytes for load in rpz)


def assess(estimated: int, limit_bytes: int | None) -> MemoryAssessment:
    """Compare an estimate with the agents' limit, or the documented default
    when none was reported. Warns at :data:`WARN_FRACTION` of the limit."""
    source: LimitSource = "agent" if limit_bytes else "default"
    limit = limit_bytes or DEFAULT_LIMIT_BYTES
    percent = round(100.0 * estimated / limit, 1)
    return MemoryAssessment(
        estimated_bytes=estimated,
        limit_bytes=limit,
        limit_source=source,
        percent=percent,
        warn=estimated >= WARN_FRACTION * limit,
    )


def zone_copies(per_view: Sequence[tuple[str, Any, int]]) -> list[tuple[tuple[str, ...], int]]:
    """Group a zone's view copies into the copies named actually loads.

    ``per_view`` is ``(view name, share key, records)`` in render order; two
    views whose share keys are equal render the same copy, which the agent
    loads once and references with ``in-view``. Returns ``(views, records)``
    per loaded copy.
    """
    copies: dict[Any, tuple[list[str], int]] = {}
    for view, key, records in per_view:
        if key in copies:
            copies[key][0].append(view)
        else:
            copies[key] = ([view], records)
    return [(tuple(views), records) for views, records in copies.values()]


def _fmt(n: int) -> str:
    if n >= 1024 * MIB:
        return f"{n / (1024 * MIB):.1f} GiB"
    return f"{n / MIB:.0f} MiB"


def warning_message(est: GroupMemoryEstimate) -> str:
    a = est.assessment
    whose = (
        f"reported by {est.limit_server}"
        if a.limit_source == "agent" and est.limit_server
        else "the default DNS pod limit; no agent in this group has reported its own"
    )
    parts = [
        f"named in this group is estimated to need about {_fmt(a.estimated_bytes)}, "
        f"{a.percent:.0f}% of its {_fmt(a.limit_bytes)} memory limit ({whose})."
    ]
    # Per view, the RPZ owners it loads: each view folds the group's lists
    # into a zone of its own, so the same entries are loaded once per view.
    per_view: dict[str, int] = {}
    for r in est.rpz:
        for v in r.views:
            per_view[v] = per_view.get(v, 0) + r.entries
    if len(per_view) > 1:
        listing = ", ".join(f"{v} {n:,}" for v, n in per_view.items())
        parts.append(
            f"Blocklists take about {_fmt(est.rpz_bytes)} of that: each of the "
            f"{len(per_view)} views loads its own copy of the lists it applies "
            f"(entries per view: {listing}), and BIND cannot share a blocklist "
            "between views."
        )
    parts.append(
        "Have fewer views draw on the same lists, or raise the DNS pod's memory limit, "
        "before named is OOM-killed."
    )
    return " ".join(parts)


# ── Gathering the inputs ────────────────────────────────────────────────────


async def _rpz_entry_count(
    db: AsyncSession,
    lists: list[DNSBlockList],
    exceptions: Iterable[str],
    memo: dict[Any, int] | None = None,
) -> int:
    """Owner names the RPZ zone for ``lists`` holds: each domain once across
    every enabled list (the #878 first-writer-wins dedup), plus the
    exception domains, which render as passthru owners in place of any entry
    they cancel.

    ``memo`` keeps one count per set of lists and exceptions: under views
    every view folds the same group lists into a zone of its own, and the
    deduplicated count over a million-entry feed takes seconds."""
    ids = sorted({bl.id for bl in lists if bl.enabled})
    if not ids:
        return 0
    exc = sorted({e.lower() for e in exceptions})
    key = (tuple(ids), tuple(exc))
    if memo is not None and key in memo:
        return memo[key]
    if len(ids) == 1 and not exc:
        # One list holds each domain once (``uq_dns_blocklist_entry_list_domain``)
        # and every writer stores it lowercased, so there is nothing to
        # deduplicate: a plain count over the list's index.
        n = int(
            await db.scalar(
                select(func.count())
                .select_from(DNSBlockListEntry)
                .where(DNSBlockListEntry.list_id == ids[0])
            )
            or 0
        )
        if memo is not None:
            memo[key] = n
        return n
    parts: list[Any] = [
        select(func.lower(DNSBlockListEntry.domain).label("d")).where(
            DNSBlockListEntry.list_id.in_(ids)
        )
    ]
    if exc:
        # One array parameter, not a SELECT per domain: a feed's exceptions
        # can number in the thousands.
        parts.append(select(func.unnest(bindparam("exc", exc, type_=ARRAY(Text))).label("d")))
    # ``union`` of one SELECT renders as that SELECT alone, with no DISTINCT:
    # without exceptions a domain two lists share would count twice.
    sub = (union(*parts) if len(parts) > 1 else parts[0].distinct()).subquery()
    n = int(await db.scalar(select(func.count()).select_from(sub)) or 0)
    if memo is not None:
        memo[key] = n
    return n


async def _rpz_loads(
    db: AsyncSession,
    group_id: uuid.UUID,
    operator_views: list[DNSView],
    view_names: list[str],
) -> list[RpzLoad]:
    """What RPZ zones named loads, and in which views, mirroring the bundle:
    a view whose own lists carry entries loads its own zone (group lists
    folded in); every other view loads the group zone (#1706)."""
    from app.services.dns_blocklist import (  # noqa: PLC0415
        effective_lists_for_group,
        effective_lists_for_view,
        exception_domains,
        has_entries,
    )

    loads: list[RpzLoad] = []
    own: set[str] = set()
    memo: dict[Any, int] = {}
    for v in operator_views:
        lists = await effective_lists_for_view(db, v.id) or []
        if lists and await has_entries(db, lists):
            n = await _rpz_entry_count(db, lists, await exception_domains(db, lists), memo)
            loads.append(RpzLoad(f"spatium-blocklist-{v.name}.rpz.", (v.name,), n))
            own.add(v.name)
    if operator_views and len(own) == len(operator_views):
        return loads
    lists = await effective_lists_for_group(db, group_id) or []
    if lists and await has_entries(db, lists):
        n = await _rpz_entry_count(db, lists, await exception_domains(db, lists), memo)
        loads.append(
            RpzLoad("spatium-blocklist.rpz.", tuple(v for v in view_names if v not in own), n)
        )
    return loads


async def _zone_records_loaded(
    db: AsyncSession, group_id: uuid.UUID, descs: list[dict[str, Any]], geo_active: bool
) -> int:
    """Records summed over the zone copies named loads, each shared copy once.

    Counted, not loaded: per zone, its records without a view plus those
    scoped to each view. A view's copy is keyed by the view-scoped records it
    adds, its view's ``allow-query`` (the agent shares only across equal
    ones) and, for a zone holding pool records under geo steering, the view
    itself (geo views serve different members). Forward zones hold no data;
    a secondary's records arrive by transfer and are not known here.
    """
    zones = (
        await db.execute(
            select(DNSZone.id, DNSZone.view_id).where(
                DNSZone.group_id == group_id,
                DNSZone.deleted_at.is_(None),
                DNSZone.zone_type == "primary",
            )
        )
    ).all()
    if not zones:
        return 0
    counts: dict[uuid.UUID, dict[Any, int]] = {}
    placing: dict[uuid.UUID, set[Any]] = {}
    pooled: set[uuid.UUID] = set()
    rows = await db.execute(
        select(
            DNSRecord.zone_id,
            DNSRecord.view_id,
            func.count(),
            func.count(DNSRecord.pool_member_id),
            # Rows that place the zone in their view (``places_zone``).
            func.count().filter(places_zone_clause()),
        )
        .join(DNSZone, DNSZone.id == DNSRecord.zone_id)
        .where(DNSZone.group_id == group_id, DNSRecord.deleted_at.is_(None))
        .group_by(DNSRecord.zone_id, DNSRecord.view_id)
    )
    for zone_id, view_id, n, n_pool, n_placing in rows.all():
        counts.setdefault(zone_id, {})[view_id] = int(n)
        if view_id is not None and n_placing:
            placing.setdefault(zone_id, set()).add(view_id)
        if n_pool:
            pooled.add(zone_id)

    total = 0
    for zone_id, zone_view_id in zones:
        by_view = counts.get(zone_id, {})
        shared = by_view.get(None, 0)
        if not descs:
            total += sum(by_view.values())
            continue
        scoped = placing.get(zone_id, set())
        per_view: list[tuple[str, Any, int]] = []
        for vd in views_rendering_zone(descs, zone_view_id, scoped):
            own = by_view.get(vd["id"], 0) if vd["kind"] == "operator" else 0
            key = (
                vd["id"] if own else None,
                tuple(str(c) for c in (vd.get("allow_query") or [])),
                vd["name"] if (geo_active and zone_id in pooled) else None,
            )
            per_view.append((vd["name"], key, shared + own))
        total += sum(records for _views, records in zone_copies(per_view))
    return total


async def _limit(db: AsyncSession, group_id: uuid.UUID) -> tuple[int | None, str | None, list[str]]:
    """The smallest memory limit any BIND9 agent of the group reported (the
    group's bundle renders the same on every server, so the tightest one
    fails first), that server's name, and the servers that reported none."""
    rows = (
        await db.execute(
            select(DNSServer.name, DNSServer.memory_limit_bytes).where(
                DNSServer.group_id == group_id, DNSServer.driver == "bind9"
            )
        )
    ).all()
    known = [(lim, name) for name, lim in rows if lim]
    unknown = sorted(name for name, lim in rows if not lim)
    if not known:
        return None, None, unknown
    lim, name = min(known)
    return int(lim), name, unknown


async def group_memory_estimate(
    db: AsyncSession, group_id: uuid.UUID
) -> GroupMemoryEstimate | None:
    """The estimate for one group, or None when it has no BIND9 server (the
    view / RPZ rendering this models is BIND9's)."""
    has_bind9 = await db.scalar(
        select(func.count())
        .select_from(DNSServer)
        .where(DNSServer.group_id == group_id, DNSServer.driver == "bind9")
    )
    if not has_bind9:
        return None
    views = list(
        (
            await db.execute(
                select(DNSView)
                .where(DNSView.group_id == group_id)
                .order_by(DNSView.order, DNSView.name)
            )
        )
        .scalars()
        .all()
    )
    geo = await build_geo_steering(db, group_id)
    descs = build_view_descriptors(views, geo) if (views or geo.active) else []
    view_names = [str(d["name"]) for d in descs]

    records = await _zone_records_loaded(db, group_id, descs, geo.active)
    rpz = await _rpz_loads(db, group_id, views, view_names)
    estimated = estimate_bytes(records, rpz)
    limit, limit_server, unknown = await _limit(db, group_id)
    return GroupMemoryEstimate(
        group_id=group_id,
        views=tuple(view_names),
        zone_records_loaded=records,
        zone_bytes=records * BYTES_PER_RECORD,
        rpz=tuple(rpz),
        rpz_bytes=sum(r.bytes for r in rpz),
        baseline_bytes=BASELINE_BYTES,
        assessment=assess(estimated, limit),
        limit_server=limit_server,
        unknown_limit_servers=tuple(unknown),
    )


async def warnings_by_group(
    db: AsyncSession, group_ids: Iterable[uuid.UUID]
) -> dict[uuid.UUID, GroupMemoryEstimate]:
    """``{group id: estimate}`` for the groups whose estimate warns."""
    out: dict[uuid.UUID, GroupMemoryEstimate] = {}
    for gid in dict.fromkeys(group_ids):
        est = await group_memory_estimate(db, gid)
        if est is not None and est.assessment.warn:
            out[gid] = est
    return out


__all__ = [
    "BASELINE_BYTES",
    "BYTES_PER_RECORD",
    "BYTES_PER_RPZ_ENTRY",
    "DEFAULT_LIMIT_BYTES",
    "WARN_FRACTION",
    "GroupMemoryEstimate",
    "MemoryAssessment",
    "RpzLoad",
    "assess",
    "estimate_bytes",
    "group_memory_estimate",
    "warning_message",
    "warnings_by_group",
    "zone_copies",
]
