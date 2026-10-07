#!/usr/bin/env python3
"""End-of-run report generator (docs/PERFORMANCE_TESTING.md §8).

Off-box, post-run. Ingests one run directory (war-room NDJSON, generator stats/
HdrHistograms, snapshots, setpoint history, the resolved manifest) and produces the
deliverable: ``report/slo_results.json`` (the machine-readable gate, §8.3/§8.4) +
``report/report.md`` (+ ``.html``) with the executive verdict, the consolidated SLO
table, t0↔tEnd delta tables, the bottleneck finding, and provenance.

Design (§8.0):
  1. The report is the deliverable, not the dashboards.
  2. ALL ingestion is graceful — a missing surface => that SLO row is NO_DATA, never
     a crash. Runs cleanly against a partial / dry run dir.
  3. Every §8.3 SLO row maps to exactly one collected surface and a verdict computed
     mechanically. Structural invariants (conns<70%, deadlocks=0, REFUSED=0,
     evictions=0, restarts=0) are NOT relaxed (§8.3.1).

Invocation (the registry / cli.py contract — NOTE: no --manifest; collect reads the
resolved manifest the controller pinned into the run dir):
    python3 -m spddi_perf.collect --run-id <id> --run-root <path> [--baseline <id>] [--out <dir>] [--publish]

Grounding for the SLO sources (cited inline where a row is computed):
  * war-room NDJSON shapes      perf/warroom/{poller,psql_probe,surfaces}.py
  * generator stat shapes       perf/generators/{dhcp/perfdhcp_shard,dns/dnsperf_runner}.py
                                perf/generators/orchestrator/{device_fleet,lifecycle_log,api_mutation_stream}.py
  * §8.2.4 domain ledger        perf/warroom/psql_probe.py:167-177 (domain_counts CTE)
  * dns_record_op NEVER pruned  backend/app/services/dns/record_ops.py:82,354,384 (flip to
                                state='applied', no delete) + grep backend/app/tasks/ clean
                                of DNSRecordOp => §5.1 unbounded-growth fact (d7)
  * audit isolation (a11)       backend/app/api/v1/dhcp/agents.py:1101-1102 (device firehose
                                writes 0 audit rows) — §5.1/§5.2
  * dns_zone hot-row (a8/c3)    backend/app/services/dns/serial.py:50 bump_zone_serial — §5.3 H3
"""

from __future__ import annotations

import argparse
import json
import math
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import spddi_perf.manifest as manifest_mod
from spddi_perf import generator_tallies as gt
from spddi_perf.logging_util import atomic_write_json, get_logger, log_event, utc_now_iso
from spddi_perf.runpaths import RunPaths

SERVICE = "spddi-perf-collect"

# ── Verdict tokens (the stable slo_results.json schema) ───────────────────────
PASS = "PASS"
FAIL = "FAIL"
NO_DATA = "NO_DATA"
N_A = "N_A"
CEILING = "CEILING"   # criterion (c) — discovery, not pass/fail

# ── §5.4 focus tables (the bloat / dead-tup / soak-growth watch set) ──────────
FOCUS_TABLES = (
    "dhcp_lease", "ip_address", "dhcp_lease_history", "dns_record", "dns_record_op",
    "dns_zone", "dns_query_log_entry", "dhcp_log_entry", "audit_log",
    "dns_server_zone_state",
)
HOT_TABLES = ("dns_zone", "ip_address", "dhcp_lease")  # H3/H8 lock-watch set

# §5.1: dns_record_op rows are NEVER deleted (record_ops.py flips state='applied' and
# leaves them; no prune task references DNSRecordOp). Measured bytes/row for the disk
# projection (d7) — conservative estimate from the model's column set; refined if the
# pg_user_tables bytes/live_tup is available.
DNS_RECORD_OP_BYTES_PER_ROW = 320.0

# §8.5 — the load-bearing profile axes. Two runs that differ on ANY of these are
# NOT comparable (the dominant write table flips with the profile, §8.1).
PROFILE_AXES = (
    "d_total", "lease_seconds", "t1_seconds", "ddns", "query_log_enabled",
    "subnets", "reverse_zone_shape", "powerdns", "dnssec",
)
REGRESSION_BAND = 0.20   # §8.5 default ±20% band on latency/throughput rows


# ==============================================================================
# Graceful NDJSON / JSON ingestion helpers
# ==============================================================================
def _read_ndjson(path: Path) -> list[dict[str, Any]]:
    """Read every well-formed JSON object line; tolerate a torn last line + absence."""
    out: list[dict[str, Any]] = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue  # torn / partial last line — skip, never crash
                if isinstance(obj, dict):
                    out.append(obj)
    except (FileNotFoundError, IsADirectoryError, OSError):
        return []
    return out


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        with open(path, encoding="utf-8") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else None
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def _available(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The war-room writes {available:false,...} brackets — keep only good ones."""
    return [r for r in records if r.get("available", True)]


def _nums(values: Any) -> list[float]:
    out: list[float] = []
    for v in values or []:
        if isinstance(v, (int, float)) and not isinstance(v, bool) and not _isnan(v):
            out.append(float(v))
    return out


def _isnan(v: float) -> bool:
    try:
        return math.isnan(v)
    except (TypeError, ValueError):
        return False


def _max(values: list[float], default: float | None = None) -> float | None:
    return max(values) if values else default


def _pctile(values: list[float], pct: float) -> float | None:
    """Nearest-rank percentile (used over per-window p-series, not raw samples)."""
    vals = sorted(values)
    if not vals:
        return None
    rank = max(0, min(len(vals) - 1, math.ceil(pct / 100.0 * len(vals)) - 1))
    return vals[rank]


def _fmt(v: Any, unit: str = "") -> str:
    if v is None:
        return "—"
    if isinstance(v, bool):
        return str(v)
    if isinstance(v, float):
        s = f"{v:.3g}" if abs(v) < 1000 else f"{v:,.0f}"
        return f"{s}{unit}"
    if isinstance(v, int):
        return f"{v:,}{unit}"
    return f"{v}{unit}"


# ==============================================================================
# Run-dir ingestion — one object holding every loaded surface (all graceful)
# ==============================================================================
@dataclass
class RunData:
    rp: RunPaths
    m: manifest_mod.Manifest
    profile: str

    # setpoint history (phase boundaries, achieved curve)
    setpoints: list[dict[str, Any]] = field(default_factory=list)

    # war-room surfaces (poller)
    health: list[dict[str, Any]] = field(default_factory=list)
    pg_overview: list[dict[str, Any]] = field(default_factory=list)
    pg_connections: list[dict[str, Any]] = field(default_factory=list)
    pg_tables: list[dict[str, Any]] = field(default_factory=list)
    redis_overview: list[dict[str, Any]] = field(default_factory=list)
    redis_wakebus: list[dict[str, Any]] = field(default_factory=list)
    celery_queues: list[dict[str, Any]] = field(default_factory=list)
    metrics_dns: list[dict[str, Any]] = field(default_factory=list)
    metrics_dhcp: list[dict[str, Any]] = field(default_factory=list)

    # war-room surfaces (psql_probe)
    pg_locks: list[dict[str, Any]] = field(default_factory=list)
    pg_activity: list[dict[str, Any]] = field(default_factory=list)
    pg_user_tables: list[dict[str, Any]] = field(default_factory=list)
    domain_counts: list[dict[str, Any]] = field(default_factory=list)
    operator_mutation: list[dict[str, Any]] = field(default_factory=list)
    ui_probe: list[dict[str, Any]] = field(default_factory=list)

    # generators
    perfdhcp: list[dict[str, Any]] = field(default_factory=list)
    dnsperf: list[dict[str, Any]] = field(default_factory=list)
    orchestrator_stats: list[dict[str, Any]] = field(default_factory=list)
    orchestrator_summary: list[dict[str, Any]] = field(default_factory=list)
    lifecycle_count: int = 0

    # snapshots
    snapshots: dict[str, dict[str, Any]] = field(default_factory=dict)

    # which surfaces actually had at least one available bracket
    present: set[str] = field(default_factory=set)


def ingest(rp: RunPaths, m: manifest_mod.Manifest, log) -> RunData:
    """Load every surface from the run dir. Missing => empty (graceful)."""
    rd = RunData(rp=rp, m=m, profile=m.profile_slug)

    rd.setpoints = _read_ndjson(rp.setpoint_history)

    # poller war-room surfaces
    wr = {
        "health": "health_platform", "pg_overview": "pg_overview",
        "pg_connections": "pg_connections", "pg_tables": "pg_tables",
        "redis_overview": "redis_overview", "redis_wakebus": "redis_wakebus",
        "celery_queues": "celery_queues", "metrics_dns": "metrics_dns",
        "metrics_dhcp": "metrics_dhcp",
        # psql_probe surfaces
        "pg_locks": "pg_locks", "pg_activity": "pg_activity",
        "pg_user_tables": "pg_user_tables", "domain_counts": "domain_counts",
        "operator_mutation": "operator_mutation", "ui_probe": "ui_probe",
    }
    for attr, surface in wr.items():
        recs = _read_ndjson(rp.warroom(surface))
        setattr(rd, attr, recs)
        if _available(recs):
            rd.present.add(surface)

    # generators — perfdhcp shards (perfdhcp.shard<N>.stat) + dnsperf (dnsperf.stat)
    for stat in sorted(rp.generators_dir.glob("perfdhcp.shard*.stat")):
        rd.perfdhcp.extend(_read_ndjson(stat))
    if rd.perfdhcp:
        rd.present.add("perfdhcp")
    rd.dnsperf = _read_ndjson(rp.generator("dnsperf.stat"))
    if rd.dnsperf:
        rd.present.add("dnsperf")

    # orchestrator per-shard periodic stats + final summary
    for s in sorted(rp.generators_dir.glob("orchestrator.shard*.ndjson")):
        rd.orchestrator_stats.extend(_read_ndjson(s))
    for s in sorted(rp.generators_dir.glob("orchestrator.shard*.summary.ndjson")):
        rd.orchestrator_summary.extend(_read_ndjson(s))
    if rd.orchestrator_stats or rd.orchestrator_summary:
        rd.present.add("orchestrator")
    rd.lifecycle_count = len(_read_ndjson(rp.lifecycle))

    # snapshots — load every <name>.json (t0_baseline / final / ceiling / resperf_*)
    if rp.snapshots_dir.is_dir():
        for snap in sorted(rp.snapshots_dir.glob("*.json")):
            obj = _read_json(snap)
            if obj is not None:
                rd.snapshots[snap.stem] = obj

    log_event(log, 20, "ingest_complete", profile=rd.profile,
              present=sorted(rd.present), setpoint_ticks=len(rd.setpoints),
              orchestrator_stat_rows=len(rd.orchestrator_stats),
              lifecycle_rows=rd.lifecycle_count,
              snapshots=sorted(rd.snapshots.keys()))
    return rd


# ==============================================================================
# Cross-shard generator aggregation
# ==============================================================================
def _agg_summary_metric(rd: RunData, key: str) -> dict[str, float] | None:
    """Aggregate one orchestrator cumulative_summary metric across shards.

    Each shard emits {count,p50,p95,p99,p999,max}. Percentiles can't be summed; we
    take the count-weighted-worst-tail conservatively (max of p99/p999/max, count-
    weighted mean of p50/p95) so the criterion-(b) verdict never under-reports the
    tail across shards.
    """
    rows = [s.get(key) for s in rd.orchestrator_summary if isinstance(s.get(key), dict)]
    rows = [r for r in rows if r and int(r.get("count") or 0) > 0]
    if not rows:
        return None
    total = sum(int(r.get("count") or 0) for r in rows)
    if total <= 0:
        return None

    def _wmean(field_: str) -> float:
        return sum(float(r.get(field_) or 0) * int(r.get("count") or 0) for r in rows) / total

    return {
        "count": total,
        "p50": round(_wmean("p50"), 3),
        "p95": round(_wmean("p95"), 3),
        "p99": round(max(float(r.get("p99") or 0) for r in rows), 3),
        "p999": round(max(float(r.get("p999") or 0) for r in rows), 3),
        "max": round(max(float(r.get("max") or 0) for r in rows), 3),
    }


def _orchestrator_window_series(rd: RunData, key: str) -> list[float]:
    """Per-window values of an orchestrator periodic field across all shards."""
    return _nums([r.get(key) for r in rd.orchestrator_stats])


def _phase_windows(rd: RunData, predicate) -> list[dict[str, Any]]:
    """Orchestrator stat windows whose setpoint phase matches predicate(phase).

    The orchestrator rows carry no phase tag, so we map each window's ts back to the
    nearest setpoint tick by timestamp ordering. Falls back to all windows.
    """
    if not rd.setpoints:
        return rd.orchestrator_stats
    # Build (ts, phase) from setpoint history.
    sp_phases = [(s.get("ts"), s.get("phase")) for s in rd.setpoints if s.get("ts")]
    if not sp_phases:
        return rd.orchestrator_stats
    matched_phases = {p for _, p in sp_phases if p and predicate(p)}
    if not matched_phases:
        return []
    out: list[dict[str, Any]] = []
    for r in rd.orchestrator_stats:
        ts = r.get("ts")
        if not ts:
            continue
        # nearest preceding setpoint phase
        phase = None
        for sp_ts, sp_phase in sp_phases:
            if sp_ts and sp_ts <= ts:
                phase = sp_phase
        if phase in matched_phases:
            out.append(r)
    return out


def _is_steady(phase: str) -> bool:
    p = (phase or "").lower()
    return "steady" in p or "soak" in p or "plateau" in p


def _is_peak(phase: str) -> bool:
    p = (phase or "").lower()
    return "peak" in p or "ceiling" in p or "surge" in p


# ==============================================================================
# Snapshot t0 ↔ tEnd selection (graceful, name-tolerant)
# ==============================================================================
def _pick_snapshot(rd: RunData, *names: str) -> dict[str, Any] | None:
    for n in names:
        if n in rd.snapshots:
            return rd.snapshots[n]
    return None


def _t0_snapshot(rd: RunData) -> dict[str, Any] | None:
    return _pick_snapshot(rd, "t0_baseline", "t0", "baseline", "prune-pre", "provision")


def _tend_snapshot(rd: RunData) -> dict[str, Any] | None:
    return _pick_snapshot(rd, "final", "tEnd", "tend", "ceiling")


# ==============================================================================
# SLO row construction
# ==============================================================================
def _row(rid: str, slo: str, source: str, measured: Any, threshold: Any,
         verdict: str, *, note: str = "") -> dict[str, Any]:
    return {
        "id": rid, "slo": slo, "source": source,
        "measured": measured, "threshold": threshold, "verdict": verdict,
        "note": note,
    }


def _verdict_lt(measured: float | None, threshold: float, *, no_data_ok: bool = False) -> str:
    if measured is None:
        return NO_DATA
    return PASS if measured < threshold else FAIL


def _verdict_le(measured: float | None, threshold: float) -> str:
    if measured is None:
        return NO_DATA
    return PASS if measured <= threshold else FAIL


def _verdict_eq0(measured: float | None) -> str:
    if measured is None:
        return NO_DATA
    return PASS if measured == 0 else FAIL


# ── Criterion (a) — DB never bottlenecks ──────────────────────────────────────
def criterion_a(rd: RunData) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    ov = _available(rd.pg_overview)
    conns = _available(rd.pg_connections)
    locks = _available(rd.pg_locks)
    tables = _available(rd.pg_user_tables)

    # a1 — peak active conns vs 200, PASS < 70% (140). Structural invariant.
    # (postgres overview active_connections / max_connections — surfaces.map_pg_overview)
    peak_conns = _max(_nums([r.get("active_connections") for r in ov]))
    max_conns = None
    if ov:
        max_conns = _max(_nums([r.get("max_connections") for r in ov])) or 200.0
    threshold_conns = 0.70 * (max_conns or 200.0)
    a1_pct = (peak_conns / max_conns * 100.0) if (peak_conns is not None and max_conns) else None
    rows.append(_row(
        "a1", "Peak PG active conns < 70% of max_connections (structural)",
        "pg_overview.active_connections",
        f"{_fmt(peak_conns)}/{_fmt(max_conns)} ({_fmt(a1_pct, '%')})",
        f"< {_fmt(threshold_conns)} (70%)",
        _verdict_lt(peak_conns, threshold_conns),
        note="not relaxed after baseline (§8.3.1)"))

    # a2 — app-pool saturation (composite, D7): lease-events p95 rising while conns
    # flat below 30×api-replicas. We only have one of the two signals reliably; if
    # we can't prove the co-occurrence we report N_A with what we saw.
    rows.append(_row(
        "a2", "App-pool saturation (no sustained co-occurrence)",
        "composite: lease-events p95 + pg conns flat",
        "inferred — needs lease-events p95 + replica count",
        "never all-true >60s",
        N_A,
        note="composite (D7); reported as N_A unless both legs present"))

    # a3 — idle-in-transaction < 10, not climbing. (pg_connections by_state)
    iit = []
    for r in conns:
        bs = r.get("by_state") or {}
        iit.append(float(bs.get("idle_in_transaction", 0)))
    peak_iit = _max(iit)
    a3_climb = ""
    if len(iit) >= 2:
        a3_climb = "tEnd≈t0" if abs(iit[-1] - iit[0]) <= 2 else f"t0={iit[0]:.0f}→tEnd={iit[-1]:.0f}"
    rows.append(_row(
        "a3", "idle-in-transaction < 10 and not climbing",
        "pg_connections.by_state.idle_in_transaction",
        f"peak {_fmt(peak_iit)} {a3_climb}".strip(), "< 10 (peak) [tune]",
        _verdict_lt(peak_iit, 10.0) if peak_iit is not None else NO_DATA))

    # a4 — deadlocks exactly 0. (pg_locks.pg_database.deadlocks) — structural.
    deadlocks = None
    for r in locks:
        d = (r.get("pg_database") or {}).get("deadlocks")
        if d is not None:
            deadlocks = max(deadlocks or 0, int(d))
    # pg_stat_database deadlocks is monotonic; any final value > 0 means deadlocks fired.
    rows.append(_row(
        "a4", "Deadlocks exactly 0 (structural)",
        "pg_locks.pg_database.deadlocks",
        _fmt(deadlocks), "= 0",
        _verdict_eq0(float(deadlocks) if deadlocks is not None else None),
        note="any increment = FAIL; not relaxed (§8.3.1)"))

    # a5 — lock-wait waiters: no window > 30s with waiters > 0. We approximate "no
    # sustained" as: count of consecutive samples with locks_waiting>0 stays small.
    waiting = _nums([r.get("locks_waiting") for r in locks])
    peak_wait = _max(waiting)
    sustained_wait = _max_consecutive(waiting, lambda v: v > 0)
    rows.append(_row(
        "a5", "No sustained lock-wait waiters (> 30s window)",
        "pg_locks.locks_waiting",
        f"peak {_fmt(peak_wait)}, max-consecutive {sustained_wait} samples",
        "no sustained window > 0",
        (NO_DATA if not waiting else (PASS if sustained_wait <= 1 else FAIL)),
        note="psql cadence ~30s; >1 consecutive sample ≈ sustained"))

    # a6 — cache hit ratio min over steady ≥ 90% (floor); ≥95% steady target.
    cache = _nums([r.get("cache_hit_ratio") for r in ov])
    cache = [c * 100.0 if c <= 1.0 else c for c in cache]  # surfaces emits 0..1
    min_cache = min(cache) if cache else None
    rows.append(_row(
        "a6", "Cache hit ratio ≥ 90% floor (≥95% steady) (structural floor)",
        "pg_overview.cache_hit_ratio",
        f"min {_fmt(min_cache, '%')}", "≥ 90%",
        (NO_DATA if min_cache is None else (PASS if min_cache >= 90.0 else FAIL))))

    # a7 — autovacuum keeping up: no focus table's dead_tup strictly increasing
    # (oscillates good, monotonic ramp = autovacuum losing). pg_user_tables.tables.
    a7_offenders = _monotonic_dead_tup_offenders(tables)
    rows.append(_row(
        "a7", "Autovacuum keeps up (no focus table dead_tup monotonic ramp)",
        "pg_user_tables.tables.<t>.dead_tup trajectory",
        ("oscillating (ok)" if not a7_offenders else f"ramping: {', '.join(a7_offenders)}"),
        "no monotonic ramp",
        (NO_DATA if not tables else (PASS if not a7_offenders else FAIL))))

    # a8 — dns_zone hot-row contention (H3): no sustained lock-wait on dns_zone.
    zone_waits = []
    for r in locks:
        rw = r.get("relation_waiting") or {}
        zone_waits.append(float(rw.get("dns_zone", 0)))
    peak_zone_wait = _max(zone_waits)
    zone_sustained = _max_consecutive(zone_waits, lambda v: v > 0)
    rows.append(_row(
        "a8", "dns_zone hot-row: no sustained lock-wait at first-DDNS peak (H3)",
        "pg_locks.relation_waiting.dns_zone",
        f"peak {_fmt(peak_zone_wait)}, max-consecutive {zone_sustained}",
        "no sustained wait; reclaimed each cycle",
        (NO_DATA if not zone_waits else (PASS if zone_sustained <= 1 else FAIL)),
        note="predicted qlog-OFF first-to-give (§5.3 H3 / serial.py:50)"))

    # a9 — temp_files / spill bounded (work_mem=16MB context). pg_locks.pg_database.
    temp_bytes = []
    for r in locks:
        tb = (r.get("pg_database") or {}).get("temp_bytes")
        if tb is not None:
            temp_bytes.append(float(tb))
    # cumulative counter — report delta across the run.
    temp_delta = (temp_bytes[-1] - temp_bytes[0]) if len(temp_bytes) >= 2 else None
    rows.append(_row(
        "a9", "temp_files/spill bounded (work_mem=16MB)",
        "pg_locks.pg_database.temp_bytes (Δ over run)",
        _fmt(temp_delta, " B"), "no large sustained spill [tune]",
        (NO_DATA if temp_delta is None else N_A),
        note="reported; threshold is [tune-after-baseline]"))

    # a10 — WAL rate bounded, correlates with load (no decoupled growth). pg_locks.
    wal_rates = _nums([r.get("wal_bytes_per_s") for r in locks])
    peak_wal = _max(wal_rates)
    rows.append(_row(
        "a10", "WAL rate bounded; correlates with load",
        "pg_locks.wal_bytes_per_s",
        f"peak {_fmt(peak_wal, ' B/s')}", "no decoupled growth",
        (NO_DATA if not wal_rates else N_A),
        note="reported; correlation judged in the timeline chart"))

    # a11 — audit_log device-load isolation: 0 audit rows from device load.
    # (§5.1: device firehose writes ZERO audit rows — agents.py:1101-1102.) We prove
    # it by audit_rows delta during device-only windows ≈ operator-mutation count.
    a11 = _audit_isolation(rd)
    rows.append(_row(
        "a11", "audit_log device-load isolation (0 audit rows from device firehose)",
        "domain_counts.audit_rows Δ vs operator_mutation.audited_ops",
        a11["measured"], "device-only Δ ≈ operator stream only",
        a11["verdict"],
        note="§5.1 agents.py:1101-1102 — device firehose writes 0 audit rows"))

    # a12 ⚑ — daily log-prune DELETE (qlog-on only). bloat reclaimed in-window.
    if rd.m.scale.query_log_enabled:
        prune_pre = _pick_snapshot(rd, "prune-pre", "prune_pre")
        prune_post = _pick_snapshot(rd, "prune-post", "prune_post")
        rows.append(_row(
            "a12", "Daily log-prune DELETE completes; bloat reclaimed in-window (qlog-on)",
            "snapshots/prune-{pre,post}",
            ("present" if (prune_pre and prune_post) else "missing prune snapshots"),
            "DELETE finishes; reclaimed before tEnd",
            (PASS if (prune_pre and prune_post) else NO_DATA)))
    else:
        rows.append(_row(
            "a12", "Daily log-prune DELETE (qlog-on only)",
            "snapshots/prune-{pre,post}", "qlog-off — not exercised", "n/a", N_A,
            note="⚑ profile-conditional (query_log_enabled=false)"))
    return rows


def _max_consecutive(values: list[float], pred) -> int:
    best = cur = 0
    for v in values:
        if pred(v):
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best


def _monotonic_dead_tup_offenders(tables_recs: list[dict[str, Any]]) -> list[str]:
    """Focus tables whose dead_tup is strictly non-decreasing across the run (ramp).

    dns_record_op grows forever BUT its dead_tup should still be reclaimed (rows are
    flipped to 'applied', not deleted — §5.1), so its dead_tup ramping is the a7 smell.
    """
    series: dict[str, list[float]] = {t: [] for t in FOCUS_TABLES}
    for rec in tables_recs:
        tbls = rec.get("tables") or {}
        for t in FOCUS_TABLES:
            dt = (tbls.get(t) or {}).get("dead_tup")
            if dt is not None:
                series[t].append(float(dt))
    offenders = []
    for t, vals in series.items():
        if len(vals) < 4:
            continue
        # strictly non-decreasing with a meaningful net climb (no oscillation reset)
        non_decreasing = all(vals[i] <= vals[i + 1] + 1 for i in range(len(vals) - 1))
        net_climb = vals[-1] - min(vals)
        if non_decreasing and net_climb > max(1000.0, 0.5 * (max(vals) or 1)):
            offenders.append(t)
    return offenders


def _audit_isolation(rd: RunData) -> dict[str, Any]:
    """a11: audit_rows growth should be explained entirely by the operator stream.

    audit_rows (domain_counts, monotonic) Δ over the run should ≈ the operator
    stream's audited_ops total. A large excess => device load wrote audit rows
    (a §5.1 violation / regression).
    """
    dc = _available(rd.domain_counts)
    audit_series = _nums([r.get("audit_rows") for r in dc])
    if len(audit_series) < 2:
        return {"measured": "no domain_counts", "verdict": NO_DATA}
    audit_delta = audit_series[-1] - audit_series[0]
    op_audited = sum(int(r.get("audited_ops") or 0) for r in _available(rd.operator_mutation))
    if not rd.operator_mutation:
        # No operator stream ran — then audit_delta MUST be ~0 (pure device load).
        verdict = PASS if audit_delta <= 5 else FAIL
        return {"measured": f"Δaudit={audit_delta:.0f}, no operator stream",
                "verdict": verdict}
    # With an operator stream: device-attributable excess = audit_delta - op_audited.
    excess = audit_delta - op_audited
    # Allow modest slack (integration reconcilers / startup); device load must be ~0.
    verdict = PASS if excess <= max(10.0, 0.10 * max(1.0, op_audited)) else FAIL
    return {"measured": f"Δaudit={audit_delta:.0f}, operator audited≈{op_audited}, "
                        f"device-excess≈{excess:.0f}", "verdict": verdict}


# ── Criterion (b) — end-to-end latency SLOs (per phase) ───────────────────────
def criterion_b(rd: RunData) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    slo = rd.m.slo

    # DHCP ACK percentiles — orchestrator dora_ack cumulative summary is the truth
    # (HdrHistogram); perfdhcp is the protocol-ceiling cross-check.
    dora = _agg_summary_metric(rd, "dora_ack")
    renew = _agg_summary_metric(rd, "renew_ack")
    dns = _agg_summary_metric(rd, "dns_resolve")
    prop_dns = _agg_summary_metric(rd, "propagation_ipam_to_dns")

    # b1 — DHCP ACK p50 (DORA) < 10ms on-LAN.
    rows.append(_row(
        "b1", "DHCP ACK p50 (DORA) < 10 ms on-LAN",
        "orchestrator dora_ack.p50 (HdrHistogram)",
        _fmt(dora.get("p50") if dora else None, " ms"), "< 10 ms",
        _verdict_lt(dora.get("p50") if dora else None, 10.0)))

    # b2 — DHCP ACK p99 (DORA) < 50ms steady / < 250ms peak. Use steady-phase windows
    # for the steady gate (phase-aware).
    steady_dora_p99 = _phase_p99(rd, "ack_dora_p99", _is_steady)
    peak_dora_p99 = _phase_p99(rd, "ack_dora_p99", _is_peak)
    b2_meas = f"steady {_fmt(steady_dora_p99, ' ms')}, peak {_fmt(peak_dora_p99, ' ms')}"
    b2_verdict = _phase_pair_verdict(steady_dora_p99, slo.dhcp_ack_p99_ms,
                                     peak_dora_p99, 250.0)
    rows.append(_row(
        "b2", "DHCP ACK p99 (DORA) < 50 ms steady / < 250 ms peak (per phase)",
        "orchestrator ack_dora_p99 (per-window, phase-aware)",
        b2_meas, f"< {slo.dhcp_ack_p99_ms} ms / < 250 ms", b2_verdict))

    # b3 — DHCP renewal p99 < 30ms steady.
    steady_renew_p99 = _phase_p99(rd, "ack_renew_p99", _is_steady)
    rows.append(_row(
        "b3", "DHCP renewal p99 < 30 ms steady",
        "orchestrator ack_renew_p99 (steady)",
        _fmt(steady_renew_p99 if steady_renew_p99 is not None
             else (renew.get("p99") if renew else None), " ms"),
        "< 30 ms",
        _verdict_lt(steady_renew_p99 if steady_renew_p99 is not None
                    else (renew.get("p99") if renew else None), 30.0)))

    # b4 — DNS resolve p99 (auth, UDP, on-LAN) < 10ms steady.
    steady_dns_p99 = _phase_p99(rd, "dns_p99", _is_steady)
    dns_p99 = steady_dns_p99 if steady_dns_p99 is not None else (dns.get("p99") if dns else None)
    rows.append(_row(
        "b4", "DNS resolve p99 (auth, UDP, on-LAN) < 10 ms steady",
        "orchestrator dns_p99 (steady) / dnsperf",
        _fmt(dns_p99, " ms"), f"< {slo.dns_resolve_p99_ms} ms",
        _verdict_lt(dns_p99, slo.dns_resolve_p99_ms)))

    # b5 — DNS resolve p999 / max < 50 / < 200ms.
    p999 = dns.get("p999") if dns else None
    dns_max = dns.get("max") if dns else None
    b5_verdict = NO_DATA
    if p999 is not None or dns_max is not None:
        b5_verdict = PASS if ((p999 is None or p999 < 50.0) and (dns_max is None or dns_max < 200.0)) else FAIL
    rows.append(_row(
        "b5", "DNS resolve p999 < 50 ms / max < 200 ms (tail bounded)",
        "orchestrator dns_resolve.p999/max",
        f"p999 {_fmt(p999, ' ms')}, max {_fmt(dns_max, ' ms')}", "< 50 / < 200 ms",
        b5_verdict))

    # The orchestrator's own DNS stream, by rcode (#1057). Before per-rcode
    # accounting its answers were invisible to b6/b6a: a run whose 606k queries
    # BIND answered REFUSED read "ok 0, timeouts 46" and b6a said NO_DATA.
    orch_c = gt.sum_counters(rd.orchestrator_summary)
    orch_rc = gt.dns_rcodes(orch_c)
    orch_sent = int(orch_c.get("dns_sent") or 0)
    has_orch = bool(rd.orchestrator_summary)

    # b6 — DNS SERVFAIL rate < 0.1% steady. dnsperf rcode + orchestrator rcode,
    # both halves over queries SENT (dnsperf `sent`, orchestrator `dns_sent`):
    # a query that timed out was sent and did not SERVFAIL, so the rate is per
    # attempt on either side and reproduces against BIND's own
    # SERVFAIL / QUERY ratio. (Over `dns_answered` a heavy-timeout run would
    # read higher than BIND does.)
    dp_sent, dp_servfail = _dnsperf_rcode_totals(rd, "SERVFAIL")
    sf_total = dp_sent + orch_sent
    servfail = ((dp_servfail + orch_rc.get("SERVFAIL", 0)) / sf_total) if sf_total else None
    rows.append(_row(
        "b6", "DNS SERVFAIL rate < 0.1% steady",
        "dnsperf.rcode.SERVFAIL / sent + orchestrator dns_rcode_SERVFAIL / dns_sent",
        _fmt(servfail * 100.0 if servfail is not None else None, "%"), "< 0.1%",
        _verdict_lt(servfail, 0.001) if servfail is not None else NO_DATA))

    # b6a — DNS REFUSED rate exactly 0 (structural; out-of-zone leak detector §4.9).
    # The orchestrator's REFUSED count joins dnsperf's: a refused query measured
    # nothing, whether the name escaped the validator or the generator queried
    # from a vantage outside the served view — the run cannot stand either way.
    refused_dnsperf = sum(int((r.get("rcode") or {}).get("REFUSED", r.get("refused", 0)) or 0)
                          for r in rd.dnsperf)
    refused_orch = int(orch_rc.get("REFUSED", 0))
    refused_total = refused_dnsperf + refused_orch
    has_refused_data = bool(rd.dnsperf) or has_orch
    rows.append(_row(
        "b6a", "DNS REFUSED rate exactly 0 (structural — out-of-zone leak, §4.9)",
        "dnsperf.rcode.REFUSED + orchestrator dns_rcode_REFUSED",
        (f"{refused_total} (dnsperf {refused_dnsperf}, orchestrator {refused_orch})"
         if has_refused_data else _fmt(None)), "= 0",
        (NO_DATA if not has_refused_data else (PASS if refused_total == 0 else FAIL)),
        note="any REFUSED = an out-of-zone query escaped the §4.9 validator (bug/leak), "
             "or the generator queried from outside the served view (vantage)"))

    # b7 — DNS timeout/drop rate ~0 steady. dnsperf timeouts + orchestrator dns_timeout
    # (+ dns_error: exceptions that were not timeouts, once one counter — #1057).
    # The orchestrator counters are cumulative per shard: read the run's final
    # summary, or the last window per shard — never a sum over windows, which
    # multiplied every earlier window's timeouts into the figure printed here.
    timeouts = sum(int(r.get("timeouts") or 0) for r in rd.dnsperf if r.get("kind") == "dnsperf_window")
    sent = sum(int(r.get("sent") or 0) for r in rd.dnsperf if r.get("kind") == "dnsperf_window")
    if has_orch:
        orch_dns_to = int(orch_c.get("dns_timeout") or 0)
    else:
        orch_dns_to = gt.dns_timeouts_from_windows(rd.orchestrator_stats)
    orch_dns_err = int(orch_c.get("dns_error") or 0)
    to_rate = (timeouts / sent) if sent else None
    rows.append(_row(
        "b7", "DNS timeout/drop rate ~0 steady",
        "dnsperf.timeouts/sent + orchestrator dns_timeout (+ dns_error)",
        f"{_fmt(to_rate * 100.0 if to_rate is not None else None, '%')} "
        f"(+{orch_dns_to} orch timeouts, +{orch_dns_err} errors)".strip(),
        "~0 (no sustained timeouts)",
        (NO_DATA if to_rate is None and not (rd.orchestrator_stats or has_orch)
         else (PASS if (to_rate or 0) < 0.005 and orch_dns_to == 0 and orch_dns_err == 0
               else FAIL))))

    # b8 — lease→IPAM→DNS propagation p95 (phase-aware) < 10s. propagation_ipam_to_dns.
    steady_prop_p95 = _phase_p95(rd, "propagation_dns_p95", _is_steady)
    peak_prop_p95 = _phase_p95(rd, "propagation_dns_p95", _is_peak)
    cum_prop_p95 = (prop_dns.get("p95") if prop_dns else None)
    # ms → s for the propagation summary (LatencyAccumulator stores ms).
    def _ms2s(v):
        return v / 1000.0 if v is not None else None
    b8_steady = _ms2s(steady_prop_p95) if steady_prop_p95 is not None else _ms2s(cum_prop_p95)
    b8_peak = _ms2s(peak_prop_p95)
    b8_meas = f"steady {_fmt(b8_steady, ' s')}, peak {_fmt(b8_peak, ' s')}"
    b8_verdict = _phase_pair_verdict(b8_steady, slo.lease_to_ipam_to_dns_p95_s,
                                     b8_peak, slo.lease_to_ipam_to_dns_p95_s)
    rows.append(_row(
        "b8", "lease→IPAM→DNS propagation p95 < 10 s (phase-aware)",
        "orchestrator propagation_ipam_to_dns p95",
        b8_meas, f"< {slo.lease_to_ipam_to_dns_p95_s} s", b8_verdict,
        note="the criterion-(b) headline no protocol tool can produce (§8.2.3)"))

    # b9 — propagation p99 < 12s.
    prop_p99 = _ms2s(prop_dns.get("p99")) if prop_dns else None
    rows.append(_row(
        "b9", "propagation p99 < 12 s (ceiling of budget)",
        "orchestrator propagation_ipam_to_dns.p99",
        _fmt(prop_p99, " s"), "< 12 s",
        _verdict_lt(prop_p99, 12.0)))

    # b10 — zone-state convergence gap returns to 0 (last_serial − reported_serial).
    # No native NDJSON surface emits the per-server serial gap in this harness; the
    # drain-convergence proxy is dns_record_op_pending → 0. Report from domain_counts.
    pend_series = _nums([r.get("dns_record_op_pending") for r in _available(rd.domain_counts)])
    final_pending = pend_series[-1] if pend_series else None
    peak_pending = _max(pend_series)
    rows.append(_row(
        "b10", "zone-state convergence gap returns to 0; never unbounded",
        "domain_counts.dns_record_op_pending (drain proxy)",
        f"peak {_fmt(peak_pending)}, final {_fmt(final_pending)}",
        "converges to 0; bounded",
        (NO_DATA if not pend_series else (PASS if (final_pending or 0) <= 1 else FAIL)),
        note="proxy via record_op_pending drain (no native per-server serial NDJSON)"))

    # b11 — lease-events POST p95 < 500ms steady / < 1s peak. No dedicated NDJSON
    # surface in this harness; closest is the agent-side POST path which the
    # orchestrator does not separately time. Reported NO_DATA unless present.
    rows.append(_row(
        "b11", "lease-events POST p95 < 500 ms steady / < 1 s peak (write-pressure)",
        "lease_events_post_p95 (Prometheus/structlog)",
        "no NDJSON surface in run dir", "< 500 ms / < 1 s", NO_DATA,
        note="sourced from external Prometheus extract (§8.2.1), not the NDJSON bundle"))

    # b12 — API mutation p95 < 1s; 5xx = 0. operator_mutation NDJSON.
    om = _available(rd.operator_mutation)
    op_p95 = _pctile(_nums([r.get("p95_ms") for r in om]), 95.0)
    op_5xx = sum(int(r.get("http_5xx") or 0) for r in om)
    b12_verdict = NO_DATA
    if om:
        b12_verdict = PASS if (op_p95 is not None and op_p95 < 1000.0 and op_5xx == 0) else FAIL
    rows.append(_row(
        "b12", "API mutation p95 < 1 s AND 5xx = 0 (operator stream)",
        "operator_mutation.p95_ms / http_5xx",
        f"p95 {_fmt(op_p95, ' ms')}, 5xx {op_5xx}", "< 1 s AND 0 5xx",
        b12_verdict))

    # b13 — synthetic-UI human-usability p95; 5xx=0. ui_probe NDJSON (warroom/ui_probe).
    up = _available(rd.ui_probe)
    ui_p95 = _pctile(_nums([r.get("p95_ms") for r in up]), 95.0)
    ui_5xx = sum(int(r.get("http_5xx") or 0) for r in up)
    b13_verdict = NO_DATA
    if up:
        # [tune-after-baseline] magnitude; the structural invariant is 5xx == 0.
        b13_verdict = PASS if (ui_p95 is not None and ui_5xx == 0) else FAIL
    rows.append(_row(
        "b13", "Synthetic-UI human-usability p95 < [tune]; 5xx = 0 (§7.6.8)",
        "ui_probe.p95_ms / http_5xx (synthetic_ui_probe)",
        f"p95 {_fmt(ui_p95, ' ms')}, 5xx {ui_5xx}" if up else "no ui_probe surface in run dir",
        "p95 < [tune] AND 0 5xx", b13_verdict,
        note=None if up else "synthetic_ui_probe not present — admin-UI usability unverified"))
    return rows


def _phase_p99(rd: RunData, field_: str, predicate) -> float | None:
    return _pctile(_nums([r.get(field_) for r in _phase_windows(rd, predicate)]), 99.0)


def _phase_p95(rd: RunData, field_: str, predicate) -> float | None:
    return _pctile(_nums([r.get(field_) for r in _phase_windows(rd, predicate)]), 95.0)


def _phase_pair_verdict(steady: float | None, steady_thr: float,
                        peak: float | None, peak_thr: float) -> str:
    """PASS only if every present phase is within its own per-phase threshold."""
    seen = False
    for val, thr in ((steady, steady_thr), (peak, peak_thr)):
        if val is None:
            continue
        seen = True
        if val >= thr:
            return FAIL
    return PASS if seen else NO_DATA


def _dnsperf_rcode_totals(rd: RunData, code: str) -> tuple[int, int]:
    """(sent, answers with ``code``) over the dnsperf windows."""
    total = 0
    code_n = 0
    for r in rd.dnsperf:
        if r.get("kind") != "dnsperf_window":
            continue
        sent = int(r.get("sent") or 0)
        rc = (r.get("rcode") or {}).get(code, 0)
        total += sent
        code_n += int(rc or 0)
    return total, code_n


def _dns_rcode_rate(rd: RunData, code: str) -> float | None:
    total, code_n = _dnsperf_rcode_totals(rd, code)
    return (code_n / total) if total else None


# ── Criterion (c) — max sustainable throughput (discovery, not pass/fail) ─────
def criterion_c(rd: RunData) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    # c1 — max sustainable lease-events/sec. Highest achieved DORA+renew before the
    # first breach. We report the peak achieved DORA from perfdhcp + orchestrator.
    dhcp_achieved = _nums([r.get("achieved_rate") for r in rd.perfdhcp])
    orch_dora = _orchestrator_window_series(rd, "dora_s")
    orch_renew = _orchestrator_window_series(rd, "renew_s")
    peak_le = None
    if orch_dora or orch_renew:
        # peak combined lease-events/s observed in any window
        n = max(len(orch_dora), len(orch_renew))
        combos = []
        for i in range(n):
            d = orch_dora[i] if i < len(orch_dora) else 0.0
            rnw = orch_renew[i] if i < len(orch_renew) else 0.0
            combos.append(d + rnw)
        peak_le = _max(combos)
    rows.append(_row(
        "c1", "Max sustainable lease-events/sec (documented capacity)",
        "orchestrator dora_s+renew_s / perfdhcp achieved_rate",
        f"peak observed {_fmt(peak_le, '/s')} (perfdhcp peak {_fmt(_max(dhcp_achieved), '/s')})",
        "discovery — below first breach", CEILING,
        note="this run CREATES the baseline (no prior art to gate against)"))

    # c2 — max sustainable DNS qps. resperf ceiling / dnsperf achieved.
    resperf = _pick_snapshot(rd, "resperf_ceiling", "resperf_ceiling_tcp")
    dns_achieved = _nums([r.get("achieved_qps") for r in rd.dnsperf if r.get("kind") == "dnsperf_window"])
    ceiling_qps = resperf.get("ceiling_qps") if resperf else None
    rows.append(_row(
        "c2", "Max sustainable DNS qps (documented capacity)",
        "resperf ceiling_qps / dnsperf achieved_qps",
        f"resperf ceiling {_fmt(ceiling_qps, ' qps')}, dnsperf peak {_fmt(_max(dns_achieved), ' qps')}",
        "discovery", CEILING))

    # c3 — first-to-give component (conditioned on profile). Inferred from which
    # criterion-(a)/(b) FAIL fired first + the §5.3 prediction.
    first = _first_to_give(rd)
    rows.append(_row(
        "c3", "First-to-give component (conditioned on profile)",
        "all panels at breach + §5.3 prediction",
        first["component"], "identified with evidence", CEILING,
        note=first["evidence"]))

    # c4 — DHCP protocol headroom: perfdhcp ceiling ≫ control-plane ceiling.
    rows.append(_row(
        "c4", "DHCP protocol headroom (Kea ACK ceiling ≫ control-plane)",
        "perfdhcp peak achieved_rate vs c1",
        f"perfdhcp peak {_fmt(_max(dhcp_achieved), '/s')} vs lease-events {_fmt(peak_le, '/s')}",
        "headroom confirmed", CEILING))

    # c5 — DNS protocol headroom: resperf ramp at idle DB ≫ realistic load.
    rows.append(_row(
        "c5", "DNS protocol headroom (BIND answer-rate ≫ realistic load)",
        "resperf ceiling vs diurnal peak qps",
        f"resperf {_fmt(ceiling_qps, ' qps')} vs peak load {rd.m.diurnal.dns_qps_sustained_peak} qps",
        "headroom confirmed", CEILING))

    # c6 — saturation graceful vs catastrophic. Did latency degrade smoothly before
    # any 5xx/restart/drop? Inferred: any restart/5xx/trim => cliff risk.
    restarts = _pod_restarts(rd)
    op_5xx = sum(int(r.get("http_5xx") or 0) for r in _available(rd.operator_mutation))
    graceful = "graceful (no 5xx/restart at breach)" if (restarts == 0 and op_5xx == 0) \
        else f"cliff risk (restarts={restarts}, 5xx={op_5xx})"
    rows.append(_row(
        "c6", "Saturation graceful vs catastrophic",
        "latency curve at breach + restart/5xx ledger",
        graceful, "graceful degrade before any 5xx/restart", CEILING))

    # c7 ⚑ — audit-lock ceiling (audit-contention variant only). committed-mutations/s
    # plateau = 1/mean-audited-txn-hold-time (H1). Only meaningful when the operator
    # stream is ramped (the audit-contention manifest).
    if rd.operator_mutation:
        op_rate_peak = _max(_nums([r.get("rate") for r in _available(rd.operator_mutation)]))
        op_p99 = _pctile(_nums([r.get("p99_ms") for r in _available(rd.operator_mutation)]), 99.0)
        rows.append(_row(
            "c7", "Audit-lock ceiling (committed-mutations/s plateau, H1)",
            "operator_mutation.rate plateau + p99",
            f"peak rate {_fmt(op_rate_peak, '/s')}, p99 {_fmt(op_p99, ' ms')}",
            "1/mean-audited-txn-hold-time", CEILING,
            note="⚑ audit-contention variant; H1 = audit_chain.py advisory lock to COMMIT"))
    else:
        rows.append(_row(
            "c7", "Audit-lock ceiling (audit-contention variant)",
            "operator-stream ramp", "no operator stream — not exercised", "n/a", N_A,
            note="⚑ profile-conditional"))
    return rows


def _pod_restarts(rd: RunData) -> int:
    """Restart count — sourced from snapshots/KSM if present (else 0 observed)."""
    for snap in rd.snapshots.values():
        for key in ("pod_restarts", "restarts", "oomkills"):
            v = snap.get(key)
            if isinstance(v, int):
                return v
    return 0


def _first_to_give(rd: RunData) -> dict[str, str]:
    """Identify the saturation component. Prefer the actual FAIL signal; fall back to
    the §5.3 qlog-conditioned prediction."""
    locks = _available(rd.pg_locks)
    # Did dns_zone show sustained lock-wait? (H3 — predicted #2, qlog-OFF first-to-give)
    zone_waits = [float((r.get("relation_waiting") or {}).get("dns_zone", 0)) for r in locks]
    if _max_consecutive(zone_waits, lambda v: v > 0) > 1:
        return {"component": "dns_zone hot-row UPDATE contention",
                "evidence": "sustained pg_locks.relation_waiting.dns_zone (§5.3 H3, serial.py:50)"}
    # qlog-on: the log-entry firehose / autovacuum (H4) is #1.
    if rd.m.scale.query_log_enabled:
        return {"component": "dns_query_log_entry firehose / autovacuum (H4)",
                "evidence": "qlog-on profile — predicted #1 (§5.3 H4); confirm via "
                            "pg_user_tables dns_query_log_entry dead_tup + daily prune"}
    return {"component": "dns_zone hot-row (predicted, §5.3 H3)",
            "evidence": "qlog-OFF headline — qlog ingestion #1 cannot fire, so the "
                        "predicted first-to-give is the dns_zone serial hot-row (H3)"}


# ── Criterion (d) — 24h soak stability ────────────────────────────────────────
def criterion_d(rd: RunData) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    tables = _available(rd.pg_user_tables)

    # d1 — pod restarts / OOMKills exactly 0 (structural).
    restarts = _pod_restarts(rd)
    has_restart_data = any(any(k in s for k in ("pod_restarts", "restarts", "oomkills"))
                           for s in rd.snapshots.values())
    rows.append(_row(
        "d1", "Pod restarts / OOMKills exactly 0 (structural)",
        "KSM / pod_restarts ledger (snapshots)",
        _fmt(restarts) if has_restart_data else "no restart ledger",
        "= 0",
        (PASS if (has_restart_data and restarts == 0) else (FAIL if restarts > 0 else NO_DATA)),
        note="any restart = FAIL; not relaxed (§8.3.1)"))

    # d2 — memory leak (per-pod RSS) flat. Needs container_working_set (cAdvisor) —
    # not in the NDJSON bundle; report NO_DATA unless a snapshot carries it.
    rows.append(_row(
        "d2", "Per-pod RSS flat (tEnd ≈ first-steady-plateau ±15%)",
        "container_working_set (cAdvisor)",
        "no working-set surface in run dir", "no monotonic slope [tune]", NO_DATA,
        note="sourced from external Prometheus/cAdvisor (§8.2.5)"))

    # d3 — CNPG working-set vs 1Gi < 90%, no creep.
    rows.append(_row(
        "d3", "CNPG working-set < 90% of 1Gi, no creep",
        "cAdvisor CNPG working_set",
        "no working-set surface in run dir", "< 90% AND no trend", NO_DATA))

    # d4 — celery queue returns to baseline (drains ~0 between peaks; flat trough).
    q_series = _celery_total_series(rd)
    final_q = q_series[-1] if q_series else None
    peak_q = _max(q_series)
    trough_floor = _trough_floor_rising(q_series)
    rows.append(_row(
        "d4", "Celery queue drains to ~0 between peaks; flat trough-floor",
        "celery_queues.queues (LLEN ipam/dns/dhcp/default)",
        f"peak {_fmt(peak_q)}, final {_fmt(final_q)}, "
        f"{'rising trough' if trough_floor else 'flat trough'}".strip(),
        "drains to ~0; no rising trough-floor",
        (NO_DATA if not q_series else (PASS if (not trough_floor and (final_q or 0) < 50) else FAIL))))

    # d5 — redis memory + evictions: evicted=0; used flat (structural eviction gate).
    redis = _available(rd.redis_overview)
    evicted = None
    for r in redis:
        ev = r.get("evicted_keys")
        if ev is not None and ev >= 0:  # surfaces emits -1 for "unknown via native"
            evicted = max(evicted or 0, int(ev))
    used = _nums([r.get("used_memory") for r in redis])
    used_flat = "flat" if (len(used) >= 2 and used[-1] <= 1.2 * (min(used) or used[-1])) else "growing"
    if evicted is None:
        rows.append(_row(
            "d5", "Redis evictions = 0; used flat (structural)",
            "redis_overview.evicted_keys (native -1 = unknown)",
            f"evicted unknown via native; used {used_flat}", "evicted = 0 AND used flat",
            NO_DATA,
            note="native surface has no evicted_keys — read from redis_exporter (§6.2)"))
    else:
        rows.append(_row(
            "d5", "Redis evictions = 0; used flat (structural)",
            "redis_overview.evicted_keys",
            f"evicted {evicted}, used {used_flat}", "evicted = 0 AND used flat",
            (PASS if evicted == 0 and used_flat == "flat" else FAIL),
            note="any eviction = FAIL; not relaxed (§8.3.1)"))

    # d6 — bloat bounded per hot table: no focus table size strictly increasing
    # without reclaim. pg_user_tables (live+dead) size proxy via bytes if present.
    bloat_offenders = _bloat_offenders(rd, tables)
    rows.append(_row(
        "d6", "Bloat bounded per hot table (no unbounded growth; reclaimed)",
        "pg_user_tables size/dead-tup trajectory + snapshots bloat",
        ("bounded" if not bloat_offenders else f"growing: {', '.join(bloat_offenders)}"),
        "no focus table strictly increasing t0→tEnd",
        (NO_DATA if not tables and not bloat_offenders else (PASS if not bloat_offenders else FAIL)),
        note="dns_record_op excluded here (its growth is by-design — see d7)"))

    # d7 — dns_record_op growth (DOCUMENTED; never pruned, §5.1) + disk projection.
    rop = _dns_record_op_projection(rd)
    rows.append(_row(
        "d7", "dns_record_op growth documented (NEVER pruned, §5.1); disk-safe",
        "domain_counts.dns_record_op_total slope × bytes/row vs PVC free",
        rop["measured"], rop["threshold"], rop["verdict"],
        note="record_ops.py:82,354,384 flip to state='applied', no delete; no prune "
             "task references DNSRecordOp (grep backend/app/tasks/ clean)"))

    # d8 — disk free (root/var/CNPG PV) trajectory ≥ 0; ≥ 20% free at tEnd. pg db_size
    # is a proxy for CNPG PV growth; node disk free needs node-exporter (snapshots).
    disk = _disk_free(rd)
    rows.append(_row(
        "d8", "Disk free trajectory ≥ 0; ≥ 20% free at tEnd",
        "node_disk_free (snapshots) / db_size growth",
        disk["measured"], "≥ 20% free at tEnd; projection positive", disk["verdict"]))

    # d9 ⚑ — log-prune keeps tables bounded (qlog-on). post-prune count drops.
    if rd.m.scale.query_log_enabled:
        ql_series = _focus_table_series(tables, "dns_query_log_entry", "live_tup")
        net_growing = bool(ql_series and len(ql_series) >= 2 and ql_series[-1] > 1.5 * (min(ql_series) or 1))
        rows.append(_row(
            "d9", "Log-prune keeps tables bounded (qlog-on); not net-growing",
            "pg_user_tables.dns_query_log_entry.live_tup across the prune",
            f"{'net-growing' if net_growing else 'bounded'}",
            "prune reduces count; no net accumulation",
            (NO_DATA if not ql_series else (PASS if not net_growing else FAIL))))
    else:
        rows.append(_row(
            "d9", "Log-prune keeps tables bounded (qlog-on only)",
            "pg_user_tables.dns_query_log_entry", "qlog-off — not exercised", "n/a",
            N_A, note="⚑ profile-conditional"))

    # d10 — agent ring-buffer trims = 0 at steady/soak. agent_buffer_trims log/
    # snapshot. No NDJSON surface; report from snapshot if present, else NO_DATA.
    trims = _agent_buffer_trims(rd)
    rows.append(_row(
        "d10", "Agent ring-buffer trims = 0 at steady/soak (structural outside c-window)",
        "agent_buffer_trims.log (snapshots)",
        _fmt(trims) if trims is not None else "no trim ledger",
        "= 0 outside the deliberate ceiling-push",
        (NO_DATA if trims is None else (PASS if trims == 0 else FAIL)),
        note="any trim outside the c-window = the unambiguous ingestion-ceiling event"))

    # d11 ⚑ — audit_chain_verify 02:00 worker RSS no OOM. Needs worker working-set at
    # 02:00 — not in NDJSON; NO_DATA unless a snapshot carries it.
    rows.append(_row(
        "d11", "audit_chain_verify 02:00 worker RSS — no OOM",
        "container_working_set{worker}@02:00",
        "no worker-RSS surface in run dir", "survives the verify", NO_DATA,
        note="⚑ audit-stream-grown table; sourced from external cAdvisor (§8.2.5)"))

    # d12 — platform heartbeat continuity: all dots green 24h. health_platform.
    health = _available(rd.health)
    down = _health_down_windows(health)
    rows.append(_row(
        "d12", "Platform heartbeat continuity (all dots green 24h)",
        "health_platform.components",
        ("all green" if (health and not down) else
         (f"down: {', '.join(down)}" if down else "no health surface")),
        "no unexpected component-down",
        (NO_DATA if not health else (PASS if not down else FAIL)),
        note="excl. the deliberate fault-injection window (§7.6.6)"))

    # d13 — agent cached-config operation (fault-injection §7.6.6). bind9/kea keep
    # serving from cache during severed connectivity; reconverge cleanly. Needs the
    # fault-injection window evidence — NO_DATA unless a snapshot/event marks it.
    fi = _pick_snapshot(rd, "fault_injection", "cached_config")
    rows.append(_row(
        "d13", "Agent cached-config operation during severed connectivity (§7.6.6)",
        "orchestrator + agent logs (fault-injection window)",
        ("evidence present" if fi else "no fault-injection window in run dir"),
        "keep serving from cache; clean re-join",
        (N_A if fi is None else PASS),
        note="non-negotiable #5 — agents operate from last-known-good cache"))
    return rows


def _celery_total_series(rd: RunData) -> list[float]:
    out: list[float] = []
    for r in _available(rd.celery_queues):
        qs = r.get("queues") or {}
        total = sum(v for v in qs.values() if isinstance(v, (int, float)) and v >= 0)
        out.append(float(total))
    return out


def _trough_floor_rising(series: list[float]) -> bool:
    """Rising inter-trough baseline = worker losing ground. Compare first/last
    quartile minima."""
    if len(series) < 8:
        return False
    q = max(2, len(series) // 4)
    early_floor = min(series[:q])
    late_floor = min(series[-q:])
    return late_floor > early_floor + max(10.0, 0.5 * (early_floor or 1))


def _focus_table_series(tables_recs: list[dict[str, Any]], table: str, field_: str) -> list[float]:
    out: list[float] = []
    for rec in tables_recs:
        v = ((rec.get("tables") or {}).get(table) or {}).get(field_)
        if v is not None:
            out.append(float(v))
    return out


def _bloat_offenders(rd: RunData, tables_recs: list[dict[str, Any]]) -> list[str]:
    """Focus tables (excluding dns_record_op which grows by design) whose live_tup
    grows strictly and unbounded across the run."""
    offenders = []
    for t in FOCUS_TABLES:
        if t == "dns_record_op":
            continue  # by-design growth handled by d7
        series = _focus_table_series(tables_recs, t, "live_tup")
        if len(series) < 4:
            continue
        non_decreasing = all(series[i] <= series[i + 1] + 1 for i in range(len(series) - 1))
        net = series[-1] - min(series)
        if non_decreasing and net > max(10000.0, 1.0 * (min(series) or 1)):
            offenders.append(t)
    return offenders


def _dns_record_op_projection(rd: RunData) -> dict[str, Any]:
    """d7: report the dns_record_op_total slope + 24h projection vs PVC free.

    NEVER pruned (§5.1). FAIL only if the projection threatens disk before a horizon.
    """
    dc = _available(rd.domain_counts)
    series = []
    for r in dc:
        ts = r.get("ts")
        total = r.get("dns_record_op_total")
        if ts and total is not None:
            series.append((ts, float(total)))
    if len(series) < 2:
        return {"measured": "no domain_counts series", "threshold": "documented (no prune)",
                "verdict": NO_DATA}
    # Slope per hour from first→last using count delta over the sample span.
    first_total = series[0][1]
    last_total = series[-1][1]
    grew = last_total - first_total
    # Span in hours via ts parse (graceful).
    span_h = _ts_span_hours(series[0][0], series[-1][0]) or (len(series) / 60.0)
    rate_per_h = grew / span_h if span_h > 0 else 0.0
    proj_24h = rate_per_h * 24.0
    proj_bytes = proj_24h * DNS_RECORD_OP_BYTES_PER_ROW
    pvc_free_gb = rd.m.disk_budget.required_pv_gb
    proj_gb = proj_bytes / 1e9
    # FAIL if a single day's projected growth would consume > the configured PV free.
    verdict = PASS
    if pvc_free_gb and proj_gb > pvc_free_gb:
        verdict = FAIL
    return {
        "measured": f"+{grew:,.0f} rows over {span_h:.1f}h ⇒ {rate_per_h:,.0f}/h "
                    f"⇒ ~{proj_24h:,.0f}/day (~{proj_gb:.2f} GB/day @ "
                    f"{DNS_RECORD_OP_BYTES_PER_ROW:.0f} B/row)",
        "threshold": f"documented; FAIL if projection > {pvc_free_gb:.0f} GB PV free",
        "verdict": verdict,
    }


def _ts_span_hours(ts0: str, ts1: str) -> float | None:
    from datetime import datetime
    try:
        a = datetime.fromisoformat(ts0.replace("Z", "+00:00"))
        b = datetime.fromisoformat(ts1.replace("Z", "+00:00"))
        return max(0.0, (b - a).total_seconds() / 3600.0)
    except (ValueError, AttributeError):
        return None


def _disk_free(rd: RunData) -> dict[str, Any]:
    # node disk-free needs node-exporter; proxy via pg db_size growth direction.
    ov = _available(rd.pg_overview)
    sizes = _nums([r.get("db_size_bytes") for r in ov])
    snap_disk = None
    for s in rd.snapshots.values():
        for k in ("disk_free_pct", "node_disk_free_pct", "var_free_pct"):
            if isinstance(s.get(k), (int, float)):
                snap_disk = float(s[k])
    if snap_disk is not None:
        return {"measured": f"{snap_disk:.1f}% free at tEnd",
                "verdict": PASS if snap_disk >= 20.0 else FAIL}
    if len(sizes) >= 2:
        return {"measured": f"db_size {sizes[0]/1e9:.2f}→{sizes[-1]/1e9:.2f} GB "
                            f"(+{(sizes[-1]-sizes[0])/1e9:.2f} GB)",
                "verdict": N_A}
    return {"measured": "no disk-free / db-size surface", "verdict": NO_DATA}


def _agent_buffer_trims(rd: RunData) -> int | None:
    for s in rd.snapshots.values():
        for k in ("agent_buffer_trims", "buffer_trims", "lease_events_buffer_trimmed"):
            if isinstance(s.get(k), int):
                return int(s[k])
    return None


def _health_down_windows(health_recs: list[dict[str, Any]]) -> list[str]:
    """Components that were ever 'down' (status not ok|warn) outside maintenance."""
    down: set[str] = set()
    for r in health_recs:
        if r.get("maintenance_mode"):
            continue
        comps = r.get("components") or {}
        for name, up in comps.items():
            if up is False:
                down.add(name)
    return sorted(down)


# ==============================================================================
# Executive verdict roll-up (§8.4)
# ==============================================================================
def _criterion_verdict(rows: list[dict[str, Any]], *, discovery: bool = False) -> tuple[str, str]:
    """Roll one criterion's rows up to a single verdict + a one-line summary.

    (a)(b)(d): PASS unless any row FAILs; NO_DATA-only rows don't fail but are noted.
    (c): always CEILING (discovery) unless a graceful/identified gate trips.
    """
    fails = [r["id"] for r in rows if r["verdict"] == FAIL]
    no_data = [r["id"] for r in rows if r["verdict"] == NO_DATA]
    passes = [r["id"] for r in rows if r["verdict"] == PASS]
    if discovery:
        # (c): PASS gate = c4+c5 headroom present + c6 graceful + c3 identified.
        verdict = "CEILING FOUND"
        notes = []
        c6 = next((r for r in rows if r["id"] == "c6"), None)
        if c6 and "cliff" in str(c6.get("measured", "")):
            verdict = "CEILING (CLIFF)"
            notes.append("saturation not graceful")
        return verdict, ("; ".join(notes) if notes
                         else "ceiling documented; protocol headroom confirmed")
    if fails:
        return FAIL, f"failing: {', '.join(fails)}"
    if passes and not fails:
        if no_data:
            return PASS, f"{len(passes)} pass, {len(no_data)} no-data ({', '.join(no_data)})"
        return PASS, f"all {len(passes)} rows pass"
    return NO_DATA, f"no measurable rows ({len(no_data)} no-data)"


def _overall(verdict_a: str, verdict_b: str, verdict_d: str,
             rows_all: list[dict[str, Any]]) -> tuple[str, str]:
    """OVERALL verdict incl. CONDITIONAL PASS (§8.4)."""
    hard = [verdict_a, verdict_b, verdict_d]
    # Ship-blocking structural failures (the not-relaxed invariants).
    structural_ids = {"a1", "a4", "a6", "b6a", "d1", "d5"}
    structural_fail = [r["id"] for r in rows_all
                       if r["id"] in structural_ids and r["verdict"] == FAIL]
    if structural_fail:
        return FAIL, f"structural invariant failed: {', '.join(structural_fail)}"
    if all(v == PASS for v in hard):
        return PASS, "all criteria pass"
    if FAIL in hard:
        # Non-structural FAIL — typically a soak-growth row (e.g. d7 dns_record_op).
        d7 = next((r for r in rows_all if r["id"] == "d7"), None)
        if d7 and d7["verdict"] == FAIL:
            return "CONDITIONAL PASS", \
                "ship-blocking: dns_record_op prune (§5 mitigation H)"
        return "CONDITIONAL PASS", "non-structural FAIL — see SLO table"
    return "INCOMPLETE", "insufficient data for a full verdict (partial run)"


# ==============================================================================
# slo_results.json assembly
# ==============================================================================
def build_slo_results(rd: RunData) -> dict[str, Any]:
    rows_a = criterion_a(rd)
    rows_b = criterion_b(rd)
    rows_c = criterion_c(rd)
    rows_d = criterion_d(rd)

    va, sa = _criterion_verdict(rows_a)
    vb, sb = _criterion_verdict(rows_b)
    vc, sc = _criterion_verdict(rows_c, discovery=True)
    vd, sd = _criterion_verdict(rows_d)
    overall, overall_note = _overall(va, vb, vd, rows_a + rows_b + rows_d)

    # A watchdog-aborted or SUT-failed run must NOT report PASS regardless of the SLO
    # surfaces collected before the abort (§7.6.5). The terminal run status overrides.
    from spddi_perf.checkpoint import STATUS_ABORTED, STATUS_INVALID, read_state
    _state = read_state(rd.rp)
    run_status = _state.status if _state else None
    if run_status == STATUS_ABORTED:
        overall = "ABORTED"
        overall_note = f"run aborted (watchdog/kill-switch) — not a PASS [{overall_note}]"
    elif run_status == STATUS_INVALID:
        overall = "INVALID"
        overall_note = f"SUT failed on its own — re-run, not a verdict [{overall_note}]"

    incomplete = _is_incomplete(rd)
    return {
        "schema": "spddi-perf/slo_results/v1",
        "run_id": rd.rp.run_id,
        "profile": rd.profile,
        "generated_at": utc_now_iso(),
        "slo_thresholds_version": rd.m.slo.slo_thresholds_version,
        "run_status": run_status,
        "incomplete": incomplete,
        "criteria": {
            "a": {"name": "DB never bottlenecks", "verdict": va, "summary": sa, "rows": rows_a},
            "b": {"name": "End-to-end latency SLOs", "verdict": vb, "summary": sb, "rows": rows_b},
            "c": {"name": "Max sustainable throughput (discovery)", "verdict": vc, "summary": sc, "rows": rows_c},
            "d": {"name": "24h soak stability", "verdict": vd, "summary": sd, "rows": rows_d},
        },
        "overall": {"verdict": overall, "note": overall_note},
        "profile_key": _profile_key(rd.m),
        "present_surfaces": sorted(rd.present),
        # #1057 — the orchestrator's own ledgers, folded across shards: the
        # handshake at three strictnesses and the DNS outcome by rcode. None
        # when no shard summary exists (absence is recorded, never fabricated).
        "generator": gt.orchestrator_accounting(rd.orchestrator_summary),
    }


def _is_incomplete(rd: RunData) -> bool:
    """A run is INCOMPLETE if the core load + DB surfaces are largely absent."""
    core = {"domain_counts", "pg_overview", "orchestrator"}
    return not (core & rd.present)


def _profile_key(m: manifest_mod.Manifest) -> dict[str, Any]:
    """The §8.5 regression-comparison key — the load-bearing axes."""
    raw = m.raw or {}
    seed = raw.get("seed", {}) or {}
    dns = (seed.get("dns") or {})
    target_dns = (raw.get("target", {}) or {}).get("dns", {}) or {}
    return {
        "d_total": m.scale.unique_devices,
        "lease_seconds": m.scale.lease_time_s,
        "t1_seconds": 900,  # canonical (render_kea.py:641 hardcoded)
        "ddns": m.scale.ddns_enabled,
        "query_log_enabled": m.scale.query_log_enabled,
        "subnets": int(m.seed.subnets.get("count", 0)),
        "reverse_zone_shape": m.seed.dns.reverse_zone_shape,
        "powerdns": target_dns.get("driver") == "powerdns",
        "dnssec": bool(dns.get("dnssec", False)),
    }


# ==============================================================================
# t0 ↔ tEnd delta tables (§8.4 #5)
# ==============================================================================
def build_deltas(rd: RunData) -> dict[str, Any]:
    """The row-count ledger + per-table size/dead-tup deltas + disk-free delta."""
    dc = _available(rd.domain_counts)
    ledger = {}
    if dc:
        first, last = dc[0], dc[-1]
        for k in ("active_leases", "dhcp_lease_total", "ipam_mirror", "dns_records",
                  "dns_record_op_total", "dns_record_op_pending", "dhcp_lease_history",
                  "audit_rows"):
            v0, v1 = first.get(k), last.get(k)
            if v0 is not None and v1 is not None:
                ledger[k] = {"t0": int(v0), "tEnd": int(v1), "delta": int(v1) - int(v0)}

    # per-table dead_tup + autovacuum_count + live_tup delta from pg_user_tables
    tables = _available(rd.pg_user_tables)
    table_delta = {}
    if tables:
        first_t = (tables[0].get("tables") or {})
        last_t = (tables[-1].get("tables") or {})
        for t in FOCUS_TABLES:
            t0v, tnv = first_t.get(t) or {}, last_t.get(t) or {}
            if not t0v and not tnv:
                continue
            table_delta[t] = {
                "live_tup": {"t0": t0v.get("live_tup"), "tEnd": tnv.get("live_tup")},
                "dead_tup": {"t0": t0v.get("dead_tup"), "tEnd": tnv.get("dead_tup")},
                "autovacuum_count": {"t0": t0v.get("autovacuum_count"),
                                     "tEnd": tnv.get("autovacuum_count")},
            }

    # disk / db-size delta
    ov = _available(rd.pg_overview)
    db_size = None
    if ov:
        sizes = _nums([r.get("db_size_bytes") for r in ov])
        if len(sizes) >= 2:
            db_size = {"t0_bytes": int(sizes[0]), "tEnd_bytes": int(sizes[-1]),
                       "delta_bytes": int(sizes[-1] - sizes[0])}

    return {"row_count_ledger": ledger, "table_delta": table_delta, "db_size": db_size}


# ==============================================================================
# Bottleneck finding (§8.4 #4) — first-to-give + ready §5 mitigation
# ==============================================================================
# §5.5 ready mitigations A–I (the report cites the matching fix for the finding).
_MITIGATIONS = {
    "dns_zone": ("C", "Coalesce dns_zone serial bumps to once-per-convergence-cycle; "
                      "aggressive per-table autovacuum on dns_zone (verify SOA monotonicity)"),
    "dns_query_log_entry": ("D", "qlog-OFF posture; hourly prune; time-partition the log "
                                 "tables (prune = DROP PARTITION); ship firehose to Loki"),
    "dns_record_op": ("H", "Prune dns_record_op applied rows (new beat task deleting "
                           "state='applied' older than a short window — none exists today)"),
    "audit_log": ("A", "Batch operator mutations under one audit-lock acquisition; else "
                       "move audit hashing off the commit path (gate behind H1 firing)"),
    "dhcp_lease": ("E/G", "Per-table autovacuum tuning on dhcp_lease; (state, expires_at) "
                          "composite index + batch the 5-min sweep"),
    "connection_pool": ("B", "Raise pool size/overflow (env); add PgBouncer/CNPG pooler "
                            "(transaction mode)"),
}


def build_bottleneck(rd: RunData, slo: dict[str, Any]) -> dict[str, Any]:
    c_rows = slo["criteria"]["c"]["rows"]
    c3 = next((r for r in c_rows if r["id"] == "c3"), None)
    component = (c3 or {}).get("measured", "unknown")
    evidence = (c3 or {}).get("note", "")

    # Map the named component to a §5.5 mitigation tag.
    tag, fix = ("?", "no ready mitigation mapped")
    for key, (mtag, mfix) in _MITIGATIONS.items():
        if key.replace("_", " ") in component.lower() or key in component.lower():
            tag, fix = mtag, mfix
            break
    if "audit" in component.lower():
        tag, fix = _MITIGATIONS["audit_log"]
    if "pool" in component.lower():
        tag, fix = _MITIGATIONS["connection_pool"]

    # Also surface the d7 dns_record_op finding (always relevant — never pruned).
    d7 = next((r for r in slo["criteria"]["d"]["rows"] if r["id"] == "d7"), None)
    return {
        "first_to_give": component,
        "evidence": evidence,
        "mitigation_tag": tag,
        "mitigation": fix,
        "soak_growth_finding": {
            "table": "dns_record_op",
            "fact": "NEVER pruned (§5.1) — record_ops.py flips to state='applied' and "
                    "leaves the row; no prune task references DNSRecordOp",
            "measured": (d7 or {}).get("measured", "no data"),
            "verdict": (d7 or {}).get("verdict", NO_DATA),
            "mitigation_tag": "H",
            "mitigation": _MITIGATIONS["dns_record_op"][1],
        },
    }


# ==============================================================================
# Regression comparison (§8.5)
# ==============================================================================
def build_comparison(rd: RunData, baseline_slo: dict[str, Any],
                     new_slo: dict[str, Any], log) -> dict[str, Any]:
    """Diff new vs baseline. Refuse incomparable profiles; gate BLOCK vs WARN."""
    base_key = baseline_slo.get("profile_key", {})
    new_key = new_slo.get("profile_key", {})
    diffs = {a: (base_key.get(a), new_key.get(a)) for a in PROFILE_AXES
             if base_key.get(a) != new_key.get(a)}
    if diffs:
        return {
            "comparable": False,
            "refused": True,
            "reason": "incomparable profiles differ on load-bearing axes (§8.5)",
            "axis_diffs": {a: {"baseline": b, "new": n} for a, (b, n) in diffs.items()},
        }

    # Per-row diff with the ±20% band.
    base_rows = {r["id"]: r for c in baseline_slo["criteria"].values() for r in c["rows"]}
    new_rows = {r["id"]: r for c in new_slo["criteria"].values() for r in c["rows"]}
    row_diffs = []
    block_reasons: list[str] = []
    warn_reasons: list[str] = []
    for rid, nrow in new_rows.items():
        brow = base_rows.get(rid)
        if brow is None:
            continue
        bv, nv = brow["verdict"], nrow["verdict"]
        entry = {"id": rid, "baseline_verdict": bv, "new_verdict": nv,
                 "baseline_measured": brow.get("measured"), "new_measured": nrow.get("measured")}
        # Gate: PASS→FAIL = BLOCK; CEILING drop handled separately.
        if bv == PASS and nv == FAIL:
            entry["gate"] = "BLOCK"
            block_reasons.append(f"{rid} PASS→FAIL")
        elif bv != FAIL and nv == FAIL:
            entry["gate"] = "WARN"
            warn_reasons.append(f"{rid} → FAIL ({bv})")
        # numeric regression within the band (best-effort numeric extraction)
        bnum, nnum = _extract_num(brow.get("measured")), _extract_num(nrow.get("measured"))
        if bnum is not None and nnum is not None and bnum > 0:
            ratio = (nnum - bnum) / bnum
            entry["delta_pct"] = round(ratio * 100.0, 1)
            if ratio > REGRESSION_BAND and entry.get("gate") != "BLOCK":
                entry.setdefault("gate", "WARN")
                warn_reasons.append(f"{rid} regressed {ratio*100:.0f}% (within band check)")
        row_diffs.append(entry)

    # Structural BLOCK signals: any deadlock / restart / eviction / ceiling drop.
    structural = _structural_block_signals(baseline_slo, new_slo)
    block_reasons.extend(structural["block"])

    # Ceiling drop comparison (c1/c2).
    ceil_cmp = _ceiling_compare(base_rows, new_rows)
    if ceil_cmp.get("dropped"):
        block_reasons.append(ceil_cmp["dropped"])

    gate = "BLOCK" if block_reasons else ("WARN" if warn_reasons else "OK")
    return {
        "comparable": True,
        "refused": False,
        "baseline_run_id": baseline_slo.get("run_id"),
        "new_run_id": new_slo.get("run_id"),
        "gate": gate,
        "block_reasons": block_reasons,
        "warn_reasons": warn_reasons,
        "ceiling": ceil_cmp,
        "row_diffs": row_diffs,
        "regression_band": REGRESSION_BAND,
    }


def _extract_num(measured: Any) -> float | None:
    """Best-effort: pull the first number out of a measured string/value."""
    if isinstance(measured, (int, float)) and not isinstance(measured, bool):
        return float(measured)
    if not isinstance(measured, str):
        return None
    import re
    m = re.search(r"-?\d[\d,]*\.?\d*", measured.replace(",", ""))
    try:
        return float(m.group(0)) if m else None
    except (ValueError, AttributeError):
        return None


def _structural_block_signals(base: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    block = []
    base_rows = {r["id"]: r for c in base["criteria"].values() for r in c["rows"]}
    new_rows = {r["id"]: r for c in new["criteria"].values() for r in c["rows"]}
    for rid, label in (("a4", "deadlock"), ("d1", "pod restart"), ("d5", "redis eviction")):
        b, n = base_rows.get(rid), new_rows.get(rid)
        if n and n["verdict"] == FAIL and (not b or b["verdict"] != FAIL):
            block.append(f"{label} ({rid}) appeared")
    return {"block": block}


def _ceiling_compare(base_rows: dict[str, Any], new_rows: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for rid in ("c1", "c2"):
        b, n = base_rows.get(rid), new_rows.get(rid)
        if not (b and n):
            continue
        bnum, nnum = _extract_num(b.get("measured")), _extract_num(n.get("measured"))
        out[rid] = {"baseline": b.get("measured"), "new": n.get("measured")}
        if bnum and nnum and nnum < bnum * (1.0 - REGRESSION_BAND):
            out["dropped"] = f"{rid} ceiling dropped {(1 - nnum/bnum)*100:.0f}% (> band)"
    return out


# ==============================================================================
# Rendering — Jinja2 template (lazy import; py_compile stays clean) + md→html
# ==============================================================================
def _template_path() -> Path:
    # perf/reports/template.md.j2 (sibling of the run dir tree)
    return Path(__file__).resolve().parents[2] / "reports" / "template.md.j2"


def render_markdown(rd: RunData, slo: dict[str, Any], deltas: dict[str, Any],
                    bottleneck: dict[str, Any], comparison: dict[str, Any] | None,
                    log) -> str:
    ctx = {
        "run_id": rd.rp.run_id,
        "profile": rd.profile,
        "generated_at": slo["generated_at"],
        "slo_thresholds_version": slo["slo_thresholds_version"],
        "incomplete": slo["incomplete"],
        "criteria": slo["criteria"],
        "overall": slo["overall"],
        "deltas": deltas,
        "bottleneck": bottleneck,
        "comparison": comparison,
        "manifest": _manifest_human(rd.m),
        "present_surfaces": slo["present_surfaces"],
        "profile_key": slo["profile_key"],
        "generator": slo.get("generator"),
        "fmt_verdict": _verdict_badge,
    }
    tpl = _template_path()
    if tpl.exists():
        try:
            import jinja2  # lazy — keeps py_compile clean in a bare env
            env = jinja2.Environment(
                loader=jinja2.FileSystemLoader(str(tpl.parent)),
                undefined=jinja2.StrictUndefined, trim_blocks=True, lstrip_blocks=True,
                autoescape=False)
            env.filters["badge"] = _verdict_badge
            return env.get_template(tpl.name).render(**ctx)
        except Exception as exc:  # noqa: BLE001 — fall back to the builtin renderer
            log_event(log, 30, "jinja_render_failed_fallback", error=str(exc))
    return _render_markdown_builtin(ctx)


def _verdict_badge(v: str) -> str:
    return {PASS: "PASS ✓", FAIL: "FAIL ✗", NO_DATA: "NO DATA", N_A: "N/A",
            CEILING: "CEILING"}.get(v, v)


def _manifest_human(m: manifest_mod.Manifest) -> dict[str, Any]:
    return {
        "name": m.name,
        "unique_devices": m.scale.unique_devices,
        "peak_active_devices": m.scale.peak_active_devices,
        "lease_time_s": m.scale.lease_time_s,
        "t1_seconds": 900,
        "ddns_enabled": m.scale.ddns_enabled,
        "query_log_enabled": m.scale.query_log_enabled,
        "subnets": int(m.seed.subnets.get("count", 0)),
        "reverse_zone_shape": m.seed.dns.reverse_zone_shape,
        "dns_driver": m.target.dns.driver,
        "dns_recursion": m.target.dns.recursion,
        "dhcp_topology": m.target.dhcp.topology,
        "total_minutes": m.total_minutes(),
        "slo": {
            "dhcp_ack_p99_ms": m.slo.dhcp_ack_p99_ms,
            "dns_resolve_p99_ms": m.slo.dns_resolve_p99_ms,
            "lease_to_ipam_to_dns_p95_s": m.slo.lease_to_ipam_to_dns_p95_s,
            "api_5xx_rate_max": m.slo.api_5xx_rate_max,
            "thresholds_version": m.slo.slo_thresholds_version,
        },
    }


def _render_markdown_builtin(ctx: dict[str, Any]) -> str:
    """Self-contained markdown renderer (no jinja dependency) — same structure as the
    template, so the report is always produced even on a bare box."""
    lines: list[str] = []
    ov = ctx["overall"]
    lines.append(f"# SpatiumDDI 24h Performance Run — `{ctx['run_id']}`")
    if ctx["incomplete"]:
        lines.append("\n> ⚠️ **INCOMPLETE** — core surfaces missing; this is a partial "
                     "report (a crashed run is still evidence, §8.4).")
    man = ctx["manifest"]
    lines.append(f"\n**Profile:** `{ctx['profile']}` "
                 f"({man['unique_devices']:,} devices, {man['lease_time_s']}s lease, "
                 f"T1={man['t1_seconds']}s, DDNS {'on' if man['ddns_enabled'] else 'off'}, "
                 f"qlog {'on' if man['query_log_enabled'] else 'off'}, "
                 f"{man['dns_driver']}, {man['reverse_zone_shape']} reverse)")
    lines.append(f"\n**Generated:** {ctx['generated_at']} · "
                 f"**SLO thresholds:** `{ctx['slo_thresholds_version']}`")

    # Executive verdict block (§8.4 #1)
    lines.append("\n## Executive verdict\n")
    lines.append("```")
    lines.append(f"RUN {ctx['run_id']}  ({ctx['profile']})")
    lines.append("─" * 78)
    c = ctx["criteria"]
    lines.append(f"(a) DB never bottlenecks ...... {c['a']['verdict']:<14} ({c['a']['summary']})")
    lines.append(f"(b) Latency SLOs ............... {c['b']['verdict']:<14} ({c['b']['summary']})")
    lines.append(f"(c) Max sustainable throughput  {c['c']['verdict']:<14} ({c['c']['summary']})")
    lines.append(f"(d) 24h soak stability ........ {c['d']['verdict']:<14} ({c['d']['summary']})")
    lines.append("─" * 78)
    lines.append(f"OVERALL: {ov['verdict']} — {ov['note']}")
    lines.append("```")

    # SLO table (§8.4 #2)
    lines.append("\n## Consolidated SLO table (§8.3)\n")
    for cid, cinfo in c.items():
        lines.append(f"\n### Criterion ({cid}) — {cinfo['name']} · **{cinfo['verdict']}**\n")
        lines.append("| # | SLO | Measured | Threshold | Verdict |")
        lines.append("|---|-----|----------|-----------|---------|")
        for r in cinfo["rows"]:
            slo_txt = r["slo"].replace("|", "\\|")
            meas = str(r["measured"]).replace("|", "\\|")
            thr = str(r["threshold"]).replace("|", "\\|")
            lines.append(f"| {r['id']} | {slo_txt} | {meas} | {thr} | "
                         f"{_verdict_badge(r['verdict'])} |")

    # Generator accounting (§8.2 / #1057) — what the orchestrator itself counted,
    # so a handshake or DNS figure can be reconciled with the appliance's own.
    gen = ctx.get("generator")
    lines.append("\n## Generator accounting (orchestrator)\n")
    if gen:
        lines.extend(_generator_lines(gen))
    else:
        lines.append("_No orchestrator shard summary in the run directory._")

    # Bottleneck finding (§8.4 #4)
    b = ctx["bottleneck"]
    lines.append("\n## Bottleneck finding (first-to-give + ready §5 mitigation)\n")
    lines.append(f"- **First-to-give component:** {b['first_to_give']}")
    lines.append(f"- **Evidence:** {b['evidence']}")
    lines.append(f"- **Ready mitigation [{b['mitigation_tag']}]:** {b['mitigation']}")
    sg = b["soak_growth_finding"]
    lines.append(f"\n**Soak-growth finding — `{sg['table']}`** ({sg['verdict']}): {sg['fact']}")
    lines.append(f"- Measured: {sg['measured']}")
    lines.append(f"- Ready mitigation [{sg['mitigation_tag']}]: {sg['mitigation']}")

    # t0↔tEnd deltas (§8.4 #5)
    d = ctx["deltas"]
    lines.append("\n## t0 ↔ tEnd deltas\n")
    if d["row_count_ledger"]:
        lines.append("\n**Row-count ledger (§8.2.4)**\n")
        lines.append("| Count | t0 | tEnd | Δ |")
        lines.append("|-------|----|------|---|")
        for k, v in d["row_count_ledger"].items():
            lines.append(f"| {k} | {v['t0']:,} | {v['tEnd']:,} | {v['delta']:+,} |")
    else:
        lines.append("\n_No domain-counts ledger captured._")
    if d["table_delta"]:
        lines.append("\n**Per-table live/dead-tup + autovacuum (pg_stat_user_tables)**\n")
        lines.append("| Table | live t0→tEnd | dead t0→tEnd | autovac t0→tEnd |")
        lines.append("|-------|-------------|-------------|-----------------|")
        for t, v in d["table_delta"].items():
            lv = v["live_tup"]
            dv = v["dead_tup"]
            av = v["autovacuum_count"]
            lines.append(f"| {t} | {lv['t0']}→{lv['tEnd']} | {dv['t0']}→{dv['tEnd']} | "
                         f"{av['t0']}→{av['tEnd']} |")
    if d["db_size"]:
        ds = d["db_size"]
        lines.append(f"\n**DB size:** {ds['t0_bytes']/1e9:.2f} → {ds['tEnd_bytes']/1e9:.2f} GB "
                     f"(Δ {ds['delta_bytes']/1e9:+.2f} GB)")

    # Regression comparison (§8.5)
    cmp = ctx.get("comparison")
    if cmp:
        lines.append("\n## Regression comparison (§8.5)\n")
        if cmp.get("refused"):
            lines.append(f"> ⛔ **Comparison refused** — {cmp['reason']}.")
            for a, vv in cmp.get("axis_diffs", {}).items():
                lines.append(f"  - `{a}`: baseline `{vv['baseline']}` vs new `{vv['new']}`")
        else:
            lines.append(f"**Baseline:** `{cmp['baseline_run_id']}` → **New:** `{cmp['new_run_id']}`")
            lines.append(f"\n**Gate: {cmp['gate']}** "
                         f"(band ±{int(cmp['regression_band']*100)}%)")
            if cmp.get("block_reasons"):
                lines.append("\n_BLOCK:_ " + "; ".join(cmp["block_reasons"]))
            if cmp.get("warn_reasons"):
                lines.append("\n_WARN:_ " + "; ".join(cmp["warn_reasons"]))
            changed = [r for r in cmp.get("row_diffs", []) if r.get("gate")]
            if changed:
                lines.append("\n| # | baseline | new | Δ% | gate |")
                lines.append("|---|----------|-----|----|------|")
                for r in changed:
                    lines.append(f"| {r['id']} | {r['baseline_verdict']} | "
                                 f"{r['new_verdict']} | {r.get('delta_pct', '—')} | "
                                 f"{r.get('gate', '')} |")

    # Profile + provenance (§8.4 #6)
    lines.append("\n## Profile & provenance\n")
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    for k, v in man.items():
        if k == "slo":
            continue
        lines.append(f"| {k} | {v} |")
    lines.append("\n**Profile key (regression axes):** "
                 + ", ".join(f"`{k}={v}`" for k, v in ctx["profile_key"].items()))
    lines.append(f"\n**Surfaces present:** {', '.join(ctx['present_surfaces']) or '(none)'}")

    # Open questions (§8.4 #7) — auto-populated from NO_DATA rows + the load-bearing fact
    nodata = [r["id"] for ci in c.values() for r in ci["rows"] if r["verdict"] == NO_DATA]
    lines.append("\n## Open questions surfaced by this run\n")
    if nodata:
        lines.append(f"- NO-DATA rows needing a source next run: {', '.join(nodata)}")
    lines.append("- DDNS short-circuit ratio on renewals (the load-bearing fact §5.2): "
                 + _ddns_short_circuit_note(ctx))
    lines.append("- `[tune-after-baseline]` thresholds exercised — promote to "
                 "`v2-measured` (§8.3.1) once the idle floor is established.")
    lines.append("")
    return "\n".join(lines)


def _generator_lines(gen: dict[str, Any]) -> list[str]:
    """The generator-accounting block, one bullet per ledger (shared shape with
    the template so the two renderers stay in sync)."""
    h = gen.get("handshake") or {}
    d = gen.get("dns") or {}

    def pct(v: Any) -> str:
        return "—" if v is None else f"{v:.2f}%"

    def num(v: Any) -> str:
        # None = a summary written before the counter existed: unknown, not 0.
        return "—" if v is None else f"{v:,}"

    rc = ", ".join(f"{k} {v:,}" for k, v in (d.get("rcodes") or {}).items()) or "none"
    return [
        f"- **Shards:** {gen.get('shards', 0)}",
        f"- **DHCP handshake:** attempts {h.get('attempts', 0):,} · "
        f"acked {h.get('acked', 0):,} ({pct(h.get('strict_pct'))} strict) · "
        f"without a resend {num(h.get('acked_without_resend'))} "
        f"({pct(h.get('without_resend_pct'))}) · "
        f"after a resend {num(h.get('acked_after_resend'))} · "
        f"within budget {h.get('acked_within_budget', 0):,} ({pct(h.get('within_budget_pct'))}) · "
        f"late {h.get('acked_late', 0):,} ({pct(h.get('with_late_pct'))} with late) · "
        f"timeouts {h.get('timeouts', 0):,} · naks {h.get('naks', 0):,} · "
        f"in flight at stop {num(h.get('in_flight'))}",
        f"- **DNS stream:** sent {d.get('sent', 0):,} · answered {d.get('answered', 0):,} · "
        f"ok {d.get('ok', 0):,} ({pct(d.get('ok_pct_of_sent'))} of sent) · "
        f"timeouts {d.get('timeouts', 0):,} · errors {d.get('errors', 0):,} · "
        f"unaccounted {d.get('unaccounted', 0):,}",
        f"- **DNS rcodes:** {rc}",
    ]


def _ddns_short_circuit_note(ctx: dict[str, Any]) -> str:
    # The orchestrator emits ddns_short_circuit_ratio per window; surfaced if present.
    return ("see orchestrator ddns_short_circuit_ratio — a broken short-circuit turns "
            "every renewal into 6 DNS writes and collapses the ceiling")


def render_html(markdown_text: str) -> str:
    """Minimal, dependency-free md→html (the `markdown` package isn't guaranteed).

    Handles headings / tables / code-fences / bold / inline-code / lists — enough to
    make report.html standalone-readable. Not a full CommonMark renderer by design.
    """
    import html as _html
    import re

    out: list[str] = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<title>SpatiumDDI perf report</title>",
        (
            "<style>body{font:14px/1.5 system-ui,sans-serif;max-width:1100px;margin:2rem auto;"
            + "padding:0 1rem;color:#1a1a1a}h1,h2,h3{line-height:1.2}code,pre{font-family:"
            + "ui-monospace,monospace}pre{background:#f5f5f5;padding:1rem;overflow:auto;"
            + "border-radius:6px}table{border-collapse:collapse;width:100%;margin:1rem 0}"
            + "th,td{border:1px solid #ddd;padding:6px 10px;text-align:left;font-size:13px}"
            + "th{background:#fafafa}blockquote{border-left:4px solid #f0ad4e;margin:1rem 0;"
            + "padding:.5rem 1rem;background:#fff8e1}@media(prefers-color-scheme:dark){"
            + "body{background:#0d1117;color:#c9d1d9}pre,th{background:#161b22}"
            + "th,td{border-color:#30363d}blockquote{background:#1c1810}}</style></head><body>"
        ),
    ]
    lines = markdown_text.split("\n")
    i = 0
    in_table = False

    def _inline(s: str) -> str:
        s = _html.escape(s)
        s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
        s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
        return s

    while i < len(lines):
        ln = lines[i]
        if ln.startswith("```"):
            buf = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                buf.append(_html.escape(lines[i]))
                i += 1
            out.append("<pre>" + "\n".join(buf) + "</pre>")
            i += 1
            continue
        if ln.startswith("|") and "|" in ln[1:]:
            cells = [c.strip() for c in ln.strip().strip("|").split("|")]
            if all(set(c) <= set("-: ") for c in cells):
                i += 1
                continue  # separator row
            tag = "td"
            if not in_table:
                out.append("<table>")
                in_table = True
                tag = "th"
            out.append("<tr>" + "".join(f"<{tag}>{_inline(c)}</{tag}>" for c in cells) + "</tr>")
            i += 1
            continue
        if in_table:
            out.append("</table>")
            in_table = False
        if ln.startswith("### "):
            out.append(f"<h3>{_inline(ln[4:])}</h3>")
        elif ln.startswith("## "):
            out.append(f"<h2>{_inline(ln[3:])}</h2>")
        elif ln.startswith("# "):
            out.append(f"<h1>{_inline(ln[2:])}</h1>")
        elif ln.startswith("> "):
            out.append(f"<blockquote>{_inline(ln[2:])}</blockquote>")
        elif ln.startswith("- "):
            out.append(f"<li>{_inline(ln[2:])}</li>")
        elif ln.strip() == "":
            out.append("")
        else:
            out.append(f"<p>{_inline(ln)}</p>")
        i += 1
    if in_table:
        out.append("</table>")
    out.append("</body></html>")
    return "\n".join(out)


# ==============================================================================
# Manifest loading from the run dir (collect gets NO --manifest)
# ==============================================================================
def _load_run_manifest(rp: RunPaths, log) -> manifest_mod.Manifest:
    """Load the manifest the controller pinned into the run dir.

    Precedence: rp.manifest_resolved (controller dump_resolved) → state.manifest_path.
    Raises if neither resolves (we cannot build a profile/SLO table without it).
    """
    if rp.manifest_resolved.exists():
        return manifest_mod.load(rp.manifest_resolved)
    # fall back to the path recorded in state.json
    from spddi_perf.checkpoint import read_state
    state = read_state(rp)
    if state and state.manifest_path and Path(state.manifest_path).exists():
        log_event(log, 20, "manifest_from_state", path=state.manifest_path)
        return manifest_mod.load(state.manifest_path)
    raise FileNotFoundError(
        f"no resolved manifest at {rp.manifest_resolved} and no usable "
        f"state.manifest_path — cannot generate a report")


# ==============================================================================
# Main
# ==============================================================================
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="python3 -m spddi_perf.collect",
        description="SpatiumDDI perf end-of-run report generator (§8). Ingests a run "
                    "dir + the resolved manifest, computes the §8.3 SLO table, renders "
                    "report.md/.html + slo_results.json. --baseline runs §8.5 "
                    "regression comparison + gate policy.")
    p.add_argument("--run-id", required=True, help="the run id to report on")
    p.add_argument("--run-root", required=True, help="the run root (perf/run)")
    # NOTE: collect deliberately does NOT take --manifest — it reads the resolved
    # manifest the controller pinned into the run dir (cli.py / controller contract).
    p.add_argument("--manifest", default=None,
                   help="(optional) override manifest path; normally read from the run dir")
    p.add_argument("--baseline", default=None,
                   help="baseline run id for §8.5 regression comparison")
    p.add_argument("--out", default=None,
                   help="output dir (default: <run>/report)")
    p.add_argument("--publish", action="store_true",
                   help="also copy report/ to perf/reports/<run_id>/ for committing")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    rp = RunPaths.for_run(args.run_id, args.run_root)
    log = get_logger("collect", service=SERVICE, run_id=args.run_id)

    if not rp.root.is_dir():
        log_event(log, 40, "run_dir_missing", path=str(rp.root))
        return 2

    # Manifest from the run dir (or an explicit override).
    try:
        if args.manifest:
            m = manifest_mod.load(args.manifest)
        else:
            m = _load_run_manifest(rp, log)
    except (FileNotFoundError, manifest_mod.ManifestError) as exc:
        log_event(log, 40, "manifest_load_failed", error=str(exc))
        return 2

    rd = ingest(rp, m, log)
    slo = build_slo_results(rd)
    deltas = build_deltas(rd)
    bottleneck = build_bottleneck(rd, slo)

    # Regression comparison (§8.5)
    comparison: dict[str, Any] | None = None
    if args.baseline:
        base_rp = RunPaths.for_run(args.baseline, args.run_root)
        base_slo = _read_json(base_rp.report_dir / "slo_results.json")
        if base_slo is None:
            log_event(log, 30, "baseline_slo_missing",
                      path=str(base_rp.report_dir / "slo_results.json"),
                      note="run collect on the baseline first")
            comparison = {"comparable": False, "refused": True,
                          "reason": f"baseline slo_results.json not found for "
                                    f"'{args.baseline}'"}
        else:
            comparison = build_comparison(rd, base_slo, slo, log)

    # Output dir
    out_dir = Path(args.out) if args.out else rp.report_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    # Write slo_results.json (the CI/release gate artifact, §8.5)
    atomic_write_json(out_dir / "slo_results.json", slo)
    if comparison is not None:
        atomic_write_json(out_dir / "comparison.json", comparison)

    # Render + write report.md / report.html
    md = render_markdown(rd, slo, deltas, bottleneck, comparison, log)
    (out_dir / "report.md").write_text(md, encoding="utf-8")
    try:
        (out_dir / "report.html").write_text(render_html(md), encoding="utf-8")
    except Exception as exc:  # noqa: BLE001 — html is best-effort
        log_event(log, 30, "html_render_skipped", error=str(exc))

    # Publish (copy to the committable destination)
    if args.publish:
        dest = rp.published_report_dir
        dest.mkdir(parents=True, exist_ok=True)
        for name in ("slo_results.json", "comparison.json", "report.md", "report.html"):
            src = out_dir / name
            if src.exists():
                shutil.copy2(src, dest / name)
        log_event(log, 20, "published", dest=str(dest))

    log_event(log, 20, "report_written", out_dir=str(out_dir),
              overall=slo["overall"]["verdict"],
              criteria={k: v["verdict"] for k, v in slo["criteria"].items()},
              gate=(comparison or {}).get("gate"))
    # Exit non-zero on a hard BLOCK so CI/release gating can read the exit code.
    if comparison and comparison.get("gate") == "BLOCK":
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
