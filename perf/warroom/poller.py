#!/usr/bin/env python3
"""War-room native-surface poller (long-running, off-box).

Polls the SpatiumDDI native observability API + Redis at the per-surface cadences
in ``manifest.observability.poll`` and appends canonical NDJSON records (the EXACT
shapes the watchdog + report read) under ``rp.warroom(<surface>)``. Degrades
gracefully — an unavailable endpoint records ``{available: false}`` and is never
fatal; the loop keeps every other surface flowing.

Surfaces (cadence key -> file):
  health_platform_s    -> warroom/health_platform.ndjson   (GET /health/platform + token)
  postgres_overview_s  -> warroom/pg_overview.ndjson        (GET /admin/postgres/overview)
                       -> warroom/pg_connections.ndjson     (GET /admin/postgres/connections)
  postgres_tables_s    -> warroom/pg_tables.ndjson          (GET /admin/postgres/tables)
  redis_overview_s     -> warroom/redis_overview.ndjson     (GET /admin/redis/overview)
                       -> warroom/redis_wakebus.ndjson      (GET /admin/redis/wake-bus)
                       -> warroom/celery_queues.ndjson      (Redis LLEN ipam/dns/dhcp/default)
  metrics_timeseries_s -> warroom/metrics_dns.ndjson        (GET /metrics/dns/timeseries)
                       -> warroom/metrics_dhcp.ndjson       (GET /metrics/dhcp/timeseries)

Discipline (§5.4 / §6.0): the native /admin/postgres/* path goes through the api pool
+ CNPG, so it's corroboration only — the deep DB series (locks, deadlocks, per-table
tuples) is psql_probe.py's authoritative job. This poller is the source for the
product *rollups* (platform dots, wake-bus, redis/pg overview, the 60s timeseries).

Secrets: superadmin token from the env var NAMED in the manifest
(``observability.superadmin_token_env``, default ``SPDDI_PERF_ADMIN_TOKEN``); Redis
URL from ``SPDDI_PERF_REDIS_URL`` (the LLEN + wake-bus source). NEVER hardcoded.

Stops cleanly on: kill-switch (``rp.stop_file``), stale setpoint (controller gone
> ~3 ticks → fail safe to OFF: keep observing but log + reduce nothing — observers
have no offered rate, so "fail safe" here = log the lag and continue scraping so we
still capture the box dying), SIGTERM/SIGINT.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from typing import Any

import httpx

import spddi_perf.manifest
import spddi_perf.setpoints
from spddi_perf.logging_util import append_ndjson, get_logger, log_event, utc_now_iso
from spddi_perf.runpaths import RunPaths

# Local import (sibling module) — works because perf/warroom is on sys.path[0] when
# launched as a script, and the launcher adds perf/harness to PYTHONPATH.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import surfaces  # noqa: E402

DEFAULT_POLL = {
    "health_platform_s": 5,
    "postgres_overview_s": 15,
    "postgres_tables_s": 30,
    "redis_overview_s": 15,
    "metrics_timeseries_s": 60,
}

# A setpoint is "stale" (controller gone) if its tick hasn't advanced for this long.
# Tick cadence is 60s; ~3 ticks of grace before we conclude the controller is gone.
STALE_SETPOINT_S = 200.0


class _Stop:
    """SIGTERM/SIGINT-aware stop flag."""

    def __init__(self) -> None:
        self.flag = False
        signal.signal(signal.SIGTERM, self._handle)
        signal.signal(signal.SIGINT, self._handle)

    def _handle(self, *_: Any) -> None:
        self.flag = True


def _resolve_poll(m: spddi_perf.manifest.Manifest) -> dict[str, float]:
    poll = dict(DEFAULT_POLL)
    for k, v in (m.observability.poll or {}).items():
        if k in poll:
            try:
                poll[k] = float(v)
            except (TypeError, ValueError):
                # Malformed override in the manifest; keep the DEFAULT_POLL value
                # for this key rather than failing the whole poller config.
                pass
    return poll


def _make_redis(redis_url: str | None):
    """Return a redis-py client (or None if no URL / import fails)."""
    if not redis_url:
        return None
    try:
        import redis  # redis-py 5.x

        # Sentinel URLs (sentinel://) need the Sentinel helper; the appliance HA
        # path uses them. Plain redis:// is the common load-lab case. We only do
        # LLEN here, so connect directly for redis:// and fall back gracefully.
        if redis_url.startswith(("sentinel://", "redis+sentinel://")):
            # Best-effort: pull master via Sentinel. Keep it simple — if this lab
            # uses Sentinel, SPDDI_PERF_REDIS_URL should point at a reachable node.
            return redis.Redis.from_url(redis_url.replace("sentinel://", "redis://", 1),
                                        socket_connect_timeout=2, socket_timeout=2)
        return redis.Redis.from_url(redis_url, socket_connect_timeout=2, socket_timeout=2)
    except Exception:
        return None


class Poller:
    def __init__(self, rp: RunPaths, m: spddi_perf.manifest.Manifest, log) -> None:
        self.rp = rp
        self.m = m
        self.log = log
        self.poll = _resolve_poll(m)

        # Secrets via env-var names from the manifest (never hardcoded).
        token_env = m.observability.superadmin_token_env
        self.token = os.environ.get(token_env, "")
        if not self.token:
            log_event(log, 30, "admin_token_missing", env=token_env,
                      note="superadmin endpoints will record available=false")

        self.redis_url = os.environ.get(surfaces.REDIS_URL_ENV, "")
        self.redis = _make_redis(self.redis_url)
        if not self.redis_url:
            # Recorded as an open_item: Celery queue depth (LLEN) + native wake-bus
            # cannot be read without the Redis URL.
            log_event(log, 30, "redis_url_missing", env=surfaces.REDIS_URL_ENV,
                      open_item=("SPDDI_PERF_REDIS_URL must be supplied for Celery "
                                 "queue-depth (LLEN ipam/dns/dhcp/default)"))

        verify: Any = os.environ.get("SPDDI_PERF_CA_BUNDLE", False)
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        self.api_base = surfaces.api_v1_base(m.target.api_base)
        self.host_root = surfaces.host_root(m.target.api_base)
        # Short per-call timeout so one dead endpoint can't blow a whole cadence
        # bucket (health is 5s; a 10s stall on a sibling surface would lag it).
        self.client = httpx.Client(verify=verify, timeout=4.0, headers=headers)

        # Next-due monotonic timestamps per cadence bucket.
        now = time.monotonic()
        self._due = {k: now for k in self.poll}

    # ── HTTP helpers ─────────────────────────────────────────────────────────

    def _get(self, base: str, path: str) -> tuple[bool, dict[str, Any] | None, str | None]:
        try:
            resp = self.client.get(base + path)
            if resp.status_code != 200:
                return False, None, f"http {resp.status_code}"
            return True, resp.json(), None
        except Exception as exc:  # noqa: BLE001 — degrade, never fatal
            return False, None, str(exc)

    def _record(self, surface: str, ok: bool, mapped: dict[str, Any] | None, err: str | None) -> None:
        if ok and mapped is not None:
            append_ndjson(self.rp.warroom(surface), {"available": True, **mapped})
        else:
            append_ndjson(self.rp.warroom(surface), {"available": False, "error": err})
            log_event(self.log, 20, "surface_unavailable", surface=surface, error=err)

    # ── Per-surface scrapes ──────────────────────────────────────────────────

    def scrape_health(self) -> None:
        ok, payload, err = self._get(self.host_root, surfaces.HEALTH_PLATFORM_PATH)
        self._record("health_platform", ok, surfaces.map_health_platform(payload) if ok else None, err)

    def scrape_pg_overview(self) -> None:
        ok, payload, err = self._get(self.api_base, surfaces.API_PATHS["pg_overview"])
        self._record("pg_overview", ok, surfaces.map_pg_overview(payload) if ok else None, err)

    def scrape_pg_connections(self) -> None:
        ok, payload, err = self._get(self.api_base, surfaces.API_PATHS["pg_connections"])
        self._record("pg_connections", ok, surfaces.map_pg_connections(payload) if ok else None, err)

    def scrape_pg_tables(self) -> None:
        ok, payload, err = self._get(self.api_base, surfaces.API_PATHS["pg_tables"])
        mapped = surfaces.map_pg_tables(payload, now_iso=utc_now_iso()) if ok else None
        self._record("pg_tables", ok, mapped, err)

    def scrape_redis_overview(self) -> None:
        ok, payload, err = self._get(self.api_base, surfaces.API_PATHS["redis_overview"])
        # Native redis/overview wraps errors in {available:false,hint}; honour that.
        if ok and payload is not None and payload.get("available") is False:
            self._record("redis_overview", False, None, payload.get("hint"))
        else:
            self._record("redis_overview", ok, surfaces.map_redis_overview(payload) if ok else None, err)

    def scrape_redis_wakebus(self) -> None:
        ok, payload, err = self._get(self.api_base, surfaces.API_PATHS["redis_wakebus"])
        if ok and payload is not None and payload.get("available") is False:
            self._record("redis_wakebus", False, None, payload.get("hint"))
        else:
            self._record("redis_wakebus", ok, surfaces.map_redis_wakebus(payload) if ok else None, err)

    def scrape_celery_queues(self) -> None:
        """Celery queue depth — no native endpoint; read Redis LLEN of each queue
        list key. (§2.4 / §6.1 Layer 3; queue names from celery_app.py:72-119.)"""
        if self.redis is None:
            self._record("celery_queues", False, None, "no redis client (SPDDI_PERF_REDIS_URL)")
            return
        try:
            depths: dict[str, int] = {}
            for q in surfaces.CELERY_QUEUES:
                try:
                    depths[q] = int(self.redis.llen(q))
                except Exception as exc:  # noqa: BLE001 — per-queue degrade
                    depths[q] = -1
                    log_event(self.log, 20, "celery_llen_failed", queue=q, error=str(exc))
            self._record("celery_queues", True, {"queues": depths}, None)
        except Exception as exc:  # noqa: BLE001
            self._record("celery_queues", False, None, str(exc))

    def scrape_metrics(self, which: str) -> None:
        """which = 'dns' | 'dhcp' — latest 60s bucket from the native timeseries."""
        path = surfaces.API_PATHS[f"metrics_{which}"] + "?window=1h"
        ok, payload, err = self._get(self.api_base, path)
        self._record(f"metrics_{which}", ok,
                     surfaces.map_metrics_timeseries(payload) if ok else None, err)

    # ── Cadence buckets ──────────────────────────────────────────────────────

    def _run_due(self, now: float) -> None:
        if now >= self._due["health_platform_s"]:
            self.scrape_health()
            self._due["health_platform_s"] = now + self.poll["health_platform_s"]
        if now >= self._due["postgres_overview_s"]:
            self.scrape_pg_overview()
            self.scrape_pg_connections()
            self._due["postgres_overview_s"] = now + self.poll["postgres_overview_s"]
        if now >= self._due["postgres_tables_s"]:
            self.scrape_pg_tables()
            self._due["postgres_tables_s"] = now + self.poll["postgres_tables_s"]
        if now >= self._due["redis_overview_s"]:
            self.scrape_redis_overview()
            self.scrape_redis_wakebus()
            self.scrape_celery_queues()
            self._due["redis_overview_s"] = now + self.poll["redis_overview_s"]
        if now >= self._due["metrics_timeseries_s"]:
            self.scrape_metrics("dns")
            self.scrape_metrics("dhcp")
            self._due["metrics_timeseries_s"] = now + self.poll["metrics_timeseries_s"]

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:  # noqa: BLE001
            pass
        if self.redis is not None:
            try:
                self.redis.close()
            except Exception:  # noqa: BLE001
                pass


def _setpoint_stale(rp: RunPaths, last_tick: int, last_seen_at: float) -> tuple[int, float, bool]:
    """Track setpoint tick advancement. Returns (tick, seen_at, is_stale)."""
    sp = spddi_perf.setpoints.read_current(rp)
    now = time.monotonic()
    if sp is None:
        # No setpoint yet (pre-first-publish). Not "stale" — just not started.
        return last_tick, last_seen_at, False
    if sp.tick != last_tick:
        return sp.tick, now, False
    stale = (now - last_seen_at) > STALE_SETPOINT_S
    return last_tick, last_seen_at, stale


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="War-room native-surface poller (off-box). Polls /health/platform, "
                    "/admin/postgres/*, /admin/redis/*, /metrics/* + Redis LLEN at the "
                    "manifest cadences, appending canonical NDJSON to warroom/<surface>.")
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--run-root", required=True)
    ap.add_argument("--manifest", required=True)
    args = ap.parse_args(argv)

    rp = RunPaths.for_run(args.run_id, args.run_root)
    m = spddi_perf.manifest.load(args.manifest)
    log = get_logger("warroom.poller", service="spddi-perf-warroom",
                     run_id=args.run_id, logfile=rp.worker_log("warroom_poller"))

    log_event(log, 20, "poller_start", api_base=surfaces.api_v1_base(m.target.api_base),
              host_root=surfaces.host_root(m.target.api_base),
              poll=_resolve_poll(m), redis_url_set=bool(os.environ.get(surfaces.REDIS_URL_ENV)))

    stop = _Stop()
    poller = Poller(rp, m, log)
    last_tick = -1
    last_seen_at = time.monotonic()
    stale_logged = False
    try:
        while not stop.flag:
            if rp.stop_file.exists():
                log_event(log, 20, "kill_switch_seen", path=str(rp.stop_file))
                break

            last_tick, last_seen_at, stale = _setpoint_stale(rp, last_tick, last_seen_at)
            if stale and not stale_logged:
                # Observers have no offered rate to throttle; "fail safe to OFF" for
                # a monitor = keep scraping (so we still capture the box dying) but
                # loudly flag that the controller is gone. Log once.
                log_event(log, 30, "setpoint_lag_controller_gone", last_tick=last_tick,
                          note="controller stale > %.0fs — continuing to observe" % STALE_SETPOINT_S)
                stale_logged = True
            elif not stale:
                stale_logged = False

            poller._run_due(time.monotonic())

            # Sleep to the soonest due time, capped at 1s for responsive kill-switch.
            now = time.monotonic()
            nxt = min(poller._due.values())
            time.sleep(max(0.2, min(1.0, nxt - now)) if nxt > now else 0.2)
    finally:
        poller.close()
        log_event(log, 20, "poller_stop")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
