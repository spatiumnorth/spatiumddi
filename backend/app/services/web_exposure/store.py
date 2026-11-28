"""Bounded, coarse, local counters for web exposure detection (#3651).

A per-request counter cannot write to Postgres, so: an in-process buffer keyed
by ``(hour, bucket)`` is flushed to Redis every few seconds in one pipeline
(the api runs several workers / pods; Redis is the join point). One Redis hash
per hour holds every field, expires after 8 days, and is capped in size, so
memory is bounded by construction: a scanner cannot grow it past
``MAX_FIELDS_PER_HOUR`` however many addresses it uses. If Redis is down the
counters are dropped, never spooled to disk: detection degrades, it never
consumes the api.

What is kept is the operator's own clients: the /24 or /48 bucket as the key,
a capped sample of exact addresses and request paths per bucket, and counts.
A submitted username is stored only as a hash inside a HyperLogLog (a count of
distinct names, never the names).
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

from app.config import settings
from app.core.redis_client import make_async_redis

logger = structlog.get_logger(__name__)

#: Signals that are recorded.
SIGNAL_LOGIN_PAGE = "login_page"  # unauthenticated GET /api/v1/settings/public
SIGNAL_UNAUTH = "unauth_api"  # 401 / 403 on /api/v1/*
SIGNAL_VERSION = "version"  # GET /api/v1/version (never reaches the threshold alone)
SIGNAL_LOGIN_FAILURE = "login_failure"
SIGNAL_HOST_REFUSED = "host_refused"
SIGNAL_PROXY_NO_REAL_IP = "proxy_no_real_ip"  # attribution warning, not a source signal
SIGNALS = (
    SIGNAL_LOGIN_PAGE,
    SIGNAL_UNAUTH,
    SIGNAL_VERSION,
    SIGNAL_LOGIN_FAILURE,
    SIGNAL_HOST_REFUSED,
    SIGNAL_PROXY_NO_REAL_IP,
)

KEY_PREFIX = "webexp:"
HOUR_TTL_SECONDS = 8 * 24 * 3600
MAX_FIELDS_PER_HOUR = 4000
MAX_BUFFER_ENTRIES = 256
SAMPLE_ADDRESSES = 5
SAMPLE_PATHS = 5
FLUSH_INTERVAL_SECONDS = 3.0

_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def hour_of(ts: float) -> int:
    return int(ts // 3600)


def hour_key(hour: int) -> str:
    return f"{KEY_PREFIX}h:{hour}"


def users_key(hour: int) -> str:
    return f"{KEY_PREFIX}u:{hour}"


def clean_path(path: str) -> str:
    """First four segments, control characters stripped, clamped: the path is
    attacker-supplied and lands in a stored sample and in alert text."""
    segs = [s for s in path.split("?")[0].split("/") if s][:4]
    return _CTRL.sub("", "/" + "/".join(segs))[:80]


def username_hash(username: str) -> str:
    return hashlib.sha256(username.strip().lower().encode("utf-8", "replace")).hexdigest()[:16]


@dataclass
class _Delta:
    counts: dict[str, int] = field(default_factory=dict)
    addrs: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    users: set[str] = field(default_factory=set)
    first: float = 0.0
    last: float = 0.0


_buffer: dict[tuple[int, str], _Delta] = {}
_last_flush = 0.0
_flush_task: asyncio.Task[None] | None = None
dropped = 0


def reset_buffer() -> None:
    """Test hook."""
    global _last_flush, _flush_task, dropped
    _buffer.clear()
    _last_flush = 0.0
    _flush_task = None
    dropped = 0


def record(
    bucket: str,
    address: str,
    signal: str,
    *,
    path: str | None = None,
    username: str | None = None,
    now: float | None = None,
) -> None:
    """Count one external-source signal. Synchronous and allocation-light: the
    request path never waits on Redis. A full buffer drops the NEW bucket's
    counts (bounded memory beats completeness)."""
    global dropped
    ts = time.time() if now is None else now
    key = (hour_of(ts), bucket)
    delta = _buffer.get(key)
    if delta is None:
        if len(_buffer) >= MAX_BUFFER_ENTRIES:
            dropped += 1
            return
        delta = _Delta(first=ts)
        _buffer[key] = delta
    delta.counts[signal] = delta.counts.get(signal, 0) + 1
    delta.last = ts
    if address not in delta.addrs and len(delta.addrs) < SAMPLE_ADDRESSES:
        delta.addrs.append(address)
    if path:
        p = clean_path(path)
        if p not in delta.paths and len(delta.paths) < SAMPLE_PATHS:
            delta.paths.append(p)
    if username and len(delta.users) < 64:
        delta.users.add(username_hash(username))
    _maybe_schedule_flush(ts)


def _maybe_schedule_flush(ts: float) -> None:
    global _flush_task, _last_flush
    if ts - _last_flush < FLUSH_INTERVAL_SECONDS:
        return
    if _flush_task is not None and not _flush_task.done():
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    _last_flush = ts
    _flush_task = loop.create_task(flush())


def _redis() -> Any:
    return make_async_redis(settings.redis_url, socket_connect_timeout=2)


async def flush() -> None:
    """Move the buffer into Redis. Never raises."""
    global _last_flush
    _last_flush = time.time()
    if not _buffer:
        return
    batch = dict(_buffer)
    _buffer.clear()
    try:
        r = _redis()
        try:
            by_hour: dict[int, dict[str, _Delta]] = {}
            for (hour, bucket), delta in batch.items():
                by_hour.setdefault(hour, {})[bucket] = delta
            for hour, buckets in by_hour.items():
                await _flush_hour(r, hour, buckets)
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001 — counters are dropped, never retried
        logger.warning("web_exposure_flush_failed", error=str(exc)[:200])


async def _flush_hour(r: Any, hour: int, buckets: dict[str, _Delta]) -> None:
    key = hour_key(hour)
    names = list(buckets)
    existing = await r.hmget(key, [f"f:{b}" for b in names])
    hlen = int(await r.hlen(key))
    pipe = r.pipeline(transaction=False)
    wrote = False
    for bucket, present in zip(names, existing, strict=True):
        delta = buckets[bucket]
        if present is None:
            # A new bucket needs at most ~12 fields; refuse it once the hour is full.
            if hlen + 12 > MAX_FIELDS_PER_HOUR:
                continue
            hlen += 12
        wrote = True
        pipe.hsetnx(key, f"f:{bucket}", int(delta.first))
        pipe.hset(key, f"l:{bucket}", int(delta.last))
        for sig, n in delta.counts.items():
            pipe.hincrby(key, f"n:{bucket}:{sig}", n)
        if delta.addrs:
            pipe.hsetnx(key, f"a:{bucket}", ",".join(delta.addrs))
        if delta.paths:
            pipe.hsetnx(key, f"p:{bucket}", ",".join(delta.paths))
        if delta.users:
            pipe.pfadd(users_key(hour), *delta.users)
            pipe.expire(users_key(hour), HOUR_TTL_SECONDS)
    if wrote:
        pipe.expire(key, HOUR_TTL_SECONDS)
        await pipe.execute()


# ── Reading the window ──────────────────────────────────────────────


@dataclass
class BucketEvidence:
    bucket: str
    counts: dict[str, int]
    first_seen: int
    last_seen: int
    addresses: list[str]
    paths: list[str]

    @property
    def total(self) -> int:
        return sum(v for k, v in self.counts.items() if k != SIGNAL_PROXY_NO_REAL_IP)


@dataclass
class WindowData:
    buckets: list[BucketEvidence]
    distinct_usernames: int
    proxy_no_real_ip: int


async def read_window(hours: int, *, now: float | None = None) -> WindowData | None:
    """Aggregate the trailing ``hours`` hourly hashes. ``None`` when Redis is
    unreachable (the caller reports "unknown", never "not observed")."""
    ts = time.time() if now is None else now
    cur = hour_of(ts)
    hrs = list(range(cur - hours + 1, cur + 1))
    try:
        r = _redis()
        try:
            pipe = r.pipeline(transaction=False)
            for h in hrs:
                pipe.hgetall(hour_key(h))
            raw = await pipe.execute()
            users = await r.pfcount(*[users_key(h) for h in hrs])
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001
        logger.warning("web_exposure_read_failed", error=str(exc)[:200])
        return None

    agg: dict[str, BucketEvidence] = {}
    no_real_ip = 0
    for h in raw:
        for k, v in (h or {}).items():
            k = k.decode() if isinstance(k, bytes) else k
            v = v.decode() if isinstance(v, bytes) else v
            kind, _, rest = k.partition(":")
            if kind == "n":
                bucket, _, sig = rest.rpartition(":")
                ev = agg.setdefault(bucket, BucketEvidence(bucket, {}, 0, 0, [], []))
                if sig == SIGNAL_PROXY_NO_REAL_IP:
                    no_real_ip += int(v)
                ev.counts[sig] = ev.counts.get(sig, 0) + int(v)
            elif kind == "f":
                ev = agg.setdefault(rest, BucketEvidence(rest, {}, 0, 0, [], []))
                ev.first_seen = int(v) if not ev.first_seen else min(ev.first_seen, int(v))
            elif kind == "l":
                ev = agg.setdefault(rest, BucketEvidence(rest, {}, 0, 0, [], []))
                ev.last_seen = max(ev.last_seen, int(v))
            elif kind == "a":
                ev = agg.setdefault(rest, BucketEvidence(rest, {}, 0, 0, [], []))
                for a in v.split(","):
                    if a and a not in ev.addresses and len(ev.addresses) < SAMPLE_ADDRESSES:
                        ev.addresses.append(a)
            elif kind == "p":
                ev = agg.setdefault(rest, BucketEvidence(rest, {}, 0, 0, [], []))
                for p in v.split(","):
                    if p and p not in ev.paths and len(ev.paths) < SAMPLE_PATHS:
                        ev.paths.append(p)
    buckets = sorted(agg.values(), key=lambda b: (-b.total, b.bucket))
    return WindowData(buckets=buckets, distinct_usernames=int(users), proxy_no_real_ip=no_real_ip)
