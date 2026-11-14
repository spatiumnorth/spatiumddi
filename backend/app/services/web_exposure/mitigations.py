"""Opt-in responses to an exposed verdict (#3651). Every one defaults OFF.

The property that keeps a wrong threshold from ever touching the operator's own
networks: a source that classifies as ``trusted`` or ``internal`` is NEVER
subject to any tier here, whatever the settings say. On top of that:

* **Fail open.** Redis unreachable means no throttle, no ban.
* **Bounded.** A ban lasts at most ``ban_max_hours``, the list holds at most
  ``MAX_BANS`` entries (oldest evicted), and a Redis restart clears it.
* **Visible and undoable.** Bans are listed and cleared in Settings, from any
  internal address, and every ban and clear is audited.
* **Break glass.** ``WEB_EXPOSURE_MITIGATIONS=off`` in the api environment
  disables every tier whatever is stored (docs/features/SYSTEM_ADMIN.md).
* **No auto-arming.** Nothing here turns on because of a verdict.

Tier 1a (``external_throttle``) and tier 1b (``ban``) act on ``/auth/login``
and ``/auth/login/mfa`` only. Tier 2 refuses a *local* account without TOTP at
sign-in from an external source; TOTP-enrolled users, SSO / LDAP / RADIUS /
TACACS+ users and API tokens are unaffected. Tier 3a is a bridge to the existing
appliance Web UI source restriction and its own lock-out guards.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import structlog

from app.config import settings
from app.core.auth_throttle import incr_with_window
from app.core.redis_client import make_async_redis
from app.services.web_exposure import store
from app.services.web_exposure.classify import bucket_of, classify, is_private_fast
from app.services.web_exposure.config import (
    RuntimeConfig,
    get_runtime_config,
    mitigations_break_glass,
)

logger = structlog.get_logger(__name__)

MAX_BANS = 200


def _k(name: str) -> str:
    """A Redis key under the module's prefix (read at call time)."""
    return f"{store.KEY_PREFIX}{name}"


def _redis() -> Any:
    return make_async_redis(settings.redis_url, socket_connect_timeout=2)


@dataclass(frozen=True)
class LoginDecision:
    allowed: bool
    retry_after: int = 0
    reason: str = ""


ALLOW = LoginDecision(True)


async def _external_bucket(ip: str | None) -> tuple[RuntimeConfig, str] | None:
    """The runtime config and bucket for a source the mitigations may touch,
    or None: unknown / private / trusted sources, a disabled module, a
    break-glass override and an all-off configuration all return None."""
    if not ip or is_private_fast(ip) or mitigations_break_glass():
        return None
    rt = await get_runtime_config()
    if not rt.enabled or not rt.config.any_mitigation():
        return None
    if classify(ip, rt.trusted) != "external":
        return None
    bucket = bucket_of(ip)
    return (rt, bucket) if bucket else None


async def check_login_allowed(ip: str | None) -> LoginDecision:
    """Tier 1a + 1b, evaluated before the password is looked at."""
    try:
        hit = await _external_bucket(ip)
        if hit is None:
            return ALLOW
        rt, bucket = hit
        cfg = rt.config
        r = _redis()
        try:
            if cfg.ban_enabled:
                raw = await r.hget(_k("bans"), bucket)
                if raw:
                    until = float(json.loads(raw).get("until", 0))
                    left = int(until - time.time())
                    if left > 0:
                        return LoginDecision(False, left, "source_banned")
            if cfg.external_throttle_enabled:
                n = await incr_with_window(
                    r, _k(f"thr:{bucket}"), cfg.external_throttle_window_seconds
                )
                if n > cfg.external_throttle_attempts:
                    ttl = int(await r.ttl(_k(f"thr:{bucket}")))
                    return LoginDecision(False, max(ttl, 1), "external_throttle")
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001 — mitigations fail open
        logger.warning("web_exposure_login_check_unavailable", error=str(exc)[:200])
    return ALLOW


async def register_failure(ip: str | None) -> dict[str, Any] | None:
    """Tier 1b: count a failed sign-in from an external source and ban its
    bucket once it crosses the threshold. Returns the ban record when one was
    just applied (the caller audits it), else None. Never raises."""
    try:
        hit = await _external_bucket(ip)
        if hit is None or not hit[0].config.ban_enabled:
            return None
        cfg, bucket = hit[0].config, hit[1]
        r = _redis()
        try:
            n = await incr_with_window(r, _k(f"fail:{bucket}"), cfg.ban_failure_window_minutes * 60)
            if n < cfg.ban_failures:
                return None
            await r.delete(_k(f"fail:{bucket}"))
            lvl_key = _k(f"banlvl:{bucket}")
            level = int(await r.incr(lvl_key))
            await r.expire(lvl_key, cfg.ban_max_hours * 3600 * 2)
            minutes = min(cfg.ban_base_minutes * (2 ** (level - 1)), cfg.ban_max_hours * 60)
            now = time.time()
            record = {
                "bucket": bucket,
                "until": now + minutes * 60,
                "since": now,
                "level": level,
                "minutes": minutes,
                "failures": int(n),
            }
            await r.hset(_k("bans"), bucket, json.dumps(record))
            await _evict(r)
            return record
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001
        logger.warning("web_exposure_ban_unavailable", error=str(exc)[:200])
        return None


async def _evict(r: Any) -> None:
    """Drop expired bans, then the oldest, down to ``MAX_BANS``."""
    raw = await r.hgetall(_k("bans"))
    now = time.time()
    rows: list[tuple[str, dict[str, Any]]] = []
    for k, v in raw.items():
        k = k.decode() if isinstance(k, bytes) else k
        rec = json.loads(v)
        if float(rec.get("until", 0)) <= now:
            await r.hdel(_k("bans"), k)
        else:
            rows.append((k, rec))
    if len(rows) > MAX_BANS:
        rows.sort(key=lambda kv: float(kv[1].get("since", 0)))
        for k, _ in rows[: len(rows) - MAX_BANS]:
            await r.hdel(_k("bans"), k)


async def list_bans() -> list[dict[str, Any]] | None:
    """Active bans, newest first; None when Redis is unreachable."""
    try:
        r = _redis()
        try:
            await _evict(r)
            raw = await r.hgetall(_k("bans"))
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001
        logger.warning("web_exposure_bans_unreadable", error=str(exc)[:200])
        return None
    out = [json.loads(v) for v in raw.values()]
    return sorted(out, key=lambda b: -float(b.get("since", 0)))


async def clear_bans(bucket: str | None) -> int:
    """Clear one ban (and its backoff level), or all of them."""
    r = _redis()
    try:
        raw = await r.hgetall(_k("bans"))
        names = [k.decode() if isinstance(k, bytes) else k for k in raw]
        targets = [bucket] if bucket else names
        cleared = 0
        for b in targets:
            cleared += int(await r.hdel(_k("bans"), b))
            await r.delete(_k(f"banlvl:{b}"), _k(f"fail:{b}"))
        return cleared
    finally:
        await r.aclose()


async def mfa_required_from_outside(ip: str | None) -> bool:
    """Tier 2: True when a local account WITHOUT a second factor must be
    refused at this sign-in. The caller has already verified the password and
    has already excluded TOTP-enrolled and non-local users."""
    try:
        hit = await _external_bucket(ip)
        return hit is not None and hit[0].config.require_mfa_external
    except Exception:  # noqa: BLE001
        return False


MFA_OUTSIDE_DETAIL = (
    "Sign-in from outside your organisation's networks requires a second factor, and this "
    "account has none enrolled. Sign in from an internal network to enrol an authenticator "
    "(Profile -> Two-factor authentication), then try again."
)
