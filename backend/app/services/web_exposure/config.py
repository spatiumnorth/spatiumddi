"""Configuration of the ``security.web_exposure`` module (#3651).

Stored as one JSONB blob on ``platform_settings.web_exposure``. Every
mitigation defaults OFF, and the module itself ships off (non-negotiable #14,
declared in ``tests/test_feature_module_defaults.py``; no seeded row).
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass
from typing import Any

import structlog
from pydantic import BaseModel, Field, field_validator

from app.services.web_exposure.classify import IPNetwork, parse_networks

logger = structlog.get_logger(__name__)

MODULE_ID = "security.web_exposure"


class WebExposureConfig(BaseModel):
    # ── Detection ────────────────────────────────────────────────
    #: Escape hatch for public ranges the operator uses internally. A
    #: classification list, not an allow-list: nothing is refused because of it.
    trusted_networks: list[str] = Field(default_factory=list)
    #: "I mean to be on the internet": demotes reachability to ``info`` and keeps
    #: only the attack-evidence escalation live.
    intentional: bool = False
    window_hours: int = Field(default=24, ge=1, le=168)
    #: Distinct external buckets with a login-page load or a 401 that make
    #: the verdict ``exposed``.
    threshold: int = Field(default=3, ge=1, le=1000)

    # ── Tier 1a: stricter per-source throttle for external sources ──
    external_throttle_enabled: bool = False
    external_throttle_attempts: int = Field(default=5, ge=1, le=1000)
    external_throttle_window_seconds: int = Field(default=60, ge=10, le=3600)

    # ── Tier 1b: temporary source ban with backoff ──────────────
    ban_enabled: bool = False
    ban_failures: int = Field(default=10, ge=3, le=1000)
    ban_failure_window_minutes: int = Field(default=15, ge=1, le=1440)
    ban_base_minutes: int = Field(default=15, ge=1, le=1440)
    ban_max_hours: int = Field(default=24, ge=1, le=168)

    # ── Tier 2: second factor required from outside ─────────────
    require_mfa_external: bool = False

    @field_validator("trusted_networks")
    @classmethod
    def _v_networks(cls, v: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for c in v:
            s = (c or "").strip()
            if not s:
                continue
            try:
                canon = str(ipaddress.ip_network(s, strict=False))
            except ValueError as exc:
                raise ValueError(f"invalid CIDR {c!r}: {exc}") from exc
            if canon not in seen:
                seen.add(canon)
                out.append(canon)
        if len(out) > 256:
            raise ValueError("at most 256 trusted networks")
        return out

    def any_mitigation(self) -> bool:
        return self.external_throttle_enabled or self.ban_enabled or self.require_mfa_external


def config_from_row(raw: dict[str, Any] | None) -> WebExposureConfig:
    """Tolerant read: an unparseable stored blob falls back to the shipped
    defaults (everything off) rather than breaking sign-in."""
    try:
        return WebExposureConfig.model_validate(raw or {})
    except Exception as exc:  # noqa: BLE001 — a bad blob must never break the api
        logger.warning("web_exposure_config_invalid", error=str(exc)[:200])
        return WebExposureConfig()


def mitigations_break_glass() -> bool:
    """``WEB_EXPOSURE_MITIGATIONS=off`` in the api environment disables every
    mitigation regardless of stored settings: the break-glass path for an
    operator who cannot reach the Settings page."""
    from app.config import settings  # noqa: PLC0415

    return settings.web_exposure_mitigations.strip().lower() in {"off", "0", "false", "no"}


@dataclass(frozen=True)
class RuntimeConfig:
    """What the per-request hook needs, cached: module state + config."""

    enabled: bool
    config: WebExposureConfig
    trusted: tuple[IPNetwork, ...]


_TTL_S = 10.0
_cached: RuntimeConfig | None = None
_loaded_at = 0.0


def invalidate_cache() -> None:
    global _cached, _loaded_at
    _cached = None
    _loaded_at = 0.0


async def get_runtime_config() -> RuntimeConfig:
    """Module enabled + config, from a short-TTL process-local cache. A failed
    read answers "disabled" (detection degrades, it never fails a request)."""
    global _cached, _loaded_at
    now = time.monotonic()
    if _cached is not None and now - _loaded_at < _TTL_S:
        return _cached
    from sqlalchemy import select  # noqa: PLC0415

    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.settings import PlatformSettings  # noqa: PLC0415
    from app.services import feature_modules  # noqa: PLC0415

    try:
        async with AsyncSessionLocal() as db:
            enabled = await feature_modules.is_module_enabled(db, MODULE_ID)
            raw = (
                await db.execute(
                    select(PlatformSettings.web_exposure).where(PlatformSettings.id == 1)
                )
            ).scalar_one_or_none()
    except Exception as exc:  # noqa: BLE001
        logger.warning("web_exposure_config_unreadable", error=str(exc)[:200])
        # Remember the failure for one TTL (keeping the last good value when
        # there is one): an unreachable database must cost a request one cache
        # lookup, not one connection attempt, or a flood of external requests
        # would pile onto a database that is already down.
        _cached = _cached or RuntimeConfig(False, WebExposureConfig(), ())
        _loaded_at = now
        return _cached
    cfg = config_from_row(raw)
    _cached = RuntimeConfig(enabled, cfg, parse_networks(cfg.trusted_networks))
    _loaded_at = now
    return _cached
