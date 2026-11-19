"""Fingerbank API integration — passive DHCP device fingerprinting.

The fingerbank project (https://fingerbank.org) maintains a curated
database mapping DHCP option-55 / option-60 / DHCPv6 / user-agent
signatures to device-type / device-class / manufacturer triples. We
query their public REST endpoint
``https://api.fingerbank.org/api/v2/combinations/interrogate`` with
each unique fingerprint we observe and cache the result on the
``dhcp_fingerprint`` row for ``FINGERBANK_CACHE_DAYS`` days.

API key configuration lives on the singleton ``platform_settings``
row as a Fernet-encrypted column. Operators set it via Settings →
Platform; if unset, the agent still collects raw fingerprints — they
just don't get enriched (the device shows up as "fingerprint
collected, no lookup" in the IP detail modal).

Failure modes intentionally swallowed:
  - **No API key configured.** Returns ``None``; the caller leaves
    the row's fingerbank_* columns empty.
  - **Network / DNS error.** Stamps ``fingerbank_last_error`` so the
    UI surfaces "fingerbank unreachable" and returns ``None``.
  - **HTTP 429 rate limit.** Treated like a network error — same
    error message + retry on the next ingestion cycle.
  - **HTTP 5xx.** Same as 429.
  - **Malformed JSON / unexpected schema.** Logged + treated as
    error, never raised.

The cache window is intentionally short (7 days) so the device
taxonomy stays fresh as fingerbank improves their corpus, but long
enough that a stable fleet doesn't burn API quota. Devices that
re-enter the network after the cache expires get re-looked-up on
the next agent push for that MAC.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_str
from app.core.exc_text import describe_http_exc
from app.models.dhcp_fingerprint import DHCPFingerprint
from app.models.settings import PlatformSettings

logger = structlog.get_logger(__name__)

FINGERBANK_API_URL = "https://api.fingerbank.org/api/v2/combinations/interrogate"
FINGERBANK_CACHE_DAYS = 7
FINGERBANK_TIMEOUT = 10.0


@dataclass(frozen=True)
class FingerbankResult:
    """Normalised view of a fingerbank response.

    Fields map directly onto ``DHCPFingerprint.fingerbank_*`` columns
    so the caller can stamp the row in one assignment loop.
    """

    device_id: int | None
    device_name: str | None
    device_class: str | None
    manufacturer: str | None
    score: int | None


async def _load_api_key(db: AsyncSession) -> str | None:
    """Fetch + decrypt the fingerbank API key from platform_settings.

    Returns ``None`` if the operator hasn't configured one — that's
    the "passive collection only, no enrichment" mode.
    """
    settings = await db.get(PlatformSettings, 1)
    if settings is None or not settings.fingerbank_api_key_encrypted:
        return None
    try:
        return decrypt_str(settings.fingerbank_api_key_encrypted).strip() or None
    except ValueError as exc:
        logger.warning("fingerbank_api_key_decrypt_failed", error=str(exc))
        return None


def _within_cache_window(last_lookup_at: datetime | None) -> bool:
    """True if the cached row is fresh enough to skip re-lookup."""
    if last_lookup_at is None:
        return False
    cutoff = datetime.now(UTC) - timedelta(days=FINGERBANK_CACHE_DAYS)
    return last_lookup_at >= cutoff


def _parse_response(payload: dict[str, Any]) -> FingerbankResult:
    """Pull the fields we care about out of fingerbank's response shape.

    Fingerbank returns a nested ``device`` object plus a top-level
    ``score`` and ``manufacturer.name``. We normalise everything
    through ``str()`` and clamp lengths to fit the column widths so a
    surprise schema change doesn't crash the stamping loop.
    """
    device = payload.get("device") or {}
    manufacturer_obj = payload.get("manufacturer") or {}

    device_id_raw = device.get("id") or payload.get("device_id")
    try:
        device_id: int | None = int(device_id_raw) if device_id_raw is not None else None
    except (TypeError, ValueError):
        device_id = None

    score_raw = payload.get("score")
    try:
        score: int | None = int(score_raw) if score_raw is not None else None
    except (TypeError, ValueError):
        score = None

    def _clamp(value: Any, max_len: int) -> str | None:
        if value is None:
            return None
        s = str(value).strip()
        return s[:max_len] if s else None

    # Fingerbank's device record carries a ``parents`` list with the
    # top-level taxonomy node first (e.g. "Operating System / iOS /
    # iPhone"). The IP detail modal renders device_class as the broad
    # category, so we pick the first parent name when one is present;
    # otherwise fall back to the device's own ``name``.
    parents = device.get("parents") or []
    device_class_value: str | None = None
    if isinstance(parents, list) and parents:
        first_parent = parents[0]
        if isinstance(first_parent, dict):
            device_class_value = first_parent.get("name")

    return FingerbankResult(
        device_id=device_id,
        device_name=_clamp(device.get("name"), 255),
        device_class=_clamp(device_class_value, 100),
        manufacturer=_clamp(manufacturer_obj.get("name"), 100),
        score=score,
    )


async def lookup(
    db: AsyncSession,
    *,
    fingerprint: DHCPFingerprint,
) -> FingerbankResult | None:
    """Hit fingerbank for ``fingerprint`` and stamp the result back on the row.

    Returns the parsed result on success, ``None`` on cache hit / no
    API key / API failure. The caller is responsible for committing
    — this function only mutates the ORM row in place so it composes
    cleanly inside a Celery task's transaction.
    """
    if _within_cache_window(fingerprint.fingerbank_last_lookup_at):
        logger.debug(
            "fingerbank_cache_hit",
            mac=str(fingerprint.mac_address),
            last_lookup_at=(
                fingerprint.fingerbank_last_lookup_at.isoformat()
                if fingerprint.fingerbank_last_lookup_at
                else None
            ),
        )
        return None

    api_key = await _load_api_key(db)
    if not api_key:
        logger.debug("fingerbank_no_api_key", mac=str(fingerprint.mac_address))
        return None

    if not fingerprint.option_55:
        # Fingerbank requires at least the parameter request list. A
        # signature with only option_60 is too thin for a useful query.
        logger.debug("fingerbank_skip_no_option_55", mac=str(fingerprint.mac_address))
        return None

    payload: dict[str, Any] = {
        "dhcp_fingerprint": fingerprint.option_55,
        "mac": str(fingerprint.mac_address),
    }
    if fingerprint.option_60:
        payload["dhcp_vendor"] = fingerprint.option_60
    if fingerprint.option_77:
        payload["user_class"] = fingerprint.option_77

    try:
        async with httpx.AsyncClient(timeout=FINGERBANK_TIMEOUT) as client:
            resp = await client.post(
                FINGERBANK_API_URL,
                params={"key": api_key},
                json=payload,
            )
    except httpx.HTTPError as exc:
        msg = f"fingerbank request failed: {describe_http_exc(exc)}"
        fingerprint.fingerbank_last_error = msg[:500]
        fingerprint.fingerbank_last_lookup_at = datetime.now(UTC)
        logger.warning("fingerbank_http_error", mac=str(fingerprint.mac_address), error=str(exc))
        return None

    if resp.status_code == 404:
        # Fingerbank returns 404 when no device matches — that's a
        # "lookup happened, no enrichment available" case rather than
        # an error. Stamp last_lookup_at so we cache the negative
        # result for the cache window.
        fingerprint.fingerbank_last_lookup_at = datetime.now(UTC)
        fingerprint.fingerbank_last_error = None
        logger.info(
            "fingerbank_no_match",
            mac=str(fingerprint.mac_address),
            option_55=fingerprint.option_55,
        )
        return None

    if resp.status_code != 200:
        msg = f"fingerbank HTTP {resp.status_code}: {resp.text[:200]}"
        fingerprint.fingerbank_last_error = msg[:500]
        fingerprint.fingerbank_last_lookup_at = datetime.now(UTC)
        logger.warning(
            "fingerbank_bad_status",
            mac=str(fingerprint.mac_address),
            status=resp.status_code,
        )
        return None

    try:
        data = resp.json()
    except ValueError as exc:
        msg = f"fingerbank invalid JSON: {exc}"
        fingerprint.fingerbank_last_error = msg[:500]
        fingerprint.fingerbank_last_lookup_at = datetime.now(UTC)
        logger.warning("fingerbank_invalid_json", mac=str(fingerprint.mac_address))
        return None

    result = _parse_response(data)
    fingerprint.fingerbank_device_id = result.device_id
    fingerprint.fingerbank_device_name = result.device_name
    fingerprint.fingerbank_device_class = result.device_class
    fingerprint.fingerbank_manufacturer = result.manufacturer
    fingerprint.fingerbank_score = result.score
    fingerprint.fingerbank_last_lookup_at = datetime.now(UTC)
    fingerprint.fingerbank_last_error = None

    logger.info(
        "fingerbank_lookup_ok",
        mac=str(fingerprint.mac_address),
        device_name=result.device_name,
        device_class=result.device_class,
        manufacturer=result.manufacturer,
        score=result.score,
    )
    return result


__all__ = [
    "FINGERBANK_API_URL",
    "FINGERBANK_CACHE_DAYS",
    "FingerbankResult",
    "lookup",
]
