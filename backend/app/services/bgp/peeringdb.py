"""PeeringDB client (issue #122).

PeeringDB is the canonical IXP-presence + peering-policy registry.
Free, optional auth (rate-limited harder without — we cache 24h
to stay well under the unauthenticated quota).

Endpoints we touch:

* ``net?asn=<n>`` — registered network record. Carries org name +
  policy + IRR record + looking-glass URL.
* ``netixlan?asn=<n>`` — IXP membership. Each row is one peering
  port at one IX with a speed + IPv4 / IPv6 IP.

Returns soft-failure shapes (``available: False`` + error string)
on any upstream issue, same as the RIPEstat client.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import httpx
import structlog

from app.services.bgp._errors import classify_http_error
from app.services.bgp.cache import PEERINGDB_TTL_SECONDS
from app.services.bgp.cache import get as cache_get
from app.services.bgp.cache import set_ as cache_set

logger = structlog.get_logger(__name__)

_BASE_URL = "https://www.peeringdb.com/api"
_USER_AGENT = "SpatiumDDI/0.1 (+https://github.com/spatiumnorth/spatiumddi; bgp-enrichment)"
_TIMEOUT = httpx.Timeout(15.0, connect=5.0, read=15.0)

# Schemes PeeringDB itself accepts for each field. A value with any other
# scheme is dropped at ingest rather than passed to the UI (#1361).
_WEBSITE_SCHEMES = frozenset({"http", "https"})
_LOOKING_GLASS_SCHEMES = frozenset({"http", "https", "telnet", "ssh"})


def _url_with_scheme(value: Any, allowed: frozenset[str]) -> str | None:
    """``value`` if it is an absolute URL with an allowed scheme, else None."""
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if parts.scheme.lower() not in allowed or not parts.netloc:
        return None
    return value


async def _fetch(path: str, params: dict[str, Any], cache_key: str) -> Any:
    cached = cache_get("peeringdb", cache_key, PEERINGDB_TTL_SECONDS)
    if cached is not None:
        return cached

    url = f"{_BASE_URL}/{path}"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                url,
                params=params,
                headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
            )
            # PeeringDB returns 404 when the ASN simply isn't
            # registered there (most ASes aren't — only ~30k of the
            # ~80k allocated 16-bit ASNs have PeeringDB records).
            # That's not "unreachable" — it's a clean "no record",
            # which our normalised shape models as ``found: False``
            # downstream. Cache it like a normal payload so we don't
            # re-query for the next 24 h.
            if resp.status_code == 404:
                empty: dict[str, Any] = {"data": []}
                cache_set("peeringdb", cache_key, empty)
                return empty
            resp.raise_for_status()
            payload = resp.json()
    except httpx.HTTPError as exc:
        # Full str(exc) lands in the structured log; the response
        # carries only a sanitized category so we don't leak the
        # upstream URL / hostname to the client (CodeQL
        # py/stack-trace-exposure).
        logger.info("peeringdb_fetch_failed", path=path, error=str(exc))
        return {"available": False, "error": classify_http_error(exc)}
    except ValueError:
        logger.info("peeringdb_malformed_response", path=path)
        return {"available": False, "error": "malformed_response"}

    cache_set("peeringdb", cache_key, payload)
    return payload


async def fetch_asn_network(asn: int) -> dict[str, Any]:
    """Network record for ``AS<asn>``.

    Normalised shape::

        {
          "available": True,
          "asn": 15169,
          "name": "Google LLC",
          "aka": "GOOGLE",
          "info_type": "Content",
          "info_traffic": "100+ Tbps",
          "info_scope": "Global",
          "policy_general": "Selective",
          "irr_as_set": "AS-GOOGLE",
          "looking_glass": "https://...",
          "website": "https://...",
        }
    """
    raw = await _fetch("net", {"asn": asn}, f"net|asn={asn}")
    if isinstance(raw, dict) and not raw.get("available", True):
        return {"available": False, "asn": asn, "error": raw.get("error", "unavailable")}
    data = raw.get("data") if isinstance(raw, dict) else None
    if not data:
        return {"available": True, "asn": asn, "found": False}
    row = data[0] if isinstance(data, list) and data else None
    if not isinstance(row, dict):
        return {"available": True, "asn": asn, "found": False}
    return {
        "available": True,
        "asn": asn,
        "found": True,
        "name": row.get("name"),
        "aka": row.get("aka"),
        "info_type": row.get("info_type"),
        "info_traffic": row.get("info_traffic"),
        "info_scope": row.get("info_scope"),
        "policy_general": row.get("policy_general"),
        "policy_locations": row.get("policy_locations"),
        "irr_as_set": row.get("irr_as_set"),
        "looking_glass": _url_with_scheme(row.get("looking_glass"), _LOOKING_GLASS_SCHEMES),
        "website": _url_with_scheme(row.get("website"), _WEBSITE_SCHEMES),
    }


async def fetch_asn_ixps(asn: int) -> dict[str, Any]:
    """IXP membership rollup for ``AS<asn>``.

    Each row is one peering port at one IX. Operators with a single
    AS at multiple IXes will see N rows where N = number of ports
    they've registered. Group-by-IX is left to the renderer.

    Normalised row shape::

        {
          "ix_name": "AMS-IX",
          "city": "Amsterdam",
          "speed_mbit": 100000,
          "ipv4": "80.249.208.1",
          "ipv6": "2001:7f8:1::a500:15169:1",
          "is_rs_peer": True,
          "operational": True,
        }
    """
    raw = await _fetch("netixlan", {"asn": asn}, f"netixlan|asn={asn}")
    if isinstance(raw, dict) and not raw.get("available", True):
        return {"available": False, "asn": asn, "error": raw.get("error", "unavailable")}
    data = raw.get("data") if isinstance(raw, dict) else None
    rows: list[dict[str, Any]] = []
    if isinstance(data, list):
        for entry in data:
            if not isinstance(entry, dict):
                continue
            rows.append(
                {
                    "ix_name": entry.get("name"),
                    "city": entry.get("city"),
                    "speed_mbit": entry.get("speed"),
                    "ipv4": entry.get("ipaddr4"),
                    "ipv6": entry.get("ipaddr6"),
                    "is_rs_peer": bool(entry.get("is_rs_peer")),
                    "operational": entry.get("operational", True),
                }
            )
    return {
        "available": True,
        "asn": asn,
        "ixps": rows,
        "ixp_count": len(rows),
    }
