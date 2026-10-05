"""Hetzner DNS driver (agentless, REST API — issue #37).

Hetzner hosts authoritative zones and exposes a flat REST API at
``https://dns.hetzner.com/api/v1``. SpatiumDDI manages those zones exactly
like a local BIND9 / PowerDNS zone — same Zones / Records group surfaces —
driving the API directly from the control plane rather than an agent (see
:mod:`app.drivers.dns._cloud_base` for the agentless contract).

Authentication is a single account-scoped **API token** carried in the
``Auth-API-Token`` header (note: *not* a ``Bearer`` Authorization header —
this is Hetzner-specific). Records are scoped by an opaque ``zone_id`` so
``_resolve_zone_id`` looks the id up by name (``GET /zones?name=``) and the
methods cache nothing — each call is cheap and idempotent.

Like Cloudflare, Hetzner needs no vendor SDK: the API is plain JSON over
HTTPS, so this driver uses ``httpx`` directly (already a top-level
dependency). ``_client`` is the single seam tests patch to inject a fake
transport.

Credential dict shape (decrypted from ``DNSServer.credentials_encrypted``)::

    {"api_token": "<account-api-token>"}

TTL: Hetzner has no numeric "automatic" sentinel — a record with no ``ttl``
falls back to the zone default, and the API simply omits the field. So this
driver maps an *absent* ``ttl`` on read to ``ttl=None`` and, on write, omits
the ``ttl`` key entirely when ``RecordData.ttl`` is ``None`` (mirroring
Cloudflare's ``_TTL_AUTO`` round-trip, just keyed on presence not a value).
"""

from __future__ import annotations

from typing import Any

import httpx

from app.drivers.dns._cloud_base import (
    CloudDNSDriverBase,
    CloudDNSError,
    CloudDNSZone,
    normalize_fqdn,
)
from app.drivers.dns.base import RecordChange, RecordData

# Hetzner DNS API v1 base. Pinned here (not configurable) — there is no
# self-hosted Hetzner DNS. The token in the Auth-API-Token header is the
# only per-server input.
_API_BASE = "https://dns.hetzner.com/api/v1"

# Hetzner's per-page maximum is 100; 50 keeps responses small while still
# rarely needing a second round trip for typical accounts.
_PER_PAGE = 50


class HetznerDNSDriver(CloudDNSDriverBase):
    """Agentless driver for Hetzner-hosted authoritative zones."""

    name = "hetzner"
    # The Add-DNS-server modal renders + the probe requires only the token.
    credential_fields: tuple[str, ...] = ("api_token",)

    # ── HTTP plumbing ───────────────────────────────────────────────────
    def _client(self, token: str) -> httpx.AsyncClient:
        """Return an httpx client bound to the API base + auth token header.

        This is the single seam tests patch to inject a fake transport —
        keep all request construction flowing through the returned client.
        Hetzner authenticates with a bare ``Auth-API-Token`` header, *not*
        an ``Authorization: Bearer`` header.
        """
        return httpx.AsyncClient(
            base_url=_API_BASE,
            headers={
                "Auth-API-Token": token,
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )

    @staticmethod
    def _unwrap(response: Any) -> dict[str, Any]:
        """Validate a Hetzner response and return its parsed body.

        Hetzner returns the bare resource envelope on success
        (``{"zones": [...], "meta": {...}}`` / ``{"records": [...]}`` /
        ``{"record": {...}}``) and signals failure with a non-2xx status.
        The error body is either ``{"error": {"message", "code"}}`` or a
        flat ``{"message": ...}``. Raise :class:`CloudDNSError` with the
        cleanest message available on any non-2xx reply.
        """
        body: dict[str, Any]
        try:
            body = response.json()
        except (ValueError, TypeError):
            body = {}
        status = getattr(response, "status_code", 0)
        if 200 <= status < 300:
            return body if isinstance(body, dict) else {}
        detail = ""
        err = body.get("error") if isinstance(body, dict) else None
        if isinstance(err, dict):
            detail = str(err.get("message") or err.get("code") or "")
        elif isinstance(body, dict):
            detail = str(body.get("message") or "")
        if not detail:
            detail = f"HTTP {status}"
        raise CloudDNSError(f"Hetzner API error: {detail}")

    def _token(self, creds: dict[str, Any]) -> str:
        token = (creds or {}).get("api_token")
        if not token:
            raise CloudDNSError("Hetzner credentials missing 'api_token'.")
        return str(token)

    async def _resolve_zone_id(self, client: httpx.AsyncClient, zone_fqdn: str) -> str:
        """Look up the opaque Hetzner zone id for a zone FQDN.

        Hetzner's ``GET /zones?name=`` filter wants the bare name with no
        trailing dot, so the apex FQDN is de-dotted before the query.
        """
        name = normalize_fqdn(zone_fqdn).rstrip(".")
        resp = await client.get("/zones", params={"name": name})
        body = self._unwrap(resp)
        zones = body.get("zones") or []
        if not zones:
            raise CloudDNSError(f"Hetzner zone {name!r} not found on this account.")
        return str(zones[0]["id"])

    @staticmethod
    def _relativize(record_name: str, zone_fqdn: str) -> str:
        """Return ``record_name`` relative to ``zone_fqdn`` (apex → ``"@"``).

        Hetzner already returns names relative to the zone apex (apex as
        ``"@"``, sub-labels as the bare left-hand label). This still
        normalises the input — collapsing an absolute FQDN or an empty /
        ``"@"`` name to ``"@"`` at the apex — so the pull is robust if
        Hetzner ever returns an absolute name.
        """
        raw = (record_name or "").strip()
        if not raw or raw == "@":
            return "@"
        # Already-relative label (Hetzner's normal case): no trailing dot,
        # not the zone itself → return verbatim.
        zone = normalize_fqdn(zone_fqdn)
        candidate = normalize_fqdn(raw)
        if candidate == zone:
            return "@"
        if candidate.endswith("." + zone):
            return candidate[: -(len(zone) + 1)]
        # A bare relative label that isn't an FQDN under the zone — return
        # it stripped of any stray trailing dot.
        return raw.rstrip(".")

    # ── Zone reads ──────────────────────────────────────────────────────
    async def _list_zones(self, server: Any, creds: dict[str, Any]) -> list[CloudDNSZone]:
        token = self._token(creds)
        zones: list[CloudDNSZone] = []
        async with self._client(token) as client:
            page = 1
            while True:
                resp = await client.get("/zones", params={"per_page": _PER_PAGE, "page": page})
                body = self._unwrap(resp)
                for z in body.get("zones") or []:
                    name = normalize_fqdn(z["name"])
                    is_reverse = name.endswith((".in-addr.arpa.", ".ip6.arpa."))
                    zones.append(
                        CloudDNSZone(
                            name=name,
                            zone_id=str(z["id"]),
                            is_reverse=is_reverse,
                            # Hetzner has no online DNSSEC signing — leave
                            # False; capability advertising is the source of
                            # truth for signing support.
                            dnssec_enabled=False,
                            record_count=None,
                        )
                    )
                pagination = (body.get("meta") or {}).get("pagination") or {}
                last_page = int(pagination.get("last_page") or 1)
                if page >= last_page:
                    break
                page += 1
        return zones

    async def _list_zone_records(
        self, server: Any, creds: dict[str, Any], zone_name: str
    ) -> list[RecordData]:
        token = self._token(creds)
        zone_fqdn = normalize_fqdn(zone_name)
        records: list[RecordData] = []
        async with self._client(token) as client:
            zone_id = await self._resolve_zone_id(client, zone_fqdn)
            page = 1
            while True:
                resp = await client.get(
                    "/records",
                    params={"zone_id": zone_id, "per_page": _PER_PAGE, "page": page},
                )
                body = self._unwrap(resp)
                for rec in body.get("records") or []:
                    # Absent ttl → zone default → surface as None.
                    raw_ttl = rec.get("ttl")
                    records.append(
                        RecordData(
                            name=self._relativize(rec["name"], zone_fqdn),
                            record_type=rec["type"],
                            value=rec["value"],
                            ttl=raw_ttl,
                            priority=rec.get("priority"),
                        )
                    )
                pagination = (body.get("meta") or {}).get("pagination") or {}
                last_page = int(pagination.get("last_page") or 1)
                if page >= last_page:
                    break
                page += 1
        return records

    # ── Record writes ───────────────────────────────────────────────────
    @staticmethod
    def _absolute_name(label: str, zone_fqdn: str) -> str:
        """Render the relative record name Hetzner expects.

        Hetzner stores names relative to the zone apex: apex is ``"@"`` and
        sub-records are the bare left-hand label (``"www"``, ``"a.b"``). So
        this collapses apex / empty to ``"@"`` and strips the zone suffix
        from an absolute FQDN, leaving the relative label.
        """
        zone = normalize_fqdn(zone_fqdn)
        rel = (label or "").strip()
        if not rel or rel == "@":
            return "@"
        candidate = normalize_fqdn(rel)
        if candidate == zone:
            return "@"
        if candidate.endswith("." + zone):
            return candidate[: -(len(zone) + 1)]
        # Already a bare relative label — return it without a trailing dot.
        return rel.rstrip(".")

    def _record_payload(self, change: RecordChange, zone_id: str, zone_fqdn: str) -> dict[str, Any]:
        rec = change.record
        payload: dict[str, Any] = {
            "zone_id": zone_id,
            "type": rec.record_type,
            "name": self._absolute_name(rec.name, zone_fqdn),
            "value": rec.value,
        }
        # Hetzner has no numeric "automatic" sentinel: omit ttl entirely to
        # inherit the zone default; only send it when an explicit TTL is set.
        if rec.ttl is not None:
            payload["ttl"] = rec.ttl
        return payload

    async def _find_record_id(
        self,
        client: httpx.AsyncClient,
        zone_id: str,
        name: str,
        record_type: str,
        value: str | None = None,
        priority: int | None = None,
    ) -> str | None:
        """Return the Hetzner record id matching name+type+value, or ``None``.

        SpatiumDDI keys DNS records per value and supports round-robin
        (multiple A/AAAA at one hostname) and multiple MX/NS/TXT. So when
        ``value`` is given we must match the *specific* value being changed —
        matching on name+type alone returns the first row of a multi-value
        RRset and would update/delete the wrong value (issue #331).

        Hetzner has no server-side ``value`` filter on ``GET /records``, so
        we page the whole zone's record set and match client-side
        (``priority`` too for MX/SRV). Pagination is required — without it a
        zone with more than ``_PER_PAGE`` records could miss the target row
        and wrongly fall back to create-on-miss (update) or no-op (delete).
        """
        all_records: list[dict[str, Any]] = []
        page = 1
        while True:
            resp = await client.get(
                "/records",
                params={"zone_id": zone_id, "per_page": _PER_PAGE, "page": page},
            )
            body = self._unwrap(resp)
            all_records.extend(body.get("records") or [])
            pagination = (body.get("meta") or {}).get("pagination") or {}
            if page >= int(pagination.get("last_page") or 1):
                break
            page += 1
        # ``name`` here is already the relative label the payload uses (apex
        # as "@"), which is exactly how Hetzner stores it — compare directly.
        results = [r for r in all_records if r.get("name") == name and r.get("type") == record_type]
        if not results:
            return None
        # Name+type-only lookup (value unknown): keep legacy first-match.
        if value is None:
            return str(results[0]["id"])
        # Value-keyed lookup: pick the row whose value (and priority for
        # MX/SRV) actually matches.
        for rec in results:
            if rec.get("value") != value:
                continue
            if priority is not None and rec.get("priority") != priority:
                continue
            return str(rec["id"])
        return None

    async def _apply_record(self, server: Any, creds: dict[str, Any], change: RecordChange) -> None:
        token = self._token(creds)
        zone_fqdn = normalize_fqdn(change.zone_name)
        async with self._client(token) as client:
            zone_id = await self._resolve_zone_id(client, zone_fqdn)
            payload = self._record_payload(change, zone_id, zone_fqdn)

            if change.op == "create":
                resp = await client.post("/records", json=payload)
                self._unwrap(resp)
                return

            if change.op == "update":
                rid = await self._find_record_id(
                    client,
                    zone_id,
                    payload["name"],
                    change.record.record_type,
                    value=change.record.value,
                    priority=change.record.priority,
                )
                if rid is None:
                    # No existing row to update — treat as create so the
                    # desired state still lands (mirrors the windows_dns +
                    # _cloud_base "update is create on miss" contract).
                    resp = await client.post("/records", json=payload)
                    self._unwrap(resp)
                    return
                resp = await client.put(f"/records/{rid}", json=payload)
                self._unwrap(resp)
                return

            if change.op == "delete":
                rid = await self._find_record_id(
                    client,
                    zone_id,
                    payload["name"],
                    change.record.record_type,
                    value=change.record.value,
                    priority=change.record.priority,
                )
                if rid is None:
                    # Idempotent delete — nothing to remove.
                    return
                resp = await client.delete(f"/records/{rid}")
                self._unwrap(resp)
                return

            raise CloudDNSError(f"Hetzner: unsupported record op {change.op!r}")

    # ── Zone writes ─────────────────────────────────────────────────────
    async def _apply_zone(
        self,
        server: Any,
        creds: dict[str, Any],
        zone: Any,
        op: str,
        *,
        managed_records: list[RecordData] | None = None,
    ) -> None:
        token = self._token(creds)
        zone_fqdn = normalize_fqdn(getattr(zone, "name", ""))
        bare = zone_fqdn.rstrip(".")
        async with self._client(token) as client:
            if op == "create":
                resp = await client.post("/zones", json={"name": bare})
                self._unwrap(resp)
                return

            if op == "delete":
                zone_id = await self._resolve_zone_id(client, zone_fqdn)
                resp = await client.delete(f"/zones/{zone_id}")
                self._unwrap(resp)
                return

            raise CloudDNSError(f"Hetzner: unsupported zone op {op!r}")

    # ── Capabilities ────────────────────────────────────────────────────
    def capabilities(self) -> dict[str, Any]:
        return {
            "name": "hetzner",
            "agentless": True,
            "manages_zones": True,
            "views": False,
            "rpz": False,
            # Hetzner DNS Console has no online DNSSEC signing via the API.
            "dnssec_online": False,
            "record_types": [
                "A",
                "AAAA",
                "CNAME",
                "MX",
                "TXT",
                "NS",
                "SRV",
                "CAA",
                "PTR",
                "SOA",
            ],
            "notes": (
                "Agentless Hetzner DNS driver over the v1 REST API "
                "(Auth-API-Token header, not Bearer). Zones + records "
                "managed from the control plane. No online DNSSEC signing "
                "via the API; the SOA record is read-only on Hetzner. "
                "Records with no explicit TTL inherit the zone default."
            ),
        }


__all__ = ["HetznerDNSDriver"]
