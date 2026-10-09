"""DigitalOcean DNS driver (agentless, REST API — issue #37).

DigitalOcean hosts authoritative zones ("domains") and exposes a flat REST
API at ``https://api.digitalocean.com/v2``. SpatiumDDI manages those zones
exactly like a local BIND9 / PowerDNS zone — same Zones / Records group
surfaces — driving the API directly from the control plane rather than an
agent (see :mod:`app.drivers.dns._cloud_base` for the agentless contract).

Authentication is a single Personal Access / OAuth **API token** sent as a
``Bearer`` header. Unlike Cloudflare, DigitalOcean scopes records by the bare
**domain name** (``/v2/domains/{name}/records``) rather than an opaque zone
id, so there is no zone-id resolution step — the zone FQDN (de-dotted) is the
handle. The integer ``id`` returned per record is still needed to scope
update / delete calls.

Like the other token-only cloud drivers, DigitalOcean needs no vendor SDK:
the API is plain JSON over HTTPS, so this driver uses ``httpx`` directly
(already a top-level dependency). ``_client`` is the single seam tests patch
to inject a fake transport.

Credential dict shape (decrypted from ``DNSServer.credentials_encrypted``)::

    {"api_token": "<personal-access-token>"}
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

# DigitalOcean API v2 base. Pinned here (not configurable) — there is no
# self-hosted DigitalOcean. The token in the Authorization header is the
# only per-server input.
_API_BASE = "https://api.digitalocean.com/v2"

# DigitalOcean's per-page maximum is 200; 50 keeps responses small while
# still rarely needing a second round trip for typical accounts.
_PER_PAGE = 50

# DigitalOcean stamps records with no explicit TTL at 1800s (the account
# default). We surface that as ``ttl=None`` on the neutral RecordData so it
# round-trips as "let the provider decide" rather than a literal value, and
# omit ``ttl`` from writes when None so the API applies its default.
_TTL_DEFAULT = 1800


class DigitalOceanDNSDriver(CloudDNSDriverBase):
    """Agentless driver for DigitalOcean-hosted authoritative zones."""

    name = "digitalocean"
    # The Add-DNS-server modal renders + the probe requires only the token.
    credential_fields: tuple[str, ...] = ("api_token",)

    # ── HTTP plumbing ───────────────────────────────────────────────────
    def _client(self, token: str) -> httpx.AsyncClient:
        """Return an httpx client bound to the API base + bearer token.

        This is the single seam tests patch to inject a fake transport —
        keep all request construction flowing through the returned client.
        """
        return httpx.AsyncClient(
            base_url=_API_BASE,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )

    @staticmethod
    def _unwrap(response: Any) -> dict[str, Any]:
        """Validate a DigitalOcean response and return its parsed body.

        DigitalOcean has no success-envelope: a 2xx status *is* the success
        signal (DELETE returns 204 with an empty body). Failures come back
        non-2xx with ``{"id": "...", "message": "...", "request_id": "..."}``.
        Raise :class:`CloudDNSError` carrying that ``message`` on any non-2xx.
        """
        body: dict[str, Any]
        try:
            parsed = response.json()
            body = parsed if isinstance(parsed, dict) else {}
        except (ValueError, TypeError):
            body = {}
        status = getattr(response, "status_code", 0)
        if 200 <= status < 300:
            return body
        detail = str(body.get("message") or "") or f"HTTP {status}"
        raise CloudDNSError(f"DigitalOcean API error: {detail}")

    def _token(self, creds: dict[str, Any]) -> str:
        token = (creds or {}).get("api_token")
        if not token:
            raise CloudDNSError("DigitalOcean credentials missing 'api_token'.")
        return str(token)

    @staticmethod
    def _zone_handle(zone_fqdn: str) -> str:
        """DigitalOcean scopes records by the bare domain name (no trailing dot)."""
        return normalize_fqdn(zone_fqdn).rstrip(".")

    @staticmethod
    def _relativize(name: str, zone_fqdn: str) -> str:
        """Return the record name relative to ``zone_fqdn`` (apex → ``"@"``).

        DigitalOcean already stores names relative to the apex (and emits
        ``"@"`` for apex), but a record list can surface fully-qualified
        names in some edge cases, so we normalise defensively the same way
        the Cloudflare driver does. A name equal to the apex collapses to
        ``"@"`` to match the BIND9 / Windows pull convention.
        """
        raw = (name or "").strip()
        if not raw or raw == "@":
            return "@"
        candidate = normalize_fqdn(raw)
        zone = normalize_fqdn(zone_fqdn)
        if candidate == zone:
            return "@"
        if candidate.endswith("." + zone):
            return candidate[: -(len(zone) + 1)]
        # Already a relative label DigitalOcean handed back verbatim.
        return raw.rstrip(".")

    @staticmethod
    def _write_name(label: str) -> str:
        """Render the record name DigitalOcean expects on a write.

        DigitalOcean takes **relative** names with ``"@"`` for the apex, so
        an empty / ``"@"`` label stays ``"@"`` and any other label is sent as
        the bare relative form (trailing dot stripped).
        """
        rel = (label or "").strip().rstrip(".")
        if not rel or rel == "@":
            return "@"
        return rel

    # ── Zone reads ──────────────────────────────────────────────────────
    async def _list_zones(self, server: Any, creds: dict[str, Any]) -> list[CloudDNSZone]:
        token = self._token(creds)
        zones: list[CloudDNSZone] = []
        async with self._client(token) as client:
            page = 1
            while True:
                resp = await client.get("/domains", params={"per_page": _PER_PAGE, "page": page})
                body = self._unwrap(resp)
                for z in body.get("domains") or []:
                    name = normalize_fqdn(z["name"])
                    is_reverse = name.endswith((".in-addr.arpa.", ".ip6.arpa."))
                    zones.append(
                        CloudDNSZone(
                            name=name,
                            # DigitalOcean has no opaque zone id — record
                            # calls are scoped by the bare domain name. Store
                            # it so the neutral shape still carries a handle.
                            zone_id=name.rstrip("."),
                            is_reverse=is_reverse,
                            # DigitalOcean exposes no online DNSSEC state via
                            # the API; capability advertising is the source of
                            # truth (dnssec_online is False).
                            dnssec_enabled=False,
                            record_count=None,
                        )
                    )
                if not self._has_next_page(body):
                    break
                page += 1
        return zones

    @staticmethod
    def _has_next_page(body: dict[str, Any]) -> bool:
        """True when the response advertises a ``links.pages.next`` URL."""
        pages = ((body.get("links") or {}).get("pages")) or {}
        return bool(pages.get("next"))

    async def _list_zone_records(
        self, server: Any, creds: dict[str, Any], zone_name: str
    ) -> list[RecordData]:
        token = self._token(creds)
        zone_fqdn = normalize_fqdn(zone_name)
        handle = self._zone_handle(zone_fqdn)
        records: list[RecordData] = []
        async with self._client(token) as client:
            page = 1
            while True:
                resp = await client.get(
                    f"/domains/{handle}/records",
                    params={"per_page": _PER_PAGE, "page": page},
                )
                body = self._unwrap(resp)
                for rec in body.get("domain_records") or []:
                    raw_ttl = rec.get("ttl")
                    ttl = None if raw_ttl == _TTL_DEFAULT else raw_ttl
                    records.append(
                        RecordData(
                            name=self._relativize(rec.get("name", "@"), zone_fqdn),
                            record_type=rec["type"],
                            value=rec.get("data", ""),
                            ttl=ttl,
                            priority=rec.get("priority"),
                            weight=rec.get("weight"),
                            port=rec.get("port"),
                        )
                    )
                if not self._has_next_page(body):
                    break
                page += 1
        return records

    # ── Record writes ───────────────────────────────────────────────────
    def _record_payload(self, change: RecordChange) -> dict[str, Any]:
        rec = change.record
        payload: dict[str, Any] = {
            "type": rec.record_type,
            "name": self._write_name(rec.name),
            "data": rec.value,
        }
        # Omit ttl when None so DigitalOcean applies its account default
        # (1800s), mirroring the auto-TTL round-trip on the read path.
        if rec.ttl is not None:
            payload["ttl"] = rec.ttl
        if rec.priority is not None:
            payload["priority"] = rec.priority
        if rec.port is not None:
            payload["port"] = rec.port
        if rec.weight is not None:
            payload["weight"] = rec.weight
        return payload

    async def _find_record_id(
        self,
        client: httpx.AsyncClient,
        handle: str,
        zone_fqdn: str,
        name: str,
        record_type: str,
        value: str | None = None,
        priority: int | None = None,
    ) -> int | None:
        """Return the DigitalOcean record id matching name+type+value, or ``None``.

        SpatiumDDI keys DNS records per value and supports round-robin (multiple
        A/AAAA at one hostname) and multiple MX/NS/TXT. So when ``value`` is
        given we must match the *specific* value being changed — matching on
        name+type alone returns the first row of a multi-value RRset and would
        update/delete the wrong value (issue #331).

        DigitalOcean's record list has no server-side ``data`` filter, so we
        page through the records and match the relative name + type +
        ``data`` (and ``priority`` for MX/SRV) entirely client-side.
        """
        target_name = self._write_name(name)
        page = 1
        first_match: int | None = None
        while True:
            resp = await client.get(
                f"/domains/{handle}/records",
                params={"per_page": _PER_PAGE, "page": page},
            )
            body = self._unwrap(resp)
            for rec in body.get("domain_records") or []:
                if rec.get("type") != record_type:
                    continue
                if self._relativize(rec.get("name", "@"), zone_fqdn) != self._relativize(
                    target_name, zone_fqdn
                ):
                    continue
                # Name+type-only lookup (value unknown): remember first match.
                if value is None:
                    if first_match is None:
                        first_match = int(rec["id"])
                    continue
                if rec.get("data") != value:
                    continue
                if priority is not None and rec.get("priority") != priority:
                    continue
                return int(rec["id"])
            if not self._has_next_page(body):
                break
            page += 1
        return first_match

    async def _apply_record(self, server: Any, creds: dict[str, Any], change: RecordChange) -> None:
        token = self._token(creds)
        zone_fqdn = normalize_fqdn(change.zone_name)
        handle = self._zone_handle(zone_fqdn)
        payload = self._record_payload(change)
        async with self._client(token) as client:
            if change.op == "create":
                resp = await client.post(f"/domains/{handle}/records", json=payload)
                self._unwrap(resp)
                return

            if change.op == "update":
                rid = await self._find_record_id(
                    client,
                    handle,
                    zone_fqdn,
                    change.record.name,
                    change.record.record_type,
                    value=change.record.value,
                    priority=change.record.priority,
                )
                if rid is None:
                    # No existing row to update — treat as create so the
                    # desired state still lands (mirrors the windows_dns +
                    # _cloud_base "update is create on miss" contract).
                    resp = await client.post(f"/domains/{handle}/records", json=payload)
                    self._unwrap(resp)
                    return
                resp = await client.put(f"/domains/{handle}/records/{rid}", json=payload)
                self._unwrap(resp)
                return

            if change.op == "delete":
                rid = await self._find_record_id(
                    client,
                    handle,
                    zone_fqdn,
                    change.record.name,
                    change.record.record_type,
                    value=change.record.value,
                    priority=change.record.priority,
                )
                if rid is None:
                    # Idempotent delete — nothing to remove.
                    return
                resp = await client.delete(f"/domains/{handle}/records/{rid}")
                self._unwrap(resp)
                return

            raise CloudDNSError(f"DigitalOcean: unsupported record op {change.op!r}")

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
                resp = await client.post("/domains", json={"name": bare})
                self._unwrap(resp)
                return

            if op == "delete":
                resp = await client.delete(f"/domains/{bare}")
                self._unwrap(resp)
                return

            raise CloudDNSError(f"DigitalOcean: unsupported zone op {op!r}")

    # ── Capabilities ────────────────────────────────────────────────────
    def capabilities(self) -> dict[str, Any]:
        return {
            "name": "digitalocean",
            "agentless": True,
            "manages_zones": True,
            "views": False,
            "rpz": False,
            # DigitalOcean does not expose online DNSSEC signing via the API.
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
                "Agentless DigitalOcean DNS driver over the v2 REST API "
                "(Bearer API token). Zones ('domains') + records managed from "
                "the control plane; records are scoped by domain name (no "
                "opaque zone id). Online DNSSEC is not exposed via the API."
            ),
        }


__all__ = ["DigitalOceanDNSDriver"]
