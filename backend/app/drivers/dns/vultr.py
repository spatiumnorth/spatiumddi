"""Vultr DNS driver (agentless, REST API — issue #29 cloud DNS family).

Vultr hosts authoritative zones ("domains") and exposes a flat REST API at
``https://api.vultr.com/v2``. SpatiumDDI manages those zones exactly like a
local BIND9 / PowerDNS zone — same Zones / Records group surfaces — driving
the API directly from the control plane rather than an agent (see
:mod:`app.drivers.dns._cloud_base` for the agentless contract).

Authentication is a single personal **API token** (``Bearer`` header). Unlike
Cloudflare, record calls are scoped by the domain **name** (not an opaque
zone id), so there is no zone-id resolution step — the FQDN's bare name is
threaded straight into the record path.

Unlike the AWS / Azure / GCP cloud drivers, Vultr needs no vendor SDK: the API
is plain JSON over HTTPS, so this driver uses ``httpx`` directly (already a
top-level dependency). ``_client`` is the single seam tests patch to inject a
fake transport.

Credential dict shape (decrypted from ``DNSServer.credentials_encrypted``)::

    {"api_token": "<personal-api-token>"}
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

# Vultr API v2 base. Pinned here (not configurable) — there is no self-hosted
# Vultr. The token in the Authorization header is the only per-server input.
_API_BASE = "https://api.vultr.com/v2"

# Vultr's per-page maximum is 500; 100 keeps responses small while still
# rarely needing a second cursor round trip for typical accounts.
_PER_PAGE = 100

# Vultr encodes "automatic / default TTL" as the sentinel value 0 on a record
# (the API auto-assigns when ttl is omitted/0). We surface that as
# ``ttl=None`` on the neutral RecordData so it round-trips as "let the provider
# decide" rather than a literal 0-second TTL, and map None back to 0 on write.
_TTL_AUTO = 0


class VultrDNSDriver(CloudDNSDriverBase):
    """Agentless driver for Vultr-hosted authoritative zones (domains)."""

    name = "vultr"
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
        """Validate a Vultr response and return its parsed body.

        Vultr has no success envelope — a 2xx status is the only signal. On a
        non-2xx the body is ``{"error": "<message>"}`` (sometimes with extra
        ``status`` keys); raise :class:`CloudDNSError` with that message.

        Success bodies for DELETE / PATCH are commonly empty (HTTP 204); a body
        that doesn't parse as a dict collapses to ``{}`` so callers that ignore
        the return value (writes) work uniformly.
        """
        status = getattr(response, "status_code", 0)
        body: dict[str, Any]
        try:
            parsed = response.json()
            body = parsed if isinstance(parsed, dict) else {}
        except (ValueError, TypeError):
            body = {}
        if 200 <= status < 300:
            return body
        detail = str(body.get("error") or "").strip() or f"HTTP {status}"
        raise CloudDNSError(f"Vultr API error: {detail}")

    def _token(self, creds: dict[str, Any]) -> str:
        token = (creds or {}).get("api_token")
        if not token:
            raise CloudDNSError("Vultr credentials missing 'api_token'.")
        return str(token)

    @staticmethod
    def _zone_label(zone_fqdn: str) -> str:
        """Return the bare domain name Vultr scopes record/zone calls by."""
        return normalize_fqdn(zone_fqdn).rstrip(".")

    @staticmethod
    def _relativize(name: str, zone_fqdn: str) -> str:
        """Return ``name`` relative to ``zone_fqdn`` (apex → ``"@"``).

        Vultr already returns record names relative to the apex (``""`` for
        apex), but it may also hand back a fully-qualified label in some
        responses, so normalise both shapes. Both sides are normalised to
        trailing-dot FQDNs first so the suffix match is exact; a name equal to
        the apex (or empty) collapses to ``"@"`` to match the BIND9 / Windows
        pull convention.
        """
        rel = (name or "").strip()
        if not rel or rel == "@":
            return "@"
        zone = normalize_fqdn(zone_fqdn)
        fqdn = normalize_fqdn(rel)
        if fqdn == zone:
            return "@"
        if fqdn.endswith("." + zone):
            return fqdn[: -(len(zone) + 1)]
        # Already a bare relative label (Vultr's normal case) — strip any
        # accidental trailing dot and return as-is.
        return rel.rstrip(".")

    @staticmethod
    def _relative_name(label: str) -> str:
        """Render the relative record name Vultr expects on writes.

        Vultr's record model stores names **relative** to the zone apex with
        the empty string for the apex (not ``"@"``). So apex → ``""`` and any
        other label is passed through de-dotted.
        """
        rel = (label or "").strip().rstrip(".")
        if not rel or rel == "@":
            return ""
        return rel

    @staticmethod
    def _srv_data(record: RecordData) -> str:
        """Compose Vultr's SRV ``data`` string from the split columns.

        Vultr's record model has a ``priority`` field of its own but no
        weight / port fields (#1526): its API docs say to omit the
        priority from ``data``, so the SRV data string is
        ``"<weight> <port> <target>"``.
        """
        weight = record.weight if record.weight is not None else 0
        port = record.port if record.port is not None else 0
        return f"{weight} {port} {record.value}"

    @staticmethod
    def _split_srv_data(data: str) -> tuple[str, int | None, int | None]:
        """Split Vultr's SRV ``data`` into ``(target, weight, port)``.

        Inverse of :meth:`_srv_data`. A value that doesn't parse is
        returned verbatim with ``None`` fields rather than failing the pull.
        """
        parts = (data or "").strip().split(None, 2)
        if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
            return parts[2].strip(), int(parts[0]), int(parts[1])
        return (data or "").strip(), None, None

    # ── Zone reads ──────────────────────────────────────────────────────
    async def _list_zones(self, server: Any, creds: dict[str, Any]) -> list[CloudDNSZone]:
        token = self._token(creds)
        zones: list[CloudDNSZone] = []
        async with self._client(token) as client:
            cursor: str | None = None
            while True:
                params: dict[str, Any] = {"per_page": _PER_PAGE}
                if cursor:
                    params["cursor"] = cursor
                resp = await client.get("/domains", params=params)
                body = self._unwrap(resp)
                for d in body.get("domains") or []:
                    name = normalize_fqdn(d["domain"])
                    is_reverse = name.endswith((".in-addr.arpa.", ".ip6.arpa."))
                    zones.append(
                        CloudDNSZone(
                            name=name,
                            # Vultr scopes by domain name, not an opaque id;
                            # store the bare name so downstream callers have a
                            # stable handle.
                            zone_id=self._zone_label(name),
                            is_reverse=is_reverse,
                            dnssec_enabled=str(d.get("dns_sec") or "").lower() == "enabled",
                            record_count=None,
                        )
                    )
                cursor = self._next_cursor(body)
                if not cursor:
                    break
        return zones

    @staticmethod
    def _next_cursor(body: dict[str, Any]) -> str | None:
        """Pull ``meta.links.next`` from a Vultr list body (empty → done)."""
        meta = body.get("meta") or {}
        links = meta.get("links") or {}
        nxt = links.get("next")
        return str(nxt) if nxt else None

    async def _list_zone_records(
        self, server: Any, creds: dict[str, Any], zone_name: str
    ) -> list[RecordData]:
        token = self._token(creds)
        zone_fqdn = normalize_fqdn(zone_name)
        label = self._zone_label(zone_fqdn)
        records: list[RecordData] = []
        async with self._client(token) as client:
            cursor: str | None = None
            while True:
                params: dict[str, Any] = {"per_page": _PER_PAGE}
                if cursor:
                    params["cursor"] = cursor
                resp = await client.get(f"/domains/{label}/records", params=params)
                body = self._unwrap(resp)
                for rec in body.get("records") or []:
                    raw_ttl = rec.get("ttl")
                    ttl = None if raw_ttl == _TTL_AUTO else raw_ttl
                    # Vultr returns priority 0 (or -1) for non-MX/SRV records;
                    # only surface it for record types that carry a priority.
                    priority = rec.get("priority")
                    if rec.get("type") not in ("MX", "SRV"):
                        priority = None
                    value = rec["data"]
                    weight: int | None = None
                    port: int | None = None
                    if rec.get("type") == "SRV":
                        # Priority is Vultr's own field; weight/port ride
                        # inside the data string (#1526).
                        value, weight, port = self._split_srv_data(value)
                    records.append(
                        RecordData(
                            name=self._relativize(rec.get("name", ""), zone_fqdn),
                            record_type=rec["type"],
                            value=value,
                            ttl=ttl,
                            priority=priority,
                            weight=weight,
                            port=port,
                        )
                    )
                cursor = self._next_cursor(body)
                if not cursor:
                    break
        return records

    # ── Record writes ───────────────────────────────────────────────────
    def _record_payload(self, change: RecordChange) -> dict[str, Any]:
        rec = change.record
        payload: dict[str, Any] = {
            "name": self._relative_name(rec.name),
            "type": rec.record_type,
            # SRV: weight/port have no Vultr fields — they ride in data
            # (priority stays in its own field, omitted from data) (#1526).
            "data": self._srv_data(rec) if rec.record_type.upper() == "SRV" else rec.value,
            # Vultr's "automatic" TTL is the sentinel 0.
            "ttl": _TTL_AUTO if rec.ttl is None else rec.ttl,
        }
        if rec.priority is not None:
            payload["priority"] = rec.priority
        return payload

    async def _find_record_id(
        self,
        client: httpx.AsyncClient,
        label: str,
        name: str,
        record_type: str,
        content: str,
        priority: int | None = None,
    ) -> str | None:
        """Return the Vultr record id matching name+type+value, or ``None``.

        SpatiumDDI keys DNS records per value and supports round-robin (multiple
        A/AAAA at one hostname) and multiple MX/NS/TXT. So we must match the
        *specific* value being changed — matching on name+type alone returns the
        first row of a multi-value RRset and would update/delete the wrong value
        (issue #331).

        Vultr's ``GET /domains/{domain}/records`` has no server-side content
        filter, so we page the whole record set and match client-side on
        name+type+data (and ``priority`` too for MX/SRV).
        """
        cursor: str | None = None
        while True:
            params: dict[str, Any] = {"per_page": _PER_PAGE}
            if cursor:
                params["cursor"] = cursor
            resp = await client.get(f"/domains/{label}/records", params=params)
            body = self._unwrap(resp)
            for rec in body.get("records") or []:
                if rec.get("type") != record_type:
                    continue
                if (rec.get("name") or "") != name:
                    continue
                if rec.get("data") != content:
                    continue
                if priority is not None and rec.get("priority") != priority:
                    continue
                return str(rec["id"])
            cursor = self._next_cursor(body)
            if not cursor:
                break
        return None

    async def _apply_record(self, server: Any, creds: dict[str, Any], change: RecordChange) -> None:
        token = self._token(creds)
        zone_fqdn = normalize_fqdn(change.zone_name)
        label = self._zone_label(zone_fqdn)
        payload = self._record_payload(change)
        async with self._client(token) as client:
            if change.op == "create":
                resp = await client.post(f"/domains/{label}/records", json=payload)
                self._unwrap(resp)
                return

            if change.op == "update":
                rid = await self._find_record_id(
                    client,
                    label,
                    payload["name"],
                    change.record.record_type,
                    payload["data"],
                    priority=change.record.priority,
                )
                if rid is None:
                    # No existing row to update — treat as create so the desired
                    # state still lands (mirrors the windows_dns + _cloud_base
                    # "update is create on miss" contract).
                    resp = await client.post(f"/domains/{label}/records", json=payload)
                    self._unwrap(resp)
                    return
                # Vultr updates records via PATCH (not PUT). It accepts a partial
                # body; send the full payload so name/data/ttl/priority all land.
                resp = await client.patch(f"/domains/{label}/records/{rid}", json=payload)
                self._unwrap(resp)
                return

            if change.op == "delete":
                rid = await self._find_record_id(
                    client,
                    label,
                    payload["name"],
                    change.record.record_type,
                    payload["data"],
                    priority=change.record.priority,
                )
                if rid is None:
                    # Idempotent delete — nothing to remove.
                    return
                resp = await client.delete(f"/domains/{label}/records/{rid}")
                self._unwrap(resp)
                return

            raise CloudDNSError(f"Vultr: unsupported record op {change.op!r}")

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
        label = self._zone_label(getattr(zone, "name", ""))
        async with self._client(token) as client:
            if op == "create":
                # Omit "ip" so Vultr creates an empty zone (no seeded A record);
                # SpatiumDDI then pushes records explicitly. DNSSEC defaults off.
                payload = {"domain": label, "dns_sec": "disabled"}
                resp = await client.post("/domains", json=payload)
                self._unwrap(resp)
                return

            if op == "delete":
                resp = await client.delete(f"/domains/{label}")
                self._unwrap(resp)
                return

            raise CloudDNSError(f"Vultr: unsupported zone op {op!r}")

    # ── Capabilities ────────────────────────────────────────────────────
    def capabilities(self) -> dict[str, Any]:
        return {
            "name": "vultr",
            "agentless": True,
            "manages_zones": True,
            "views": False,
            "rpz": False,
            # Vultr exposes pre-generated DNSSEC keys for upload to the
            # registrar but offers no online sign/unsign API, so SpatiumDDI
            # cannot drive DNSSEC signing here.
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
                "Agentless Vultr DNS driver over the v2 REST API "
                "(Bearer API token). Zones ('domains') + records managed "
                "from the control plane; record calls are scoped by domain "
                "name (no opaque zone id). Record updates use PATCH; "
                "DNSSEC keys are export-only (no online signing)."
            ),
        }


__all__ = ["VultrDNSDriver"]
