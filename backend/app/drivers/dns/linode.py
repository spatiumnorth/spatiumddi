"""Linode DNS Manager driver (agentless, REST API — issue #29 / #37 Part B).

Linode (Akamai) hosts authoritative zones — "Domains" in their parlance —
and exposes a flat REST API at ``https://api.linode.com/v4``. SpatiumDDI
manages those zones exactly like a local BIND9 / PowerDNS zone — same
Zones / Records group surfaces — driving the API directly from the
control plane rather than an agent (see :mod:`app.drivers.dns._cloud_base`
for the agentless contract).

Authentication is a single Personal Access Token (``Bearer`` header). A
zone's numeric domain id is required to scope every record call, so
``_resolve_domain_id`` looks it up by name (via the ``X-Filter`` header)
and the methods cache nothing — each call is cheap and idempotent.

Like the Cloudflare driver, Linode needs no vendor SDK: the API is plain
JSON over HTTPS, so this driver uses ``httpx`` directly (already a
top-level dependency). ``_client`` is the single seam tests patch to
inject a fake transport.

Key shape differences from Cloudflare:

* No ``{"success": bool}`` envelope — Linode signals failure purely with a
  non-2xx status and a ``{"errors": [{"reason", "field?"}]}`` body. The
  ``_unwrap`` helper joins ``errors[].reason``.
* No server-side ``content`` filter on records, so the multi-value RRset
  disambiguation (issue #331) lists every record of the matching
  name+type and matches the desired ``target`` (and ``priority`` for
  MX/SRV) client-side.
* Record names are stored **relative** to the zone apex with the apex as
  the empty string ``""`` (Cloudflare uses the absolute name). We map the
  empty/``"@"`` apex form on both read and write.
* ``ttl_sec == 0`` means "use the zone default TTL" — surfaced as
  ``ttl=None`` on the neutral RecordData and written back as ``0``.

Credential dict shape (decrypted from ``DNSServer.credentials_encrypted``)::

    {"api_token": "<personal-access-token>"}
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from app.drivers.dns._cloud_base import (
    CloudDNSDriverBase,
    CloudDNSError,
    CloudDNSZone,
    normalize_fqdn,
)
from app.drivers.dns.base import RecordChange, RecordData

# Linode API v4 base. Pinned here (not configurable) — there is no
# self-hosted Linode. The token in the Authorization header is the only
# per-server input.
_API_BASE = "https://api.linode.com/v4"

# Linode's per-page maximum is 500; 100 (the API default) keeps responses
# small while still rarely needing a second round trip for typical zones.
_PER_PAGE = 100

# Linode encodes "use the zone default TTL" as ttl_sec == 0. We surface
# that as ``ttl=None`` on the neutral RecordData so it round-trips as
# "let the provider decide" rather than a literal 0-second TTL.
_TTL_DEFAULT = 0

# Record types carried as the neutral RecordData.priority that Linode also
# disambiguates by priority within a name+type set (MX preference, SRV
# priority). Used to decide whether priority participates in RRset matching.
_PRIORITY_TYPES = frozenset({"MX", "SRV"})


class LinodeDNSDriver(CloudDNSDriverBase):
    """Agentless driver for Linode-hosted (DNS Manager) authoritative zones."""

    name = "linode"
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
        """Validate a Linode response and return its parsed body.

        Linode has no ``success`` envelope — it signals failure with a
        non-2xx status and a body shaped ``{"errors": [{"reason", "field"}]}``.
        Raise :class:`CloudDNSError` with the joined ``errors[].reason`` on
        any non-2xx status.
        """
        body: dict[str, Any]
        try:
            body = response.json()
        except (ValueError, TypeError):
            body = {}
        status = getattr(response, "status_code", 0)
        if 200 <= status < 300:
            return body
        errors = body.get("errors") or []
        messages = []
        for e in errors:
            if not e:
                continue
            reason = e.get("reason") if isinstance(e, dict) else None
            field = e.get("field") if isinstance(e, dict) else None
            if reason and field:
                messages.append(f"{field}: {reason}")
            elif reason:
                messages.append(str(reason))
            else:
                messages.append(str(e))
        detail = "; ".join(m for m in messages if m) or f"HTTP {status}"
        raise CloudDNSError(f"Linode API error: {detail}")

    def _token(self, creds: dict[str, Any]) -> str:
        token = (creds or {}).get("api_token")
        if not token:
            raise CloudDNSError("Linode credentials missing 'api_token'.")
        return str(token)

    async def _resolve_domain_id(self, client: httpx.AsyncClient, zone_fqdn: str) -> int:
        """Look up the numeric Linode domain id for a zone FQDN.

        Linode's list endpoint accepts an ``X-Filter`` header (JSON) to
        narrow server-side; the apex FQDN is de-dotted for the match.
        """
        name = normalize_fqdn(zone_fqdn).rstrip(".")
        resp = await client.get(
            "/domains",
            headers={"X-Filter": json.dumps({"domain": name})},
        )
        body = self._unwrap(resp)
        results = body.get("data") or []
        for d in results:
            if str(d.get("domain", "")).lower().rstrip(".") == name:
                return int(d["id"])
        raise CloudDNSError(f"Linode domain {name!r} not found on this account.")

    @staticmethod
    def _relativize(label: str, zone_fqdn: str) -> str:
        """Return a Linode record ``name`` relative to the apex (apex → ``"@"``).

        Linode already stores names relative to the zone (apex is the empty
        string), so this collapses the apex sentinel to ``"@"`` to match the
        BIND9 / Windows pull convention and otherwise hands the label back
        with any stray trailing dot trimmed.
        """
        rel = (label or "").strip().rstrip(".")
        if not rel or rel == "@":
            return "@"
        # Defensive: if the provider ever returned an absolute name, strip
        # the zone suffix so the stored value stays relative.
        zone = normalize_fqdn(zone_fqdn).rstrip(".")
        if zone and rel.lower().endswith("." + zone):
            return rel[: -(len(zone) + 1)]
        if zone and rel.lower() == zone:
            return "@"
        return rel

    @staticmethod
    def _relative_name(label: str, zone_fqdn: str) -> str:
        """Render the relative record ``name`` Linode expects on writes.

        Linode uses the **empty string** for the apex and a bare relative
        label for sub-names. An absolute label under the zone is reduced to
        its relative form; the apex (``"@"`` / empty) → ``""``.
        """
        rel = (label or "").strip().rstrip(".")
        if not rel or rel == "@":
            return ""
        zone = normalize_fqdn(zone_fqdn).rstrip(".")
        if zone and rel.lower().endswith("." + zone):
            return rel[: -(len(zone) + 1)]
        if zone and rel.lower() == zone:
            return ""
        return rel

    # ── Zone reads ──────────────────────────────────────────────────────
    async def _list_zones(self, server: Any, creds: dict[str, Any]) -> list[CloudDNSZone]:
        token = self._token(creds)
        zones: list[CloudDNSZone] = []
        async with self._client(token) as client:
            page = 1
            while True:
                resp = await client.get("/domains", params={"page_size": _PER_PAGE, "page": page})
                body = self._unwrap(resp)
                for d in body.get("data") or []:
                    name = normalize_fqdn(d["domain"])
                    is_reverse = name.endswith((".in-addr.arpa.", ".ip6.arpa."))
                    zones.append(
                        CloudDNSZone(
                            name=name,
                            zone_id=str(d["id"]),
                            is_reverse=is_reverse,
                            # Linode online-DNSSEC signing is not offered;
                            # capabilities() advertises dnssec_online=False.
                            dnssec_enabled=False,
                            record_count=None,
                        )
                    )
                total_pages = int(body.get("pages") or 1)
                if page >= total_pages:
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
            domain_id = await self._resolve_domain_id(client, zone_fqdn)
            page = 1
            while True:
                resp = await client.get(
                    f"/domains/{domain_id}/records",
                    params={"page_size": _PER_PAGE, "page": page},
                )
                body = self._unwrap(resp)
                for rec in body.get("data") or []:
                    raw_ttl = rec.get("ttl_sec")
                    ttl = None if raw_ttl in (None, _TTL_DEFAULT) else raw_ttl
                    is_srv = str(rec["type"]).upper() == "SRV"
                    records.append(
                        RecordData(
                            name=self._relativize(rec.get("name") or "", zone_fqdn),
                            record_type=rec["type"],
                            value=rec["target"],
                            ttl=ttl,
                            priority=rec.get("priority"),
                            # SRV weight/port are their own Linode fields
                            # (#1526); other types don't carry them.
                            weight=rec.get("weight") if is_srv else None,
                            port=rec.get("port") if is_srv else None,
                        )
                    )
                total_pages = int(body.get("pages") or 1)
                if page >= total_pages:
                    break
                page += 1
        return records

    # ── Record writes ───────────────────────────────────────────────────
    def _record_payload(self, change: RecordChange, zone_fqdn: str) -> dict[str, Any]:
        rec = change.record
        payload: dict[str, Any] = {
            "type": rec.record_type,
            "name": self._relative_name(rec.name, zone_fqdn),
            "target": rec.value,
            # Linode's "use the zone default TTL" is the sentinel 0.
            "ttl_sec": _TTL_DEFAULT if rec.ttl is None else rec.ttl,
        }
        if rec.priority is not None:
            payload["priority"] = rec.priority
        if rec.record_type.upper() == "SRV":
            # Linode carries SRV weight/port as their own fields (#1526) —
            # without them the SRV write is malformed.
            if rec.weight is not None:
                payload["weight"] = rec.weight
            if rec.port is not None:
                payload["port"] = rec.port
        return payload

    async def _find_record_id(
        self,
        client: httpx.AsyncClient,
        domain_id: int,
        name: str,
        record_type: str,
        target: str | None = None,
        priority: int | None = None,
    ) -> int | None:
        """Return the Linode record id matching name+type+target, or ``None``.

        SpatiumDDI keys DNS records per value and supports round-robin
        (multiple A/AAAA at one hostname) and multiple MX/NS/TXT. So when
        ``target`` is given we must match the *specific* value being changed
        — matching on name+type alone returns the first row of a
        multi-value RRset and would update/delete the wrong value
        (issue #331).

        Linode offers no server-side ``content`` filter, so we narrow with
        ``X-Filter`` on name+type and then verify the match client-side over
        the returned list (``priority`` too for MX/SRV).
        """
        x_filter: dict[str, Any] = {"type": record_type, "name": name}
        results: list[dict[str, Any]] = []
        page = 1
        while True:
            resp = await client.get(
                f"/domains/{domain_id}/records",
                params={"page_size": _PER_PAGE, "page": page},
                headers={"X-Filter": json.dumps(x_filter)},
            )
            body = self._unwrap(resp)
            results.extend(body.get("data") or [])
            total_pages = int(body.get("pages") or 1)
            if page >= total_pages:
                break
            page += 1
        if not results:
            return None
        # Name+type-only lookup (target unknown): keep legacy first-match.
        if target is None:
            return int(results[0]["id"])
        # Value-keyed lookup: pick the row whose target (and priority for
        # MX/SRV) actually matches.
        match_priority = priority is not None and record_type in _PRIORITY_TYPES
        for rec in results:
            if rec.get("target") != target:
                continue
            if match_priority and rec.get("priority") != priority:
                continue
            return int(rec["id"])
        return None

    async def _apply_record(self, server: Any, creds: dict[str, Any], change: RecordChange) -> None:
        token = self._token(creds)
        zone_fqdn = normalize_fqdn(change.zone_name)
        payload = self._record_payload(change, zone_fqdn)
        async with self._client(token) as client:
            domain_id = await self._resolve_domain_id(client, zone_fqdn)

            if change.op == "create":
                resp = await client.post(f"/domains/{domain_id}/records", json=payload)
                self._unwrap(resp)
                return

            if change.op == "update":
                rid = await self._find_record_id(
                    client,
                    domain_id,
                    payload["name"],
                    change.record.record_type,
                    target=change.record.value,
                    priority=change.record.priority,
                )
                if rid is None:
                    # No existing row to update — treat as create so the
                    # desired state still lands (mirrors the windows_dns +
                    # _cloud_base "update is create on miss" contract).
                    resp = await client.post(f"/domains/{domain_id}/records", json=payload)
                    self._unwrap(resp)
                    return
                resp = await client.put(f"/domains/{domain_id}/records/{rid}", json=payload)
                self._unwrap(resp)
                return

            if change.op == "delete":
                rid = await self._find_record_id(
                    client,
                    domain_id,
                    payload["name"],
                    change.record.record_type,
                    target=change.record.value,
                    priority=change.record.priority,
                )
                if rid is None:
                    # Idempotent delete — nothing to remove.
                    return
                resp = await client.delete(f"/domains/{domain_id}/records/{rid}")
                self._unwrap(resp)
                return

            raise CloudDNSError(f"Linode: unsupported record op {change.op!r}")

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
                # Linode master zones REQUIRE a soa_email; derive a sane
                # placeholder when the caller has no contact to offer.
                payload: dict[str, Any] = {
                    "domain": bare,
                    "type": "master",
                    "soa_email": f"hostmaster@{bare}",
                }
                resp = await client.post("/domains", json=payload)
                self._unwrap(resp)
                return

            if op == "delete":
                domain_id = await self._resolve_domain_id(client, zone_fqdn)
                resp = await client.delete(f"/domains/{domain_id}")
                self._unwrap(resp)
                return

            raise CloudDNSError(f"Linode: unsupported zone op {op!r}")

    # ── Capabilities ────────────────────────────────────────────────────
    def capabilities(self) -> dict[str, Any]:
        return {
            "name": "linode",
            "agentless": True,
            "manages_zones": True,
            "views": False,
            "rpz": False,
            # Linode DNS Manager does not offer online DNSSEC signing.
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
                "Agentless Linode DNS Manager driver over the v4 REST API "
                "(Bearer personal access token). Zones ('Domains') + records "
                "managed from the control plane. Master zone creation derives "
                "a placeholder soa_email (hostmaster@<zone>) since Linode "
                "requires one. No online DNSSEC signing."
            ),
        }


__all__ = ["LinodeDNSDriver"]
