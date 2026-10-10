"""Hetzner DNS driver (agentless, Hetzner Cloud API — issue #37).

Hetzner moved DNS out of the standalone DNS Console and into the Hetzner
Cloud Console. The retired DNS Console API now answers every request with
a ``301`` redirect to the Cloud Console's web UI, so a driver still
pointed at it fails before it can say anything useful
("Hetzner API error: HTTP 301"). Zones are managed through the **Cloud
API** instead (``https://api.hetzner.cloud/v1``), which SpatiumDDI drives
directly from the control plane like every other agentless provider (see
:mod:`app.drivers.dns._cloud_base` for the contract).

What changed with the move, and why each matters here:

* **Auth** is a Hetzner Cloud *project* API token in an ordinary
  ``Authorization: Bearer`` header. A DNS-Console token does not work.
  The token needs **Read & Write** to apply changes; a read-only token can
  still list and import.
* **Records are RRsets.** The API addresses ``(name, type)`` sets, not
  individual records, and changes a set through actions
  (``set_records`` / ``add_records`` / ``remove_records`` / ``change_ttl``).
  That maps directly onto :class:`~app.drivers.dns.base.RRsetData` (#783),
  so an op carrying the complete desired set becomes ONE whole-set write.
* **Writes are asynchronous.** Every mutation returns an ``action`` that may
  still be ``running``; the driver waits for it to finish before reporting
  success, or a failed change would be reported as applied.
* **Values are zone-file presentation format.** ``MX`` is
  ``"10 mail.example.com."``, ``TXT`` is quoted, hostnames are absolute with
  a trailing dot. The driver quotes/unquotes ``TXT`` and absolutises
  hostname targets so a value stored without the dot is not read as
  relative to the zone.
* **Only primary-mode zones carry records.** Secondary zones are AXFR'd by
  Hetzner from the operator's own primaries, so listing their RRsets is a
  ``422 incorrect_zone_mode``; they are skipped on import.

Like Cloudflare, Hetzner needs no vendor SDK: the API is plain JSON over
HTTPS, so this driver uses ``httpx`` directly. ``_client`` is the single
seam tests patch to inject a fake transport.

Credential dict shape (decrypted from ``DNSServer.credentials_encrypted``)::

    {"api_token": "<hetzner-cloud-project-token>"}

TTL: an RRset with no explicit TTL inherits the zone default and the API
returns ``ttl: null`` — surfaced as ``ttl=None`` on read, and on write the
``ttl`` is only sent when ``RecordData.ttl`` is set.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any
from urllib.parse import quote

import httpx

from app.drivers.dns._cloud_base import (
    CloudDNSDriverBase,
    CloudDNSError,
    CloudDNSZone,
    normalize_fqdn,
)
from app.drivers.dns.base import RecordChange, RecordData

# Hetzner Cloud API base. Pinned here (not configurable) — there is no
# self-hosted Hetzner Cloud. The bearer token is the only per-server input.
_API_BASE = "https://api.hetzner.cloud/v1"

# ``GET /zones`` allows up to 50 per page, ``GET …/rrsets`` up to 100.
_ZONES_PER_PAGE = 50
_RRSETS_PER_PAGE = 100

# Writes return an ``action`` that may still be running. Bounded so a
# stuck action surfaces as an error instead of hanging the request.
_ACTION_TIMEOUT_S = 60.0
# Polling backs off from 1 s to 5 s. The Cloud API allows 3600 requests per
# hour per project (refilled at one a second) and asks clients not to poll
# actions too often; a fixed 0.5 s poll cost ~20 requests per write, which a
# bulk sync of a few hundred records would exhaust.
_ACTION_POLL_FIRST_S = 1.0
_ACTION_POLL_MAX_S = 5.0

# ``423 locked``: another action is still running on the zone. Writes are
# retried with backoff for up to this long rather than failed outright, since
# consecutive writes to one zone routinely overlap.
_LOCKED_RETRY_S = 60.0

# Types whose value ends in a hostname that must be absolute on the wire.
_HOSTNAME_TARGET_TYPES = {"CNAME", "NS", "PTR", "MX", "SRV"}

# A single TXT character-string is at most 255 bytes (RFC 1035 §3.3).
_TXT_CHUNK = 255

_TXT_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')


class HetznerDNSDriver(CloudDNSDriverBase):
    """Agentless driver for Hetzner-hosted authoritative zones."""

    name = "hetzner"
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
    def _status(response: Any) -> int:
        return int(getattr(response, "status_code", 0) or 0)

    @classmethod
    def _unwrap(cls, response: Any) -> dict[str, Any]:
        """Validate a Hetzner Cloud response and return its parsed body.

        Success is any 2xx with the resource envelope as the body. Failure
        is a non-2xx carrying ``{"error": {"code", "message", "details"}}``;
        raise :class:`CloudDNSError` with the cleanest message available.
        A 3xx is called out explicitly: it is what the retired DNS-Console
        API answers, and "HTTP 301" alone tells an operator nothing.
        """
        body: dict[str, Any]
        try:
            body = response.json()
        except (ValueError, TypeError):
            body = {}
        status = cls._status(response)
        if 200 <= status < 300:
            return body if isinstance(body, dict) else {}
        if 300 <= status < 400:
            raise CloudDNSError(
                f"Hetzner API error: unexpected redirect (HTTP {status}). "
                "The DNS Console API has been retired; this driver talks to "
                "the Hetzner Cloud API."
            )
        detail = ""
        err = body.get("error") if isinstance(body, dict) else None
        if isinstance(err, dict):
            detail = str(err.get("message") or err.get("code") or "")
            code = err.get("code")
            if code and detail and code not in detail:
                detail = f"{detail} ({code})"
        elif isinstance(body, dict):
            detail = str(body.get("message") or "")
        if not detail:
            detail = f"HTTP {status}"
        raise CloudDNSError(f"Hetzner API error: {detail}")

    @staticmethod
    def _error_code(response: Any) -> str:
        try:
            body = response.json()
        except (ValueError, TypeError):
            return ""
        err = body.get("error") if isinstance(body, dict) else None
        return str(err.get("code") or "") if isinstance(err, dict) else ""

    async def _send(self, client: httpx.AsyncClient, method: str, path: str, **kwargs: Any) -> Any:
        """Issue a write, retrying while the zone is locked by another action.

        A ``429`` is reported with the time the limit resets rather than as
        a bare error, so an operator can tell a throttled sync from a broken
        one.
        """
        deadline = time.monotonic() + _LOCKED_RETRY_S
        delay = _ACTION_POLL_FIRST_S
        while True:
            resp = await getattr(client, method)(path, **kwargs)
            status = self._status(resp)
            if status == 423 and self._error_code(resp) == "locked":
                if time.monotonic() + delay > deadline:
                    return resp  # _unwrap reports the lock
                await asyncio.sleep(delay)
                delay = min(delay * 2, _ACTION_POLL_MAX_S)
                continue
            if status == 429:
                headers = getattr(resp, "headers", None) or {}
                reset = headers.get("RateLimit-Reset") if hasattr(headers, "get") else None
                when = ""
                if reset:
                    try:
                        when = f"; it resets in {max(0, int(reset) - int(time.time()))} s"
                    except (TypeError, ValueError):
                        when = ""
                raise CloudDNSError(
                    "Hetzner API rate limit reached (3600 requests per hour per " f"project){when}."
                )
            return resp

    def _token(self, creds: dict[str, Any]) -> str:
        token = (creds or {}).get("api_token")
        if not token:
            raise CloudDNSError("Hetzner credentials missing 'api_token'.")
        return str(token)

    async def _wait_action(self, client: httpx.AsyncClient, body: dict[str, Any]) -> None:
        """Block until the ``action`` in a write response has finished.

        Hetzner returns writes as soon as they are accepted, with the
        action still ``running``. Reporting success at that point would
        let a change the API later fails show as applied.
        """
        action = body.get("action") if isinstance(body, dict) else None
        if not isinstance(action, dict):
            return
        deadline = time.monotonic() + _ACTION_TIMEOUT_S
        delay = _ACTION_POLL_FIRST_S
        while True:
            status = action.get("status")
            if status == "success":
                return
            if status == "error":
                err = action.get("error") or {}
                msg = err.get("message") or err.get("code") or "action failed"
                raise CloudDNSError(f"Hetzner action {action.get('command', '')}: {msg}")
            if time.monotonic() >= deadline:
                raise CloudDNSError(
                    f"Hetzner action {action.get('id')} still {status!r} after "
                    f"{int(_ACTION_TIMEOUT_S)} s"
                )
            await asyncio.sleep(delay)
            delay = min(delay * 2, _ACTION_POLL_MAX_S)
            resp = await client.get(f"/zones/actions/{action['id']}")
            action = self._unwrap(resp).get("action") or {}

    # ── Name / value translation ────────────────────────────────────────
    @staticmethod
    def _relativize(record_name: str, zone_fqdn: str) -> str:
        """Return ``record_name`` relative to ``zone_fqdn`` (apex → ``"@"``)."""
        raw = (record_name or "").strip()
        if not raw or raw == "@":
            return "@"
        zone = normalize_fqdn(zone_fqdn)
        candidate = normalize_fqdn(raw)
        if candidate == zone:
            return "@"
        if candidate.endswith("." + zone):
            return candidate[: -(len(zone) + 1)]
        return raw.rstrip(".")

    @classmethod
    def _rr_name(cls, label: str, zone_fqdn: str) -> str:
        """The RRset name Hetzner expects: lower case, relative, apex ``@``."""
        return cls._relativize(label, zone_fqdn).lower()

    @staticmethod
    def _zone_ref(zone_fqdn: str) -> str:
        """Zone path segment — the API accepts the zone name in place of its id."""
        return quote(normalize_fqdn(zone_fqdn).rstrip("."), safe="")

    @classmethod
    def _rrset_path(cls, zone_fqdn: str, name: str, rtype: str) -> str:
        return f"/zones/{cls._zone_ref(zone_fqdn)}/rrsets/{quote(name, safe='@*')}/{rtype}"

    @staticmethod
    def _absolute(host: str) -> str:
        host = host.strip()
        if not host or host == "." or host.endswith("."):
            return host
        return f"{host}." if "." in host else host

    @staticmethod
    def _txt_chunks(raw: str) -> list[str]:
        """Split ``raw`` into strings of at most 255 UTF-8 bytes.

        The limit is in bytes (RFC 1035 §3.3), so a character count is only
        right for ASCII. Splitting on character boundaries keeps every chunk
        valid UTF-8.
        """
        chunks: list[str] = []
        cur: list[str] = []
        size = 0
        for ch in raw:
            n = len(ch.encode("utf-8"))
            if size + n > _TXT_CHUNK:
                chunks.append("".join(cur))
                cur, size = [], 0
            cur.append(ch)
            size += n
        if cur or not chunks:
            chunks.append("".join(cur))
        return chunks

    @classmethod
    def _txt_to_wire(cls, value: str) -> str:
        """Quote a TXT value, splitting it into ≤255-byte strings."""
        raw = value
        # Already in presentation form (``"a" "b"``) — leave it alone.
        if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
            return raw
        return " ".join(
            '"' + c.replace("\\", "\\\\").replace('"', '\\"') + '"' for c in cls._txt_chunks(raw)
        )

    @staticmethod
    def _txt_from_wire(value: str) -> str:
        """Join a quoted TXT presentation value back into one plain string."""
        parts = _TXT_STRING.findall(value or "")
        if not parts:
            return value
        return "".join(re.sub(r"\\(.)", r"\1", p) for p in parts)

    @classmethod
    def _wire_value(cls, rec: RecordData) -> str:
        """Render one neutral record as the presentation value Hetzner stores."""
        rtype = rec.record_type.upper()
        value = (rec.value or "").strip()
        if rtype == "TXT":
            return cls._txt_to_wire(rec.value or "")
        if rtype == "MX":
            parts = value.split()
            if len(parts) == 1 and rec.priority is not None:
                parts = [str(rec.priority), parts[0]]
            if len(parts) == 2:
                return f"{parts[0]} {cls._absolute(parts[1])}"
            return value
        if rtype == "SRV":
            parts = value.split()
            if len(parts) == 1 and None not in (rec.priority, rec.weight, rec.port):
                parts = [str(rec.priority), str(rec.weight), str(rec.port), parts[0]]
            if len(parts) == 4:
                return " ".join(parts[:3] + [cls._absolute(parts[3])])
            return value
        if rtype in _HOSTNAME_TARGET_TYPES:
            return cls._absolute(value)
        return value

    @classmethod
    def _read_value(cls, rtype: str, value: str) -> str:
        return cls._txt_from_wire(value) if rtype.upper() == "TXT" else value

    # ── Zone reads ──────────────────────────────────────────────────────
    async def _paged(
        self, client: httpx.AsyncClient, path: str, key: str, per_page: int
    ) -> list[dict[str, Any]]:
        """Collect every page of a list endpoint (``meta.pagination.next_page``)."""
        out: list[dict[str, Any]] = []
        page = 1
        while True:
            resp = await client.get(path, params={"page": page, "per_page": per_page})
            body = self._unwrap(resp)
            out.extend(body.get(key) or [])
            nxt = ((body.get("meta") or {}).get("pagination") or {}).get("next_page")
            if not nxt or int(nxt) <= page:
                break
            page = int(nxt)
        return out

    async def _list_zones(self, server: Any, creds: dict[str, Any]) -> list[CloudDNSZone]:
        token = self._token(creds)
        zones: list[CloudDNSZone] = []
        async with self._client(token) as client:
            for z in await self._paged(client, "/zones", "zones", _ZONES_PER_PAGE):
                # Secondary zones are AXFR'd by Hetzner from the operator's
                # own primaries — there are no RRsets to manage here.
                if (z.get("mode") or "primary") != "primary":
                    continue
                name = normalize_fqdn(z["name"])
                zones.append(
                    CloudDNSZone(
                        name=name,
                        zone_id=str(z["id"]),
                        is_reverse=name.endswith((".in-addr.arpa.", ".ip6.arpa.")),
                        # No online DNSSEC signing via the API.
                        dnssec_enabled=False,
                        record_count=z.get("record_count"),
                    )
                )
        return zones

    async def _list_zone_records(
        self, server: Any, creds: dict[str, Any], zone_name: str
    ) -> list[RecordData]:
        token = self._token(creds)
        zone_fqdn = normalize_fqdn(zone_name)
        records: list[RecordData] = []
        async with self._client(token) as client:
            rrsets = await self._paged(
                client, f"/zones/{self._zone_ref(zone_fqdn)}/rrsets", "rrsets", _RRSETS_PER_PAGE
            )
        for rrset in rrsets:
            rtype = str(rrset["type"]).upper()
            name = self._relativize(rrset.get("name") or "@", zone_fqdn)
            for rec in rrset.get("records") or []:
                records.append(
                    RecordData(
                        name=name,
                        record_type=rtype,
                        value=self._read_value(rtype, rec.get("value", "")),
                        ttl=rrset.get("ttl"),
                    )
                )
        return records

    # ── Record writes ───────────────────────────────────────────────────
    async def _get_rrset(
        self, client: httpx.AsyncClient, zone_fqdn: str, name: str, rtype: str
    ) -> dict[str, Any] | None:
        resp = await client.get(self._rrset_path(zone_fqdn, name, rtype))
        if self._status(resp) == 404:
            return None
        return self._unwrap(resp).get("rrset") or None

    async def _post_action(
        self, client: httpx.AsyncClient, path: str, body: dict[str, Any]
    ) -> None:
        resp = await self._send(client, "post", path, json=body)
        await self._wait_action(client, self._unwrap(resp))

    async def _create_rrset(
        self,
        client: httpx.AsyncClient,
        zone_fqdn: str,
        name: str,
        rtype: str,
        values: list[str],
        ttl: int | None,
    ) -> None:
        body: dict[str, Any] = {
            "name": name,
            "type": rtype,
            "records": [{"value": v} for v in values],
        }
        if ttl is not None:
            body["ttl"] = ttl
        await self._post_action(client, f"/zones/{self._zone_ref(zone_fqdn)}/rrsets", body)

    async def _delete_rrset(
        self, client: httpx.AsyncClient, zone_fqdn: str, name: str, rtype: str
    ) -> None:
        resp = await self._send(client, "delete", self._rrset_path(zone_fqdn, name, rtype))
        if self._status(resp) == 404:
            return  # idempotent delete
        await self._wait_action(client, self._unwrap(resp))

    async def _set_ttl_if_needed(
        self,
        client: httpx.AsyncClient,
        zone_fqdn: str,
        name: str,
        rtype: str,
        current: dict[str, Any],
        ttl: int | None,
    ) -> None:
        if ttl is None or current.get("ttl") == ttl:
            return
        await self._post_action(
            client, f"{self._rrset_path(zone_fqdn, name, rtype)}/actions/change_ttl", {"ttl": ttl}
        )

    async def _apply_record(self, server: Any, creds: dict[str, Any], change: RecordChange) -> None:
        token = self._token(creds)
        zone_fqdn = normalize_fqdn(change.zone_name)
        rec = change.record
        rtype = rec.record_type.upper()
        name = self._rr_name(rec.name, zone_fqdn)
        if change.op not in ("create", "update", "delete"):
            raise CloudDNSError(f"Hetzner: unsupported record op {change.op!r}")

        async with self._client(token) as client:
            # #783 — the complete desired set is known: converge the RRset
            # to exactly that in one write. Replaying the op is harmless.
            if change.rrset is not None:
                desired = [self._wire_value(r) for r in change.rrset.as_records(rec)]
                desired = list(dict.fromkeys(desired))  # API refuses duplicates
                ttl = change.rrset.ttl if change.rrset.ttl is not None else rec.ttl
                current = await self._get_rrset(client, zone_fqdn, name, rtype)
                if not desired:
                    if current is not None:
                        await self._delete_rrset(client, zone_fqdn, name, rtype)
                    return
                if current is None:
                    await self._create_rrset(client, zone_fqdn, name, rtype, desired, ttl)
                    return
                have = {r.get("value") for r in current.get("records") or []}
                if have != set(desired):
                    await self._post_action(
                        client,
                        f"{self._rrset_path(zone_fqdn, name, rtype)}/actions/set_records",
                        {"records": [{"value": v} for v in desired]},
                    )
                await self._set_ttl_if_needed(client, zone_fqdn, name, rtype, current, ttl)
                return

            # No resolved set (DNS pools, the cutover TTL pre-flight, or an
            # op that predates #783): per-value semantics against the live set.
            value = self._wire_value(rec)
            current = await self._get_rrset(client, zone_fqdn, name, rtype)
            values = [r.get("value") for r in (current or {}).get("records") or []]

            if change.op == "delete":
                if current is None or value not in values:
                    return  # idempotent delete — nothing to remove
                if values == [value]:
                    await self._delete_rrset(client, zone_fqdn, name, rtype)
                else:
                    await self._post_action(
                        client,
                        f"{self._rrset_path(zone_fqdn, name, rtype)}/actions/remove_records",
                        {"records": [{"value": value}]},
                    )
                return

            # create / update: create-on-miss, add the value if absent,
            # then bring the TTL in line.
            if current is None:
                await self._create_rrset(client, zone_fqdn, name, rtype, [value], rec.ttl)
                return
            if value not in values:
                await self._post_action(
                    client,
                    f"{self._rrset_path(zone_fqdn, name, rtype)}/actions/add_records",
                    {"records": [{"value": value}]},
                )
            await self._set_ttl_if_needed(client, zone_fqdn, name, rtype, current, rec.ttl)

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
        async with self._client(token) as client:
            if op == "create":
                resp = await self._send(
                    client,
                    "post",
                    "/zones",
                    json={"name": zone_fqdn.rstrip("."), "mode": "primary"},
                )
                await self._wait_action(client, self._unwrap(resp))
                return

            if op == "delete":
                resp = await self._send(client, "delete", f"/zones/{self._zone_ref(zone_fqdn)}")
                if self._status(resp) == 404:
                    return
                await self._wait_action(client, self._unwrap(resp))
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
            # The Cloud API has no online DNSSEC signing.
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
                "TLSA",
                "HTTPS",
                "SVCB",
                "SOA",
            ],
            "notes": (
                "Agentless Hetzner DNS driver over the Hetzner Cloud API "
                "(api.hetzner.cloud, Bearer project token with Read & Write). "
                "Zones + RRsets managed from the control plane; only "
                "primary-mode zones are listed. No online DNSSEC signing; the "
                "SOA is managed by Hetzner. RRsets with no explicit TTL "
                "inherit the zone default."
            ),
        }


__all__ = ["HetznerDNSDriver"]
