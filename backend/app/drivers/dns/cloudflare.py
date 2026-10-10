"""Cloudflare DNS driver (agentless, REST API — issue #37).

Cloudflare hosts authoritative zones and exposes a flat REST API at
``https://api.cloudflare.com/client/v4``. SpatiumDDI manages those zones
exactly like a local BIND9 / PowerDNS zone — same Zones / Records group
surfaces — driving the API directly from the control plane rather than an
agent (see :mod:`app.drivers.dns._cloud_base` for the agentless contract).

Authentication is a single scoped **API token** (``Bearer`` header). The
account's zone-id is opaque and required to scope every record call, so
``_resolve_zone_id`` looks it up by name and the methods cache nothing —
each call is cheap and idempotent.

Unlike the AWS / Azure / GCP cloud drivers, Cloudflare needs no vendor SDK:
the API is plain JSON over HTTPS, so this driver uses ``httpx`` directly
(already a top-level dependency). ``_client`` is the single seam tests
patch to inject a fake transport.

Credential dict shape (decrypted from ``DNSServer.credentials_encrypted``)::

    {"api_token": "<scoped-token>", "account_id": "<optional>"}

``account_id`` is only consulted when *creating* a zone — Cloudflare's
``POST /zones`` requires the owning account, but record / read calls do not.
"""

from __future__ import annotations

import ipaddress
from typing import Any

import httpx
import structlog

from app.drivers.dns._cloud_base import (
    CloudDNSDriverBase,
    CloudDNSError,
    CloudDNSZone,
    compose_structured_rdata,
    normalize_fqdn,
    split_structured_rdata,
)
from app.drivers.dns.base import RecordChange, RecordData, RRsetData, RRsetMember

logger = structlog.get_logger(__name__)

# Cloudflare API error 1061, "Zone already exists" (zone create, #1537).
_ZONE_ALREADY_EXISTS = 1061


class _CloudflareAPIError(CloudDNSError):
    """A Cloudflare API failure that keeps its HTTP status and error codes.

    Lets the zone create / delete paths tell the one converged answer apart
    from auth, throttling and server errors without matching message text.
    """

    def __init__(self, message: str, *, status: int, codes: list[Any]) -> None:
        super().__init__(message)
        self.status = status
        self.codes = codes


# Cloudflare API v4 base. Pinned here (not configurable) — there is no
# self-hosted Cloudflare. The token in the Authorization header is the
# only per-server input.
_API_BASE = "https://api.cloudflare.com/client/v4"

# Cloudflare's per-page maximum is 100; 50 keeps responses small while
# still rarely needing a second round trip for typical accounts.
_PER_PAGE = 50

# Cloudflare encodes "automatic TTL" as the sentinel value 1. We surface
# that as ``ttl=None`` on the neutral RecordData so it round-trips as
# "let the provider decide" rather than a literal 1-second TTL.
_TTL_AUTO = 1

# Types whose priority is part of the record's identity (two MX with the
# same exchange and different preferences are two records).
_PRIORITY_TYPES = frozenset({"MX", "SRV", "URI"})

# Types whose content is a host name: compared case-insensitively and with
# or without the trailing dot, which is how they come back from the API.
_NAME_CONTENT_TYPES = frozenset({"CNAME", "NS", "MX", "PTR", "DNAME"})


def _content_key(record_type: str, content: str) -> str:
    """The form in which two spellings of the same value compare equal.

    SpatiumDDI and Cloudflare do not always spell a value alike: a TXT value
    stored with or without its surrounding quotes, a host name with or
    without the root dot, an IPv6 address in another notation. Compared
    literally, the RRset write would read an unchanged record as missing and
    POST it again, which Cloudflare refuses as an identical record.
    """
    value = (content or "").strip()
    rtype = record_type.upper()
    if rtype == "TXT":
        # One quoted string only; a multi-string value ("a" "b") is kept as is.
        if len(value) >= 2 and value[0] == value[-1] == '"' and '" "' not in value:
            return value[1:-1]
        return value
    if rtype in ("A", "AAAA"):
        try:
            return ipaddress.ip_address(value).compressed
        except ValueError:
            return value.lower()
    if rtype in _NAME_CONTENT_TYPES:
        return value.rstrip(".").lower()
    return value


def _srv_member_key(member: RRsetMember) -> tuple[int, int, int, str]:
    """``(priority, weight, port, target)`` for a desired SRV member.

    Missing numeric fields default to 0, as the ``data`` payload sends them.
    """
    return (
        member.priority if member.priority is not None else 0,
        member.weight if member.weight is not None else 0,
        member.port if member.port is not None else 0,
        member.value.rstrip(".").lower(),
    )


def _srv_row_key(row: dict[str, Any]) -> tuple[int, int, int, str] | None:
    """``(priority, weight, port, target)`` for a live Cloudflare SRV row.

    Read from the ``data`` object when present, otherwise split out of the
    composed ``content`` string. ``None`` when neither parses, so the row is
    never mistaken for a member.
    """
    data = row.get("data") or {}
    if data:
        try:
            return (
                int(data.get("priority") or 0),
                int(data.get("weight") or 0),
                int(data.get("port") or 0),
                str(data.get("target") or "").rstrip(".").lower(),
            )
        except (TypeError, ValueError):
            return None
    content = str(row.get("content") or "")
    target, priority, weight, port = split_structured_rdata("SRV", content)
    if priority is not None and weight is not None and port is not None:
        return (priority, weight, port, target.rstrip(".").lower())
    # Cloudflare's own SRV content omits the priority ("<weight> <port>
    # <target>") and carries it as the row's top-level ``priority``.
    parts = content.split(None, 2)
    if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
        try:
            prio = int(row.get("priority") or 0)
        except (TypeError, ValueError):
            return None
        return (prio, int(parts[0]), int(parts[1]), parts[2].strip().rstrip(".").lower())
    return None


class CloudflareDNSDriver(CloudDNSDriverBase):
    """Agentless driver for Cloudflare-hosted authoritative zones."""

    name = "cloudflare"
    # The Add-DNS-server modal renders + the probe requires only the token.
    # ``account_id`` is optional (zone-create only) so it is not listed here.
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
        """Validate a Cloudflare response envelope and return its body.

        Cloudflare wraps every reply as ``{"success": bool, "errors": [...],
        "result": ..., "result_info": {...}}``. Raise :class:`CloudDNSError`
        with the joined ``errors[].message`` on a non-2xx status *or* an
        ``success: false`` envelope (the API returns 200 with
        ``success: false`` for some validation failures).
        """
        body: dict[str, Any]
        try:
            body = response.json()
        except (ValueError, TypeError):
            body = {}
        status = getattr(response, "status_code", 0)
        ok = 200 <= status < 300 and bool(body.get("success", False))
        if ok:
            return body
        errors = body.get("errors") or []
        messages = [str(e.get("message", e)) for e in errors if e]
        detail = "; ".join(m for m in messages if m) or f"HTTP {status}"
        raise _CloudflareAPIError(
            f"Cloudflare API error: {detail}",
            status=status,
            codes=[e.get("code") for e in errors if isinstance(e, dict)],
        )

    def _token(self, creds: dict[str, Any]) -> str:
        token = (creds or {}).get("api_token")
        if not token:
            raise CloudDNSError("Cloudflare credentials missing 'api_token'.")
        return str(token)

    async def _resolve_zone_id(self, client: httpx.AsyncClient, zone_fqdn: str) -> str:
        """Look up the opaque Cloudflare zone id for a zone FQDN.

        Cloudflare's ``GET /zones?name=`` filter wants the bare name with no
        trailing dot, so the apex FQDN is de-dotted before the query.
        """
        name = normalize_fqdn(zone_fqdn).rstrip(".")
        resp = await client.get("/zones", params={"name": name})
        body = self._unwrap(resp)
        results = body.get("result") or []
        if not results:
            raise CloudDNSError(f"Cloudflare zone {name!r} not found on this account.")
        return str(results[0]["id"])

    @staticmethod
    def _relativize(fqdn: str, zone_fqdn: str) -> str:
        """Return ``fqdn`` relative to ``zone_fqdn`` (apex → ``"@"``).

        Both sides are normalised to trailing-dot FQDNs first so the suffix
        match is exact. A name equal to the apex collapses to ``"@"`` to
        match the BIND9 / Windows pull convention.
        """
        name = normalize_fqdn(fqdn)
        zone = normalize_fqdn(zone_fqdn)
        if name == zone:
            return "@"
        if name.endswith("." + zone):
            return name[: -(len(zone) + 1)]
        # Not actually under the zone — return the de-dotted name as a
        # best-effort fallback rather than raising mid-import.
        return name.rstrip(".")

    # ── Zone reads ──────────────────────────────────────────────────────
    async def _list_zones(self, server: Any, creds: dict[str, Any]) -> list[CloudDNSZone]:
        token = self._token(creds)
        zones: list[CloudDNSZone] = []
        async with self._client(token) as client:
            page = 1
            while True:
                resp = await client.get("/zones", params={"per_page": _PER_PAGE, "page": page})
                body = self._unwrap(resp)
                for z in body.get("result") or []:
                    name = normalize_fqdn(z["name"])
                    is_reverse = name.endswith((".in-addr.arpa.", ".ip6.arpa."))
                    zones.append(
                        CloudDNSZone(
                            name=name,
                            zone_id=str(z["id"]),
                            is_reverse=is_reverse,
                            # Cloudflare reports DNSSEC via a separate
                            # endpoint; we leave it False on the list pull
                            # and treat capability advertising as the source
                            # of truth for online-signing support.
                            dnssec_enabled=False,
                            record_count=None,
                        )
                    )
                info = body.get("result_info") or {}
                total_pages = int(info.get("total_pages") or 1)
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
            zone_id = await self._resolve_zone_id(client, zone_fqdn)
            page = 1
            while True:
                resp = await client.get(
                    f"/zones/{zone_id}/dns_records",
                    params={"per_page": _PER_PAGE, "page": page},
                )
                body = self._unwrap(resp)
                for rec in body.get("result") or []:
                    raw_ttl = rec.get("ttl")
                    ttl = None if raw_ttl == _TTL_AUTO else raw_ttl
                    rtype = str(rec["type"]).upper()
                    value = rec.get("content") or ""
                    priority = rec.get("priority")
                    weight: int | None = None
                    port: int | None = None
                    if rtype == "SRV":
                        # SRV components live in the ``data`` object
                        # (#1526); ``content`` is the composed string.
                        data = rec.get("data") or {}
                        if data:
                            value = str(data.get("target") or value)
                            priority = data.get("priority", priority)
                            weight = data.get("weight")
                            port = data.get("port")
                        else:
                            value, priority, weight, port = split_structured_rdata(rtype, value)
                    records.append(
                        RecordData(
                            name=self._relativize(rec["name"], zone_fqdn),
                            record_type=rec["type"],
                            value=value,
                            ttl=ttl,
                            priority=priority,
                            weight=weight,
                            port=port,
                        )
                    )
                info = body.get("result_info") or {}
                total_pages = int(info.get("total_pages") or 1)
                if page >= total_pages:
                    break
                page += 1
        return records

    # ── Record writes ───────────────────────────────────────────────────
    @staticmethod
    def _absolute_name(label: str, zone_fqdn: str) -> str:
        """Render the absolute record name Cloudflare expects (no trailing dot).

        Apex (``"@"`` / empty) → the bare zone name; otherwise the relative
        label joined to the zone.
        """
        zone = normalize_fqdn(zone_fqdn).rstrip(".")
        rel = (label or "").strip().rstrip(".")
        if not rel or rel == "@":
            return zone
        if rel.endswith("." + zone) or rel == zone:
            return rel
        return f"{rel}.{zone}"

    def _record_payload(self, change: RecordChange, zone_fqdn: str) -> dict[str, Any]:
        rec = change.record
        payload: dict[str, Any] = {
            "type": rec.record_type,
            "name": self._absolute_name(rec.name, zone_fqdn),
            # Cloudflare's "automatic" TTL is the sentinel 1.
            "ttl": _TTL_AUTO if rec.ttl is None else rec.ttl,
        }
        if rec.record_type.upper() == "SRV":
            # Cloudflare takes SRV components as a ``data`` object, not a
            # content string (#1526): priority / weight / port / target.
            payload["data"] = {
                "priority": rec.priority if rec.priority is not None else 0,
                "weight": rec.weight if rec.weight is not None else 0,
                "port": rec.port if rec.port is not None else 0,
                "target": rec.value,
            }
            return payload
        payload["content"] = rec.value
        if rec.priority is not None:
            payload["priority"] = rec.priority
        return payload

    async def _find_record_id(
        self,
        client: httpx.AsyncClient,
        zone_id: str,
        name: str,
        record_type: str,
        content: str | None = None,
        priority: int | None = None,
    ) -> str | None:
        """Return the Cloudflare record id matching name+type+value, or ``None``."""
        rec = await self._find_record(client, zone_id, name, record_type, content, priority)
        return None if rec is None else str(rec["id"])

    async def _find_record(
        self,
        client: httpx.AsyncClient,
        zone_id: str,
        name: str,
        record_type: str,
        content: str | None = None,
        priority: int | None = None,
    ) -> dict[str, Any] | None:
        """Return the Cloudflare record matching name+type+value, or ``None``.

        SpatiumDDI keys DNS records per value and supports round-robin (multiple
        A/AAAA at one hostname) and multiple MX/NS/TXT. So when ``content`` is
        given we must match the *specific* value being changed — matching on
        name+type alone returns the first row of a multi-value RRset and would
        update/delete the wrong value (issue #331).

        We narrow server-side with the ``content`` filter, then verify the
        match client-side over the returned list (``priority`` too for
        MX/SRV) so a content filter that normalises differently for a given
        rrtype can't silently hand back a sibling value.
        """
        params: dict[str, Any] = {"name": name, "type": record_type}
        if content is not None:
            params["content"] = content
        resp = await client.get(f"/zones/{zone_id}/dns_records", params=params)
        body = self._unwrap(resp)
        results = body.get("result") or []
        if not results:
            return None
        # Name+type-only lookup (content unknown): keep legacy first-match.
        if content is None:
            return dict(results[0])
        # Value-keyed lookup: pick the row whose content (and priority for
        # MX/SRV) actually matches — the server-side filter is a narrowing
        # hint, not a guarantee.
        for rec in results:
            if rec.get("content") != content:
                continue
            if priority is not None and rec.get("priority") != priority:
                continue
            return dict(rec)
        return None

    async def _list_rrset(
        self, client: httpx.AsyncClient, zone_id: str, name: str, record_type: str
    ) -> list[dict[str, Any]]:
        """Every Cloudflare record at ``name`` + ``record_type``."""
        out: list[dict[str, Any]] = []
        page = 1
        while True:
            resp = await client.get(
                f"/zones/{zone_id}/dns_records",
                params={"name": name, "type": record_type, "per_page": 100, "page": page},
            )
            body = self._unwrap(resp)
            out.extend(r for r in body.get("result") or [] if r.get("type") == record_type)
            info = body.get("result_info") or {}
            if page >= int(info.get("total_pages") or 1):
                return out
            page += 1

    async def _write_rrset(
        self,
        client: httpx.AsyncClient,
        zone_id: str,
        zone_fqdn: str,
        change: RecordChange,
        rrset: RRsetData,
    ) -> None:
        """Make the records at the op's name + type exactly ``change.rrset``.

        Cloudflare stores one row per value, and the op names only the value
        it changes TO. Looking the row up by that value (the per-value path
        below) cannot find the row being changed, so an edit that changes a
        value used to POST a second record next to the old one: two TXT
        records where there was one, and two DMARC records make the domain's
        DMARC policy invalid. The op carries the complete desired set (#783),
        so the set is reconciled instead: rows that match a member are kept
        (TTL corrected in place), missing members are created, and only then
        are the rows no member matches removed, so the name never goes empty.

        SpatiumDDI does not model Cloudflare's ``proxied`` flag, and a PUT or
        POST without it lands DNS-only, publishing the origin address. So a
        kept row's flag is carried into its PUT (a proxied row is never PUT:
        its TTL always reads back as auto), and a created row joins the
        proxy status the rows at the name already have.
        """
        rec = change.record
        rtype = rec.record_type
        name = self._absolute_name(rec.name, zone_fqdn)
        ttl = rrset.ttl if rrset.ttl is not None else rec.ttl
        wire_ttl = _TTL_AUTO if ttl is None else ttl
        keyed_priority = rtype in _PRIORITY_TYPES

        unmatched = await self._list_rrset(client, zone_id, name, rtype)
        proxied = any(r.get("proxied") for r in unmatched)
        to_create: list[dict[str, Any]] = []
        is_srv = rtype.upper() == "SRV"
        for member in rrset.members:
            payload: dict[str, Any] = {"type": rtype, "name": name, "ttl": wire_ttl}
            if is_srv:
                # SRV goes out as a ``data`` object (#1526), matched on all
                # four components rather than on ``content``.
                srv_key = _srv_member_key(member)
                payload["data"] = {
                    "priority": srv_key[0],
                    "weight": srv_key[1],
                    "port": srv_key[2],
                    "target": member.value,
                }
                match = next((r for r in unmatched if _srv_row_key(r) == srv_key), None)
            else:
                payload["content"] = member.value
                if member.priority is not None:
                    payload["priority"] = member.priority
                key = _content_key(rtype, member.value)
                match = next(
                    (
                        r
                        for r in unmatched
                        if _content_key(rtype, str(r.get("content") or "")) == key
                        and (not keyed_priority or r.get("priority") == member.priority)
                    ),
                    None,
                )
            if match is None:
                if proxied:
                    payload["proxied"] = True
                to_create.append(payload)
                continue
            unmatched.remove(match)
            # A proxied record's TTL is auto whatever was set, so it would
            # always read as mismatched; there is nothing to correct.
            if not match.get("proxied") and match.get("ttl") != wire_ttl:
                if "proxied" in match:
                    payload["proxied"] = match["proxied"]
                resp = await client.put(f"/zones/{zone_id}/dns_records/{match['id']}", json=payload)
                self._unwrap(resp)

        for payload in to_create:
            resp = await client.post(f"/zones/{zone_id}/dns_records", json=payload)
            try:
                self._unwrap(resp)
            except CloudDNSError as exc:
                if "identical record already exists" not in str(exc).lower():
                    raise
                # Cloudflare says the value is there, but it did not match
                # any row above, so it is one of the rows still unmatched.
                # Deleting them now could delete the very record that was
                # just reported as present: stop before the delete pass.
                shown = payload.get("content", payload.get("data"))
                raise CloudDNSError(
                    f"Cloudflare: {name} {rtype} {shown!r} exists in a form "
                    "this driver does not recognise; left the existing records in place."
                ) from exc

        for row in unmatched:
            resp = await client.delete(f"/zones/{zone_id}/dns_records/{row['id']}")
            self._unwrap(resp)

    async def _apply_record(self, server: Any, creds: dict[str, Any], change: RecordChange) -> None:
        token = self._token(creds)
        zone_fqdn = normalize_fqdn(change.zone_name)
        payload = self._record_payload(change, zone_fqdn)
        async with self._client(token) as client:
            zone_id = await self._resolve_zone_id(client, zone_fqdn)

            # #783 — a create or update that carries the complete desired
            # RRset is a set write. Without one (a caller that opted out via
            # ``rrset_action``) the per-value behaviour below stands.
            if change.op in ("create", "update") and change.rrset and change.rrset.members:
                await self._write_rrset(client, zone_id, zone_fqdn, change, change.rrset)
                return

            if change.op == "create":
                resp = await client.post(f"/zones/{zone_id}/dns_records", json=payload)
                self._unwrap(resp)
                return

            if change.op == "update":
                existing = await self._find_record(
                    client,
                    zone_id,
                    payload["name"],
                    change.record.record_type,
                    content=(
                        compose_structured_rdata(change.record)
                        if change.record.record_type.upper() == "SRV"
                        else change.record.value
                    ),
                    priority=change.record.priority,
                )
                if existing is None:
                    # No existing row to update — treat as create so the
                    # desired state still lands (mirrors the windows_dns +
                    # _cloud_base "update is create on miss" contract).
                    resp = await client.post(f"/zones/{zone_id}/dns_records", json=payload)
                    self._unwrap(resp)
                    return
                # A PUT replaces the whole record: without the row's own
                # ``proxied`` it would land DNS-only.
                if "proxied" in existing:
                    payload["proxied"] = existing["proxied"]
                resp = await client.put(
                    f"/zones/{zone_id}/dns_records/{existing['id']}", json=payload
                )
                self._unwrap(resp)
                return

            if change.op == "delete":
                rid = await self._find_record_id(
                    client,
                    zone_id,
                    payload["name"],
                    change.record.record_type,
                    content=(
                        compose_structured_rdata(change.record)
                        if change.record.record_type.upper() == "SRV"
                        else change.record.value
                    ),
                    priority=change.record.priority,
                )
                if rid is None:
                    # Idempotent delete — nothing to remove.
                    return
                resp = await client.delete(f"/zones/{zone_id}/dns_records/{rid}")
                self._unwrap(resp)
                return

            raise CloudDNSError(f"Cloudflare: unsupported record op {change.op!r}")

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
                payload: dict[str, Any] = {"name": bare}
                # Real Cloudflare requires the owning account on zone create;
                # include it when the operator supplied an account_id.
                account_id = (creds or {}).get("account_id")
                if account_id:
                    payload["account"] = {"id": str(account_id)}
                resp = await client.post("/zones", json=payload)
                try:
                    self._unwrap(resp)
                except _CloudflareAPIError as exc:
                    # #1537 — error 1061 "Zone already exists" is the only
                    # converged signal. Confirm the token can see a zone of
                    # that name (a lookup scoped to the token's account)
                    # before calling it done; a zone held by ANOTHER
                    # account is a different error code and stays a failure.
                    if _ZONE_ALREADY_EXISTS not in exc.codes:
                        raise
                    await self._resolve_zone_id(client, zone_fqdn)
                    logger.info(
                        "cloudflare.apply_zone.create_already_exists",
                        server=str(getattr(server, "id", "")),
                        zone=bare,
                    )
                return

            if op == "delete":
                try:
                    zone_id = await self._resolve_zone_id(client, zone_fqdn)
                except CloudDNSError as exc:
                    # #1537 — an already-absent zone is the desired end state.
                    # Only the "zone not found" lookup miss; auth, rate-limit
                    # and 5xx errors from the lookup propagate.
                    if isinstance(exc, _CloudflareAPIError):
                        raise
                    if "not found on this account" in str(exc):
                        logger.info(
                            "cloudflare.apply_zone.delete_noop_absent",
                            server=str(getattr(server, "id", "")),
                            zone=bare,
                        )
                        return
                    raise
                resp = await client.delete(f"/zones/{zone_id}")
                try:
                    self._unwrap(resp)
                except _CloudflareAPIError as exc:
                    # Gone between the lookup and the delete (HTTP 404 only).
                    if exc.status != 404:
                        raise
                    logger.info(
                        "cloudflare.apply_zone.delete_noop_absent",
                        server=str(getattr(server, "id", "")),
                        zone=bare,
                    )
                return

            raise CloudDNSError(f"Cloudflare: unsupported zone op {op!r}")

    # ── Capabilities ────────────────────────────────────────────────────
    def capabilities(self) -> dict[str, Any]:
        return {
            "name": "cloudflare",
            "agentless": True,
            "manages_zones": True,
            "views": False,
            "rpz": False,
            # #29 — Cloudflare DNSSEC is a zone-level enable (PATCH /dnssec),
            # not the per-record online signing these ops model; deferred.
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
            "apex_cname": "flatten",
            "notes": (
                "Agentless Cloudflare DNS driver over the v4 REST API "
                "(Bearer API token). Zones + records managed from the "
                "control plane; CNAME-at-apex is auto-flattened by "
                "Cloudflare. account_id credential is only needed for "
                "zone creation."
            ),
        }


__all__ = ["CloudflareDNSDriver"]
