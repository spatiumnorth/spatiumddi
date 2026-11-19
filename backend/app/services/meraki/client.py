"""Minimal async Cisco Meraki Dashboard API client (issue #606).

One JSON REST surface (``https://api.meraki.com/api/v1/...``, header
``Authorization: Bearer <api_key>``) covers everything we read: the
organization + its appliance networks, per-network VLANs (with their MX
interface IPs + fixed-IP reservations), org-wide policy objects/groups, the
appliance NAT rules (one-to-one + port-forward), and the network client list.

Read paths are strictly read-only. The only writes are the per-client
device-policy set (Shape 2 enforcement, #601 tier — ``Blocked`` / ``Normal``)
via ``set_client_policy`` — never object / rule / config CRUD.

Two GET flavours are used:

* ``_get_json(path, params)`` — a single-shot GET returning the decoded JSON.
* ``_get_paginated(path, params)`` — follows the RFC5988 ``Link`` header's
  ``rel="next"`` cursor, accumulating array results (hard cap 20 pages).

The Dashboard API rate-limits with HTTP 429 + a ``Retry-After`` header; both
helpers funnel through ``_request`` which retries a 429 (honouring
``Retry-After``, capped) up to a small bound.

Defensive parsing throughout — Meraki response shapes vary across firmware and
we can't hit a real dashboard in tests, so every accessor guards missing keys /
unexpected types.
"""

from __future__ import annotations

import asyncio
import re
import ssl
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

from app.core.exc_text import describe_exc

logger = structlog.get_logger(__name__)

_MAX_429_RETRIES = 3
_MAX_RETRY_AFTER_SECONDS = 5.0
_MAX_PAGES = 20
# `<url>; rel="next"` (or rel=next) — one link entry of an RFC5988 Link header.
_LINK_NEXT_RE = re.compile(r"<([^>]+)>\s*;\s*rel=\"?next\"?", re.IGNORECASE)


class MerakiClientError(Exception):
    """Raised when the Meraki API returns an error we can't recover from.

    ``status_code`` is the HTTP status when the failure was a response and
    ``None`` for transport-level failures (timeout / connection refused).
    Callers use it to tell a genuine 404 (safe to treat as an empty table)
    apart from a transient 5xx / timeout (must abort the reconcile rather than
    diff against an empty desired set — NN#5).
    """

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


# ── Read-shape dataclasses ───────────────────────────────────────────


@dataclass
class _MerakiOrgInfo:
    id: str
    name: str
    url: str


@dataclass
class _MerakiNetwork:
    id: str
    name: str
    product_types: list[str] = field(default_factory=list)


@dataclass
class _MerakiVlan:
    network_id: str
    network_name: str
    vlan_id: str  # stringified
    name: str
    cidr: str  # "192.168.1.0/24" (from the vlan "subnet" field)
    appliance_ip: str  # the MX interface IP in the vlan, or ""


@dataclass
class _MerakiReservation:
    network_id: str
    address: str
    mac: str | None
    name: str  # reservation name/hostname, or ""


@dataclass
class _MerakiPolicyObject:
    name: str
    kind: str  # host | network | range | fqdn | group  (map from Meraki type)
    value: str  # CIDR / ip / fqdn / comma-joined group member names
    description: str  # "" (Meraki policy objects have no description; use category)
    tags: list[str] = field(default_factory=list)  # [category] or []


@dataclass
class _MerakiNatRule:
    name: str
    kind: str  # "1to1" for one-to-one NAT, "port-forward" for port forwarding
    source: str  # ""
    original_dst: str | None  # public IP
    translated_dst: str | None  # LAN IP
    translated_src: str | None  # None
    description: str


@dataclass
class _MerakiClientRow:
    network_id: str
    address: str
    mac: str | None
    hostname: str
    description: str


@dataclass
class _MerakiClientPolicy:
    client_id: str
    mac: str
    device_policy: str  # e.g. "Normal" | "Blocked" | "Group policy"


# ── Module-level parse helpers ───────────────────────────────────────


def _normalise_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    m = mac.strip().lower().replace("-", ":")
    if not m or m in {"(incomplete)", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}:
        return None
    return m


def classify_meraki_object(entry: dict[str, Any]) -> tuple[str, str]:
    """Return ``(kind, value)`` for a Meraki policy-object entry.

    A Meraki policy object carries a ``type`` of ``cidr`` / ``ipAndMask`` /
    ``ip`` / ``fqdn`` alongside the matching value field. We map to our
    ``host | network | fqdn`` kinds:

    * ``cidr`` → ``network`` unless it's a ``/32`` host (value = the cidr).
    * ``ipAndMask`` → same treatment as ``cidr`` (value = the cidr).
    * ``ip`` → ``host`` (value = the ip).
    * ``fqdn`` → ``fqdn`` (value = the fqdn).
    * anything else → ``host`` with an empty value.
    """
    obj_type = str(entry.get("type") or "").strip()
    cidr = str(entry.get("cidr") or "").strip()
    if obj_type in ("cidr", "ipAndMask") and cidr:
        kind = "host" if cidr.endswith("/32") else "network"
        return kind, cidr
    ip = str(entry.get("ip") or "").strip()
    if obj_type == "ip" and ip:
        return "host", ip
    fqdn = str(entry.get("fqdn") or "").strip()
    if obj_type == "fqdn" and fqdn:
        return "fqdn", fqdn
    # Fall through: some firmwares omit `type` but still carry one value field.
    if cidr:
        kind = "host" if cidr.endswith("/32") else "network"
        return kind, cidr
    if fqdn:
        return "fqdn", fqdn
    if ip:
        return "host", ip
    return "host", ""


def _parse_next_link(link_header: str | None) -> str | None:
    """Extract the ``rel="next"`` URL from an RFC5988 ``Link`` header, or None."""
    if not link_header:
        return None
    match = _LINK_NEXT_RE.search(link_header)
    return match.group(1) if match else None


class MerakiClient:
    """Per-organization async client. One instance per reconcile / push pass."""

    def __init__(
        self,
        *,
        api_key: str,
        org_id: str,
        base_url: str = "https://api.meraki.com/api/v1",
        verify_tls: bool = True,
        ca_bundle_pem: str = "",
    ) -> None:
        self._base = base_url.rstrip("/")
        self._api_key = api_key
        self._org_id = org_id.strip()
        self._verify_tls = verify_tls
        self._ca_bundle_pem = ca_bundle_pem.strip()
        self._client: httpx.AsyncClient | None = None

    # ── Lifecycle ────────────────────────────────────────────────────

    @staticmethod
    def _build_verify(verify_tls: bool, ca_bundle_pem: str, endpoint: str) -> Any:
        if not verify_tls:
            logger.warning("meraki_tls_verification_disabled", endpoint=endpoint)
            return False
        ca = (ca_bundle_pem or "").strip()
        if ca:
            return ssl.create_default_context(cadata=ca)
        return True

    async def __aenter__(self) -> MerakiClient:
        verify = self._build_verify(self._verify_tls, self._ca_bundle_pem, self._base)
        self._client = httpx.AsyncClient(
            base_url=self._base,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Accept": "application/json",
            },
            verify=verify,
            timeout=30.0,
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ── HTTP helpers ─────────────────────────────────────────────────

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """Issue one request with 429 retry (honours ``Retry-After``, capped).

        Maps transport failures + HTTP >= 400 to ``MerakiClientError``; 401/403
        get a friendlier message. On 429 we sleep ``Retry-After`` seconds (or a
        1s default), capped, up to ``_MAX_429_RETRIES`` retries before giving up.
        """
        assert self._client is not None, "use within 'async with'"
        # `path` may be an absolute URL (a paginated `next` link) — httpx uses it
        # verbatim; a relative path resolves against the client base_url.
        attempts = 0
        while True:
            try:
                resp = await self._client.request(method, path, params=params, json=json)
            except httpx.HTTPError as exc:
                raise MerakiClientError(f"{method} {path}: {describe_exc(exc)}") from exc
            if resp.status_code == 429 and attempts < _MAX_429_RETRIES:
                attempts += 1
                retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
                await asyncio.sleep(min(retry_after, _MAX_RETRY_AFTER_SECONDS))
                continue
            if resp.status_code == 401:
                raise MerakiClientError(
                    f"{method} {path}: HTTP 401 — API key invalid", status_code=401
                )
            if resp.status_code == 403:
                raise MerakiClientError(
                    f"{method} {path}: HTTP 403 — API key lacks access to this org/resource",
                    status_code=403,
                )
            if resp.status_code >= 400:
                raise MerakiClientError(
                    f"{method} {path}: HTTP {resp.status_code} {resp.text[:200]}",
                    status_code=resp.status_code,
                )
            return resp

    async def _get_json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """GET a single (non-paginated) resource and return the decoded JSON."""
        resp = await self._request("GET", path, params=params)
        try:
            return resp.json()
        except ValueError as exc:
            raise MerakiClientError(f"GET {path}: response was not JSON ({exc})") from exc

    async def _get_paginated(
        self, path: str, params: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """GET a list endpoint, following ``Link: rel="next"`` up to 20 pages."""
        out: list[dict[str, Any]] = []
        next_path: str | None = path
        next_params: dict[str, Any] | None = params
        pages = 0
        while next_path is not None and pages < _MAX_PAGES:
            pages += 1
            resp = await self._request("GET", next_path, params=next_params)
            try:
                body = resp.json()
            except ValueError as exc:
                raise MerakiClientError(f"GET {next_path}: response was not JSON ({exc})") from exc
            if isinstance(body, list):
                out.extend(e for e in body if isinstance(e, dict))
            next_link = _parse_next_link(resp.headers.get("Link"))
            # The next link is a fully-qualified URL carrying its own query
            # string, so drop the original params on the follow-up request.
            next_path = next_link
            next_params = None
        return out

    # ── Read surface ─────────────────────────────────────────────────

    async def get_organization(self) -> _MerakiOrgInfo:
        """``GET /organizations/{org_id}`` — auth + sanity probe."""
        body = await self._get_json(f"/organizations/{self._org_id}")
        if not isinstance(body, dict):
            raise MerakiClientError("organization: unexpected response shape")
        return _MerakiOrgInfo(
            id=str(body.get("id") or self._org_id),
            name=str(body.get("name") or ""),
            url=str(body.get("url") or ""),
        )

    async def list_networks(self, network_ids: list[str] | None = None) -> list[_MerakiNetwork]:
        """Appliance networks via ``GET /organizations/{org_id}/networks``.

        Keeps only networks whose ``productTypes`` contains ``appliance``; when
        ``network_ids`` is non-empty, further restricts to those ids.
        """
        wanted = {n for n in (network_ids or []) if n}
        out: list[_MerakiNetwork] = []
        for e in await self._get_paginated(f"/organizations/{self._org_id}/networks"):
            net_id = str(e.get("id") or "").strip()
            if not net_id:
                continue
            product_types = [str(p) for p in (e.get("productTypes") or []) if p]
            if "appliance" not in product_types:
                continue
            if wanted and net_id not in wanted:
                continue
            out.append(
                _MerakiNetwork(
                    id=net_id,
                    name=str(e.get("name") or ""),
                    product_types=product_types,
                )
            )
        return out

    async def _fetch_vlans(self, network_id: str) -> list[dict[str, Any]]:
        """Raw ``GET /networks/{id}/appliance/vlans`` list.

        When VLANs are disabled on the network Meraki returns HTTP 400 with a
        body mentioning "VLANs are not enabled" — we treat that specific case as
        an empty list (single-LAN network). Every other 400 propagates.
        """
        try:
            body = await self._get_json(f"/networks/{network_id}/appliance/vlans")
        except MerakiClientError as exc:
            if exc.status_code == 400 and "vlans are not enabled" in str(exc).lower():
                return []
            raise
        if not isinstance(body, list):
            return []
        return [e for e in body if isinstance(e, dict)]

    @staticmethod
    def _vlan_from_entry(
        e: dict[str, Any], network_id: str, network_name: str
    ) -> _MerakiVlan | None:
        subnet = str(e.get("subnet") or "").strip()
        if not subnet:
            return None  # no CIDR configured on this vlan — skip
        return _MerakiVlan(
            network_id=network_id,
            network_name=network_name,
            vlan_id=str(e.get("id") or "").strip(),
            name=str(e.get("name") or ""),
            cidr=subnet,
            appliance_ip=str(e.get("applianceIp") or "").strip(),
        )

    @staticmethod
    def _reservations_from_entry(e: dict[str, Any], network_id: str) -> list[_MerakiReservation]:
        assignments = e.get("fixedIpAssignments")
        if not isinstance(assignments, dict):
            return []
        out: list[_MerakiReservation] = []
        for mac_key, spec in assignments.items():
            if not isinstance(spec, dict):
                continue
            ip = str(spec.get("ip") or "").strip()
            if not ip:
                continue
            out.append(
                _MerakiReservation(
                    network_id=network_id,
                    address=ip,
                    mac=_normalise_mac(str(mac_key)),
                    name=str(spec.get("name") or ""),
                )
            )
        return out

    async def list_vlans(self, network_id: str, network_name: str = "") -> list[_MerakiVlan]:
        """Per-network VLANs (with subnet CIDR + MX interface IP)."""
        return [
            v
            for e in await self._fetch_vlans(network_id)
            if (v := self._vlan_from_entry(e, network_id, network_name)) is not None
        ]

    async def list_reservations(self, network_id: str) -> list[_MerakiReservation]:
        """Fixed-IP reservations, flattened out of each vlan's
        ``fixedIpAssignments`` (a dict keyed by MAC → ``{"ip", "name"}``)."""
        out: list[_MerakiReservation] = []
        for e in await self._fetch_vlans(network_id):
            out.extend(self._reservations_from_entry(e, network_id))
        return out

    async def list_vlans_and_reservations(
        self, network_id: str, network_name: str = ""
    ) -> tuple[list[_MerakiVlan], list[_MerakiReservation]]:
        """VLANs + fixed-IP reservations from a SINGLE ``appliance/vlans`` fetch.

        The reconciler wants both and they come from the same endpoint —
        fetching once halves the API calls per network against the rate-limited
        Dashboard API (vs calling ``list_vlans`` + ``list_reservations``)."""
        entries = await self._fetch_vlans(network_id)
        vlans = [
            v
            for e in entries
            if (v := self._vlan_from_entry(e, network_id, network_name)) is not None
        ]
        reservations: list[_MerakiReservation] = []
        for e in entries:
            reservations.extend(self._reservations_from_entry(e, network_id))
        return vlans, reservations

    async def list_policy_objects(self) -> list[_MerakiPolicyObject]:
        """Org policy objects + groups.

        Individual objects come from ``GET
        /organizations/{org_id}/policyObjects`` (paginated); groups come from
        ``GET /organizations/{org_id}/policyObjects/groups``.
        """
        out: list[_MerakiPolicyObject] = []
        for e in await self._get_paginated(f"/organizations/{self._org_id}/policyObjects"):
            name = str(e.get("name") or "").strip()
            if not name:
                continue
            kind, value = classify_meraki_object(e)
            category = str(e.get("category") or "").strip()
            out.append(
                _MerakiPolicyObject(
                    name=name,
                    kind=kind,
                    value=value,
                    description=category,
                    tags=[category] if category else [],
                )
            )
        groups = await self._get_json(f"/organizations/{self._org_id}/policyObjects/groups")
        if isinstance(groups, list):
            for g in groups:
                if not isinstance(g, dict):
                    continue
                name = str(g.get("name") or "").strip()
                if not name:
                    continue
                object_ids = [str(o) for o in (g.get("objectIds") or []) if o]
                out.append(
                    _MerakiPolicyObject(
                        name=name,
                        kind="group",
                        value=", ".join(object_ids),
                        description="",
                        tags=["group"],
                    )
                )
        return out

    async def list_nat_rules(self, network_id: str) -> list[_MerakiNatRule]:
        """One-to-one NAT + port-forwarding rules, combined into one list."""
        out: list[_MerakiNatRule] = []

        one_to_one = await self._get_json(
            f"/networks/{network_id}/appliance/firewall/oneToOneNatRules"
        )
        for r in _rules_list(one_to_one):
            public_ip = str(r.get("publicIp") or "").strip() or None
            lan_ip = str(r.get("lanIp") or "").strip() or None
            out.append(
                _MerakiNatRule(
                    name=str(r.get("name") or "").strip() or f"1to1-{public_ip or lan_ip or '?'}",
                    kind="1to1",
                    source="",
                    original_dst=public_ip,
                    translated_dst=lan_ip,
                    translated_src=None,
                    description="",
                )
            )

        port_forward = await self._get_json(
            f"/networks/{network_id}/appliance/firewall/portForwardingRules"
        )
        for r in _rules_list(port_forward):
            lan_ip = str(r.get("lanIp") or "").strip() or None
            public_port = str(r.get("publicPort") or "").strip()
            name = str(r.get("name") or "").strip()
            if not name:
                name = f"pf-{lan_ip or '?'}:{public_port}" if public_port else f"pf-{lan_ip or '?'}"
            out.append(
                _MerakiNatRule(
                    name=name,
                    kind="port-forward",
                    source="",
                    original_dst=None,
                    translated_dst=lan_ip,
                    translated_src=None,
                    description="",
                )
            )
        return out

    async def list_clients(
        self, network_id: str, timespan_seconds: int = 86400
    ) -> list[_MerakiClientRow]:
        """Network clients via ``GET /networks/{id}/clients`` (Link-paginated).

        Clients with no ``ip`` are skipped (they can't seed IPAM).
        """
        out: list[_MerakiClientRow] = []
        params = {"perPage": 1000, "timespan": timespan_seconds}
        for c in await self._get_paginated(f"/networks/{network_id}/clients", params):
            ip = str(c.get("ip") or "").strip()
            if not ip:
                continue
            hostname = (
                str(c.get("description") or "").strip()
                or str(c.get("dhcpHostname") or "").strip()
                or str(c.get("hostname") or "").strip()
            )
            out.append(
                _MerakiClientRow(
                    network_id=network_id,
                    address=ip,
                    mac=_normalise_mac(str(c.get("mac") or "") or None),
                    hostname=hostname,
                    description=str(c.get("description") or "").strip(),
                )
            )
        return out

    # ── Enforcement surface — per-client device policy (#601 tier) ───

    async def find_client(self, network_id: str, mac: str) -> str | None:
        """Return the Meraki client id whose MAC matches, or None.

        Scans ``GET /networks/{id}/clients`` over a 31-day timespan so a client
        that hasn't been chatty in the last day is still resolvable.
        """
        target = _normalise_mac(mac)
        if target is None:
            return None
        params = {"perPage": 1000, "timespan": 2678400}
        for c in await self._get_paginated(f"/networks/{network_id}/clients", params):
            if _normalise_mac(str(c.get("mac") or "") or None) == target:
                client_id = str(c.get("id") or "").strip()
                if client_id:
                    return client_id
        return None

    async def get_client_policy(self, network_id: str, client_id: str) -> _MerakiClientPolicy:
        """``GET /networks/{id}/clients/{client_id}/policy``."""
        body = await self._get_json(f"/networks/{network_id}/clients/{client_id}/policy")
        if not isinstance(body, dict):
            raise MerakiClientError("client policy: unexpected response shape")
        return _MerakiClientPolicy(
            client_id=client_id,
            mac=str(body.get("mac") or ""),
            device_policy=str(body.get("devicePolicy") or ""),
        )

    async def set_client_policy(self, network_id: str, client_id: str, device_policy: str) -> None:
        """``PUT /networks/{id}/clients/{client_id}/policy`` with the given
        ``devicePolicy`` (``Blocked`` / ``Normal`` for this phase)."""
        await self._request(
            "PUT",
            f"/networks/{network_id}/clients/{client_id}/policy",
            json={"devicePolicy": device_policy},
        )


# ── Module-level JSON parse helpers ──────────────────────────────────


def _parse_retry_after(value: str | None) -> float:
    """Parse a ``Retry-After`` header (delta-seconds) → float, default 1.0."""
    if not value:
        return 1.0
    try:
        return max(0.0, float(value.strip()))
    except (ValueError, TypeError):
        return 1.0


def _rules_list(body: Any) -> list[dict[str, Any]]:
    """Extract the ``rules`` array out of a firewall-rules response."""
    if isinstance(body, dict):
        rules = body.get("rules")
        if isinstance(rules, list):
            return [r for r in rules if isinstance(r, dict)]
    if isinstance(body, list):
        return [r for r in body if isinstance(r, dict)]
    return []


__all__ = [
    "MerakiClient",
    "MerakiClientError",
    "_MerakiClientPolicy",
    "_MerakiClientRow",
    "_MerakiNatRule",
    "_MerakiNetwork",
    "_MerakiOrgInfo",
    "_MerakiPolicyObject",
    "_MerakiReservation",
    "_MerakiVlan",
    "classify_meraki_object",
]
