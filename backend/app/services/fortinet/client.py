"""Minimal async FortiGate FortiOS REST API client (#606).

FortiGate is reached at ``https://{host}:{port}`` with **bearer-token auth**
(header ``Authorization: Bearer <api_token>``). Every request carries the
``vdom=<vdom>`` query param (default ``root``) — FortiOS scopes objects per
virtual domain and omitting it silently targets the management VDOM.

Read paths are strictly read-only — this client implements **no** write
methods. FortiGate enforcement (the DAG-equivalent tier) is driven by a polled
feed on the FortiGate side, not by client writes.

Defensive parsing throughout — FortiOS response shapes vary across versions and
we can't hit a real box in tests, so every accessor guards missing keys /
unexpected types. Mirrors the structure of ``services/panos/client.py``.
"""

from __future__ import annotations

import ipaddress
import ssl
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

from app.core.exc_text import describe_exc

logger = structlog.get_logger(__name__)


class FortinetClientError(Exception):
    """Raised when the FortiGate API returns an error we can't recover from.

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
class _FortiSystemInfo:
    version: str
    model: str
    hostname: str
    serial: str


@dataclass
class _FortiAddressObject:
    """A FortiGate address object OR group, normalised.

    ``kind`` ∈ host | network | range | fqdn | group. For a group the
    ``value`` is a comma-joined member-name list.
    """

    name: str
    kind: str
    value: str
    description: str
    tags: list[str] = field(default_factory=list)


@dataclass
class _FortiNatRule:
    name: str
    kind: str  # always "1to1" for a VIP (DNAT)
    source: str  # "" (VIPs have no source) — informational
    original_dst: str | None  # the VIP extip (external / public IP)
    translated_dst: str | None  # the VIP mappedip (internal IP)
    translated_src: str | None  # None for VIPs
    description: str


@dataclass
class _FortiInterface:
    name: str
    cidr: str
    address: str
    zone: str


@dataclass
class _FortiLease:
    address: str
    mac: str | None
    hostname: str
    state: str


# ── Pure parse helpers ───────────────────────────────────────────────


def _normalise_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    m = mac.strip().lower().replace("-", ":")
    if not m or m in {"(incomplete)", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}:
        return None
    return m


def _first_ip(value: Any) -> str | None:
    """Return the first IP from a bare IP or a ``a-b`` range string, else None."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v:
        return None
    candidate = v.split("-", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except (ValueError, TypeError):
        return None


def _subnet_to_cidr(subnet: str) -> str | None:
    """Convert FortiOS ``"10.0.0.0 255.255.255.0"`` → ``"10.0.0.0/24"``.

    A value already in CIDR form (``"10.0.0.0/24"``) passes through. Returns
    ``None`` on anything unparseable.
    """
    s = (subnet or "").strip()
    if not s:
        return None
    parts = s.split()
    if len(parts) == 2:
        addr, mask = parts
        try:
            return str(ipaddress.ip_network(f"{addr}/{mask}", strict=False))
        except (ValueError, TypeError):
            return None
    # Bare CIDR or bare address passthrough.
    try:
        return str(ipaddress.ip_network(s, strict=False))
    except (ValueError, TypeError):
        return None


def classify_fortinet_address(entry: dict[str, Any]) -> tuple[str, str]:
    """Return ``(kind, value)`` for a FortiOS firewall/address entry.

    ``ipmask`` → ``host`` (/32) or ``network`` with a CIDR value; ``iprange``
    → ``range`` (``start-end``); ``fqdn`` → ``fqdn``; anything else
    (geography / wildcard / unknown) → ``host`` with an empty value so the
    reconciler can skip it cleanly.
    """
    atype = str(entry.get("type") or "").strip().lower()

    if atype == "ipmask" or (not atype and entry.get("subnet")):
        cidr = _subnet_to_cidr(str(entry.get("subnet") or ""))
        if not cidr:
            return "host", ""
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except (ValueError, TypeError):
            return "host", ""
        kind = "host" if net.prefixlen == net.max_prefixlen else "network"
        return kind, cidr

    if atype == "iprange" or (not atype and entry.get("start-ip")):
        start = str(entry.get("start-ip") or "").strip()
        end = str(entry.get("end-ip") or "").strip()
        if start and end:
            return "range", f"{start}-{end}"
        return "range", start or end

    if atype == "fqdn" or (not atype and entry.get("fqdn")):
        return "fqdn", str(entry.get("fqdn") or "").strip()

    return "host", ""


def _tags_from_tagging(entry: dict[str, Any]) -> list[str]:
    """Flatten FortiOS ``tagging: [{"tags": ["t1", "t2"]}, ...]`` → ``["t1", "t2"]``."""
    out: list[str] = []
    tagging = entry.get("tagging")
    if isinstance(tagging, list):
        for group in tagging:
            if not isinstance(group, dict):
                continue
            tags = group.get("tags")
            if isinstance(tags, list):
                out.extend(str(t) for t in tags if t)
            elif isinstance(tags, str) and tags:
                out.append(tags)
    return out


# ── Client ───────────────────────────────────────────────────────────


class FortinetClient:
    """Per-firewall async client. One instance per reconcile pass."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        api_token: str,
        vdom: str = "root",
        verify_tls: bool = True,
        ca_bundle_pem: str = "",
    ) -> None:
        self._base = f"https://{host}:{port}"
        self._api_token = api_token
        self._vdom = vdom.strip() or "root"
        self._verify_tls = verify_tls
        self._ca_bundle_pem = ca_bundle_pem.strip()
        self._client: httpx.AsyncClient | None = None

    # ── Lifecycle ────────────────────────────────────────────────────

    @staticmethod
    def _build_verify(verify_tls: bool, ca_bundle_pem: str, endpoint: str) -> Any:
        if not verify_tls:
            logger.warning("fortinet_tls_verification_disabled", endpoint=endpoint)
            return False
        ca = (ca_bundle_pem or "").strip()
        if ca:
            return ssl.create_default_context(cadata=ca)
        return True

    async def __aenter__(self) -> FortinetClient:
        verify = self._build_verify(self._verify_tls, self._ca_bundle_pem, self._base)
        self._client = httpx.AsyncClient(
            base_url=self._base,
            headers={
                "Authorization": f"Bearer {self._api_token}",
                "Accept": "application/json",
            },
            verify=verify,
            timeout=25.0,
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ── HTTP helpers ─────────────────────────────────────────────────

    async def _get_json(self, path: str) -> Any:
        """GET ``path`` with the mandatory ``vdom`` param; return parsed JSON."""
        assert self._client is not None, "use within 'async with'"
        try:
            resp = await self._client.get(path, params={"vdom": self._vdom})
        except httpx.HTTPError as exc:
            raise FortinetClientError(f"{path}: {describe_exc(exc)}") from exc
        if resp.status_code == 401:
            raise FortinetClientError(f"{path}: HTTP 401 — API token invalid", status_code=401)
        if resp.status_code == 403:
            raise FortinetClientError(
                f"{path}: HTTP 403 — API token lacks privilege for this path", status_code=403
            )
        if resp.status_code >= 400:
            raise FortinetClientError(
                f"{path}: HTTP {resp.status_code} {resp.text[:200]}", status_code=resp.status_code
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise FortinetClientError(f"{path}: response was not JSON ({exc})") from exc

    async def _get_results(self, path: str) -> list[dict[str, Any]]:
        """GET ``path`` and return its ``results`` list (defensively normalised)."""
        body = await self._get_json(path)
        results = body.get("results") if isinstance(body, dict) else None
        if results is None:
            return []
        if isinstance(results, dict):  # single-entry responses aren't always listed
            results = [results]
        if not isinstance(results, list):
            return []
        return [r for r in results if isinstance(r, dict)]

    # ── Read surface ─────────────────────────────────────────────────

    async def get_system_info(self) -> _FortiSystemInfo:
        """``GET /api/v2/monitor/system/status`` — auth + sanity probe."""
        body = await self._get_json("/api/v2/monitor/system/status")
        raw_version = str(body.get("version") or "").strip() if isinstance(body, dict) else ""
        version = _clean_version(raw_version) or "unknown"
        results = body.get("results") if isinstance(body, dict) else None
        if not isinstance(results, dict):
            results = {}
        return _FortiSystemInfo(
            version=version,
            model=str(results.get("model_name") or results.get("model") or "").strip(),
            hostname=str(results.get("hostname") or "").strip(),
            serial=str(results.get("serial") or "").strip(),
        )

    async def list_address_objects(self) -> list[_FortiAddressObject]:
        """Address objects via ``GET /api/v2/cmdb/firewall/address``."""
        out: list[_FortiAddressObject] = []
        for e in await self._get_results("/api/v2/cmdb/firewall/address"):
            name = str(e.get("name") or "").strip()
            if not name:
                continue
            kind, value = classify_fortinet_address(e)
            out.append(
                _FortiAddressObject(
                    name=name,
                    kind=kind,
                    value=value,
                    description=str(e.get("comment") or "").strip(),
                    tags=_tags_from_tagging(e),
                )
            )
        return out

    async def list_address_groups(self) -> list[_FortiAddressObject]:
        """Address groups via ``GET /api/v2/cmdb/firewall/addrgrp``."""
        out: list[_FortiAddressObject] = []
        for e in await self._get_results("/api/v2/cmdb/firewall/addrgrp"):
            name = str(e.get("name") or "").strip()
            if not name:
                continue
            members: list[str] = []
            member = e.get("member")
            if isinstance(member, list):
                for m in member:
                    if isinstance(m, dict):
                        mn = str(m.get("name") or "").strip()
                        if mn:
                            members.append(mn)
                    elif isinstance(m, str) and m.strip():
                        members.append(m.strip())
            out.append(
                _FortiAddressObject(
                    name=name,
                    kind="group",
                    value=", ".join(members),
                    description=str(e.get("comment") or "").strip(),
                    tags=_tags_from_tagging(e),
                )
            )
        return out

    async def list_nat_rules(self) -> list[_FortiNatRule]:
        """VIPs (DNAT) via ``GET /api/v2/cmdb/firewall/vip``.

        A FortiGate VIP is an inbound 1:1 / port-forward — ``extip`` (external)
        maps to ``mappedip`` (internal). We fold each into the neutral
        ``nat_mapping`` shape the mirror consumes.
        """
        out: list[_FortiNatRule] = []
        for e in await self._get_results("/api/v2/cmdb/firewall/vip"):
            name = str(e.get("name") or "").strip()
            if not name:
                continue
            original_dst = _first_ip(e.get("extip"))
            translated_dst = _mapped_first_ip(e.get("mappedip"))
            out.append(
                _FortiNatRule(
                    name=name,
                    kind="1to1",
                    source="",
                    original_dst=original_dst,
                    translated_dst=translated_dst,
                    translated_src=None,
                    description=str(e.get("comment") or "").strip(),
                )
            )
        return out

    async def list_interfaces(self) -> list[_FortiInterface]:
        """Interfaces via ``GET /api/v2/cmdb/system/interface``.

        Only entries carrying a real IPv4 CIDR are returned; ``0.0.0.0``
        (unset) and unparseable values are skipped.
        """
        out: list[_FortiInterface] = []
        for e in await self._get_results("/api/v2/cmdb/system/interface"):
            name = str(e.get("name") or "").strip()
            if not name:
                continue
            ip_raw = str(e.get("ip") or "").strip()
            parts = ip_raw.split()
            if len(parts) != 2:
                continue
            addr, mask = parts
            if addr in ("0.0.0.0", ""):
                continue
            try:
                iface = ipaddress.ip_interface(f"{addr}/{mask}")
            except (ValueError, TypeError):
                continue
            out.append(
                _FortiInterface(
                    name=name,
                    cidr=str(iface.network),
                    address=str(iface.ip),
                    zone=str(e.get("zone") or "").strip(),
                )
            )
        return out

    async def list_dhcp_leases(self) -> list[_FortiLease]:
        """DHCP-server leases via ``GET /api/v2/monitor/system/dhcp``."""
        out: list[_FortiLease] = []
        for r in await self._get_results("/api/v2/monitor/system/dhcp"):
            ip = str(r.get("ip") or "").strip()
            if not ip:
                continue
            state = str(r.get("status") or r.get("type") or "").strip() or "unknown"
            out.append(
                _FortiLease(
                    address=ip,
                    mac=_normalise_mac(str(r.get("mac") or "") or None),
                    hostname=str(r.get("hostname") or "").strip(),
                    state=state,
                )
            )
        return out


# ── Module-level parse helpers ───────────────────────────────────────


def _clean_version(raw: str) -> str:
    """``"v7.4.3 build1234"`` → ``"7.4.3"`` — strip a leading ``v``, first token."""
    v = (raw or "").strip()
    if not v:
        return ""
    v = v.split()[0]
    if v[:1].lower() == "v":
        v = v[1:]
    return v


def _mapped_first_ip(value: Any) -> str | None:
    """Extract the first IP from a FortiOS VIP ``mappedip`` field.

    Shape is usually a list of ``{"range": "10.0.0.5"}`` objects; sometimes a
    bare string. Take the first entry's first IP.
    """
    if isinstance(value, list):
        if not value:
            return None
        first = value[0]
        if isinstance(first, dict):
            return _first_ip(first.get("range"))
        if isinstance(first, str):
            return _first_ip(first)
        return None
    if isinstance(value, str):
        return _first_ip(value)
    return None


__all__ = [
    "FortinetClient",
    "FortinetClientError",
    "_FortiAddressObject",
    "_FortiInterface",
    "_FortiLease",
    "_FortiNatRule",
    "_FortiSystemInfo",
    "classify_fortinet_address",
]
