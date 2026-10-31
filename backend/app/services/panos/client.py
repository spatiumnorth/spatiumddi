"""Minimal async Palo Alto PAN-OS / Panorama API client.

Two API surfaces are used:

* **REST API** (``/restapi/v{ver}/...``, header ``X-PAN-KEY``, JSON) for the
  object/policy reads that have good REST coverage — Address objects,
  Address Groups, NAT rules.
* **Legacy XML API** (``/api/?type=...&key=``, XML) for what REST doesn't
  cover cleanly: ``type=keygen`` (mint an API key from admin creds),
  ``type=op`` (op-commands — system info, interface IPs, DHCP leases,
  registered-IP dump), and ``type=user-id`` (the Dynamic-Address-Group
  ``IP → tag`` register/unregister — no policy commit).

Read paths are strictly read-only. The only writes are the User-ID tag
register/unregister (Shape 2 enforcement, #601 tier) — never object / rule /
config CRUD, never a commit.

``location`` scoping: a standalone NGFW is ``location=vsys&vsys=<vsys>``; a
Panorama device-group is ``location=device-group&device-group=<dg>``. One
``PANOSFirewall`` row = one scope.

Defensive parsing throughout — PAN-OS response shapes vary and we can't hit a
real box in tests, so every accessor guards missing keys / unexpected types.
XML responses come from the operator's own authenticated firewall; parsed with
the stdlib ElementTree (matching the codebase precedent in
``services/nmap/runner.py`` + ``services/backup/targets/webdav.py``).
"""

from __future__ import annotations

import ipaddress
import ssl
import xml.etree.ElementTree as ET  # noqa: S405 - firewall-controlled XML, no DTD
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

from app.core.exc_text import describe_exc

logger = structlog.get_logger(__name__)


class PANOSClientError(Exception):
    """Raised when the PAN-OS API returns an error we can't recover from.

    ``status_code`` is the HTTP status when the failure was a response and
    ``None`` for transport-level failures (timeout / connection refused). As
    with the OPNsense client, callers use it to tell a genuine 404 (safe to
    treat as an empty table) apart from a transient 5xx / timeout (must abort
    the reconcile rather than diff against an empty desired set — NN#5).
    """

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


# ── Read-shape dataclasses ───────────────────────────────────────────


@dataclass
class _PANSystemInfo:
    version: str
    model: str
    hostname: str
    serial: str


@dataclass
class _PANAddressObject:
    """A PAN-OS address object OR group, normalised.

    ``kind`` ∈ host | network | range | fqdn | group. For a group the
    ``value`` is a comma-joined member-name list (static group) or the DAG
    filter expression (dynamic group).
    """

    name: str
    kind: str
    value: str
    description: str
    tags: list[str] = field(default_factory=list)


@dataclass
class _PANNatRule:
    name: str
    kind: str  # 1to1 | pat | hide
    source: str  # original source (comma-joined) — informational
    original_dst: str | None  # original destination IP (external)
    translated_dst: str | None  # translated destination IP (internal, for DNAT)
    translated_src: str | None  # translated source IP (for SNAT)
    description: str


@dataclass
class _PANInterface:
    name: str
    cidr: str
    address: str
    zone: str


@dataclass
class _PANLease:
    address: str
    mac: str | None
    hostname: str
    state: str


@dataclass
class _PANRegisteredIP:
    ip: str
    tags: list[str] = field(default_factory=list)


def _normalise_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    m = mac.strip().lower().replace("-", ":")
    if not m or m in {"(incomplete)", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}:
        return None
    return m


def classify_address_value(entry: dict[str, Any]) -> tuple[str, str]:
    """Return ``(kind, value)`` for a REST Address entry.

    PAN-OS address objects carry exactly one of ``ip-netmask`` /
    ``ip-range`` / ``ip-wildcard`` / ``fqdn``. We map to our
    ``host | network | range | fqdn`` kinds (``ip-wildcard`` folds into
    ``network`` best-effort).
    """
    netmask = entry.get("ip-netmask")
    if isinstance(netmask, str) and netmask:
        # /32 (or no prefix) → host; anything wider → network.
        kind = "network" if "/" in netmask and not netmask.endswith("/32") else "host"
        return kind, netmask
    iprange = entry.get("ip-range")
    if isinstance(iprange, str) and iprange:
        return "range", iprange
    fqdn = entry.get("fqdn")
    if isinstance(fqdn, str) and fqdn:
        return "fqdn", fqdn
    wildcard = entry.get("ip-wildcard")
    if isinstance(wildcard, str) and wildcard:
        return "network", wildcard
    return "host", ""


def resolved_cidr_for(kind: str, value: str) -> str | None:
    """Best-effort canonical IP/CIDR for the IPAM drift join.

    ``host``/``network`` → the CIDR (``10.0.0.5/32`` → ``10.0.0.5/32``);
    ``range`` → the first IP as ``/32``; ``fqdn``/``group`` → ``None``.
    """
    value = (value or "").strip()
    if not value:
        return None
    try:
        if kind in ("host", "network"):
            if "/" in value:
                return str(ipaddress.ip_interface(value))
            # Bare address — validate before stamping /32 so a non-IP value
            # (e.g. a wildcard mask or garbage) resolves to None, not "junk/32".
            return f"{ipaddress.ip_address(value)}/32"
        if kind == "range":
            first = value.split("-", 1)[0].strip()
            ipaddress.ip_address(first)
            return f"{first}/32"
    except (ValueError, TypeError):
        return None
    return None


def _tags_from(entry: dict[str, Any]) -> list[str]:
    tag = entry.get("tag")
    if isinstance(tag, dict):
        members = tag.get("member")
        if isinstance(members, list):
            return [str(m) for m in members if m]
        if isinstance(members, str):
            return [members]
    return []


class PANOSClient:
    """Per-firewall async client. One instance per reconcile / push pass."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        api_key: str,
        api_version: str = "10.1",
        is_panorama: bool = False,
        vsys: str = "vsys1",
        device_group: str = "",
        verify_tls: bool = True,
        ca_bundle_pem: str = "",
    ) -> None:
        self._base = f"https://{host}:{port}"
        self._api_key = api_key
        self._api_version = api_version.strip() or "10.1"
        self._is_panorama = is_panorama
        self._vsys = vsys.strip() or "vsys1"
        self._device_group = device_group.strip()
        self._verify_tls = verify_tls
        self._ca_bundle_pem = ca_bundle_pem.strip()
        self._client: httpx.AsyncClient | None = None

    # ── Lifecycle ────────────────────────────────────────────────────

    @staticmethod
    def _build_verify(verify_tls: bool, ca_bundle_pem: str, endpoint: str) -> Any:
        if not verify_tls:
            logger.warning("panos_tls_verification_disabled", endpoint=endpoint)
            return False
        ca = (ca_bundle_pem or "").strip()
        if ca:
            return ssl.create_default_context(cadata=ca)
        return True

    async def __aenter__(self) -> PANOSClient:
        verify = self._build_verify(self._verify_tls, self._ca_bundle_pem, self._base)
        self._client = httpx.AsyncClient(
            base_url=self._base,
            headers={"X-PAN-KEY": self._api_key, "Accept": "application/json"},
            verify=verify,
            timeout=25.0,
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ── Location scoping ─────────────────────────────────────────────

    def _rest_location_params(self) -> dict[str, str]:
        if self._is_panorama:
            return {"location": "device-group", "device-group": self._device_group}
        return {"location": "vsys", "vsys": self._vsys}

    # ── REST helper ──────────────────────────────────────────────────

    async def _rest_get(self, resource: str) -> list[dict[str, Any]]:
        """GET a REST object/policy list and return its ``result.entry`` list.

        A 404 is returned as an empty list only by the caller that opts in —
        here we raise so callers distinguish absent-endpoint from transient.
        """
        assert self._client is not None, "use within 'async with'"
        path = f"/restapi/v{self._api_version}/{resource}"
        params = self._rest_location_params()
        try:
            resp = await self._client.get(path, params=params)
        except httpx.HTTPError as exc:
            raise PANOSClientError(f"{path}: {describe_exc(exc)}") from exc
        if resp.status_code == 401:
            raise PANOSClientError(f"{path}: HTTP 401 — API key invalid", status_code=401)
        if resp.status_code == 403:
            raise PANOSClientError(
                f"{path}: HTTP 403 — API key lacks privilege for this path", status_code=403
            )
        if resp.status_code >= 400:
            raise PANOSClientError(
                f"{path}: HTTP {resp.status_code} {resp.text[:200]}", status_code=resp.status_code
            )
        try:
            body = resp.json()
        except ValueError as exc:
            raise PANOSClientError(f"{path}: response was not JSON ({exc})") from exc
        result = body.get("result") if isinstance(body, dict) else None
        entries = result.get("entry") if isinstance(result, dict) else None
        if entries is None:
            return []
        if isinstance(entries, dict):  # single-entry responses aren't wrapped in a list
            entries = [entries]
        return [e for e in entries if isinstance(e, dict)]

    # ── XML API helper ───────────────────────────────────────────────

    async def _xml_request(self, params: dict[str, str]) -> ET.Element:
        """Issue an XML-API request and return the parsed ``<response>`` root.

        Raises ``PANOSClientError`` on transport failure, HTTP error, unparsable
        XML, or a ``status="error"`` response envelope.
        """
        assert self._client is not None, "use within 'async with'"
        query = dict(params)
        query["key"] = self._api_key
        try:
            resp = await self._client.get("/api/", params=query)
        except httpx.HTTPError as exc:
            raise PANOSClientError(f"/api/ ({params.get('type')}): {describe_exc(exc)}") from exc
        if resp.status_code == 403:
            raise PANOSClientError(
                f"/api/ ({params.get('type')}): HTTP 403 — key lacks privilege", status_code=403
            )
        if resp.status_code >= 400:
            raise PANOSClientError(
                f"/api/ ({params.get('type')}): HTTP {resp.status_code} {resp.text[:200]}",
                status_code=resp.status_code,
            )
        try:
            root = ET.fromstring(resp.text)  # noqa: S314 - firewall-controlled XML, no DTD
        except ET.ParseError as exc:
            raise PANOSClientError(f"/api/ ({params.get('type')}): bad XML ({exc})") from exc
        if root.get("status") == "error":
            msg = "".join(root.itertext()).strip() or "unknown error"
            raise PANOSClientError(f"/api/ ({params.get('type')}): {msg[:200]}")
        return root

    async def _op(self, cmd: str) -> ET.Element:
        return await self._xml_request({"type": "op", "cmd": cmd})

    # ── Keygen (static — mint an API key from admin creds) ───────────

    @classmethod
    async def keygen(
        cls,
        *,
        host: str,
        port: int,
        username: str,
        password: str,
        verify_tls: bool = True,
        ca_bundle_pem: str = "",
    ) -> str:
        """Mint an API key via ``type=keygen``. Used by the test/create flow so
        operators supply admin creds once instead of pasting a raw key."""
        base = f"https://{host}:{port}"
        verify = cls._build_verify(verify_tls, ca_bundle_pem, base)
        async with httpx.AsyncClient(base_url=base, verify=verify, timeout=25.0) as client:
            try:
                resp = await client.get(
                    "/api/",
                    params={"type": "keygen", "user": username, "password": password},
                )
            except httpx.HTTPError as exc:
                raise PANOSClientError(f"keygen: {describe_exc(exc)}") from exc
            if resp.status_code >= 400:
                raise PANOSClientError(
                    f"keygen: HTTP {resp.status_code} {resp.text[:200]}",
                    status_code=resp.status_code,
                )
            try:
                root = ET.fromstring(resp.text)  # noqa: S314 - firewall-controlled XML
            except ET.ParseError as exc:
                raise PANOSClientError(f"keygen: bad XML ({exc})") from exc
            if root.get("status") == "error":
                msg = "".join(root.itertext()).strip() or "invalid credentials"
                raise PANOSClientError(f"keygen: {msg[:200]}")
            key_el = root.find(".//key")
            key_text = (key_el.text or "").strip() if key_el is not None else ""
            if not key_text:
                raise PANOSClientError("keygen: no key in response")
            return key_text

    # ── Read surface ─────────────────────────────────────────────────

    async def get_system_info(self) -> _PANSystemInfo:
        """``show system info`` — auth + sanity probe."""
        root = await self._op("<show><system><info></info></system></show>")
        info = root.find(".//result/system")

        def _text(tag: str) -> str:
            if info is None:
                return ""
            el = info.find(tag)
            return (el.text or "").strip() if el is not None and el.text else ""

        return _PANSystemInfo(
            version=_text("sw-version") or "unknown",
            model=_text("model"),
            hostname=_text("hostname"),
            serial=_text("serial"),
        )

    async def list_address_objects(self) -> list[_PANAddressObject]:
        """Address objects via REST ``Objects/Addresses``."""
        out: list[_PANAddressObject] = []
        for e in await self._rest_get("Objects/Addresses"):
            name = str(e.get("@name") or "").strip()
            if not name:
                continue
            kind, value = classify_address_value(e)
            out.append(
                _PANAddressObject(
                    name=name,
                    kind=kind,
                    value=value,
                    description=str(e.get("description") or "").strip(),
                    tags=_tags_from(e),
                )
            )
        return out

    async def list_address_groups(self) -> list[_PANAddressObject]:
        """Address groups via REST ``Objects/AddressGroups``.

        A static group carries ``static.member`` (list of member names); a
        dynamic group carries ``dynamic.filter`` (a DAG tag expression).
        """
        out: list[_PANAddressObject] = []
        for e in await self._rest_get("Objects/AddressGroups"):
            name = str(e.get("@name") or "").strip()
            if not name:
                continue
            value = ""
            static = e.get("static")
            if isinstance(static, dict):
                members = static.get("member")
                if isinstance(members, list):
                    value = ", ".join(str(m) for m in members if m)
                elif isinstance(members, str):
                    value = members
            dynamic = e.get("dynamic")
            if isinstance(dynamic, dict) and dynamic.get("filter"):
                value = f"filter: {dynamic['filter']}"
            out.append(
                _PANAddressObject(
                    name=name,
                    kind="group",
                    value=value,
                    description=str(e.get("description") or "").strip(),
                    tags=_tags_from(e),
                )
            )
        return out

    async def list_nat_rules(self) -> list[_PANNatRule]:
        """NAT rules via REST ``Policies/NatRules``.

        We extract the destination-NAT (DNAT — original dst → translated dst,
        i.e. an inbound 1:1 / port-forward) and source-NAT (SNAT — hide /
        static) shapes into a neutral form the ``nat_mapping`` mirror consumes.
        """
        out: list[_PANNatRule] = []
        for e in await self._rest_get("Policies/NatRules"):
            name = str(e.get("@name") or "").strip()
            if not name:
                continue
            src = _members_str(e.get("source"))
            orig_dst_list = _members_list(e.get("destination"))
            orig_dst = orig_dst_list[0] if orig_dst_list else None

            translated_dst = None
            dst_trans = e.get("destination-translation")
            if isinstance(dst_trans, dict):
                translated_dst = _first_str(dst_trans.get("translated-address"))

            translated_src = None
            kind = "1to1"
            src_trans = e.get("source-translation")
            if isinstance(src_trans, dict):
                if "dynamic-ip-and-port" in src_trans:
                    kind = "hide"
                    translated_src = _dip_translated(src_trans.get("dynamic-ip-and-port"))
                elif "static-ip" in src_trans:
                    kind = "1to1"
                    st = src_trans.get("static-ip")
                    translated_src = (
                        _first_str(st.get("translated-address")) if isinstance(st, dict) else None
                    )
                elif "dynamic-ip" in src_trans:
                    kind = "hide"
                    di = src_trans.get("dynamic-ip")
                    translated_src = (
                        _first_str(di.get("translated-address")) if isinstance(di, dict) else None
                    )
            if translated_dst is not None:
                kind = "1to1"  # DNAT / port-forward — inbound 1:1

            out.append(
                _PANNatRule(
                    name=name,
                    kind=kind,
                    source=src,
                    original_dst=orig_dst,
                    translated_dst=translated_dst,
                    translated_src=translated_src,
                    description=str(e.get("description") or "").strip(),
                )
            )
        return out

    async def list_interfaces(self) -> list[_PANInterface]:
        """Interface IPs via ``show interface all`` (op).

        Returns only ifnet entries carrying a real IPv4/IPv6 CIDR. Zone is
        looked up from the same response's ``hw`` / ``ifnet`` where present.
        """
        root = await self._op("<show><interface>all</interface></show>")
        out: list[_PANInterface] = []
        ifnet = root.find(".//result/ifnet")
        if ifnet is None:
            return out
        for entry in ifnet.findall("entry"):
            name = _el_text(entry, "name")
            ip = _el_text(entry, "ip")
            zone = _el_text(entry, "zone")
            if not name or not ip or ip in ("N/A", "unknown"):
                continue
            try:
                iface = ipaddress.ip_interface(ip)
            except (ValueError, TypeError):
                continue
            out.append(
                _PANInterface(
                    name=name,
                    cidr=str(iface.network),
                    address=str(iface.ip),
                    zone=zone,
                )
            )
        return out

    async def list_dhcp_leases(self) -> list[_PANLease]:
        """DHCP-server leases via ``show dhcp server lease`` (op).

        Empty list when the firewall is not a DHCP server (no lease element).
        """
        root = await self._op(
            "<show><dhcp><server><lease><interface>all</interface>"
            "</lease></server></dhcp></show>"
        )
        out: list[_PANLease] = []
        for entry in root.findall(".//result/interface/lease/entry"):
            ip = _el_text(entry, "ip")
            if not ip:
                continue
            out.append(
                _PANLease(
                    address=ip,
                    mac=_normalise_mac(_el_text(entry, "mac")),
                    hostname=_el_text(entry, "hostname"),
                    state=_el_text(entry, "state") or "unknown",
                )
            )
        return out

    # ── Write surface — User-ID DAG tag register (#601 tier, opt-in) ─

    async def list_registered_ips(self, tag: str | None = None) -> list[_PANRegisteredIP]:
        """Dump registered IP→tag mappings via
        ``show object registered-ip [tag <t>]`` (op).

        Used so DAG enforcement can read current on-device state and add only
        what's missing / remove only what it owns — never diff against a
        bad-empty set (NN#5)."""
        if tag:
            cmd = (
                "<show><object><registered-ip><tag>"
                f"<entry name='{_xml_escape(tag)}'/>"
                "</tag></registered-ip></object></show>"
            )
        else:
            cmd = "<show><object><registered-ip><all></all></registered-ip></object></show>"
        root = await self._op(cmd)
        out: list[_PANRegisteredIP] = []
        for entry in root.findall(".//result/entry"):
            ip = (entry.get("ip") or "").strip()
            if not ip:
                continue
            tags = [
                (m.text or "").strip()
                for m in entry.findall(".//member")
                if m.text and m.text.strip()
            ]
            out.append(_PANRegisteredIP(ip=ip, tags=tags))
        return out

    async def register_ip_tag(self, ip: str, tag: str) -> None:
        """Register ``ip → tag`` via the User-ID API (no commit).

        ``timeout='0'`` = persistent registration. A pre-created Dynamic
        Address Group matching ``tag`` enforces it near-instantly.
        """
        await self._user_id(
            "<register>"
            f"<entry ip='{_xml_escape(ip)}'><tag>"
            f"<member timeout='0'>{_xml_escape(tag)}</member>"
            "</tag></entry></register>"
        )

    async def unregister_ip_tag(self, ip: str, tag: str) -> None:
        """Remove a single ``ip → tag`` registration via the User-ID API."""
        await self._user_id(
            "<unregister>"
            f"<entry ip='{_xml_escape(ip)}'><tag>"
            f"<member>{_xml_escape(tag)}</member>"
            "</tag></entry></unregister>"
        )

    async def _user_id(self, payload_inner: str) -> None:
        cmd = (
            "<uid-message><version>1.0</version><type>update</type>"
            f"<payload>{payload_inner}</payload></uid-message>"
        )
        params = {"type": "user-id", "cmd": cmd}
        if not self._is_panorama:
            params["vsys"] = self._vsys
        await self._xml_request(params)


# ── Module-level XML/JSON parse helpers ──────────────────────────────


def _el_text(parent: ET.Element, tag: str) -> str:
    el = parent.find(tag)
    return (el.text or "").strip() if el is not None and el.text else ""


def _members_list(node: Any) -> list[str]:
    if isinstance(node, dict):
        m = node.get("member")
        if isinstance(m, list):
            return [str(x) for x in m if x]
        if isinstance(m, str):
            return [m]
    if isinstance(node, list):
        return [str(x) for x in node if x]
    if isinstance(node, str):
        return [node]
    return []


def _members_str(node: Any) -> str:
    return ", ".join(_members_list(node))


def _first_str(node: Any) -> str | None:
    vals = _members_list(node)
    return vals[0] if vals else None


def _dip_translated(node: Any) -> str | None:
    if isinstance(node, dict):
        return _first_str(node.get("translated-address"))
    return None


def _xml_escape(value: str) -> str:
    """Escape a value for safe interpolation into an XML-API command string.

    IPs / tag names are already tightly validated upstream, but the User-ID
    cmd is built by string concat, so escape defensively."""
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("'", "&apos;")
        .replace('"', "&quot;")
    )


__all__ = [
    "PANOSClient",
    "PANOSClientError",
    "_PANAddressObject",
    "_PANInterface",
    "_PANLease",
    "_PANNatRule",
    "_PANRegisteredIP",
    "_PANSystemInfo",
    "classify_address_value",
    "resolved_cidr_for",
]
