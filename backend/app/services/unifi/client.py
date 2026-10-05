"""Async UniFi Network client — dual-transport (local + cloud) and
dual-API (public Integration v1 + legacy controller).

Why two APIs:
    The public Integration API at ``/proxy/network/integration/v1/...``
    is well-documented and X-API-Key authenticated, but the
    response payloads deliberately omit the fields we need to
    mirror clients into IPAM (no ``mac``, no ``hostname``, no
    ``network_id``, no ``oui``, no ``fixed_ip``, no DHCP scope on
    networks, no ``ip_subnet``). The legacy controller API at
    ``/proxy/network/api/s/{site}/...`` returns the full data and
    is what the UniFi UI itself calls. Both ride the same TLS
    connection and accept the same ``X-API-Key`` header on modern
    UniFi OS controllers; we route per-call to whichever one
    actually carries the field we need.

Why two transports:
    Local controllers are reached directly:
        https://<controller>:443/proxy/network/...
    Cloud-hosted controllers are reached through the cloud
    connector at api.ui.com:
        https://api.ui.com/proxy/network/integration/v1/connector/
        consoles/<host_id>/<rest_of_path>
    Same HTTP semantics either way — the client just prepends the
    cloud connector segment when ``mode='cloud'``.

Auth:
    * ``api_key`` — modern UniFi OS (≥ 4.x). Header
      ``X-API-Key: <key>``. Required for cloud mode.
    * ``user_password`` — legacy local-only fallback. POST
      ``/api/login`` returns a session cookie + an ``X-CSRF-Token``
      header that must be replayed on writes. Reads work with
      cookie alone, which is all we need for v1.

Defensive parsing:
    The legacy controller API is undocumented and shifts between
    UniFi OS versions. Every field we read is treated as optional;
    rows whose required fields (``mac``, ``ip``, ``ip_subnet``)
    are missing are logged-and-skipped rather than crashing the
    pass.
"""

from __future__ import annotations

import ipaddress
import ssl
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

from app.services._mirror_shape import require_keyed_list, require_list

logger = structlog.get_logger(__name__)


class UnifiClientError(Exception):
    """Raised when the controller / cloud proxy returns an error
    we can't recover from. Carries HTTP status + path + first
    200 bytes of the body so operator-facing messages are useful.
    """


# ── Wire-shape dataclasses ───────────────────────────────────────────


@dataclass
class _UnifiVersion:
    version: str  # e.g. "9.0.114"


@dataclass(frozen=True)
class _UnifiSite:
    """A site as returned by the legacy ``/api/self/sites`` (preferred,
    carries ``desc`` + ``name`` together) or the public Integration
    API ``/sites`` (only carries ``id`` + ``name``).

    ``name`` is the short id (``default``, ``branch1``); ``desc`` is
    the human label. ``site_id`` is the controller's UUID for the
    site — the public Integration API requires this in URLs but the
    legacy API uses ``name`` instead. We populate both.

    Frozen so the reconciler can use site objects as dict keys
    without crashing the whole sweep on the first sync.
    """

    name: str  # short id ("default")
    desc: str  # human label ("Branch Office")
    site_id: str | None = None  # UUID, integration-API only


@dataclass
class _UnifiNetwork:
    """One network from ``rest/networkconf``. Only the fields we
    actually mirror are kept — UniFi adds many more (DHCP options,
    IGMP snooping, IPv6 RA, …) that aren't relevant for IPAM.

    Note: ``ip_subnet`` is the canonical CIDR; ``vlan`` is the
    802.1Q tag (0 = untagged); ``purpose`` distinguishes user
    networks (``corporate`` / ``guest``) from non-LAN ones (``vpn``
    / ``vlan-only`` / ``wan``) we want to skip.
    """

    network_id: str  # UniFi internal id
    name: str
    purpose: str  # "corporate" | "guest" | "vpn" | "wan" | ...
    enabled: bool
    ip_subnet: str | None  # "10.0.0.1/24" — the gateway with prefix
    vlan: int | None
    domain_name: str | None
    dhcpd_enabled: bool
    dhcpd_start: str | None
    dhcpd_stop: str | None
    dhcpd_leasetime: int | None
    dhcpd_dns: list[str] = field(default_factory=list)


@dataclass
class _UnifiClient:
    """A connected client (active or fixed-IP reservation).

    ``fixed_ip`` is set on operator-defined DHCP reservations and on
    "user-defined fixed IPs" from ``rest/user``. ``last_seen`` is a
    UNIX epoch in seconds (UniFi convention).

    ``is_wired`` distinguishes Ethernet / VPN from wireless, gates
    the include_wired / include_wireless toggles. ``is_vpn`` only
    becomes true on legacy versions that surface VPN clients in the
    same list — newer UniFi OS keeps them separate, so this is
    best-effort and the include_vpn toggle is informational either
    way.
    """

    mac: str  # canonical lowercase colon-separated
    ip: str | None
    hostname: str | None
    name: str | None  # operator-set alias (overrides hostname in UI)
    network_id: str | None
    oui: str | None
    fixed_ip: bool
    is_wired: bool
    is_vpn: bool
    is_guest: bool
    last_seen: int | None


# ── Helpers ───────────────────────────────────────────────────────────


def _normalise_mac(mac: str) -> str:
    """Canonical: lowercase, colon-separated, no whitespace.
    Returns empty string if the input clearly isn't a MAC.
    """
    s = mac.strip().lower().replace("-", ":").replace(".", ":")
    if not s or len(s.replace(":", "")) != 12:
        return ""
    return s


def _ip_subnet_to_cidr(value: str | None) -> str | None:
    """UniFi's ``ip_subnet`` format is ``<gateway>/<prefix>``
    (e.g. ``10.0.0.1/24``). Convert to a network CIDR
    (``10.0.0.0/24``) — that's how we mirror subnets.

    Returns ``None`` for empty / malformed input.
    """
    if not value or not isinstance(value, str):
        return None
    try:
        iface = ipaddress.ip_interface(value)
        return str(iface.network)
    except (ValueError, ipaddress.AddressValueError):
        return None


def _ip_subnet_to_gateway(value: str | None) -> str | None:
    """Return just the host IP from ``<gateway>/<prefix>``."""
    if not value or not isinstance(value, str):
        return None
    try:
        iface = ipaddress.ip_interface(value)
        return str(iface.ip)
    except (ValueError, ipaddress.AddressValueError):
        return None


def _is_ipam_relevant_purpose(purpose: str) -> bool:
    """Skip non-LAN networks that have no IPAM meaning.

    ``vpn`` networks are addressing pools managed inside the VPN
    server config and aren't bound to a physical L2 segment;
    ``wan`` is the upstream WAN config; ``vlan-only`` is an L2
    trunk with no L3 — we still surface it as a VLAN row but no
    subnet. ``site-vpn`` likewise.
    """
    return purpose in {"corporate", "guest", "remote-user-vpn"} or (purpose == "vlan-only")


# ── Client ────────────────────────────────────────────────────────────


@dataclass
class UnifiClientConfig:
    mode: str  # "local" | "cloud"
    host: str | None  # local only
    port: int  # local only
    cloud_host_id: str | None  # cloud only
    verify_tls: bool
    ca_bundle_pem: str
    auth_kind: str  # "api_key" | "user_password"
    api_key: str  # decrypted
    username: str  # decrypted
    password: str  # decrypted


class UnifiClient:
    """Per-controller async client. One instance per reconcile pass.

    Caller is responsible for ``async with`` lifecycle. Holds a
    single ``httpx.AsyncClient`` so every list call shares the TLS
    + cookie session.
    """

    def __init__(self, cfg: UnifiClientConfig) -> None:
        self._cfg = cfg
        self._client: httpx.AsyncClient | None = None
        # CSRF token captured from the legacy login response —
        # required on writes (we don't do writes in v1, but read
        # paths still pass the token through if present).
        self._csrf: str | None = None

    # ── Lifecycle ───────────────────────────────────────────────────

    async def __aenter__(self) -> UnifiClient:
        verify: Any
        if not self._cfg.verify_tls:
            verify = False
        elif self._cfg.ca_bundle_pem.strip():
            verify = ssl.create_default_context(cadata=self._cfg.ca_bundle_pem.strip())
        else:
            verify = True

        if self._cfg.mode == "cloud":
            base = "https://api.ui.com"
        else:
            host = (self._cfg.host or "").strip()
            if not host:
                raise UnifiClientError("local mode requires host")
            base = f"https://{host}:{self._cfg.port}"

        headers: dict[str, str] = {"Accept": "application/json"}
        if self._cfg.auth_kind == "api_key" and self._cfg.api_key:
            headers["X-API-Key"] = self._cfg.api_key

        if verify is False:
            # Operator opted out of TLS verification for this controller.
            # Surface it on every connect so the insecure posture is
            # visible in the centralized logs (#5); the who/when of
            # enabling it lives in the integration-target audit row.
            logger.warning("unifi_tls_verification_disabled", endpoint=base)

        self._client = httpx.AsyncClient(
            base_url=base,
            headers=headers,
            verify=verify,
            timeout=20.0,
            follow_redirects=True,
        )

        # Legacy controller-API password auth — only valid in local
        # mode (api.ui.com only accepts API keys).
        if self._cfg.auth_kind == "user_password" and self._cfg.mode == "local":
            await self._login_user_password()

        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _login_user_password(self) -> None:
        """Hit ``/api/login`` (legacy) — captures the session cookie
        on the httpx client and the CSRF token in ``self._csrf``.
        """
        assert self._client is not None
        try:
            resp = await self._client.post(
                "/api/login",
                json={
                    "username": self._cfg.username,
                    "password": self._cfg.password,
                    "remember": False,
                },
            )
        except httpx.HTTPError as exc:
            raise UnifiClientError(f"/api/login: {exc}") from exc
        if resp.status_code >= 400:
            raise UnifiClientError(f"/api/login: HTTP {resp.status_code} {resp.text[:200]}")
        # Newer controllers return the CSRF in a header; older ones
        # in a Set-Cookie value. Capture either.
        self._csrf = resp.headers.get("X-CSRF-Token") or resp.headers.get("X-Csrf-Token")

    # ── URL builders ────────────────────────────────────────────────

    def _integration_path(self, suffix: str) -> str:
        """Public Integration v1 path. Cloud mode wraps with the
        connector segment so the same suffix works in both transports.
        """
        suffix = suffix.lstrip("/")
        if self._cfg.mode == "cloud":
            host_id = (self._cfg.cloud_host_id or "").strip()
            if not host_id:
                raise UnifiClientError("cloud mode requires cloud_host_id")
            # Cloud connector wraps the integration path one level deeper.
            return f"/proxy/network/integration/v1/connector/consoles/{host_id}/proxy/network/integration/v1/{suffix}"
        return f"/proxy/network/integration/v1/{suffix}"

    def _legacy_path(self, suffix: str) -> str:
        """Legacy controller-API path (``/proxy/network/api/...``).
        Cloud mode tunnels through the connector at ``proxy/network``
        below it.
        """
        suffix = suffix.lstrip("/")
        if self._cfg.mode == "cloud":
            host_id = (self._cfg.cloud_host_id or "").strip()
            if not host_id:
                raise UnifiClientError("cloud mode requires cloud_host_id")
            return f"/proxy/network/integration/v1/connector/consoles/{host_id}/proxy/network/api/{suffix}"
        return f"/proxy/network/api/{suffix}"

    # ── Low-level GET helpers ───────────────────────────────────────

    async def _get_integration(self, suffix: str) -> Any:
        return await self._get(self._integration_path(suffix))

    async def _get_legacy(self, suffix: str) -> Any:
        """Legacy responses are wrapped ``{"meta": {...}, "data": [...]}``;
        unwrap to ``data`` for callers."""
        body = await self._get(self._legacy_path(suffix))
        if isinstance(body, dict):
            # #1555 — the legacy controller also signals failure in-band:
            # HTTP 200 with ``{"meta": {"rc": "error", ...}}`` (same
            # convention ``_post_legacy`` already honours for writes). A
            # read that "succeeded" this way must raise, not unwrap to a
            # missing/empty ``data`` the caller would treat as zero rows.
            meta = body.get("meta")
            if isinstance(meta, dict) and str(meta.get("rc", "")).lower() == "error":
                raise UnifiClientError(
                    f"{suffix}: controller reported an error — {meta.get('msg') or 'rc=error'}"
                )
            if "data" in body:
                return body["data"]
        return body

    async def _get(self, path: str) -> Any:
        assert self._client is not None, "use within 'async with'"
        try:
            resp = await self._client.get(path)
        except httpx.HTTPError as exc:
            raise UnifiClientError(f"{path}: {exc}") from exc
        if resp.status_code == 401:
            raise UnifiClientError(f"{path}: HTTP 401 — auth invalid / expired")
        if resp.status_code == 403:
            raise UnifiClientError(f"{path}: HTTP 403 — token / role denies this path")
        if resp.status_code == 404:
            raise UnifiClientError(f"{path}: HTTP 404 — endpoint not present on this controller")
        if resp.status_code == 429:
            raise UnifiClientError(f"{path}: HTTP 429 — rate-limited; backoff applied next pass")
        if resp.status_code >= 400:
            raise UnifiClientError(f"{path}: HTTP {resp.status_code} {resp.text[:200]}")
        try:
            return resp.json()
        except ValueError as exc:  # non-JSON body (HTML error page, …)
            raise UnifiClientError(f"{path}: non-JSON body: {resp.text[:200]}") from exc

    async def _post_legacy(self, suffix: str, payload: dict[str, Any]) -> Any:
        """POST to the legacy controller API, replaying the captured CSRF
        token (user_password auth) and relying on the ``X-API-Key`` header
        set at construction (api_key auth).

        The public Integration v1 API deliberately omits client-block, so
        every write rides this legacy path. Used only by the active
        block-sync surface (#601) — reads never write.
        """
        assert self._client is not None, "use within 'async with'"
        path = self._legacy_path(suffix)
        headers: dict[str, str] = {}
        if self._csrf:
            headers["X-CSRF-Token"] = self._csrf
        try:
            resp = await self._client.post(path, json=payload, headers=headers)
        except httpx.HTTPError as exc:
            raise UnifiClientError(f"{path}: {exc}") from exc
        if resp.status_code == 401:
            raise UnifiClientError(f"{path}: HTTP 401 — auth invalid / expired")
        if resp.status_code == 403:
            raise UnifiClientError(f"{path}: HTTP 403 — token / role denies this write")
        if resp.status_code >= 400:
            raise UnifiClientError(f"{path}: HTTP {resp.status_code} {resp.text[:200]}")
        try:
            body = resp.json()
        except ValueError:
            # Some stamgr responses are empty-bodied 200s — treat as success.
            return {}
        # The legacy controller signals command failure in-band: HTTP 200 with
        # ``{"meta": {"rc": "error", "msg": "api.err.…"}}`` (wrong site, a
        # key/role without device-block rights, unknown MAC). Without this a
        # failed block-sta would be recorded as a converged push (#601 review).
        if isinstance(body, dict):
            meta = body.get("meta")
            if isinstance(meta, dict) and str(meta.get("rc", "")).lower() == "error":
                raise UnifiClientError(
                    f"{path}: controller rejected command — {meta.get('msg') or 'rc=error'}"
                )
        return body

    # ── Write surface (active block sync #601, opt-in) ───────────────
    #
    # L2 client quarantine at the AP/switch via the same ``cmd/stamgr``
    # command the UniFi UI issues. Idempotent-ish: re-blocking a blocked
    # device is a no-op on the controller. Requires an admin key / admin
    # login (distinct from the read mirror's creds).

    async def block_client(self, site_name: str, mac: str) -> None:
        """Quarantine a device by MAC (``block-sta``)."""
        await self._post_legacy(f"s/{site_name}/cmd/stamgr", {"cmd": "block-sta", "mac": mac})

    async def unblock_client(self, site_name: str, mac: str) -> None:
        """Lift a device quarantine by MAC (``unblock-sta``)."""
        await self._post_legacy(f"s/{site_name}/cmd/stamgr", {"cmd": "unblock-sta", "mac": mac})

    # ── Public surface ───────────────────────────────────────────────

    async def get_version(self) -> _UnifiVersion:
        """Probe the application info endpoint. The integration API
        exposes this at ``/info``; legacy controllers at ``/status``.
        Try integration first.
        """
        try:
            data = await self._get_integration("info")
        except UnifiClientError:
            # Fall back to legacy ``/status`` which works on both
            # OS-and-not-OS controllers.
            data = await self._get(self._legacy_path("../status"))
            if isinstance(data, dict) and "meta" in data:
                meta = data.get("meta") or {}
                return _UnifiVersion(version=str(meta.get("server_version") or ""))
            return _UnifiVersion(version="")
        if isinstance(data, dict):
            v = data.get("applicationVersion") or data.get("version") or ""
            return _UnifiVersion(version=str(v))
        return _UnifiVersion(version="")

    async def list_sites(self) -> list[_UnifiSite]:
        """Prefer the legacy ``/self/sites`` because it returns both
        ``name`` (short id) and ``desc`` (human label) — the public
        Integration API only returns ``name``. Fall back to the
        Integration API if legacy 404s (token scoped to v1 only).
        """
        try:
            data = await self._get_legacy("self/sites")
        except UnifiClientError as exc:
            logger.debug("unifi_legacy_sites_unavailable", error=str(exc))
            data = None
        out: list[_UnifiSite] = []
        if isinstance(data, list):
            for s in data:
                if not isinstance(s, dict):
                    continue
                name = str(s.get("name") or "")
                desc = str(s.get("desc") or s.get("name") or "")
                if not name:
                    continue
                out.append(_UnifiSite(name=name, desc=desc))
            if out:
                return out
        # Integration API fallback. Returns paged ``data`` envelope.
        try:
            page = await self._get_integration("sites")
        except UnifiClientError as exc:
            raise UnifiClientError(f"unable to list sites: {exc}") from exc
        # #1555 — a 200 whose body lacks a ``data`` list (proxy error page
        # served as JSON, envelope change, ``data: null``) is a degraded
        # read, not "this controller has no sites": returning [] here
        # would empty the whole controller mirror in the absence-delete
        # passes. Raise so the reconcile aborts with rows intact.
        rows = require_keyed_list(
            page, "data", make_error=UnifiClientError, context="list_sites (integration)"
        )
        for s in rows:
            if not isinstance(s, dict):
                continue
            site_id = str(s.get("id") or "")
            name = str(s.get("internalReference") or s.get("name") or "")
            desc = str(s.get("name") or "")
            if not site_id:
                continue
            out.append(_UnifiSite(name=name or site_id, desc=desc, site_id=site_id))
        return out

    async def list_networks(self, site_name: str) -> list[_UnifiNetwork]:
        """Pull networks via legacy ``rest/networkconf`` because that's
        the only path that returns ``ip_subnet`` + ``vlan`` + ``dhcpd_*``.
        """
        data = await self._get_legacy(f"s/{site_name}/rest/networkconf")
        # #1555 — wrong-shape 200 (incl. ``data: null`` unwrapped by
        # ``_get_legacy``) is a degraded read, not "site has no networks".
        data = require_list(
            data, make_error=UnifiClientError, context=f"list_networks site {site_name}"
        )
        out: list[_UnifiNetwork] = []
        for n in data:
            if not isinstance(n, dict):
                continue
            net_id = str(n.get("_id") or n.get("id") or "")
            if not net_id:
                continue
            name = str(n.get("name") or "")
            purpose = str(n.get("purpose") or "")
            ip_subnet = n.get("ip_subnet")
            if not isinstance(ip_subnet, str):
                ip_subnet = None
            vlan_raw = n.get("vlan")
            vlan: int | None
            try:
                vlan = (
                    int(vlan_raw)  # type: ignore[arg-type]
                    if vlan_raw not in (None, "", 0)
                    else None
                )
            except (TypeError, ValueError):
                vlan = None
            dns_servers: list[str] = []
            for k in ("dhcpd_dns_1", "dhcpd_dns_2", "dhcpd_dns_3", "dhcpd_dns_4"):
                v = n.get(k)
                if isinstance(v, str) and v.strip():
                    dns_servers.append(v.strip())
            try:
                lease = int(n.get("dhcpd_leasetime") or 0) or None
            except (TypeError, ValueError):
                lease = None
            out.append(
                _UnifiNetwork(
                    network_id=net_id,
                    name=name,
                    purpose=purpose,
                    enabled=bool(n.get("enabled", True)),
                    ip_subnet=ip_subnet,
                    vlan=vlan,
                    domain_name=str(n.get("domain_name") or "") or None,
                    dhcpd_enabled=bool(n.get("dhcpd_enabled", False)),
                    dhcpd_start=str(n.get("dhcpd_start") or "") or None,
                    dhcpd_stop=str(n.get("dhcpd_stop") or "") or None,
                    dhcpd_leasetime=lease,
                    dhcpd_dns=dns_servers,
                )
            )
        return out

    async def list_active_clients(self, site_name: str) -> list[_UnifiClient]:
        """Active clients via legacy ``stat/sta``. Includes all currently
        connected devices (wired + wireless + VPN, depending on UniFi
        OS version). The reconciler filters by include_wired /
        include_wireless / include_vpn afterwards.
        """
        data = await self._get_legacy(f"s/{site_name}/stat/sta")
        # #1555 — see list_networks: a wrong-shape 200 must raise, not
        # read as "no active clients on this site".
        data = require_list(
            data, make_error=UnifiClientError, context=f"list_active_clients site {site_name}"
        )
        return [c for c in (_parse_client_row(r) for r in data) if c is not None]

    async def list_known_clients(self, site_name: str) -> list[_UnifiClient]:
        """Known clients via legacy ``rest/user``. Includes operator-
        named clients and DHCP fixed-IP reservations even when the
        device is currently offline. Only rows with ``use_fixedip=True``
        and a populated ``fixed_ip`` are useful for v1 (the
        ``mirror_fixed_ips`` toggle).
        """
        data = await self._get_legacy(f"s/{site_name}/rest/user")
        # #1555 — see list_networks: a wrong-shape 200 must raise, not
        # read as "no known clients / fixed-IP reservations on this site".
        data = require_list(
            data, make_error=UnifiClientError, context=f"list_known_clients site {site_name}"
        )
        return [c for c in (_parse_client_row(r) for r in data) if c is not None]


def _parse_client_row(row: Any) -> _UnifiClient | None:
    """Parse one ``stat/sta`` or ``rest/user`` entry. Returns
    ``None`` if the row lacks a usable MAC (the only required key
    for IPAM mirroring).
    """
    if not isinstance(row, dict):
        return None
    mac = _normalise_mac(str(row.get("mac") or ""))
    if not mac:
        return None
    # ``rest/user`` carries ``use_fixedip`` + ``fixed_ip``; ``stat/sta``
    # carries ``ip`` for live IP and may carry ``use_fixedip`` too.
    fixed_ip_addr = row.get("fixed_ip")
    use_fixedip = bool(row.get("use_fixedip"))
    live_ip = row.get("ip")
    ip = (
        str(fixed_ip_addr)
        if use_fixedip and isinstance(fixed_ip_addr, str) and fixed_ip_addr
        else (str(live_ip) if isinstance(live_ip, str) and live_ip else None)
    )
    hostname = row.get("hostname")
    name = row.get("name")
    last_seen_raw = row.get("last_seen")
    try:
        last_seen = int(last_seen_raw) if last_seen_raw is not None else None
    except (TypeError, ValueError):
        last_seen = None
    return _UnifiClient(
        mac=mac,
        ip=ip,
        hostname=str(hostname) if isinstance(hostname, str) and hostname else None,
        name=str(name) if isinstance(name, str) and name else None,
        network_id=str(row.get("network_id") or "") or None,
        oui=str(row.get("oui") or "") or None,
        fixed_ip=use_fixedip,
        is_wired=bool(row.get("is_wired", False)),
        is_vpn=bool(row.get("is_vpn", False)),
        is_guest=bool(row.get("is_guest", False)),
        last_seen=last_seen,
    )


__all__ = [
    "UnifiClient",
    "UnifiClientConfig",
    "UnifiClientError",
    "_UnifiClient",
    "_UnifiNetwork",
    "_UnifiSite",
    "_UnifiVersion",
    "_ip_subnet_to_cidr",
    "_ip_subnet_to_gateway",
    "_is_ipam_relevant_purpose",
    "_normalise_mac",
    "_parse_client_row",
]
