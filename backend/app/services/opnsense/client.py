"""Minimal async OPNsense REST client.

Endpoints consumed (all read-only unless noted):

* ``GET  /api/core/firmware/status`` — sanity + firmware version.
* ``GET  /api/interfaces/overview/export`` — the primary interface read.
  A list of interfaces carrying ``identifier`` (``lan`` / ``opt1``),
  ``description``, ``device``, ``link_type``, ``vlan_tag`` and the
  ``ipv4[]`` / ``ipv6[]`` address arrays.
* ``GET  /api/diagnostics/interface/getInterfaceConfig`` — fallback
  interface read. A passthrough of configd ``interface list ifconfig``,
  so it is keyed by **OS device** with the same ``ipv4[]`` / ``ipv6[]``
  arrays, but no logical name and no description.
* ``GET  /api/interfaces/vlan_settings/get`` — VLAN definitions
  (``vlan.vlan.<uuid>`` rows with parent / tag / description). Only
  needed for the fallback path now that the overview carries the tag.
* DHCPv4 leases + reservations, unioned across three backends —
  ``/api/kea/*``, ``/api/dnsmasq/*`` and the legacy ISC
  ``/api/dhcpv4/*``. See the "DHCP backends" comment below.
* ``GET  /api/diagnostics/interface/getArp`` — ARP table (secondary
  population, opt-in).

Auth is HTTP Basic: the API key is the username and the API secret is
the password. OPNsense API keys are minted per-user under System →
Access → Users → API keys.

Defensive parsing throughout — response shapes vary across firmware
versions, so every accessor guards missing keys / unexpected types and
the ``rows[]``-wrapper convention is handled in one place
(``_unwrap_rows``).

A word on why the parsers below are shaped the way they are (#797).
This client was originally written without a live firewall to test
against, and the interface parser was written against an invented
response shape — flat ``ipaddr`` / ``subnet`` string keys on a
logical-name-keyed dict — that ``getInterfaceConfig`` has never
returned. The fiction was encoded in the unit-test fixtures too, so the
tests passed while the integration mirrored nothing on every real box.
Two rules came out of that and are worth keeping:

1. Fixtures are copied from real firewalls, not imagined. The shapes in
   ``tests/test_opnsense_client.py`` are captured payloads.
2. A non-empty payload that parses to zero rows is treated as a
   degraded read and raises, rather than being reported as a
   legitimately-empty result. Silence is the failure mode that let the
   original bug live indefinitely.
"""

from __future__ import annotations

import ipaddress
import ssl
from dataclasses import dataclass
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)


class OPNsenseClientError(Exception):
    """Raised when the OPNsense API returns an error we can't recover from.

    The message carries the HTTP status + path + first 200 bytes of the
    response body so operator-facing error messages are useful.

    ``status_code`` is the HTTP status when the failure was a response
    (``401`` / ``403`` / ``5xx`` / …) and ``None`` for transport-level
    failures (timeout / connection refused / non-JSON body). Callers use
    it to tell a genuine "endpoint absent" 404 (safe to treat as an empty
    table) apart from a transient 5xx / timeout (must abort the reconcile
    rather than diff against an empty desired set — see #5).
    """

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass
class _OPNFirmwareInfo:
    # OPNsense reports the running product version under several keys
    # depending on firmware; we normalise to a single string.
    version: str


@dataclass
class _OPNInterface:
    """A configured interface with at least one IPv4/IPv6 address.

    ``cidr`` is the *network* CIDR (e.g. ``10.0.0.0/24``) derived from
    the interface address + prefix. ``device`` is the OS device name
    (``igb0`` / ``vlan0.10``); ``name`` is the OPNsense logical name
    (``lan`` / ``opt1``); ``description`` is the operator-set label.
    """

    name: str  # logical name (lan / wan / opt1 / ...)
    device: str  # OS device (igb0, vlan0.10, ...)
    description: str
    cidr: str  # network CIDR (10.0.0.0/24)
    address: str  # the firewall's own interface IP (10.0.0.1)
    # Carried natively by ``interfaces/overview/export``; ``None`` when
    # the interface isn't a VLAN, or when the fallback ifconfig parser
    # supplied this row (it has no VLAN linkage). The reconciler prefers
    # this over joining ``vlan_settings/get`` by device name.
    vlan_tag: int | None = None


@dataclass
class _OPNVlan:
    """A VLAN definition from ``interfaces/vlan_settings/get``."""

    device: str  # vlan device name (vlan0.10)
    parent: str  # physical parent (igb0)
    tag: int | None
    description: str


@dataclass
class _OPNLease:
    """A DHCPv4 lease row, normalised across the three DHCP backends."""

    address: str
    mac: str | None
    hostname: str
    state: str  # "active" / "expired" / ... (best-effort)


@dataclass
class _OPNReservation:
    """A static DHCP mapping, normalised across the three DHCP backends."""

    address: str
    mac: str | None
    hostname: str
    description: str


@dataclass
class _OPNLeaseResult:
    """Leases plus *which backends answered*.

    The counts alone can't distinguish "DHCP is off" from "we asked a
    firmware that no longer has these endpoints" — the ambiguity that
    let #797 report a successful sync with zero results on every pass
    for as long as the integration existed. ``sources_found`` empty
    means no DHCP backend was reachable at all.

    ``sources_forbidden`` lists backends that exist but returned 403.
    The Kea lease endpoints carry their own ACL entries
    (opnsense/core#7770), so a minimal read-only API user hits this and
    needs a privilege added rather than a firmware change.
    """

    leases: list[_OPNLease]
    sources_found: list[str]
    sources_forbidden: list[str]


@dataclass
class _OPNReservationResult:
    """Reservations plus which backends answered. See ``_OPNLeaseResult``."""

    reservations: list[_OPNReservation]
    sources_found: list[str]
    sources_forbidden: list[str]


# Kea reports lease state as a number (kea-dhcp4 lease states); map it to
# the same vocabulary the ISC path yields so the reconciler has one
# concept of "active" rather than a backend-specific digit.
_KEA_LEASE_STATE = {
    "0": "active",
    "1": "declined",
    "2": "expired",
}


def _kea_lease_state(raw: Any) -> str:
    """Map Kea's numeric lease state, whether it arrives as ``0`` or ``"0"``.

    The obvious ``str(raw or "")`` is wrong here and quietly so: ``0`` is
    falsy, so an integer 0 — the ACTIVE state, and the one that matters —
    collapses to ``""`` and every live lease reads as ``unknown``. The API
    currently serialises these as strings, but nothing guarantees that,
    and the failure would be silent rather than loud.
    """
    if raw is None:
        return "unknown"
    return _KEA_LEASE_STATE.get(str(raw).strip(), "unknown")


@dataclass
class _OPNArpEntry:
    """An ARP-table row from ``diagnostics/interface/getArp``."""

    address: str
    mac: str | None
    hostname: str
    interface: str


def _normalise_mac(mac: str | None) -> str | None:
    """Canonical form: colon-separated, lowercase, no whitespace.

    Returns ``None`` for blanks / OPNsense placeholders (``(incomplete)``
    shows up in ARP tables for unresolved entries).
    """
    if not mac:
        return None
    m = mac.strip().lower().replace("-", ":")
    if not m or m in {"(incomplete)", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}:
        return None
    return m


def _unwrap_rows(body: Any) -> list[dict[str, Any]]:
    """Pull the row list out of an OPNsense search-style response.

    Handles the common ``{"rows": [...]}`` envelope, a bare list, and
    the occasional ``{"<n>": {...}}`` keyed-dict shape. Always returns
    a list of dicts (dropping any non-dict members defensively).
    """
    rows: Any
    if isinstance(body, dict) and "rows" in body:
        rows = body.get("rows")
    elif isinstance(body, list):
        rows = body
    elif isinstance(body, dict):
        # Keyed dict: values are the rows.
        rows = list(body.values())
    else:
        rows = []
    if not isinstance(rows, list):
        return []
    return [r for r in rows if isinstance(r, dict)]


def _assert_alias_op_ok(data: Any, label: str) -> None:
    """Raise ``OPNsenseClientError`` unless an alias_util / reconfigure
    response reports success.

    OPNsense returns ``{"status": "done"}`` (add/delete/reconfigure) or
    ``{"result": "saved"}`` on success. A ``{"status": "failed"}`` or a
    validation envelope means the operation didn't take — surface it so
    the reconciler marks the push errored instead of falsely converged.
    """
    if isinstance(data, dict):
        status_val = str(data.get("status") or data.get("result") or "").strip().lower()
        if status_val in {"done", "saved", "ok"}:
            return
        # Some firmwares return an empty {} for add-of-already-present.
        if not status_val and not data.get("validations"):
            return
    raise OPNsenseClientError(f"{label}: unexpected response {str(data)[:200]}")


def _network_cidr(address: str, prefix: Any) -> str | None:
    """Build the network CIDR (``10.0.0.0/24``) from an interface IP +
    prefix length. Returns ``None`` on parse failure.
    """
    try:
        plen = int(prefix)
    except (TypeError, ValueError):
        return None
    try:
        iface = ipaddress.ip_interface(f"{address}/{plen}")
        return str(iface.network)
    except (ValueError, TypeError):
        return None


def _truthy(value: Any) -> bool:
    """OPNsense mixes booleans, ``"1"``/``"0"`` and ``"yes"``/``"no"``
    for the same field across endpoints. Treat all three uniformly.
    """
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _addresses_from_arrays(cfg: dict[str, Any]) -> tuple[list[tuple[str, str]], bool]:
    """Pull ``(address, network_cidr)`` pairs out of an interface entry.

    Both ``interfaces/overview/export`` and the ``getInterfaceConfig``
    passthrough carry addresses the same way — ``ipv4`` / ``ipv6`` lists
    of ``{"ipaddr": "10.0.0.1", "subnetbits": 24}``. Only the first
    usable entry per family is returned: on OPNsense the first is the
    primary and the rest are VIPs / secondaries, which would otherwise
    mirror as extra subnets nobody asked for.

    The second return value reports whether this entry carried an
    address *container* at all (an ``ipv4``/``ipv6`` key holding a
    list), regardless of whether anything usable was inside it. The
    caller uses it to tell "this firewall genuinely has no addressed
    interfaces" apart from "the response shape is not what we parse" —
    the distinction that #797 turned on, where a valid 200 parsed to
    zero and the integration reported success forever.
    """
    out: list[tuple[str, str]] = []
    saw_container = False
    for family in ("ipv4", "ipv6"):
        entries = cfg.get(family)
        if not isinstance(entries, list):
            continue
        saw_container = True
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            addr = str(entry.get("ipaddr") or "").strip()
            if not addr:
                continue
            if not _is_mirrorable_address(addr):
                continue
            # A tunnel endpoint's "subnet" is the peer address, not a
            # LAN — mirroring it would invent a subnet that isn't one.
            if _truthy(entry.get("tunnel")):
                continue
            cidr = _network_cidr(addr, entry.get("subnetbits"))
            if cidr is None:
                continue
            out.append((addr, cidr))
            break  # primary only
    return out, saw_container


def _is_mirrorable_address(addr: str) -> bool:
    """Whether an interface address describes a subnet worth mirroring.

    ``ifconfig`` reports every interface the kernel has, including ones
    that are not networks anybody administers. Without this filter the
    fallback parser mirrors ``lo0`` — producing a 16.7-million-address
    ``127.0.0.0/8`` subnet, an auto-created wrapper block for it, and a
    "gateway" reservation for 127.0.0.1 — plus ``::1/128`` beside it.

    Excluded:

    * **loopback** — not a network, and identical on every firewall, so
      two mirrored routers would collide on the same CIDR.
    * **link-local** (169.254/16, fe80::/10) — per-link by definition,
      and likewise identical across interfaces and hosts.
    * **unspecified** (0.0.0.0, ::) — an unconfigured placeholder.

    Anything else, including RFC 1918 and public space, is mirrored:
    deciding which *routable* ranges an operator cares about is their
    call, not ours.
    """
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])  # strip any zone id
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_link_local or ip.is_unspecified)


def _assert_interface_shape(entries: int, saw_any_container: bool, source: str) -> None:
    """Raise when a non-empty interface payload carried no address
    container on any entry.

    That combination means the response shape is not the one we parse —
    the #797 failure, where ``getInterfaceConfig`` returned a full,
    valid 200 keyed by device with ``ipv4[]`` arrays while the parser
    looked for flat ``ipaddr``/``subnet`` string keys, matched nothing,
    and reported a successful sync with zero interfaces on every pass
    for as long as the integration existed.

    Raising (rather than returning ``[]``) routes this into the same
    degraded-read handling as #430/#426: the reconciler aborts the pass
    and surfaces the error instead of diffing against an empty desired
    set and absence-deleting every mirrored subnet.

    A payload whose entries DO carry ``ipv4``/``ipv6`` lists that are
    simply empty is a legitimate zero — a firewall with only DHCP/
    unconfigured interfaces — and returns cleanly.
    """
    if entries and not saw_any_container:
        raise OPNsenseClientError(
            f"{source} returned {entries} interface entries but none carried an "
            "ipv4/ipv6 address list — the response shape is not the one this "
            "client parses. Treating as a degraded read rather than zero "
            "interfaces."
        )


def _interfaces_from_overview(data: Any) -> list[_OPNInterface]:
    """Parse ``GET /api/interfaces/overview/export``.

    Returns one entry per addressed, enabled interface. This is the
    richest source: it is the only one carrying the logical identifier
    (``lan`` / ``opt1``), the operator's description and the VLAN tag
    alongside the addresses.
    """
    rows = _unwrap_rows(data)
    # #430 — a firewall always has interfaces, so an empty or non-list /
    # non-dict 200 (proxy error body, envelope change) is a degraded read,
    # never a legitimate zero. Returning [] here would diff against an
    # empty desired set and absence-delete every mirrored subnet. The
    # ifconfig fallback carries the same guard; this endpoint needs its
    # own because ``_unwrap_rows`` turns any of those bodies into [].
    if not rows:
        raise OPNsenseClientError(
            "interfaces/overview/export returned no interface entries — "
            "treating as a degraded read, not zero interfaces"
        )
    out: list[_OPNInterface] = []
    saw_any_container = False
    for cfg in rows:
        # Shape detection runs on EVERY row, before any policy filter.
        # Accumulating it after the filters would conflate "we don't
        # recognise this payload" with "every interface was skipped for a
        # reason we understand" — so a WAN-only DHCP box, or one whose
        # link_type vocabulary we don't know, would raise the degraded-read
        # error and abort the pass instead of reaching the zero-interface
        # warning that exists for exactly that case.
        pairs, saw_container = _addresses_from_arrays(cfg)
        saw_any_container = saw_any_container or saw_container
        # ``enabled`` absent means "not reported" — mirror it rather than
        # assume disabled, since only some firmwares emit the key.
        if "enabled" in cfg and not _truthy(cfg.get("enabled")):
            continue
        # Dynamically-addressed and unconfigured interfaces don't
        # describe a subnet this IPAM should own.
        if str(cfg.get("link_type") or "").strip().lower() in {"dhcp", "none"}:
            continue
        device = str(cfg.get("device") or "")
        name = str(cfg.get("identifier") or "") or device
        for addr, cidr in pairs:
            out.append(
                _OPNInterface(
                    name=name,
                    device=device or name,
                    description=str(cfg.get("description") or ""),
                    cidr=cidr,
                    address=addr,
                    vlan_tag=_coerce_vlan_tag(cfg.get("vlan_tag")),
                )
            )
    _assert_interface_shape(len(rows), saw_any_container, "interfaces/overview/export")
    return out


def _interfaces_from_ifconfig(data: Any) -> list[_OPNInterface]:
    """Parse ``GET /api/diagnostics/interface/getInterfaceConfig``.

    A passthrough of the configd command ``interface list ifconfig``,
    so the payload is keyed by **OS device** and carries no logical name
    and no description. Only used when ``overview/export`` is absent;
    subnet names fall back to the device.
    """
    if not isinstance(data, dict) or not data:
        raise OPNsenseClientError(
            "getInterfaceConfig returned no interfaces — treating as a "
            "degraded read, not zero interfaces"
        )
    out: list[_OPNInterface] = []
    saw_any_container = False
    for device_key, cfg in data.items():
        if not isinstance(cfg, dict):
            continue
        pairs, saw_container = _addresses_from_arrays(cfg)
        saw_any_container = saw_any_container or saw_container
        device = str(cfg.get("device") or device_key)
        for addr, cidr in pairs:
            out.append(
                _OPNInterface(
                    name=device,
                    device=device,
                    description="",
                    cidr=cidr,
                    address=addr,
                    vlan_tag=None,
                )
            )
    _assert_interface_shape(len(data), saw_any_container, "getInterfaceConfig")
    return out


def _coerce_vlan_tag(raw: Any) -> int | None:
    if raw in (None, "", []):
        return None
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return None


class OPNsenseClient:
    """Per-firewall async client. One instance per reconcile pass.

    Caller is responsible for ``async with`` lifecycle. Holds a single
    ``httpx.AsyncClient`` so every call shares a TLS session.
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        api_key: str,
        api_secret: str,
        verify_tls: bool,
        ca_bundle_pem: str = "",
    ) -> None:
        self._base = f"https://{host}:{port}"
        self._auth = (api_key, api_secret)
        self._verify_tls = verify_tls
        self._ca_bundle_pem = ca_bundle_pem.strip()
        self._client: httpx.AsyncClient | None = None
        # Backends that answered 403 during the current list_* call.
        # Reset at the top of each, read into the result so the
        # reconciler can warn about a privilege gap rather than silently
        # mirroring nothing.
        self._forbidden: list[str] = []

    async def __aenter__(self) -> OPNsenseClient:
        verify: Any
        if not self._verify_tls:
            verify = False
            # Operator opted out of TLS verification for this firewall.
            # Surface it on every connect so the insecure posture is
            # visible in the centralized logs (#5); the who/when of
            # enabling it lives in the integration-target audit row.
            logger.warning("opnsense_tls_verification_disabled", endpoint=self._base)
        elif self._ca_bundle_pem:
            verify = ssl.create_default_context(cadata=self._ca_bundle_pem)
        else:
            verify = True
        self._client = httpx.AsyncClient(
            base_url=self._base,
            auth=self._auth,
            headers={"Accept": "application/json"},
            verify=verify,
            timeout=20.0,
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _request(self, method: str, path: str, *, json: Any | None = None) -> Any:
        assert self._client is not None, "use within 'async with'"
        try:
            resp = await self._client.request(method, path, json=json)
        except httpx.HTTPError as exc:
            # Transport-level failure (timeout / connection refused) — no
            # HTTP status, so status_code stays None and the caller treats
            # it as transient (abort, don't diff against empty).
            raise OPNsenseClientError(f"{path}: {exc}") from exc
        if resp.status_code == 401:
            raise OPNsenseClientError(f"{path}: HTTP 401 — API key/secret invalid", status_code=401)
        if resp.status_code == 403:
            raise OPNsenseClientError(
                f"{path}: HTTP 403 — API user lacks privilege for this path", status_code=403
            )
        if resp.status_code >= 400:
            raise OPNsenseClientError(
                f"{path}: HTTP {resp.status_code} {resp.text[:200]}",
                status_code=resp.status_code,
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise OPNsenseClientError(f"{path}: response was not JSON ({exc})") from exc

    async def _get(self, path: str) -> Any:
        return await self._request("GET", path)

    async def _post(self, path: str, json: Any | None = None) -> Any:
        return await self._request("POST", path, json=json)

    # ── Public surface ───────────────────────────────────────────────

    async def get_firmware(self) -> _OPNFirmwareInfo:
        """Best-effort firmware version. Used as the auth/sanity probe."""
        data = await self._get("/api/core/firmware/status")
        version = ""
        if isinstance(data, dict):
            # OPNsense reports the running version under one of these.
            for key in ("product_version", "os_version", "product_id"):
                v = data.get(key)
                if isinstance(v, str) and v:
                    version = v
                    break
            if not version:
                prod = data.get("product")
                if isinstance(prod, dict):
                    pv = prod.get("product_version") or prod.get("product_series")
                    if isinstance(pv, str) and pv:
                        version = pv
        return _OPNFirmwareInfo(version=version or "unknown")

    async def list_interfaces(self) -> list[_OPNInterface]:
        """Configured interfaces that carry at least one IPv4/IPv6 CIDR.

        Primary source is ``GET /api/interfaces/overview/export``, which
        is the only endpoint that carries the logical name (``lan`` /
        ``opt1``), the operator's ``description`` and the ``vlan_tag`` in
        the same payload as the addresses. Falls back to
        ``diagnostics/interface/getInterfaceConfig`` (device-keyed, no
        logical name) when the overview endpoint is absent.

        Both shapes carry addresses as ``ipv4[]`` / ``ipv6[]`` arrays of
        ``{ipaddr, subnetbits}``. The first entry is treated as the
        primary address; secondaries / VIPs are ignored for now.

        Raises rather than returning ``[]`` when a non-empty payload
        parses to zero interfaces — see ``_interfaces_from_overview``.
        """
        try:
            data = await self._get("/api/interfaces/overview/export")
        except OPNsenseClientError as exc:
            if exc.status_code not in (404, 403):
                raise
            # 404 — endpoint absent (very old firmware).
            # 403 — the API user predates this endpoint being required.
            #   Existing installs were set up against the previous docs,
            #   which only called for Diagnostics + DHCPv4 + Interfaces
            #   privileges, so upgrading must not turn a working mirror
            #   into a hard failure. Fall back rather than fail; the
            #   operator gets poorer subnet names until they widen the
            #   privilege, which beats an outage.
            logger.info(
                "opnsense_overview_export_unavailable",
                status=exc.status_code,
                error=str(exc),
            )
            return await self._list_interfaces_via_diagnostics()
        return _interfaces_from_overview(data)

    async def _list_interfaces_via_diagnostics(self) -> list[_OPNInterface]:
        """Fallback interface read via ``getInterfaceConfig``.

        This endpoint is a passthrough of the configd command
        ``interface list ifconfig``, so it is keyed by **OS device**
        (``igc0``) and carries no logical name and no description — the
        mirrored subnet names are correspondingly poorer. Used only when
        ``interfaces/overview/export`` 404s.
        """
        data = await self._get("/api/diagnostics/interface/getInterfaceConfig")
        return _interfaces_from_ifconfig(data)

    async def list_vlans(self) -> list[_OPNVlan]:
        """VLAN definitions. Empty list on 404 / 403 / no VLANs.

        The ``vlan_settings/get`` shape is
        ``{"vlan": {"vlan": {"<uuid>": {if, tag, descr, ...}}}}``.
        """
        try:
            data = await self._get("/api/interfaces/vlan_settings/get")
        except OPNsenseClientError as exc:
            logger.debug("opnsense_vlans_unavailable", error=str(exc))
            return []
        # #430 — distinguish a legitimately-empty VLAN set (envelope present,
        # inner {}) from a degraded read (envelope absent). Returning [] on a
        # degraded read would absence-delete VLAN-derived subnets. The 404 /
        # plugin-absent case is already handled by the except above.
        outer = data.get("vlan") if isinstance(data, dict) else None
        inner = outer.get("vlan") if isinstance(outer, dict) else None
        if not isinstance(inner, dict):
            raise OPNsenseClientError(
                "vlan_settings/get missing the vlan.vlan envelope — treating "
                "as a degraded read, not zero VLANs"
            )
        rows: dict[str, Any] = inner
        out: list[_OPNVlan] = []
        for _uuid, row in rows.items():
            if not isinstance(row, dict):
                continue
            device = str(row.get("vlanif") or row.get("device") or "")
            parent = str(row.get("if") or row.get("parent") or "")
            tag_raw = row.get("tag")
            tag: int | None
            try:
                tag = int(str(tag_raw)) if tag_raw not in (None, "") else None
            except (TypeError, ValueError):
                tag = None
            out.append(
                _OPNVlan(
                    device=device,
                    parent=parent,
                    tag=tag,
                    description=str(row.get("descr") or row.get("description") or ""),
                )
            )
        return out

    # ── DHCP backends ────────────────────────────────────────────────
    #
    # OPNsense has had three DHCPv4 servers over the supported range, and
    # which one answers depends on the firmware AND on what the operator
    # configured:
    #
    #   ISC dhcpd  — core through 25.1, moved out to a plugin in 25.7
    #                (opnsense/core#9155). ``/api/dhcpv4/*``.
    #   Kea        — the "advanced" option from 24.x. ``/api/kea/*``.
    #   Dnsmasq    — the factory/wizard default from 25.7. ``/api/dnsmasq/*``.
    #
    # 25.7+ can run Kea and Dnsmasq side by side on different interfaces,
    # so this is a UNION, not first-hit-wins. Each source's absence (404)
    # is normal and contributes nothing; anything else propagates, so a
    # transient 5xx still aborts the pass rather than silently emptying
    # the mirror (#5).
    #
    # ``sources_found`` on the result tells the reconciler whether any
    # backend answered at all — the difference between "DHCP is off" and
    # "we asked the wrong firewall version", which #797 could not express.

    async def list_leases(self) -> _OPNLeaseResult:
        """DHCPv4 leases, unioned across every backend present.

        Deduplicated by address; the first backend to report an address
        wins. Kea is queried first because it is the backend with the
        richest row (interface name + description come back resolved).
        """
        by_address: dict[str, _OPNLease] = {}
        sources: list[str] = []
        self._forbidden = []
        for source, fetch in (
            ("kea", self._leases_kea),
            ("dnsmasq", self._leases_dnsmasq),
            ("isc", self._leases_isc),
        ):
            rows = await fetch()
            if rows is None:
                continue  # backend absent (or forbidden) on this firmware
            sources.append(source)
            for lease in rows:
                by_address.setdefault(lease.address, lease)
        return _OPNLeaseResult(
            leases=list(by_address.values()),
            sources_found=sources,
            sources_forbidden=list(self._forbidden),
        )

    async def _leases_kea(self) -> list[_OPNLease] | None:
        """``GET /api/kea/leases4/search``. ``None`` when Kea is absent.

        Kea reports ``state`` numerically — ``0`` is active, ``1`` is
        declined, ``2`` is expired-reclaimed — so it is mapped to the
        same vocabulary the ISC path produces rather than passed through
        as a digit the reconciler would not recognise.
        """
        body = await self._get_optional("/api/kea/leases4/search", "kea leases")
        if body is None:
            return None
        out: list[_OPNLease] = []
        for r in _unwrap_rows(body):
            addr = str(r.get("address") or "").strip()
            if not addr:
                continue
            out.append(
                _OPNLease(
                    address=addr,
                    mac=_normalise_mac(r.get("hwaddr")),
                    hostname=str(r.get("hostname") or "").strip(),
                    state=_kea_lease_state(r.get("state")),
                )
            )
        return out

    async def _leases_dnsmasq(self) -> list[_OPNLease] | None:
        """``GET /api/dnsmasq/leases/search``. ``None`` when absent.

        Dnsmasq does not report a lease state — a row in its lease file
        is by definition a current lease, so they are all ``active``.
        """
        body = await self._get_optional("/api/dnsmasq/leases/search", "dnsmasq leases")
        if body is None:
            return None
        out: list[_OPNLease] = []
        for r in _unwrap_rows(body):
            addr = str(r.get("address") or "").strip()
            if not addr:
                continue
            out.append(
                _OPNLease(
                    address=addr,
                    mac=_normalise_mac(r.get("hwaddr")),
                    hostname=str(r.get("hostname") or "").strip(),
                    state="active",
                )
            )
        return out

    async def _leases_isc(self) -> list[_OPNLease] | None:
        """``POST /api/dhcpv4/leases/searchLease``. ``None`` when absent.

        Legacy path — core ISC dhcpd on ≤25.1, and 25.7+ boxes that
        installed the ISC plugin. The POST body asks for a large page so
        the full table arrives in one call.
        """
        try:
            body = await self._post(
                "/api/dhcpv4/leases/searchLease",
                json={"current": 1, "rowCount": 5000, "searchPhrase": ""},
            )
        except OPNsenseClientError as exc:
            # Same 404/403 treatment as the Kea and Dnsmasq readers. This
            # path is a POST so it can't use ``_get_optional``, but it
            # must not be stricter: a user scoped to the least-privilege
            # table in the docs gets 403 here, and failing the whole pass
            # for one absent backend is the behaviour #797 was about.
            if exc.status_code == 404:
                logger.debug("opnsense_leases_backend_absent", backend="isc", error=str(exc))
                return None
            if exc.status_code == 403:
                logger.warning(
                    "opnsense_dhcp_backend_forbidden", source="isc leases", error=str(exc)
                )
                self._forbidden.append("isc leases")
                return None
            raise
        out: list[_OPNLease] = []
        for r in _unwrap_rows(body):
            addr = str(r.get("address") or r.get("ip") or "").strip()
            if not addr:
                continue
            state = str(r.get("status") or r.get("state") or "").strip().lower() or "unknown"
            out.append(
                _OPNLease(
                    address=addr,
                    mac=_normalise_mac(r.get("mac") or r.get("hwaddr")),
                    hostname=str(r.get("hostname") or r.get("client-hostname") or "").strip(),
                    state=state,
                )
            )
        return out

    async def list_reservations(self) -> _OPNReservationResult:
        """Static DHCP mappings, unioned across every backend present.

        Deduplicated by address, first backend wins — same ordering
        rationale as ``list_leases``.
        """
        by_address: dict[str, _OPNReservation] = {}
        sources: list[str] = []
        self._forbidden = []
        for source, fetch in (
            ("kea", self._reservations_kea),
            ("dnsmasq", self._reservations_dnsmasq),
            ("isc", self._reservations_isc),
        ):
            rows = await fetch()
            if rows is None:
                continue
            sources.append(source)
            for res in rows:
                by_address.setdefault(res.address, res)
        return _OPNReservationResult(
            reservations=list(by_address.values()),
            sources_found=sources,
            sources_forbidden=list(self._forbidden),
        )

    async def _reservations_kea(self) -> list[_OPNReservation] | None:
        """``GET /api/kea/dhcpv4/searchReservation``. ``None`` when absent."""
        body = await self._get_optional("/api/kea/dhcpv4/searchReservation", "kea reservations")
        if body is None:
            return None
        out: list[_OPNReservation] = []
        for r in _unwrap_rows(body):
            addr = str(r.get("ip_address") or "").strip()
            if not addr:
                continue
            out.append(
                _OPNReservation(
                    address=addr,
                    mac=_normalise_mac(r.get("hw_address")),
                    hostname=str(r.get("hostname") or "").strip(),
                    description=str(r.get("description") or "").strip(),
                )
            )
        return out

    async def _reservations_dnsmasq(self) -> list[_OPNReservation] | None:
        """``GET /api/dnsmasq/settings/searchHost``. ``None`` when absent.

        Dnsmasq "hosts" serve double duty — a host with no MAC is a
        static DNS entry, and only one carrying a ``hwaddr`` is a DHCP
        reservation. Rows without a MAC are dropped for that reason,
        rather than mirrored as reservations they are not.
        """
        body = await self._get_optional("/api/dnsmasq/settings/searchHost", "dnsmasq reservations")
        if body is None:
            return None
        out: list[_OPNReservation] = []
        for r in _unwrap_rows(body):
            addr = str(r.get("ip") or "").strip()
            mac = _normalise_mac(r.get("hwaddr"))
            if not addr or mac is None:
                continue
            host = str(r.get("host") or "").strip()
            # The row's ``domain`` is deliberately NOT appended (#1557).
            out.append(
                _OPNReservation(
                    address=addr,
                    mac=mac,
                    # Host label only (#1557): ``host`` + ``domain`` is
                    # an FQDN, and IPAM publishing appends the zone to
                    # hostname, which doubled the suffix.
                    hostname=host,
                    description=str(r.get("descr") or "").strip(),
                )
            )
        return out

    async def _reservations_isc(self) -> list[_OPNReservation] | None:
        """``GET /api/dhcpv4/settings/getReservation``. ``None`` when absent.

        Returns the ISC ``dhcpd`` config tree
        (``{"dhcpd": {"<iface>": {"staticmap": {...}}}}``) on older
        firmware and a ``rows[]`` wrapper on newer ones; both are
        flattened here.
        """
        body = await self._get_optional("/api/dhcpv4/settings/getReservation", "isc reservations")
        if body is None:
            return None
        rows: list[dict[str, Any]] = []
        if isinstance(body, dict) and "dhcpd" in body and isinstance(body["dhcpd"], dict):
            # ISC tree shape: dhcpd → <iface> → staticmap → {uuid|idx: {...}}
            for iface_cfg in body["dhcpd"].values():
                if not isinstance(iface_cfg, dict):
                    continue
                staticmap = iface_cfg.get("staticmap")
                if isinstance(staticmap, dict):
                    rows.extend(r for r in staticmap.values() if isinstance(r, dict))
                elif isinstance(staticmap, list):
                    rows.extend(r for r in staticmap if isinstance(r, dict))
        else:
            rows = _unwrap_rows(body)

        out: list[_OPNReservation] = []
        for r in rows:
            addr = str(r.get("ipaddr") or r.get("address") or r.get("ip") or "").strip()
            if not addr:
                continue
            out.append(
                _OPNReservation(
                    address=addr,
                    mac=_normalise_mac(r.get("mac") or r.get("hwaddr")),
                    hostname=str(r.get("hostname") or "").strip(),
                    description=str(r.get("descr") or r.get("description") or "").strip(),
                )
            )
        return out

    async def _get_optional(self, path: str, label: str) -> Any | None:
        """GET a path whose absence is expected on some firmwares.

        Returns ``None`` on 404 (the module isn't installed / enabled) and
        on 403 (the API user lacks the privilege — the Kea lease and
        service endpoints carry their own ACL entries, opnsense/core#7770,
        so a minimal read-only user will be refused there while the rest
        of the mirror works). Everything else propagates, so a transient
        5xx still aborts the pass instead of emptying the mirror.

        The 403 case is logged at WARNING rather than DEBUG: unlike a 404
        it means the operator has the backend but SpatiumDDI cannot read
        it, which is a fixable misconfiguration they should see.
        """
        try:
            return await self._get(path)
        except OPNsenseClientError as exc:
            if exc.status_code == 404:
                logger.debug("opnsense_dhcp_backend_absent", source=label, error=str(exc))
                return None
            if exc.status_code == 403:
                logger.warning("opnsense_dhcp_backend_forbidden", source=label, error=str(exc))
                self._forbidden.append(label)
                return None
            raise

    # ── Write surface (active block sync #601, opt-in) ───────────────
    #
    # Firewall enforcement via *table-alias membership only* — never rule
    # CRUD. The operator pre-creates one block rule referencing an alias
    # (e.g. ``spatiumddi_blocked``); SpatiumDDI adds/removes IPs to
    # converge, then reconfigures to apply. Idempotent + no rule-ordering
    # state. These require a Firewall-privileged API user (distinct from
    # the read mirror's read-only user).

    async def alias_list_addresses(self, alias: str) -> list[str]:
        """Current member IPs of a table alias.

        ``GET /api/firewall/alias_util/list/{alias}`` returns
        ``{"total": N, "rows": [{"ip": "1.2.3.4"}, ...]}``. Raises
        (no swallow) so the reconciler can distinguish a real read from a
        transient failure and never diff against a bad-empty set (#5).
        """
        body = await self._get(f"/api/firewall/alias_util/list/{alias}")
        out: list[str] = []
        for r in _unwrap_rows(body):
            ip = str(r.get("ip") or r.get("address") or "").strip()
            if ip:
                out.append(ip)
        return out

    async def alias_add_address(self, alias: str, address: str) -> None:
        """Add one IP to a table alias.

        ``POST /api/firewall/alias_util/add/{alias}`` with
        ``{"address": "<ip>"}``. OPNsense returns ``{"status": "done"}``
        on success; anything else is surfaced as an error.
        """
        data = await self._post(f"/api/firewall/alias_util/add/{alias}", json={"address": address})
        _assert_alias_op_ok(data, f"add {address} to {alias}")

    async def alias_delete_address(self, alias: str, address: str) -> None:
        """Remove one IP from a table alias.

        ``POST /api/firewall/alias_util/delete/{alias}`` with
        ``{"address": "<ip>"}``.
        """
        data = await self._post(
            f"/api/firewall/alias_util/delete/{alias}", json={"address": address}
        )
        _assert_alias_op_ok(data, f"delete {address} from {alias}")

    async def alias_reconfigure(self) -> None:
        """Apply pending alias membership changes.

        ``POST /api/firewall/alias/reconfigure`` — cheap, and required for
        the table update to take effect in the running ruleset.
        """
        data = await self._post("/api/firewall/alias/reconfigure")
        _assert_alias_op_ok(data, "alias reconfigure")

    async def list_arp(self) -> list[_OPNArpEntry]:
        """ARP table — secondary population, only fetched when the
        operator opts in.

        Returns an empty list only on 404 (endpoint absent); a transient
        5xx / timeout is re-raised so the reconciler aborts rather than
        mistaking a transient error for an empty ARP table and deleting
        every mirrored ARP row (#5).
        """
        try:
            body = await self._get("/api/diagnostics/interface/getArp")
        except OPNsenseClientError as exc:
            if exc.status_code == 404:
                logger.debug("opnsense_arp_unavailable", error=str(exc))
                return []
            raise
        out: list[_OPNArpEntry] = []
        for r in _unwrap_rows(body):
            addr = str(r.get("ip") or r.get("address") or "").strip()
            if not addr:
                continue
            out.append(
                _OPNArpEntry(
                    address=addr,
                    mac=_normalise_mac(r.get("mac") or r.get("hwaddr")),
                    hostname=str(r.get("hostname") or "").strip(),
                    interface=str(r.get("intf") or r.get("interface") or "").strip(),
                )
            )
        return out


__all__ = [
    "OPNsenseClient",
    "OPNsenseClientError",
    "_OPNArpEntry",
    "_OPNFirmwareInfo",
    "_OPNInterface",
    "_OPNLease",
    "_OPNLeaseResult",
    "_OPNReservation",
    "_OPNReservationResult",
    "_OPNVlan",
    "_addresses_from_arrays",
    "_interfaces_from_ifconfig",
    "_interfaces_from_overview",
    "_network_cidr",
    "_normalise_mac",
    "_unwrap_rows",
]
