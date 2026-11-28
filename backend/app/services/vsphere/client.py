"""Minimal async vSphere Automation REST client (vCenter 7.0 U2+ / 8).

Endpoints consumed (all read-only):

* ``POST /api/session`` (HTTP Basic) -> session id; ``DELETE /api/session``
  closes it. Every other call carries ``vmware-api-session-id``.
* ``GET /api/appliance/system/version`` -> vCenter version (best effort;
  needs a privilege some read-only roles lack, so a failure is not fatal).
* ``GET /api/vcenter/host`` -> ESXi host roster.
* ``GET /api/vcenter/vm`` -> VM roster (name + power state).
* ``GET /api/vcenter/vm/{vm}/guest/networking/interfaces`` -> per-NIC MAC
  + guest IPs. Needs VMware Tools running in the guest; otherwise vCenter
  answers with an error that this client maps to ``tools_not_running``
  rather than treating the VM as having no addresses.

The roster endpoints are not paged: vCenter returns at most
``MAX_LIST_RESULTS`` rows and does not say it truncated, so a list that
reaches the cap is reported as truncated and the reconciler treats the read
as incomplete (it never absence-deletes on one).
"""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

from app.core.exc_text import describe_exc
from app.services._mirror_shape import require_list

logger = structlog.get_logger(__name__)

# vCenter's documented ceiling for an unfiltered /api/vcenter/vm list.
MAX_LIST_RESULTS = 4000
# Hard bound on the per-VM guest calls in one pass, and their concurrency.
MAX_GUEST_CALLS = 4000
GUEST_CONCURRENCY = 8
REQUEST_TIMEOUT = 20.0

# Guest-networking states vCenter reports for an address we do not want:
# only a preferred address is a real, in-use address.
_USABLE_IP_STATES = {"PREFERRED", ""}


class VSphereClientError(Exception):
    """Raised when vCenter returns something the reconciler cannot use."""


@dataclass
class VSphereHost:
    host: str  # moid, "host-12"
    name: str  # inventory name (often an FQDN or an IP literal)
    connection_state: str
    power_state: str


@dataclass
class VSphereGuestNic:
    mac: str | None
    ips: list[str] = field(default_factory=list)


@dataclass
class VSphereVM:
    vm: str  # moid, "vm-42"
    name: str
    power_state: str  # POWERED_ON | POWERED_OFF | SUSPENDED
    # ``reporting``: VMware Tools answered. ``tools_not_running``: the VM is
    # on but vCenter has no guest data. ``not_queried``: not powered on.
    guest_state: str = "not_queried"
    nics: list[VSphereGuestNic] = field(default_factory=list)


def normalise_mac(mac: str) -> str:
    return mac.strip().lower().replace("-", ":")


def _usable_ip(raw: Any) -> str | None:
    """A guest address worth mirroring: a global/private unicast address in
    ``PREFERRED`` state. Link-local, loopback and tentative / deprecated
    addresses are VMware Tools noise, not allocations."""
    if not isinstance(raw, dict):
        return None
    if str(raw.get("state") or "").upper() not in _USABLE_IP_STATES:
        return None
    try:
        addr = ipaddress.ip_address(str(raw.get("ip_address") or "").strip())
    except ValueError:
        return None
    if addr.is_link_local or addr.is_loopback or addr.is_multicast or addr.is_unspecified:
        return None
    return str(addr)


class VSphereClient:
    """``async with VSphereClient(...) as c`` opens a session and closes it."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str,
        password: str,
        verify_tls: bool = True,
        ca_bundle_pem: str = "",
    ) -> None:
        self._base = f"https://{host}:{port}"
        self._username = username
        self._password = password
        self._verify_tls = verify_tls
        self._ca_bundle_pem = ca_bundle_pem.strip()
        self._client: httpx.AsyncClient | None = None
        self._session_id: str | None = None
        # VMs whose guest call failed for a reason other than "tools not
        # running" (timeout, 5xx): unreadable, not "no addresses".
        self.unreadable_vms: list[str] = []
        # True when a roster list hit MAX_LIST_RESULTS.
        self.truncated = False

    async def __aenter__(self) -> VSphereClient:
        verify: Any
        if not self._verify_tls:
            verify = False
            logger.warning("vsphere_tls_verification_disabled", endpoint=self._base)
        elif self._ca_bundle_pem:
            verify = ssl.create_default_context(cadata=self._ca_bundle_pem)
        else:
            verify = True
        self._client = httpx.AsyncClient(
            base_url=self._base,
            verify=verify,
            timeout=REQUEST_TIMEOUT,
            headers={"Accept": "application/json"},
        )
        try:
            await self._open_session()
        except BaseException:
            await self._client.aclose()
            self._client = None
            raise
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client is None:
            return
        try:
            if self._session_id:
                try:
                    await self._client.delete("/api/session")
                except httpx.HTTPError as err:
                    # The session expires on its own; closing it is courtesy.
                    logger.debug("vsphere_session_close_failed", error=describe_exc(err))
        finally:
            await self._client.aclose()
            self._client = None
            self._session_id = None

    async def _open_session(self) -> None:
        assert self._client is not None
        try:
            resp = await self._client.post("/api/session", auth=(self._username, self._password))
        except httpx.HTTPError as exc:
            raise VSphereClientError(f"/api/session: {describe_exc(exc)}") from exc
        if resp.status_code == 401:
            raise VSphereClientError("/api/session: HTTP 401 — username or password rejected")
        if resp.status_code == 404:
            raise VSphereClientError(
                "/api/session: HTTP 404 — not a vSphere Automation REST endpoint "
                "(vCenter 7.0 U2 or later is required)"
            )
        if resp.status_code >= 400:
            raise VSphereClientError(f"/api/session: HTTP {resp.status_code} {resp.text[:200]}")
        try:
            token = resp.json()
        except ValueError as exc:
            raise VSphereClientError("/api/session: response is not JSON") from exc
        if not isinstance(token, str) or not token:
            raise VSphereClientError("/api/session: no session id in the response")
        self._session_id = token
        self._client.headers["vmware-api-session-id"] = token

    async def _get(self, path: str, *, params: dict[str, str] | None = None) -> Any:
        assert self._client is not None, "use within 'async with'"
        try:
            resp = await self._client.get(path, params=params)
        except httpx.HTTPError as exc:
            raise VSphereClientError(f"{path}: {describe_exc(exc)}") from exc
        if resp.status_code == 401:
            raise VSphereClientError(f"{path}: HTTP 401 — session rejected")
        if resp.status_code == 403:
            raise VSphereClientError(f"{path}: HTTP 403 — the account lacks read privileges")
        if resp.status_code >= 400:
            raise VSphereClientError(f"{path}: HTTP {resp.status_code} {resp.text[:200]}")
        try:
            return resp.json()
        except ValueError as exc:
            raise VSphereClientError(f"{path}: response is not JSON") from exc

    # ── Public surface ───────────────────────────────────────────────

    async def get_version(self) -> str | None:
        """vCenter version, or ``None`` when the account cannot read it."""
        try:
            body = await self._get("/api/appliance/system/version")
        except VSphereClientError as exc:
            logger.debug("vsphere_version_unavailable", error=str(exc))
            return None
        if isinstance(body, dict):
            return str(body.get("version") or "") or None
        return None

    async def list_hosts(self) -> list[VSphereHost]:
        items = require_list(
            await self._get("/api/vcenter/host"),
            make_error=VSphereClientError,
            context="/api/vcenter/host",
        )
        if len(items) >= MAX_LIST_RESULTS:
            self.truncated = True
        out: list[VSphereHost] = []
        for item in items:
            if not isinstance(item, dict) or not item.get("host"):
                continue
            out.append(
                VSphereHost(
                    host=str(item["host"]),
                    name=str(item.get("name") or item["host"]),
                    connection_state=str(item.get("connection_state") or ""),
                    power_state=str(item.get("power_state") or ""),
                )
            )
        return out

    async def list_vms(self) -> list[VSphereVM]:
        items = require_list(
            await self._get("/api/vcenter/vm"),
            make_error=VSphereClientError,
            context="/api/vcenter/vm",
        )
        if len(items) >= MAX_LIST_RESULTS:
            self.truncated = True
        out: list[VSphereVM] = []
        for item in items:
            if not isinstance(item, dict) or not item.get("vm"):
                continue
            out.append(
                VSphereVM(
                    vm=str(item["vm"]),
                    name=str(item.get("name") or item["vm"]),
                    power_state=str(item.get("power_state") or "UNKNOWN"),
                )
            )
        return out

    async def _guest_interfaces(self, vm: VSphereVM) -> None:
        path = f"/api/vcenter/vm/{vm.vm}/guest/networking/interfaces"
        assert self._client is not None
        try:
            resp = await self._client.get(path)
        except httpx.HTTPError as exc:
            self.unreadable_vms.append(vm.vm)
            logger.debug("vsphere_guest_read_failed", vm=vm.vm, error=describe_exc(exc))
            return
        if resp.status_code in (401, 403):
            raise VSphereClientError(f"{path}: HTTP {resp.status_code} — not permitted")
        if resp.status_code in (400, 404, 503):
            # vCenter's answer for a guest it has no data for (VMware Tools
            # not installed / not running): a known state, not a failure.
            vm.guest_state = "tools_not_running"
            return
        if resp.status_code >= 400:
            self.unreadable_vms.append(vm.vm)
            return
        try:
            body = resp.json()
        except ValueError:
            self.unreadable_vms.append(vm.vm)
            return
        if not isinstance(body, list):
            self.unreadable_vms.append(vm.vm)
            return
        vm.guest_state = "reporting"
        for nic in body:
            if not isinstance(nic, dict):
                continue
            mac = nic.get("mac_address")
            ips: list[str] = []
            ip_block = nic.get("ip")
            if isinstance(ip_block, dict):
                for raw in ip_block.get("ip_addresses") or []:
                    ip = _usable_ip(raw)
                    if ip and ip not in ips:
                        ips.append(ip)
            vm.nics.append(
                VSphereGuestNic(
                    mac=normalise_mac(mac) if isinstance(mac, str) and mac else None, ips=ips
                )
            )

    async def load_guest_networking(self, vms: list[VSphereVM]) -> None:
        """Fill ``nics`` / ``guest_state`` for every powered-on VM, with a
        bounded number of calls and bounded concurrency."""
        targets = [v for v in vms if v.power_state == "POWERED_ON"]
        if len(targets) > MAX_GUEST_CALLS:
            self.truncated = True
            targets = targets[:MAX_GUEST_CALLS]
        sem = asyncio.Semaphore(GUEST_CONCURRENCY)

        async def one(v: VSphereVM) -> None:
            async with sem:
                await self._guest_interfaces(v)

        await asyncio.gather(*(one(v) for v in targets))


__all__ = [
    "MAX_LIST_RESULTS",
    "VSphereClient",
    "VSphereClientError",
    "VSphereGuestNic",
    "VSphereHost",
    "VSphereVM",
    "normalise_mac",
]
