"""Minimal async Proxmox VE REST client.

Endpoints consumed:

* ``/version`` — sanity + feature detection.
* ``/cluster/status`` — cluster name + quorum + node roster.
* ``/cluster/sdn/vnets`` — SDN VNets (cluster-scoped).
* ``/cluster/sdn/vnets/{vnet}/subnets`` — SDN-owned subnets.
* ``/nodes`` — every node the cluster can see (for iteration).
* ``/nodes/{node}/network`` — bridges / VLAN interfaces with their
  CIDR / active flag.
* ``/nodes/{node}/qemu`` — VM inventory.
* ``/nodes/{node}/qemu/{vmid}/config`` — NIC + ``ipconfigN`` strings.
* ``/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces`` — runtime
  IPs via the QEMU guest agent. Only works when the VM has the
  guest-agent package installed AND ``agent: 1`` in its config.
* ``/nodes/{node}/lxc`` — container inventory.
* ``/nodes/{node}/lxc/{vmid}/config`` — same NIC parsing as VMs.
* ``/nodes/{node}/lxc/{vmid}/interfaces`` — runtime IPs when running.

Auth is API-token (``Authorization: PVEAPIToken=user@realm!tokenid=UUID``).
No ticket + CSRF pair — tokens skip 2FA and are designed for this.

Shape convention: every PVE response is ``{"data": ...}``. We unwrap
``.data`` in ``_get`` so the rest of this module speaks raw dicts.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

from app.services._mirror_shape import require_list

logger = structlog.get_logger(__name__)


class ProxmoxClientError(Exception):
    """Raised when the PVE API returns an error we can't recover from.

    The message carries the HTTP status + path + first 200 bytes of
    response body so operator-facing error messages are useful.
    """


@dataclass
class _ProxmoxVersion:
    version: str  # e.g. "9.1.9"
    release: str  # e.g. "9.1"
    repoid: str  # build id


@dataclass
class _ProxmoxClusterInfo:
    # ``None`` for standalone hosts (no cluster configured).
    cluster_name: str | None
    node_count: int
    quorate: bool | None  # None when standalone


@dataclass
class _ProxmoxNodeInfo:
    node: str  # hostname
    status: str  # "online" | "offline" | "unknown"


@dataclass
class _ProxmoxNetworkIface:
    node: str
    iface: str  # "vmbr0" etc.
    iface_type: str  # "bridge" | "vlan" | "bond" | ...
    cidr: str | None  # "10.0.0.1/24" when the iface carries an IP
    active: bool


@dataclass
class _ProxmoxSDNVnet:
    """VNet roster entry from ``/cluster/sdn/vnets``.

    Mirrors only the metadata we care about — the full PVE payload
    also carries a digest + type + vlanaware flag we don't use.
    """

    vnet: str  # "VLAN10"
    zone: str  # "home", "evpn1", ...
    alias: str | None  # operator-set human name
    tag: int | None  # VLAN tag when zone.type == "vlan"


@dataclass
class _ProxmoxSDNSubnet:
    """Cluster-scoped subnet declared under an SDN VNet.

    Unlike ``_ProxmoxNetworkIface``, this represents the intended IP
    plan rather than whatever happens to be configured on a host's
    Linux bridge. Operators running PVE SDN keep the source of truth
    here, so we treat it as authoritative and mirror every subnet we
    find regardless of whether the backing bridge carries an IP on
    the PVE hosts (it usually doesn't — SDN zones are pure L2
    overlays terminated on an upstream router).
    """

    vnet: str  # "vnet1"
    zone: str  # "localnetwork", "evpn1", ...
    cidr: str  # "10.0.0.0/24" — PVE already stores the network form
    gateway: str | None
    snat: bool
    alias: str | None  # free-form human label on the vnet


@dataclass
class _ProxmoxNicDef:
    """Normalised NIC parsed from a ``netN=...`` config string.

    The format is a comma-separated list of ``key=value`` pairs:
    ``virtio=BC:24:11:...,bridge=vmbr0,tag=10,firewall=1`` (VM) or
    ``name=eth0,bridge=vmbr0,hwaddr=BC:24:11:...,tag=10,ip=10.0.0.5/24,gw=10.0.0.1``
    (LXC). The first key-value pair on VMs is ``model=mac`` (virtio /
    e1000 / rtl8139 etc.) — we harvest the MAC from there.
    """

    slot: str  # "net0", "net1", ...
    mac: str | None
    bridge: str | None
    vlan_tag: int | None
    # Static IP from the config (``ipN`` for VMs via ``ipconfigN``, or
    # ``ip`` for LXC). None = DHCP / manual / unset.
    static_cidr: str | None
    # Optional gateway declared alongside the static IP (``gw=...``).
    # Only populated when the NIC's format actually ships one, so we
    # don't synthesise a gateway for VNet-inference from runtime IPs.
    static_gateway: str | None = None


@dataclass
class _ProxmoxGuest:
    """VM or LXC summary — the reconciler iterates these."""

    node: str
    vmid: int
    name: str
    kind: str  # "qemu" | "lxc"
    status: str  # "running" | "stopped" | ...
    agent_enabled: bool  # VM only; False for LXC
    nics: list[_ProxmoxNicDef] = field(default_factory=list)
    # Runtime IPs keyed by MAC (lowercase, colon-separated). Populated
    # for running guests where agent / interfaces endpoint is
    # reachable. Empty dict = fall back to ``static_cidr`` on each nic.
    runtime_ips_by_mac: dict[str, list[str]] = field(default_factory=dict)


def _parse_nic_string(slot: str, value: str) -> _ProxmoxNicDef:
    """Parse a single ``netN=...`` entry. Handles both VM + LXC shape.

    VM example: ``virtio=BC:24:11:E8:4A:3F,bridge=vmbr0,tag=10``
    LXC example: ``name=eth0,bridge=vmbr0,hwaddr=BC:24:11:E8:4A:3F,ip=10.0.0.5/24,gw=10.0.0.1``
    """
    mac: str | None = None
    bridge: str | None = None
    tag: int | None = None
    static_cidr: str | None = None
    gw: str | None = None
    # Virtio / e1000 / rtl8139 / vmxnet3 / intel-e1000-82540em / ne2k_pci —
    # PVE's VM model list. We treat the first token as "model=mac" when
    # it has no '=' equal-sign resolution... actually each part is
    # ``k=v``; the model is the KEY and the MAC is the value.
    for part in value.split(","):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip().lower()
        v = v.strip()
        if k in {
            "virtio",
            "e1000",
            "rtl8139",
            "vmxnet3",
            "ne2k_pci",
            "i82551",
            "i82557b",
            "i82559er",
        }:
            mac = v.upper() if v else None
        elif k == "hwaddr":
            mac = v.upper() if v else None
        elif k == "bridge":
            bridge = v
        elif k == "tag":
            try:
                tag = int(v)
            except ValueError:
                tag = None
        elif k == "ip":
            static_cidr = v if v and v.lower() != "dhcp" else None
        elif k == "gw":
            gw = v if v else None
    return _ProxmoxNicDef(
        slot=slot,
        mac=mac,
        bridge=bridge,
        vlan_tag=tag,
        static_cidr=static_cidr,
        static_gateway=gw,
    )


def _parse_ipconfig_string(value: str) -> str | None:
    """Pull the ``ip=...`` value out of an ``ipconfigN`` entry.

    Format: ``ip=10.0.0.5/24,gw=10.0.0.1`` or ``ip=dhcp``. Returns
    ``None`` for DHCP / unset.
    """
    for part in value.split(","):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        if k.strip().lower() == "ip" and v and v.lower() != "dhcp":
            return v.strip()
    return None


def _parse_ipconfig_gw(value: str) -> str | None:
    """Pull the ``gw=...`` value out of an ``ipconfigN`` entry.

    Returns ``None`` when the entry doesn't declare a gateway (common
    for DHCP-configured NICs or guests that share a gateway advertised
    at a higher layer).
    """
    for part in value.split(","):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        if k.strip().lower() == "gw" and v:
            return v.strip()
    return None


def _normalise_mac(mac: str) -> str:
    """Canonical form: colon-separated, lowercase, no whitespace."""
    return mac.strip().lower().replace("-", ":")


def _cidr_from_sdn_id(raw_id: str) -> str | None:
    """PVE SDN subnets use IDs like ``evpn1-10.0.0.0-24``. Reconstruct
    the CIDR when the ``cidr`` field is missing (older PVE). Returns
    ``None`` when the id can't be parsed.
    """
    if not raw_id:
        return None
    # Split off the trailing ``-<prefix>`` — a literal ``/`` isn't in
    # the id because PVE uses ``-`` as the separator everywhere.
    parts = raw_id.rsplit("-", 1)
    if len(parts) != 2:
        return None
    net_part, prefix = parts
    prefix = prefix.strip()
    if not prefix.isdigit():
        return None
    net = net_part.rsplit("-", 1)
    if len(net) != 2:
        return None
    return f"{net[1]}/{prefix}"


class ProxmoxClient:
    """Per-endpoint async client. One instance per reconcile pass.

    Caller is responsible for ``async with`` lifecycle. Holds a single
    ``httpx.AsyncClient`` so every list call shares a TLS session.
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        token_id: str,
        token_secret: str,
        verify_tls: bool,
        ca_bundle_pem: str = "",
    ) -> None:
        self._base = f"https://{host}:{port}/api2/json"
        self._headers = {
            "Authorization": f"PVEAPIToken={token_id}={token_secret}",
            "Accept": "application/json",
        }
        self._verify_tls = verify_tls
        self._ca_bundle_pem = ca_bundle_pem.strip()
        self._client: httpx.AsyncClient | None = None
        # #1559 — guests whose per-guest config fetch failed during the
        # most recent list_qemu / list_lxc pass, as ``"<node>/<kind>/<vmid>"``
        # labels. Such a guest is *unreadable*, not *gone*: the reconciler
        # reads this list and skips its address absence-delete for the pass
        # rather than deleting the guest's mirrored rows over one hiccup.
        self.unreadable_guests: list[str] = []

    async def __aenter__(self) -> ProxmoxClient:
        verify: Any
        if not self._verify_tls:
            verify = False
            # Operator opted out of TLS verification for this endpoint.
            # Surface it on every connect so the insecure posture is
            # visible in the centralized logs (#5); the who/when of
            # enabling it lives in the integration-target audit row.
            logger.warning("proxmox_tls_verification_disabled", endpoint=self._base)
        elif self._ca_bundle_pem:
            verify = ssl.create_default_context(cadata=self._ca_bundle_pem)
        else:
            verify = True
        self._client = httpx.AsyncClient(
            base_url=self._base,
            headers=self._headers,
            verify=verify,
            timeout=20.0,
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _get(self, path: str) -> Any:
        assert self._client is not None, "use within 'async with'"
        try:
            resp = await self._client.get(path)
        except httpx.HTTPError as exc:
            raise ProxmoxClientError(f"{path}: {exc}") from exc
        if resp.status_code == 401:
            raise ProxmoxClientError(f"{path}: HTTP 401 — token invalid / expired")
        if resp.status_code == 403:
            raise ProxmoxClientError(f"{path}: HTTP 403 — token ACL denies this path")
        if resp.status_code >= 400:
            raise ProxmoxClientError(f"{path}: HTTP {resp.status_code} {resp.text[:200]}")
        body = resp.json()
        if isinstance(body, dict) and "data" in body:
            return body["data"]
        return body

    # ── Public surface ───────────────────────────────────────────────

    async def get_version(self) -> _ProxmoxVersion:
        data = await self._get("/version")
        return _ProxmoxVersion(
            version=str(data.get("version") or ""),
            release=str(data.get("release") or ""),
            repoid=str(data.get("repoid") or ""),
        )

    async def get_cluster_info(self) -> _ProxmoxClusterInfo:
        """Returns cluster name + node count + quorum state.

        On a standalone host ``/cluster/status`` returns an empty list
        or a single ``{type: "node"}`` entry — we detect that by the
        absence of a ``type=cluster`` entry.
        """
        items = await self._get("/cluster/status")
        cluster_name: str | None = None
        quorate: bool | None = None
        node_count = 0
        if isinstance(items, list):
            for item in items:
                if not isinstance(item, dict):
                    continue
                if item.get("type") == "cluster":
                    cluster_name = str(item.get("name") or "") or None
                    quorate = bool(item.get("quorate"))
                elif item.get("type") == "node":
                    node_count += 1
        # Standalone hosts still expose /nodes even without a cluster,
        # so if we got zero nodes here, fall back to counting /nodes.
        if node_count == 0:
            nodes = await self._get("/nodes")
            if isinstance(nodes, list):
                node_count = len(nodes)
        return _ProxmoxClusterInfo(
            cluster_name=cluster_name, node_count=node_count, quorate=quorate
        )

    async def list_nodes(self) -> list[_ProxmoxNodeInfo]:
        # #430 — a data:null / non-list body (confused PVE, proxy error page)
        # must raise, not yield zero nodes — zero nodes collects zero guests
        # and absence-deletes every Proxmox-owned IP. Empty cluster → [].
        items = require_list(
            await self._get("/nodes"), make_error=ProxmoxClientError, context="/nodes"
        )
        out: list[_ProxmoxNodeInfo] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("node") or "")
            if not name:
                continue
            out.append(_ProxmoxNodeInfo(node=name, status=str(item.get("status") or "unknown")))
        return out

    async def list_networks(self, node: str) -> list[_ProxmoxNetworkIface]:
        """Bridges / VLAN interfaces / bonds — the stuff with a CIDR is
        what we mirror into IPAM as a subnet.
        """
        items = require_list(
            await self._get(f"/nodes/{node}/network"),
            make_error=ProxmoxClientError,
            context=f"/nodes/{node}/network",
        )
        out: list[_ProxmoxNetworkIface] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            iface = str(item.get("iface") or "")
            if not iface:
                continue
            # ``cidr`` is "10.0.0.1/24" when the iface has an IP; else
            # PVE returns ``address`` + ``netmask`` (IPv4 only) which
            # we combine. Unaddressed bridges yield None on both and
            # get skipped by the reconciler.
            cidr: str | None = None
            raw_cidr = item.get("cidr")
            if isinstance(raw_cidr, str) and raw_cidr:
                cidr = raw_cidr
            else:
                addr = item.get("address")
                mask = item.get("netmask")
                if addr and mask:
                    try:
                        import ipaddress

                        net = ipaddress.ip_interface(f"{addr}/{mask}")
                        cidr = str(net.network)
                    except (ValueError, ipaddress.AddressValueError):
                        cidr = None
            out.append(
                _ProxmoxNetworkIface(
                    node=node,
                    iface=iface,
                    iface_type=str(item.get("type") or ""),
                    cidr=cidr,
                    active=bool(item.get("active")),
                )
            )
        return out

    async def list_sdn_vnets(self) -> list[_ProxmoxSDNVnet]:
        """Every VNet the cluster knows about, regardless of whether
        it has declared subnets. Empty list on no-SDN / 404 / 403.
        """
        try:
            items = await self._get("/cluster/sdn/vnets")
        except ProxmoxClientError as exc:
            logger.debug("proxmox_sdn_vnets_unavailable", error=str(exc))
            return []
        if not isinstance(items, list):
            return []
        out: list[_ProxmoxSDNVnet] = []
        for v in items:
            if not isinstance(v, dict):
                continue
            name = str(v.get("vnet") or "")
            if not name:
                continue
            alias_raw = v.get("alias")
            alias = str(alias_raw) if isinstance(alias_raw, str) and alias_raw else None
            tag_raw = v.get("tag")
            try:
                tag = int(tag_raw) if tag_raw is not None else None
            except (TypeError, ValueError):
                tag = None
            out.append(
                _ProxmoxSDNVnet(
                    vnet=name,
                    zone=str(v.get("zone") or ""),
                    alias=alias,
                    tag=tag,
                )
            )
        return out

    async def list_sdn_subnets(self) -> list[_ProxmoxSDNSubnet]:
        """Flatten every VNet's subnets into a single list.

        Returns an empty list if the cluster has no SDN configured, if
        the PVE version predates SDN, or if the token's role lacks
        ``SDN.Audit``. We don't want SDN-not-installed to fail the
        whole reconcile — bridges still populate the subnet list in
        that case.
        """
        try:
            vnets = await self._get("/cluster/sdn/vnets")
        except ProxmoxClientError as exc:
            logger.debug("proxmox_sdn_vnets_unavailable", error=str(exc))
            return []
        if not isinstance(vnets, list):
            return []
        out: list[_ProxmoxSDNSubnet] = []
        for v in vnets:
            if not isinstance(v, dict):
                continue
            vnet_name = str(v.get("vnet") or "")
            if not vnet_name:
                continue
            zone = str(v.get("zone") or "")
            alias_raw = v.get("alias")
            alias = str(alias_raw) if isinstance(alias_raw, str) and alias_raw else None
            try:
                subnets = await self._get(f"/cluster/sdn/vnets/{vnet_name}/subnets")
            except ProxmoxClientError as exc:
                logger.debug(
                    "proxmox_sdn_subnets_unavailable",
                    vnet=vnet_name,
                    error=str(exc),
                )
                continue
            if not isinstance(subnets, list):
                continue
            for s in subnets:
                if not isinstance(s, dict):
                    continue
                cidr = str(s.get("cidr") or "")
                if not cidr:
                    # Older PVE stores the CIDR inside ``id`` as
                    # ``{zone}-{net}-{prefix}``; reconstruct in that
                    # case so we don't drop perfectly good rows.
                    raw_id = str(s.get("id") or "")
                    cidr = _cidr_from_sdn_id(raw_id)
                    if not cidr:
                        continue
                gw_raw = s.get("gateway")
                gateway = str(gw_raw) if isinstance(gw_raw, str) and gw_raw else None
                out.append(
                    _ProxmoxSDNSubnet(
                        vnet=vnet_name,
                        zone=zone,
                        cidr=cidr,
                        gateway=gateway,
                        snat=bool(s.get("snat")),
                        alias=alias,
                    )
                )
        return out

    async def list_qemu(self, node: str, *, include_stopped: bool) -> list[_ProxmoxGuest]:
        items = require_list(
            await self._get(f"/nodes/{node}/qemu"),
            make_error=ProxmoxClientError,
            context=f"/nodes/{node}/qemu",
        )
        guests: list[_ProxmoxGuest] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            vmid = int(item.get("vmid") or 0)
            if not vmid:
                continue
            status = str(item.get("status") or "unknown")
            if not include_stopped and status != "running":
                continue
            name = str(item.get("name") or f"vm-{vmid}")
            # Per-VM config for NICs + ipconfig + agent flag.
            try:
                cfg = await self._get(f"/nodes/{node}/qemu/{vmid}/config")
            except ProxmoxClientError as exc:
                logger.warning("proxmox_qemu_config_failed", node=node, vmid=vmid, error=str(exc))
                # #1559 — record the guest as unreadable so the reconciler
                # does not absence-delete its addresses this pass.
                self.unreadable_guests.append(f"{node}/qemu/{vmid}")
                continue
            agent_enabled = _agent_flag_from_config(
                cfg.get("agent") if isinstance(cfg, dict) else None
            )
            nics = _nics_from_qemu_config(cfg if isinstance(cfg, dict) else {})
            guest = _ProxmoxGuest(
                node=node,
                vmid=vmid,
                name=name,
                kind="qemu",
                status=status,
                agent_enabled=agent_enabled,
                nics=nics,
            )
            if agent_enabled and status == "running":
                await self._hydrate_qemu_runtime_ips(guest)
            guests.append(guest)
        return guests

    async def list_lxc(self, node: str, *, include_stopped: bool) -> list[_ProxmoxGuest]:
        items = require_list(
            await self._get(f"/nodes/{node}/lxc"),
            make_error=ProxmoxClientError,
            context=f"/nodes/{node}/lxc",
        )
        guests: list[_ProxmoxGuest] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            vmid = int(item.get("vmid") or 0)
            if not vmid:
                continue
            status = str(item.get("status") or "unknown")
            if not include_stopped and status != "running":
                continue
            name = str(item.get("name") or f"ct-{vmid}")
            try:
                cfg = await self._get(f"/nodes/{node}/lxc/{vmid}/config")
            except ProxmoxClientError as exc:
                logger.warning("proxmox_lxc_config_failed", node=node, vmid=vmid, error=str(exc))
                # #1559 — see list_qemu: unreadable, not gone.
                self.unreadable_guests.append(f"{node}/lxc/{vmid}")
                continue
            nics = _nics_from_lxc_config(cfg if isinstance(cfg, dict) else {})
            hostname = (str(cfg.get("hostname") or "") if isinstance(cfg, dict) else "") or name
            guest = _ProxmoxGuest(
                node=node,
                vmid=vmid,
                name=hostname,
                kind="lxc",
                status=status,
                agent_enabled=False,
                nics=nics,
            )
            if status == "running":
                await self._hydrate_lxc_runtime_ips(guest)
            guests.append(guest)
        return guests

    async def _hydrate_qemu_runtime_ips(self, guest: _ProxmoxGuest) -> None:
        """Query the QEMU guest-agent for live per-interface IPs.

        Returns silently on failure — the reconciler can still fall
        back to ``static_cidr`` on each NIC. Common failure modes:
        agent not running inside the VM, agent package not installed,
        agent channel not configured on the VM.
        """
        try:
            data = await self._get(
                f"/nodes/{guest.node}/qemu/{guest.vmid}/agent/network-get-interfaces"
            )
        except ProxmoxClientError as exc:
            logger.debug(
                "proxmox_qemu_agent_ips_failed",
                node=guest.node,
                vmid=guest.vmid,
                error=str(exc),
            )
            return
        result = data.get("result") if isinstance(data, dict) else data
        if not isinstance(result, list):
            return
        for iface in result:
            if not isinstance(iface, dict):
                continue
            mac = iface.get("hardware-address") or iface.get("hardware_address")
            if not mac:
                continue
            addrs = iface.get("ip-addresses") or iface.get("ip_addresses") or []
            ips: list[str] = []
            for a in addrs:
                if not isinstance(a, dict):
                    continue
                ip = a.get("ip-address") or a.get("ip_address")
                if not ip:
                    continue
                # Skip link-local + loopback so we don't pollute IPAM
                # with fe80:: and 127.0.0.1.
                if isinstance(ip, str) and (
                    ip.startswith("fe80:") or ip == "127.0.0.1" or ip == "::1"
                ):
                    continue
                ips.append(str(ip))
            if ips:
                guest.runtime_ips_by_mac[_normalise_mac(str(mac))] = ips

    async def _hydrate_lxc_runtime_ips(self, guest: _ProxmoxGuest) -> None:
        """LXC equivalent of the QEMU agent path — ``/interfaces`` returns
        per-iface runtime IPs directly, no guest-agent needed.
        """
        try:
            data = await self._get(f"/nodes/{guest.node}/lxc/{guest.vmid}/interfaces")
        except ProxmoxClientError as exc:
            logger.debug(
                "proxmox_lxc_interfaces_failed",
                node=guest.node,
                vmid=guest.vmid,
                error=str(exc),
            )
            return
        if not isinstance(data, list):
            return
        for iface in data:
            if not isinstance(iface, dict):
                continue
            mac = iface.get("hwaddr")
            if not mac:
                continue
            ips: list[str] = []
            inet = iface.get("inet")
            inet6 = iface.get("inet6")
            if isinstance(inet, str) and inet and "/" in inet:
                ips.append(inet.split("/", 1)[0])
            if isinstance(inet6, str) and inet6 and "/" in inet6:
                v6 = inet6.split("/", 1)[0]
                if not v6.startswith("fe80"):
                    ips.append(v6)
            if ips:
                guest.runtime_ips_by_mac[_normalise_mac(str(mac))] = ips


def _agent_flag_from_config(value: Any) -> bool:
    """PVE stores the agent flag as a comma-separated option string
    ``enabled=1,type=virtio,freeze-fs-on-backup=1``. A bare ``1`` or
    ``0`` works too. Returns True when the agent is on.
    """
    if value is None:
        return False
    if isinstance(value, int):
        return value == 1
    s = str(value).strip()
    if s in {"1", "0"}:
        return s == "1"
    # Parse option form
    for part in s.split(","):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        if k.strip().lower() == "enabled":
            return v.strip() == "1"
    return False


def _nics_from_qemu_config(cfg: dict[str, Any]) -> list[_ProxmoxNicDef]:
    """Harvest ``netN`` entries, pairing each with its matching
    ``ipconfigN`` for the static IP.
    """
    nics: list[_ProxmoxNicDef] = []
    for i in range(0, 32):
        slot = f"net{i}"
        val = cfg.get(slot)
        if not isinstance(val, str) or not val:
            continue
        nic = _parse_nic_string(slot, val)
        # VMs use ipconfigN, not an inline ip= in netN.
        ip_val = cfg.get(f"ipconfig{i}")
        if isinstance(ip_val, str) and ip_val:
            nic.static_cidr = _parse_ipconfig_string(ip_val)
            nic.static_gateway = _parse_ipconfig_gw(ip_val)
        nics.append(nic)
    return nics


def _nics_from_lxc_config(cfg: dict[str, Any]) -> list[_ProxmoxNicDef]:
    """LXC bakes the static IP into the netN string directly."""
    nics: list[_ProxmoxNicDef] = []
    for i in range(0, 32):
        slot = f"net{i}"
        val = cfg.get(slot)
        if not isinstance(val, str) or not val:
            continue
        nics.append(_parse_nic_string(slot, val))
    return nics


__all__ = [
    "ProxmoxClient",
    "ProxmoxClientError",
    "_ProxmoxClusterInfo",
    "_ProxmoxGuest",
    "_ProxmoxNetworkIface",
    "_ProxmoxNicDef",
    "_ProxmoxNodeInfo",
    "_ProxmoxSDNSubnet",
    "_ProxmoxSDNVnet",
    "_ProxmoxVersion",
    "_cidr_from_sdn_id",
    "_normalise_mac",
    "_parse_nic_string",
    "_parse_ipconfig_gw",
    "_parse_ipconfig_string",
]
