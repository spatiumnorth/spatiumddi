"""Per-endpoint Proxmox VE reconciler.

For one ``ProxmoxNode`` row (which may represent a whole cluster):

  1. Fetch cluster info + nodes from the PVE REST API.
  2. Per node: fetch networks (bridges / VLAN interfaces) + VMs + LXC.
  3. Compute the desired set of IPBlock / Subnet / IPAddress rows.
  4. Load currently-mirrored rows (FK lookup on ``proxmox_node_id``).
  5. Apply the diff: create, update, delete.
  6. Persist ``last_synced_at`` / ``last_sync_error`` / ``pve_version``
     / ``cluster_name`` / ``node_count`` + summary audit entry.

Parallels the Docker reconciler. Notable specifics:

* **Bridges without a CIDR are skipped.** PVE's common case is a
  bridge that's just an L2 span onto a physical NIC with no L3 on
  the host — those would pollute IPAM with empty "subnets". Only
  bridges with an actual address land as Subnets.
* **Runtime IPs are best-effort.** If the QEMU guest-agent isn't
  running / not installed, we fall back to the config-time static
  IP (``ipconfigN`` on VMs, inline ``ip=`` on LXC). If nothing is
  set, the NIC contributes no IPAddress row.
* **Mirror toggles default ON** — unlike Docker containers (ephemeral
  CI noise), PVE VMs + LXC are typically long-lived operator
  inventory. Toggling off ``mirror_vms`` / ``mirror_lxc`` skips the
  NIC iteration; networks still mirror.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_str
from app.models.audit import AuditLog
from app.models.ipam import IPAddress, IPBlock, Subnet
from app.models.proxmox import ProxmoxNode
from app.services.integration_ownership import owned_by_other_integration, owning_integration
from app.services.proxmox.client import (
    ProxmoxClient,
    ProxmoxClientError,
    _normalise_mac,
    _ProxmoxSDNSubnet,
    _ProxmoxSDNVnet,
)

logger = structlog.get_logger(__name__)

# Private-address supernets — auto-created as unowned top-level
# IPBlocks when a mirrored CIDR is contained and no enclosing block
# exists. Same list as the Docker reconciler so the tree stays
# consistent across integrations.
_PRIVATE_SUPERNETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
]

_BIGINT_MAX = 2**63 - 1


# ── Desired-state dataclasses ────────────────────────────────────────


@dataclass(frozen=True)
class _DesiredSubnet:
    network: str  # CIDR
    name: str
    description: str
    gateway: str | None = None


@dataclass(frozen=True)
class _DesiredAddress:
    address: str
    status: str  # proxmox-vm | proxmox-lxc | reserved (gateway)
    hostname: str
    description: str
    mac: str | None = None


@dataclass
class ReconcileSummary:
    ok: bool
    error: str | None = None
    pve_version: str | None = None
    cluster_name: str | None = None
    node_count: int = 0
    vm_count: int = 0
    lxc_count: int = 0
    blocks_created: int = 0
    blocks_deleted: int = 0
    subnets_created: int = 0
    subnets_updated: int = 0
    subnets_deleted: int = 0
    # Issue #177: counted when a pre-existing operator-owned subnet at
    # an exact-CIDR match was reused instead of creating a duplicate.
    # Surfaces in the per-run audit blob so operators can see when their
    # own rows took the path Proxmox would otherwise have created.
    subnets_matched: int = 0
    addresses_created: int = 0
    addresses_updated: int = 0
    addresses_deleted: int = 0
    skipped_no_subnet: int = 0
    warnings: list[str] = field(default_factory=list)


# ── Helpers ──────────────────────────────────────────────────────────


def _parse_net(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(value, strict=False)
    except (ValueError, TypeError):
        return None


def _cidr_of_interface(iface_cidr: str) -> str | None:
    """PVE's ``cidr`` field on a bridge is an *interface* CIDR like
    ``10.0.0.1/24`` — we want the network CIDR ``10.0.0.0/24`` for
    IPAM. Returns None on parse failure.
    """
    try:
        iface = ipaddress.ip_interface(iface_cidr)
        return str(iface.network)
    except (ValueError, TypeError):
        return None


def _ip_of_interface(iface_cidr: str) -> str | None:
    """Pull the host-side IP from an iface CIDR (``10.0.0.94/24`` →
    ``10.0.0.94``). Returns ``None`` on parse failure. This is the
    PVE host's own IP on the bridge — emphatically *not* the gateway
    of the underlying network in plain-bridge deployments where
    upstream routing happens on a separate device.
    """
    try:
        return str(ipaddress.ip_interface(iface_cidr).ip)
    except (ValueError, TypeError):
        return None


def _private_supernet_of(cidr: str) -> str | None:
    net = _parse_net(cidr)
    if net is None or not isinstance(net, ipaddress.IPv4Network):
        return None
    for parent in _PRIVATE_SUPERNETS:
        if net.subnet_of(parent) and net.prefixlen > parent.prefixlen:  # type: ignore[arg-type]
            return str(parent)
    return None


def _lan_total_ips(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> int:
    if isinstance(net, ipaddress.IPv6Network):
        return min(net.num_addresses, _BIGINT_MAX)
    if net.prefixlen >= 31:
        return net.num_addresses
    return net.num_addresses - 2


def _find_enclosing_operator_block(
    blocks: list[IPBlock], cidr: str, node_id: Any
) -> IPBlock | None:
    net = _parse_net(cidr)
    if net is None:
        return None
    best: IPBlock | None = None
    best_prefix = -1
    for b in blocks:
        if b.proxmox_node_id == node_id:
            continue
        bnet = _parse_net(str(b.network))
        if bnet is None or type(bnet) is not type(net):
            continue
        if net.subnet_of(bnet) and bnet.prefixlen > best_prefix:  # type: ignore[arg-type]
            best = b
            best_prefix = bnet.prefixlen
    return best


def _find_subnet_for_ip(subnets: list[Subnet], ip: str) -> Subnet | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    best: Subnet | None = None
    best_prefix: int = -1
    for s in subnets:
        net = _parse_net(str(s.network))
        if net is None:
            continue
        if addr in net and net.prefixlen > best_prefix:
            best = s
            best_prefix = net.prefixlen
    return best


async def _recompute_subnet_utilization(db: AsyncSession, subnet_id: Any) -> None:
    allocated = (
        await db.scalar(
            select(func.count())
            .select_from(IPAddress)
            .where(IPAddress.subnet_id == subnet_id)
            .where(IPAddress.status != "available")
        )
        or 0
    )
    subnet = await db.get(Subnet, subnet_id)
    if subnet is None:
        return
    subnet.allocated_ips = allocated
    subnet.utilization_percent = (
        round(allocated / subnet.total_ips * 100, 2) if subnet.total_ips > 0 else 0.0
    )


# ── Desired state computation ────────────────────────────────────────


def _infer_vnet_from_guests(
    vnet: _ProxmoxSDNVnet,
    guests: list[Any],
) -> tuple[str, str | None, str] | None:
    """Best-effort subnet inference for a VNet that PVE knows about
    but hasn't been given a declared subnet.

    Priority order — only the first that matches is used:

    1. Any guest NIC with ``bridge == vnet.vnet`` and a ``static_cidr``
       (from ``ipconfigN`` on VMs or inline ``ip=`` on LXC). The
       network portion is exact; gateway comes from the NIC's
       ``gw=`` when one was declared.
    2. Otherwise, guest-agent / ``/interfaces`` runtime IPv4 IPs on
       any NIC bridged to this VNet. We pick the most common /24 and
       return it with no gateway. This is the speculative path —
       wrong for /23 / /25 deployments; always logged.

    Returns ``(cidr, gateway, source)`` on success or ``None`` when
    no signal exists. ``source`` is one of ``"static_cidr"`` or
    ``"runtime_ip_guess_24"`` so the reconciler can log / describe it.
    """
    static_candidates: list[tuple[str, str | None]] = []
    runtime_ips: list[str] = []

    for g in guests:
        for nic in g.nics:
            if not nic.bridge or nic.bridge != vnet.vnet:
                continue
            if nic.static_cidr:
                try:
                    iface = ipaddress.ip_interface(nic.static_cidr)
                    static_candidates.append((str(iface.network), nic.static_gateway))
                except (ValueError, TypeError):
                    pass
            if nic.mac:
                runtime = g.runtime_ips_by_mac.get(_normalise_mac(nic.mac), [])
                for ip in runtime:
                    # Only IPv4 here — /24 is meaningless for v6.
                    try:
                        addr = ipaddress.ip_address(ip)
                    except ValueError:
                        continue
                    if isinstance(addr, ipaddress.IPv4Address):
                        runtime_ips.append(ip)

    if static_candidates:
        # Prefer the highest-prefix (most specific) network; ties go
        # to the first. Collecting the gateway from the same candidate
        # we picked the CIDR from keeps the two consistent.
        static_candidates.sort(key=lambda x: ipaddress.ip_network(x[0]).prefixlen, reverse=True)
        return (static_candidates[0][0], static_candidates[0][1], "static_cidr")

    if runtime_ips:
        # Most common /24 wins. Ties go to the lowest network — a
        # deterministic tiebreak so the same input always produces
        # the same output across reconcile passes.
        tallies: dict[str, int] = {}
        for ip in runtime_ips:
            try:
                net = ipaddress.ip_network(f"{ip}/24", strict=False)
            except (ValueError, TypeError):
                continue
            key = str(net)
            tallies[key] = tallies.get(key, 0) + 1
        if tallies:
            winner = sorted(tallies.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
            return (winner, None, "runtime_ip_guess_24")

    return None


def _compute_desired(
    node: ProxmoxNode,
    networks: list[Any],
    guests: list[Any],
    sdn_subnets: list[_ProxmoxSDNSubnet] | None = None,
    sdn_vnets: list[_ProxmoxSDNVnet] | None = None,
) -> tuple[list[_DesiredSubnet], list[_DesiredAddress]]:
    subnets: list[_DesiredSubnet] = []
    seen_networks: set[str] = set()
    # Track which VNets we've already produced a subnet for (declared
    # SDN path) so the inference pass skips them.
    vnets_with_subnet: set[str] = {s.vnet for s in (sdn_subnets or [])}

    # SDN subnets: the operator's declared IP plan. Authoritative
    # over bridge-derived rows for the same CIDR because SDN zones
    # often sit on L2-only bridges the host doesn't carry an IP on —
    # relying on bridges alone misses every VLAN the PVE host doesn't
    # terminate.
    for s in sdn_subnets or []:
        net = _parse_net(s.cidr)
        if net is None:
            continue
        cidr = str(net)
        if cidr in seen_networks:
            continue
        seen_networks.add(cidr)
        label = f"vnet:{s.vnet}"
        desc_bits = [f"Proxmox SDN VNet {s.vnet}"]
        if s.zone:
            desc_bits.append(f"zone {s.zone}")
        if s.alias:
            desc_bits.append(f"alias {s.alias}")
        subnets.append(
            _DesiredSubnet(
                network=cidr,
                name=label,
                description=" — ".join(desc_bits),
                gateway=s.gateway,
            )
        )

    # Networks: one subnet per (cidr-bearing bridge or VLAN iface).
    # Multiple PVE nodes in a cluster can advertise the same bridge —
    # dedupe by network CIDR so we don't fight over rows. If a bridge
    # happens to carry an IP on the same CIDR as an SDN subnet we
    # already emitted, the SDN row wins (it has the human-meaningful
    # vnet label and is the operator's declared intent).
    #
    # Note: we deliberately do NOT set ``gateway`` from a bridge IP.
    # In a plain-bridge deployment the host's bridge IP is just the
    # PVE node's own LAN address, not the network gateway — that
    # lives upstream on a router/firewall. SDN simple zones are the
    # only case where PVE itself routes for a subnet, and those land
    # via ``sdn_subnets`` above with their declared gateway.
    bridge_host_ips: list[tuple[str, str, str]] = []  # (cidr, ip, label)
    for n in networks:
        if not n.cidr or not n.active:
            continue
        cidr = _cidr_of_interface(n.cidr)
        if cidr is None:
            continue
        host_ip = _ip_of_interface(n.cidr)
        if host_ip is not None:
            bridge_host_ips.append((cidr, host_ip, f"{n.node}/{n.iface}"))
        if cidr in seen_networks:
            continue
        seen_networks.add(cidr)
        subnets.append(
            _DesiredSubnet(
                network=cidr,
                name=f"{node.name}/{n.iface}",
                description=f"Proxmox {n.iface_type} {n.iface} on {n.node}",
                gateway=None,
            )
        )

    # VNet subnet inference — only when ``infer_vnet_subnets`` is on.
    # For each VNet without a declared SDN subnet, try to derive the
    # CIDR from the guests attached to it. See ``_infer_vnet_from_guests``
    # for the priority order (static_cidr > runtime-ip /24 guess).
    if node.infer_vnet_subnets:
        for vnet in sdn_vnets or []:
            if vnet.vnet in vnets_with_subnet:
                continue
            inferred = _infer_vnet_from_guests(vnet, guests)
            if inferred is None:
                continue
            cidr, gateway, source = inferred
            if cidr in seen_networks:
                continue
            seen_networks.add(cidr)
            desc_bits = [f"Proxmox SDN VNet {vnet.vnet}"]
            if vnet.zone:
                desc_bits.append(f"zone {vnet.zone}")
            if vnet.alias:
                desc_bits.append(f"alias {vnet.alias}")
            desc_bits.append(f"CIDR inferred from {source}")
            if source == "runtime_ip_guess_24":
                logger.warning(
                    "proxmox_vnet_cidr_guessed",
                    vnet=vnet.vnet,
                    cidr=cidr,
                    hint="declare an SDN subnet with `pvesh create /cluster/sdn/vnets/<vnet>/subnets` for an exact CIDR",
                )
            subnets.append(
                _DesiredSubnet(
                    network=cidr,
                    name=f"vnet:{vnet.vnet}",
                    description=" — ".join(desc_bits),
                    gateway=gateway,
                )
            )

    # VM + LXC NIC → addresses. Runtime IP from guest-agent /
    # /interfaces takes priority; otherwise fall back to static_cidr;
    # otherwise skip the NIC.
    addresses: list[_DesiredAddress] = []
    for g in guests:
        for nic in g.nics:
            ips: list[str] = []
            if nic.mac:
                runtime = g.runtime_ips_by_mac.get(_normalise_mac(nic.mac))
                if runtime:
                    ips = list(runtime)
            if not ips and nic.static_cidr:
                try:
                    ips = [str(ipaddress.ip_interface(nic.static_cidr).ip)]
                except (ValueError, TypeError):
                    ips = []
            if not ips:
                continue
            status = "proxmox-vm" if g.kind == "qemu" else "proxmox-lxc"
            desc = f"{g.kind} {g.vmid} on {g.node} ({g.status})"
            for ip in ips:
                addresses.append(
                    _DesiredAddress(
                        address=ip,
                        status=status,
                        hostname=g.name,
                        description=desc,
                        mac=nic.mac,
                    )
                )

    # SDN gateway placeholder rows — when an SDN subnet declares a
    # real gateway (PVE owns L3 for the VNet), reserve the gateway IP.
    for d in subnets:
        if d.gateway:
            addresses.append(
                _DesiredAddress(
                    address=d.gateway,
                    status="reserved",
                    hostname="gateway",
                    description=f"Gateway for {d.name}",
                )
            )

    # PVE host placeholder rows — every node's own bridge IP on a
    # mirrored CIDR lands as a ``reserved`` row so the host shows up
    # in IPAM under its own identity (e.g. ``pve1`` at ``192.168.0.94``)
    # rather than masquerading as a gateway. Each PVE node in the
    # cluster contributes its own row on the same subnet.
    seen_host_ips: set[tuple[str, str]] = set()
    for cidr, host_ip, label in bridge_host_ips:
        key = (cidr, host_ip)
        if key in seen_host_ips:
            continue
        seen_host_ips.add(key)
        node_name = label.split("/", 1)[0] if "/" in label else label
        addresses.append(
            _DesiredAddress(
                address=host_ip,
                status="reserved",
                hostname=node_name,
                description=f"PVE host {label}",
            )
        )

    return subnets, addresses


# ── Apply: blocks + subnets ──────────────────────────────────────────


async def _apply_blocks_and_subnets(
    db: AsyncSession,
    node: ProxmoxNode,
    desired_subnets: list[_DesiredSubnet],
    summary: ReconcileSummary,
    sdn_vnets: list[_ProxmoxSDNVnet] | None = None,
) -> None:
    block_rows = (
        (await db.execute(select(IPBlock).where(IPBlock.space_id == node.ipam_space_id)))
        .scalars()
        .all()
    )
    blocks = list(block_rows)
    node_owned_wrappers = {str(b.network): b for b in blocks if b.proxmox_node_id == node.id}

    existing_networks = {str(b.network): b for b in blocks}
    for d in desired_subnets:
        supernet = _private_supernet_of(d.network)
        if supernet is None or supernet in existing_networks:
            continue
        parent = IPBlock(
            space_id=node.ipam_space_id,
            network=supernet,
            name=f"Private {supernet}",
            description=f"Auto-created as the private-address parent for {d.network}",
        )
        db.add(parent)
        await db.flush()
        blocks.append(parent)
        existing_networks[supernet] = parent
        summary.blocks_created += 1

    # Issue #177: match by CIDR across the whole space. Loading only
    # ``proxmox_node_id == node.id`` rows meant a manually-created or
    # different-integration subnet at the same CIDR was invisible to
    # us, and we'd spawn a duplicate ``vnet:<name>`` twin on every
    # reconcile. We now classify every subnet in the space into:
    #   * node-owned       — drives the update + delete paths below
    #   * operator-owned   — reused as-is (no claim, no overwrite) so
    #                        the operator's curated row survives untouched
    #   * foreign          — owned by another integration; we warn and
    #                        skip without creating a duplicate
    all_subnet_rows = (
        (await db.execute(select(Subnet).where(Subnet.space_id == node.ipam_space_id)))
        .scalars()
        .all()
    )
    current_subnets: dict[str, Subnet] = {}
    operator_subnets: dict[str, Subnet] = {}
    foreign_subnets: dict[str, Subnet] = {}
    for s in all_subnet_rows:
        net_key = str(s.network)
        if s.proxmox_node_id == node.id:
            current_subnets[net_key] = s
        elif owning_integration(s) is None:
            operator_subnets[net_key] = s
        else:
            foreign_subnets[net_key] = s

    desired_map = {d.network: d for d in desired_subnets}
    used_wrapper_cidrs: set[str] = set()

    # VNets that still exist on the cluster, by name. Used by the
    # delete loop below to keep ``vnet:<name>`` subnets stable across
    # reconciles where we couldn't re-infer the CIDR (e.g. all guests
    # on the VNet went offline, agent stopped responding, no
    # ``static_cidr`` on any NIC for this pass). We only delete an
    # inferred subnet when the underlying VNet has actually been
    # removed from PVE — that's the operator-meaningful event.
    extant_vnet_names = {v.vnet for v in (sdn_vnets or [])}

    for net_str, row in current_subnets.items():
        if net_str in desired_map:
            continue
        # Stickiness: if this subnet was named after a VNet and that
        # VNet still exists, keep it. Operators only see deletions
        # when PVE has genuinely removed the upstream object.
        name = row.name or ""
        if name.startswith("vnet:"):
            vnet_name = name[len("vnet:") :]
            if vnet_name in extant_vnet_names:
                used_wrapper_cidrs.add(net_str)
                continue
        await db.delete(row)
        summary.subnets_deleted += 1

    for net_str, d in desired_map.items():
        # Issue #177: an operator subnet at this exact CIDR wins. We
        # reuse it without claiming ownership or rewriting any of its
        # fields — operator-curated rows survive reconciles untouched.
        # IP addresses still mirror into it via ``_find_subnet_for_ip``
        # in the addresses apply pass.
        if net_str in operator_subnets:
            summary.subnets_matched += 1
            continue

        # Another integration already owns this CIDR. We don't duplicate
        # it and we don't try to wrest it away — the operator should
        # resolve the cross-integration overlap deliberately.
        if net_str in foreign_subnets:
            summary.warnings.append(
                f"subnet {net_str} already exists, owned by another integration; not creating duplicate"
            )
            continue

        parent_block = _find_enclosing_operator_block(blocks, d.network, node.id)

        if parent_block is None:
            wrapper = node_owned_wrappers.get(net_str)
            if wrapper is None:
                wrapper = IPBlock(
                    space_id=node.ipam_space_id,
                    network=d.network,
                    name=f"{node.name} {d.network}",
                    description=f"Auto-created for Proxmox endpoint {node.name}",
                    proxmox_node_id=node.id,
                )
                db.add(wrapper)
                await db.flush()
                blocks.append(wrapper)
                node_owned_wrappers[net_str] = wrapper
                summary.blocks_created += 1
            used_wrapper_cidrs.add(net_str)
            parent_block = wrapper

        net_parsed = _parse_net(d.network)
        expected_total = _lan_total_ips(net_parsed) if net_parsed is not None else 0

        existing = current_subnets.get(net_str)
        if existing is None:
            db.add(
                Subnet(
                    space_id=node.ipam_space_id,
                    block_id=parent_block.id,
                    network=d.network,
                    name=d.name,
                    description=d.description,
                    gateway=d.gateway,
                    proxmox_node_id=node.id,
                    total_ips=expected_total,
                )
            )
            summary.subnets_created += 1
        else:
            changed = False
            if existing.block_id != parent_block.id:
                existing.block_id = parent_block.id
                changed = True
            if existing.name != d.name:
                existing.name = d.name
                changed = True
            if existing.description != d.description:
                existing.description = d.description
                changed = True
            # Only set gateway when the integration knows one (SDN
            # subnet declared it). Bridges carry no gateway info, so
            # ``d.gateway`` is None for those — in that case, leave
            # whatever's already there alone. Operators who manually
            # set the correct upstream gateway on a Proxmox-mirrored
            # subnet shouldn't see it cleared on every sync.
            if d.gateway and existing.gateway != d.gateway:
                existing.gateway = d.gateway
                changed = True
            if existing.total_ips != expected_total:
                existing.total_ips = expected_total
                changed = True
            if changed:
                summary.subnets_updated += 1

    await db.flush()

    # Drop node-owned wrapper blocks whose subnet has been removed.
    for net_str, wrapper in node_owned_wrappers.items():
        if net_str in used_wrapper_cidrs:
            continue
        refs = await db.execute(select(Subnet).where(Subnet.block_id == wrapper.id))
        if refs.scalar_one_or_none() is None:
            await db.delete(wrapper)
            summary.blocks_deleted += 1


# ── Apply: addresses ──────────────────────────────────────────────────


async def _apply_addresses(
    db: AsyncSession,
    node: ProxmoxNode,
    desired: list[_DesiredAddress],
    summary: ReconcileSummary,
) -> None:
    subnet_rows = (
        (await db.execute(select(Subnet).where(Subnet.space_id == node.ipam_space_id)))
        .scalars()
        .all()
    )
    subnets = list(subnet_rows)

    # Dedupe by address — a guest with multiple IPs on the same NIC
    # will show up once per IP, but two NICs bridged to the same VLAN
    # with overlapping addresses is a misconfiguration we shouldn't
    # silently double-write.
    desired_map: dict[str, _DesiredAddress] = {}
    for d in desired:
        if d.address in desired_map:
            continue
        desired_map[d.address] = d

    # Phase 1 — claim any pre-existing operator-owned rows at the
    # desired (subnet, address) tuples. "Operator-owned" means
    # ``proxmox_node_id IS NULL``: an IP the user created before
    # enabling the Proxmox integration, or a row from a different
    # integration. We adopt the row by stamping ``proxmox_node_id``
    # AND ``user_modified_at = now()``, which locks the operator's
    # hostname / description / status / mac from being clobbered on
    # subsequent reconciles. We never claim rows owned by another
    # Proxmox endpoint or by Kubernetes / Docker — those are skipped
    # with a counter bump so the operator can see the conflict.
    desired_addrs = list(desired_map.keys())
    if desired_addrs:
        existing = (
            (await db.execute(select(IPAddress).where(IPAddress.address.in_(desired_addrs))))
            .scalars()
            .all()
        )
        for row in existing:
            if row.proxmox_node_id == node.id:
                continue  # already ours
            if row.proxmox_node_id is not None:
                # Owned by a different Proxmox endpoint — skip.
                summary.warnings.append(
                    f"address {row.address} owned by another Proxmox endpoint; not claiming"
                )
                continue
            if owned_by_other_integration(row, "proxmox_node_id"):
                summary.warnings.append(
                    f"address {row.address} owned by another integration; not claiming"
                )
                continue
            row.proxmox_node_id = node.id
            if row.user_modified_at is None:
                row.user_modified_at = datetime.now(UTC)
        await db.flush()

    res = await db.execute(select(IPAddress).where(IPAddress.proxmox_node_id == node.id))
    current = {str(a.address): a for a in res.scalars().all()}

    dirty_subnets: set[Any] = {s.id for s in subnets if s.proxmox_node_id == node.id}

    for addr, row in current.items():
        if addr not in desired_map:
            dirty_subnets.add(row.subnet_id)
            if row.user_modified_at is not None:
                # Operator has invested edits in this row; preserve it.
                # Releasing the FK lets the operator see a clean
                # "manually managed" row instead of having their data
                # silently deleted when a VM goes away.
                row.proxmox_node_id = None
                summary.addresses_updated += 1
            else:
                await db.delete(row)
                summary.addresses_deleted += 1

    for addr, d in desired_map.items():
        subnet = _find_subnet_for_ip(subnets, d.address)
        if subnet is None:
            summary.skipped_no_subnet += 1
            continue
        if addr in current:
            row = current[addr]
            changed = False
            # subnet_id is factual (where the address lives); always
            # update regardless of the user-modified lock.
            if row.subnet_id != subnet.id:
                dirty_subnets.add(row.subnet_id)
                row.subnet_id = subnet.id
                changed = True
            # Soft fields are skipped when the operator has touched
            # the row. Comparison short-circuits update when values
            # already match.
            if row.user_modified_at is None:
                if row.status != d.status:
                    row.status = d.status
                    changed = True
                if (row.hostname or "") != d.hostname:
                    row.hostname = d.hostname
                    changed = True
                if (row.description or "") != d.description:
                    row.description = d.description
                    changed = True
                if d.mac and (row.mac_address or "") != d.mac.lower():
                    row.mac_address = d.mac.lower()
                    changed = True
            if changed:
                dirty_subnets.add(subnet.id)
                summary.addresses_updated += 1
        else:
            db.add(
                IPAddress(
                    subnet_id=subnet.id,
                    address=d.address,
                    status=d.status,
                    hostname=d.hostname,
                    description=d.description,
                    mac_address=d.mac.lower() if d.mac else None,
                    proxmox_node_id=node.id,
                )
            )
            dirty_subnets.add(subnet.id)
            summary.addresses_created += 1

    if dirty_subnets:
        await db.flush()
        for subnet_id in dirty_subnets:
            await _recompute_subnet_utilization(db, subnet_id)


# ── Discovery payload (UI debugging) ──────────────────────────────────


def _build_discovery_payload(
    guests: list[Any],
    desired_subnets: list[_DesiredSubnet],
    desired_addresses: list[_DesiredAddress],
    sdn_vnets: list[_ProxmoxSDNVnet],
    sdn_subnets: list[_ProxmoxSDNSubnet],
) -> dict[str, Any]:
    """Per-guest diagnostic snapshot for the "Discovery" UI.

    Shape:

    ``{
        "summary": {
            "vm_total": 16,
            "vm_agent_reporting": 10,
            "vm_agent_not_responding": 3,
            "vm_agent_off": 2,
            "vm_no_nic": 1,
            "lxc_total": 6,
            "lxc_reporting": 6,
            "lxc_no_ip": 0,
            "sdn_vnets_total": 14,
            "sdn_vnets_with_subnet": 4,
            "sdn_vnets_unresolved": 10,
            "addresses_skipped_no_subnet": 13,
        },
        "guests": [
            {
                "kind": "qemu" | "lxc",
                "vmid": 100,
                "name": "vm-100",
                "node": "pve4",
                "status": "running",
                "nic_count": 1,
                "ips_mirrored": 1,
                "ips_from_agent": 1,
                "ips_from_static": 0,
                "agent_state": "reporting" | "not_responding" | "off" | "n/a",
                "issue": null | "agent_not_responding" | "agent_off" | ...,
                "hint": null | "install qemu-guest-agent inside the VM",
            },
            ...
        ],
    }``

    Each guest is categorised by a single top-level ``issue`` so the
    UI can filter "show only guests with issues". Running qemu guests
    are the interesting case — stopped / no-NIC ones just report why.
    """

    # Addresses keyed by (mac, address) so we can count per-guest
    # how many landed in IPAM and via which path (agent vs static).
    # The reconciler doesn't currently re-expose per-guest mirroring
    # details, so we rebuild it here by comparing guest NIC runtime /
    # static IPs against ``desired_addresses``. Both lists are small
    # in practice (single-digit to low-hundreds).
    desired_set = {(d.mac.lower() if d.mac else None, d.address) for d in desired_addresses}

    # Which subnets do we have (for skipped-no-subnet calc)?
    subnet_set = set()
    for d in desired_subnets:
        try:
            subnet_set.add(ipaddress.ip_network(d.network, strict=False))
        except (ValueError, TypeError):
            pass

    guest_rows: list[dict[str, Any]] = []
    counters = {
        "vm_total": 0,
        "vm_agent_reporting": 0,
        "vm_agent_not_responding": 0,
        "vm_agent_off": 0,
        "vm_no_nic": 0,
        "lxc_total": 0,
        "lxc_reporting": 0,
        "lxc_no_ip": 0,
    }

    for g in guests:
        if g.kind == "qemu":
            counters["vm_total"] += 1
        else:
            counters["lxc_total"] += 1

        ips_from_agent = 0
        ips_from_static = 0
        ips_mirrored = 0
        nic_count = len(g.nics)

        for nic in g.nics:
            mac_key = nic.mac.lower() if nic.mac else None
            runtime = (g.runtime_ips_by_mac.get(_normalise_mac(nic.mac)) if nic.mac else None) or []
            for ip in runtime:
                if (mac_key, ip) in desired_set:
                    ips_mirrored += 1
                    ips_from_agent += 1
            if not runtime and nic.static_cidr:
                try:
                    static_ip = str(ipaddress.ip_interface(nic.static_cidr).ip)
                except (ValueError, TypeError):
                    static_ip = None
                if static_ip and (mac_key, static_ip) in desired_set:
                    ips_mirrored += 1
                    ips_from_static += 1

        # Categorise — pick one top-level issue per guest.
        agent_state: str
        issue: str | None = None
        hint: str | None = None
        if g.kind == "qemu":
            if not g.agent_enabled:
                agent_state = "off"
                if ips_mirrored == 0 and nic_count > 0:
                    issue = "agent_off"
                    hint = (
                        "Enable the QEMU agent on this VM in Options → QEMU Guest Agent, "
                        "then install qemu-guest-agent inside the VM."
                    )
                elif ips_mirrored > 0:
                    # Static-only path — agent is off but ipconfigN gave
                    # us an IP. Not really an "issue", but worth noting.
                    issue = "static_only"
                    hint = (
                        "Mirroring via ipconfigN static IP only. Enable the guest agent "
                        "to pick up DHCP-assigned IPs and additional interfaces."
                    )
                else:
                    issue = "no_ip"
                    hint = (
                        "No guest agent and no static IP configured — IPAM has nothing to mirror."
                    )
            else:
                # agent_enabled == True
                if ips_from_agent > 0:
                    agent_state = "reporting"
                    counters["vm_agent_reporting"] += 1
                else:
                    agent_state = "not_responding"
                    counters["vm_agent_not_responding"] += 1
                    issue = "agent_not_responding"
                    hint = (
                        "Install qemu-guest-agent inside the VM and ensure the service "
                        "is running. On Debian/Ubuntu: `apt install qemu-guest-agent && "
                        "systemctl enable --now qemu-guest-agent`."
                    )
            if agent_state == "off" and g.agent_enabled is False:
                # No double-count — the agent-off counter only covers
                # VMs where agent=0 AND we're not "static_only" already.
                if issue == "agent_off":
                    counters["vm_agent_off"] += 1
            if nic_count == 0:
                counters["vm_no_nic"] += 1
                issue = "no_nic"
                hint = "This VM has no network interfaces configured."
        else:
            # LXC — no agent concept, uses /interfaces for runtime IPs.
            agent_state = "n/a"
            if ips_mirrored > 0:
                counters["lxc_reporting"] += 1
            else:
                counters["lxc_no_ip"] += 1
                if nic_count == 0:
                    issue = "no_nic"
                    hint = "This container has no network interfaces configured."
                else:
                    issue = "no_ip"
                    hint = (
                        "Container's /interfaces endpoint returned no usable IPs. "
                        "Make sure the container is running and has an address configured."
                    )

        guest_rows.append(
            {
                "kind": g.kind,
                "vmid": g.vmid,
                "name": g.name,
                "node": g.node,
                "status": g.status,
                "nic_count": nic_count,
                "bridges": sorted({n.bridge for n in g.nics if n.bridge}),
                "ips_mirrored": ips_mirrored,
                "ips_from_agent": ips_from_agent,
                "ips_from_static": ips_from_static,
                "agent_state": agent_state,
                "issue": issue,
                "hint": hint,
            }
        )

    # SDN resolution counters — useful for "why aren't my VNets showing up?"
    desired_networks = {d.network for d in desired_subnets}
    vnets_with_declared = {s.vnet for s in sdn_subnets}
    sdn_vnets_with_subnet = 0
    for v in sdn_vnets:
        if v.vnet in vnets_with_declared:
            sdn_vnets_with_subnet += 1
            continue
        # Inferred? — one of our desired subnets was named "vnet:<vnet>".
        for d in desired_subnets:
            if d.name == f"vnet:{v.vnet}":
                sdn_vnets_with_subnet += 1
                break

    # Addresses we had to skip because no subnet encloses the IP.
    skipped_no_subnet = 0
    for d in desired_addresses:
        try:
            addr = ipaddress.ip_address(d.address)
        except ValueError:
            continue
        matched = any(addr in net for net in subnet_set)
        if not matched:
            skipped_no_subnet += 1

    counters["sdn_vnets_total"] = len(sdn_vnets)
    counters["sdn_vnets_with_subnet"] = sdn_vnets_with_subnet
    counters["sdn_vnets_unresolved"] = len(sdn_vnets) - sdn_vnets_with_subnet
    counters["addresses_skipped_no_subnet"] = skipped_no_subnet
    counters["desired_subnets"] = len(desired_networks)

    # Stable guest ordering: issue-first, then kind, vmid.
    guest_rows.sort(
        key=lambda r: (r["issue"] is None, r["kind"], r["vmid"]),
    )
    return {
        "summary": counters,
        "guests": guest_rows,
        "generated_at": datetime.now(UTC).isoformat(),
    }


# ── Entry point ───────────────────────────────────────────────────────


async def reconcile_node(db: AsyncSession, node: ProxmoxNode) -> ReconcileSummary:
    summary = ReconcileSummary(ok=False)

    token_secret = ""
    if node.token_secret_encrypted:
        try:
            token_secret = decrypt_str(node.token_secret_encrypted)
        except ValueError as exc:
            summary.error = f"token-secret decrypt failed: {exc}"
            node.last_sync_error = summary.error
            node.last_synced_at = datetime.now(UTC)
            await db.commit()
            return summary

    try:
        async with ProxmoxClient(
            host=node.host,
            port=node.port,
            token_id=node.token_id,
            token_secret=token_secret,
            verify_tls=node.verify_tls,
            ca_bundle_pem=node.ca_bundle_pem or "",
        ) as client:
            version = await client.get_version()
            cluster = await client.get_cluster_info()
            pve_nodes = await client.list_nodes()

            # SDN is cluster-scoped — one call each, not per-node.
            sdn_subnets = await client.list_sdn_subnets()
            # VNets are fetched regardless of the infer toggle — cheap
            # single call and the metadata is useful for future surfaces.
            sdn_vnets = await client.list_sdn_vnets()

            all_networks: list[Any] = []
            all_guests: list[Any] = []
            for n in pve_nodes:
                if n.status != "online":
                    continue
                all_networks.extend(await client.list_networks(n.node))
                if node.mirror_vms:
                    all_guests.extend(
                        await client.list_qemu(n.node, include_stopped=node.include_stopped)
                    )
                if node.mirror_lxc:
                    all_guests.extend(
                        await client.list_lxc(n.node, include_stopped=node.include_stopped)
                    )
    except ProxmoxClientError as exc:
        summary.error = str(exc)
        node.last_sync_error = summary.error
        node.last_synced_at = datetime.now(UTC)
        await db.commit()
        logger.warning("proxmox_reconcile_fetch_failed", node=str(node.id), error=summary.error)
        return summary

    summary.pve_version = version.version
    summary.cluster_name = cluster.cluster_name
    summary.node_count = cluster.node_count
    summary.vm_count = sum(1 for g in all_guests if g.kind == "qemu")
    summary.lxc_count = sum(1 for g in all_guests if g.kind == "lxc")

    desired_subnets, desired_addresses = _compute_desired(
        node, all_networks, all_guests, sdn_subnets, sdn_vnets
    )

    await _apply_blocks_and_subnets(db, node, desired_subnets, summary, sdn_vnets)
    await _apply_addresses(db, node, desired_addresses, summary)

    node.last_synced_at = datetime.now(UTC)
    node.last_sync_error = None
    node.pve_version = summary.pve_version
    node.cluster_name = summary.cluster_name
    node.node_count = summary.node_count
    node.last_discovery = _build_discovery_payload(
        all_guests, desired_subnets, desired_addresses, sdn_vnets, sdn_subnets
    )

    db.add(
        AuditLog(
            user_display_name="system",
            auth_source="system",
            action="proxmox.reconcile",
            resource_type="proxmox_node",
            resource_id=str(node.id),
            resource_display=node.name,
            new_value={
                "blocks": {
                    "created": summary.blocks_created,
                    "deleted": summary.blocks_deleted,
                },
                "subnets": {
                    "created": summary.subnets_created,
                    "updated": summary.subnets_updated,
                    "deleted": summary.subnets_deleted,
                    "matched": summary.subnets_matched,
                },
                "addresses": {
                    "created": summary.addresses_created,
                    "updated": summary.addresses_updated,
                    "deleted": summary.addresses_deleted,
                    "skipped_no_subnet": summary.skipped_no_subnet,
                },
            },
        )
    )
    await db.commit()
    summary.ok = True
    logger.info(
        "proxmox_reconcile_ok",
        node=str(node.id),
        pve_version=summary.pve_version,
        cluster=summary.cluster_name,
        nodes=summary.node_count,
        vms=summary.vm_count,
        lxc=summary.lxc_count,
        blocks_created=summary.blocks_created,
        subnets_created=summary.subnets_created,
        subnets_updated=summary.subnets_updated,
        addresses_created=summary.addresses_created,
        addresses_updated=summary.addresses_updated,
        addresses_deleted=summary.addresses_deleted,
    )
    return summary


__all__ = ["ReconcileSummary", "reconcile_node"]
