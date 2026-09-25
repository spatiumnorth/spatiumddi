"""Per-firewall OPNsense reconciler.

For one ``OPNsenseRouter`` row:

  1. Fetch firmware + interfaces + VLANs + DHCPv4 leases + static
     reservations (+ ARP when ``mirror_arp``) from the OPNsense API.
  2. Compute the desired set of IPBlock / Subnet / IPAddress rows.
  3. Load currently-mirrored rows (FK lookup on ``opnsense_router_id``).
  4. Apply the diff: claim pre-existing operator rows, create, update,
     un-claim or delete rows that disappeared upstream.
  5. Recompute subnet utilization + persist sync state + audit row.

Notable specifics:

* **Interfaces are real LANs.** Unlike Kubernetes pod CIDRs (routed
  overlays with no broadcast), OPNsense LAN/OPT*/VLAN interfaces are
  genuine subnets — the firewall's interface IP is the gateway, and
  the broadcast address is real. So subnets are created with normal
  LAN semantics (gateway reserved, broadcast counted out of usable).
* **Status mapping.** DHCP leases → ``status="dhcp"`` with
  ``auto_from_lease=True`` (Kea-shape parity); static reservations →
  ``status="reserved"``; ARP → ``status="opnsense-arp"``.
* **Sibling-integration ownership guard.** A row already owned by
  another integration (any in ``app.services.integration_ownership``)
  is never claimed or duplicated.
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
from app.models.opnsense import OPNsenseRouter
from app.services.integration_ownership import owned_by_other_integration, owning_integration
from app.services.opnsense.client import (
    OPNsenseClient,
    OPNsenseClientError,
    _OPNInterface,
    _OPNVlan,
)

logger = structlog.get_logger(__name__)

# Private-address supernets — auto-created as unowned top-level
# IPBlocks when a mirrored CIDR is contained and no enclosing block
# exists. Same list as the Proxmox / Docker reconcilers so the tree
# stays consistent across integrations.
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
    status: str  # dhcp | reserved | opnsense-arp
    hostname: str
    description: str
    mac: str | None = None
    auto_from_lease: bool = False


@dataclass
class ReconcileSummary:
    ok: bool
    error: str | None = None
    firmware_version: str | None = None
    interface_count: int = 0
    lease_count: int = 0
    reservation_count: int = 0
    arp_count: int = 0
    blocks_created: int = 0
    blocks_deleted: int = 0
    subnets_created: int = 0
    subnets_updated: int = 0
    subnets_deleted: int = 0
    # Counted when a pre-existing operator-owned subnet at an exact-CIDR
    # match was reused instead of creating a duplicate (mirrors the
    # Proxmox #177 behaviour).
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
    # Real LAN — broadcast + network address are not usable hosts.
    return net.num_addresses - 2


def _find_enclosing_operator_block(
    blocks: list[IPBlock], cidr: str, router_id: Any
) -> IPBlock | None:
    net = _parse_net(cidr)
    if net is None:
        return None
    best: IPBlock | None = None
    best_prefix = -1
    for b in blocks:
        if b.opnsense_router_id == router_id:
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


def _compute_desired(
    router: OPNsenseRouter,
    interfaces: list[_OPNInterface],
    vlans: list[_OPNVlan],
    leases: list[Any],
    reservations: list[Any],
    arp: list[Any],
) -> tuple[list[_DesiredSubnet], list[_DesiredAddress]]:
    # Index VLAN descriptions by device so an interface riding a VLAN
    # device can pick up the operator's VLAN label in its description.
    vlan_by_device = {v.device: v for v in vlans if v.device}

    subnets: list[_DesiredSubnet] = []
    seen_networks: set[str] = set()
    addresses: list[_DesiredAddress] = []

    for iface in interfaces:
        net = _parse_net(iface.cidr)
        if net is None:
            continue
        cidr = str(net)
        if cidr in seen_networks:
            continue
        seen_networks.add(cidr)
        label = iface.description or iface.name
        desc_bits = [f"OPNsense interface {iface.name} ({iface.device})"]
        # ``interfaces/overview/export`` carries the VLAN tag on the
        # interface itself, so prefer it and fall back to joining
        # ``vlan_settings/get`` by device name — which is all the
        # ifconfig fallback path can offer.
        vlan = vlan_by_device.get(iface.device)
        tag = iface.vlan_tag if iface.vlan_tag is not None else (vlan.tag if vlan else None)
        if tag is not None:
            desc_bits.append(f"VLAN {tag}")
            if vlan is not None and vlan.description:
                desc_bits.append(vlan.description)
        subnets.append(
            _DesiredSubnet(
                network=cidr,
                name=f"{router.name}/{label}",
                description=" — ".join(desc_bits),
                # The firewall's own interface IP is the gateway for a
                # real LAN — emphatically unlike a plain Proxmox bridge.
                gateway=iface.address,
            )
        )
        # Reserve the firewall interface IP itself as a ``reserved`` row
        # so the gateway shows up under the firewall's identity.
        addresses.append(
            _DesiredAddress(
                address=iface.address,
                status="reserved",
                hostname=router.name,
                description=f"OPNsense {iface.name} gateway",
            )
        )

    # Static reservations → reserved rows. Done before leases so a lease
    # that also has a reservation prefers the (richer) reservation desc.
    if router.mirror_static_mappings:
        for r in reservations:
            addresses.append(
                _DesiredAddress(
                    address=r.address,
                    status="reserved",
                    hostname=r.hostname or "",
                    description=r.description or "OPNsense static DHCP reservation",
                    mac=r.mac,
                )
            )

    # DHCPv4 leases → dhcp rows (auto_from_lease=True for Kea parity).
    if router.mirror_dhcp_leases:
        for ls in leases:
            addresses.append(
                _DesiredAddress(
                    address=ls.address,
                    status="dhcp",
                    hostname=ls.hostname or "",
                    description=f"OPNsense DHCPv4 lease ({ls.state})",
                    mac=ls.mac,
                    auto_from_lease=True,
                )
            )

    # ARP table → opnsense-arp rows (opt-in, lowest priority).
    if router.mirror_arp:
        for a in arp:
            addresses.append(
                _DesiredAddress(
                    address=a.address,
                    status="opnsense-arp",
                    hostname=a.hostname or "",
                    description=(
                        f"OPNsense ARP on {a.interface}" if a.interface else "OPNsense ARP"
                    ),
                    mac=a.mac,
                )
            )

    return subnets, addresses


# ── Apply: blocks + subnets ──────────────────────────────────────────


async def _apply_blocks_and_subnets(
    db: AsyncSession,
    router: OPNsenseRouter,
    desired_subnets: list[_DesiredSubnet],
    summary: ReconcileSummary,
) -> None:
    block_rows = (
        (await db.execute(select(IPBlock).where(IPBlock.space_id == router.ipam_space_id)))
        .scalars()
        .all()
    )
    blocks = list(block_rows)
    router_owned_wrappers = {str(b.network): b for b in blocks if b.opnsense_router_id == router.id}

    existing_networks = {str(b.network): b for b in blocks}
    for d in desired_subnets:
        supernet = _private_supernet_of(d.network)
        if supernet is None or supernet in existing_networks:
            continue
        parent = IPBlock(
            space_id=router.ipam_space_id,
            network=supernet,
            name=f"Private {supernet}",
            description=f"Auto-created as the private-address parent for {d.network}",
        )
        db.add(parent)
        await db.flush()
        blocks.append(parent)
        existing_networks[supernet] = parent
        summary.blocks_created += 1

    # Classify every subnet in the space: router-owned (update/delete),
    # operator-owned (reuse untouched), or foreign (another integration
    # — warn + skip; never duplicate).
    all_subnet_rows = (
        (await db.execute(select(Subnet).where(Subnet.space_id == router.ipam_space_id)))
        .scalars()
        .all()
    )
    current_subnets: dict[str, Subnet] = {}
    operator_subnets: dict[str, Subnet] = {}
    foreign_subnets: dict[str, Subnet] = {}
    for s in all_subnet_rows:
        net_key = str(s.network)
        if s.opnsense_router_id == router.id:
            current_subnets[net_key] = s
        elif owning_integration(s) is None:
            operator_subnets[net_key] = s
        else:
            foreign_subnets[net_key] = s

    desired_map = {d.network: d for d in desired_subnets}
    used_wrapper_cidrs: set[str] = set()

    # Delete router-owned subnets that disappeared upstream — but only
    # when no non-OPNsense IPAddress rows still live in them. IPAddress
    # → Subnet is ON DELETE CASCADE with no soft-delete, so a blind
    # delete here would also sweep operator-created rows and the rows
    # _apply_addresses deliberately un-claimed (opnsense_router_id=None).
    # If any such survivor exists we un-claim the subnet (leave it as a
    # manually-managed entry) instead, mirroring the wrapper-block guard
    # below and the address-level un-claim in _apply_addresses.
    for net_str, row in current_subnets.items():
        if net_str in desired_map:
            continue
        surviving_foreign = await db.scalar(
            select(func.count())
            .select_from(IPAddress)
            .where(IPAddress.subnet_id == row.id)
            .where(IPAddress.opnsense_router_id.is_(None))
        )
        if surviving_foreign:
            # Operator / other-owned addresses still depend on this
            # subnet — don't cascade-delete them. Hand the subnet back.
            row.opnsense_router_id = None
            summary.subnets_updated += 1
        else:
            await db.delete(row)
            summary.subnets_deleted += 1

    for net_str, d in desired_map.items():
        # Operator subnet at this exact CIDR wins — reused untouched.
        if net_str in operator_subnets:
            summary.subnets_matched += 1
            continue
        # Another integration owns it — don't duplicate, don't claim.
        if net_str in foreign_subnets:
            summary.warnings.append(
                f"subnet {net_str} already exists, owned by another integration; "
                f"not creating duplicate"
            )
            continue

        parent_block = _find_enclosing_operator_block(blocks, d.network, router.id)
        if parent_block is None:
            wrapper = router_owned_wrappers.get(net_str)
            if wrapper is None:
                wrapper = IPBlock(
                    space_id=router.ipam_space_id,
                    network=d.network,
                    name=f"{router.name} {d.network}",
                    description=f"Auto-created for OPNsense firewall {router.name}",
                    opnsense_router_id=router.id,
                )
                db.add(wrapper)
                await db.flush()
                blocks.append(wrapper)
                router_owned_wrappers[net_str] = wrapper
                summary.blocks_created += 1
            used_wrapper_cidrs.add(net_str)
            parent_block = wrapper

        net_parsed = _parse_net(d.network)
        expected_total = _lan_total_ips(net_parsed) if net_parsed is not None else 0

        existing = current_subnets.get(net_str)
        if existing is None:
            db.add(
                Subnet(
                    space_id=router.ipam_space_id,
                    block_id=parent_block.id,
                    network=d.network,
                    name=d.name,
                    description=d.description,
                    gateway=d.gateway,
                    opnsense_router_id=router.id,
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
            if d.gateway and existing.gateway != d.gateway:
                existing.gateway = d.gateway
                changed = True
            if existing.total_ips != expected_total:
                existing.total_ips = expected_total
                changed = True
            if changed:
                summary.subnets_updated += 1

    await db.flush()

    # Drop router-owned wrapper blocks whose subnet has been removed.
    for net_str, wrapper in router_owned_wrappers.items():
        if net_str in used_wrapper_cidrs:
            continue
        refs = await db.execute(select(Subnet).where(Subnet.block_id == wrapper.id))
        if refs.scalar_one_or_none() is None:
            await db.delete(wrapper)
            summary.blocks_deleted += 1


# ── Apply: addresses ──────────────────────────────────────────────────


async def _apply_addresses(
    db: AsyncSession,
    router: OPNsenseRouter,
    desired: list[_DesiredAddress],
    summary: ReconcileSummary,
) -> None:
    subnet_rows = (
        (await db.execute(select(Subnet).where(Subnet.space_id == router.ipam_space_id)))
        .scalars()
        .all()
    )
    subnets = list(subnet_rows)

    # Dedupe by address. A reservation + a lease on the same IP collapse
    # to one desired row; the first-seen wins (reservations are added
    # before leases in ``_compute_desired`` so the static row prevails).
    desired_map: dict[str, _DesiredAddress] = {}
    for d in desired:
        if d.address in desired_map:
            continue
        desired_map[d.address] = d

    # Phase 1 — claim pre-existing operator-owned rows at desired
    # addresses. "Operator-owned" means no integration FK is set. We
    # adopt by stamping ``opnsense_router_id`` + ``user_modified_at``
    # (which locks soft fields from being clobbered later). Rows owned
    # by another OPNsense firewall or another integration are skipped.
    # Addresses occupied by a row we couldn't claim (owned by another
    # firewall / integration). These are skipped in the create loop so
    # we don't hit the (subnet_id, address) unique constraint trying to
    # spawn a duplicate.
    unclaimable: set[str] = set()
    desired_addrs = list(desired_map.keys())
    if desired_addrs:
        # Scope the existence lookup to THIS firewall's IPAM space. An IP
        # can legitimately exist in another space owned by a different
        # integration; without the space filter the create-guard would
        # match that foreign-space row and silently skip the firewall's
        # legitimate row in its own space (and Phase 1 could stamp the FK
        # onto a foreign-space row). Join through Subnet → space_id keeps
        # both the claim and the unclaimable guard inside our space.
        existing = (
            (
                await db.execute(
                    select(IPAddress)
                    .join(Subnet, IPAddress.subnet_id == Subnet.id)
                    .where(Subnet.space_id == router.ipam_space_id)
                    .where(IPAddress.address.in_(desired_addrs))
                )
            )
            .scalars()
            .all()
        )
        for row in existing:
            if row.opnsense_router_id == router.id:
                continue  # already ours
            if row.opnsense_router_id is not None:
                summary.warnings.append(
                    f"address {row.address} owned by another OPNsense firewall; not claiming"
                )
                unclaimable.add(str(row.address))
                continue
            if owned_by_other_integration(row, "opnsense_router_id"):
                summary.warnings.append(
                    f"address {row.address} owned by another integration; not claiming"
                )
                unclaimable.add(str(row.address))
                continue
            row.opnsense_router_id = router.id
            if row.user_modified_at is None:
                row.user_modified_at = datetime.now(UTC)
        await db.flush()

    res = await db.execute(select(IPAddress).where(IPAddress.opnsense_router_id == router.id))
    current = {str(a.address): a for a in res.scalars().all()}

    dirty_subnets: set[Any] = {s.id for s in subnets if s.opnsense_router_id == router.id}

    for addr, row in current.items():
        if addr not in desired_map:
            dirty_subnets.add(row.subnet_id)
            if row.user_modified_at is not None:
                # Operator has invested edits — un-claim, leave the row
                # as a "manually managed" entry rather than deleting it.
                row.opnsense_router_id = None
                summary.addresses_updated += 1
            else:
                await db.delete(row)
                summary.addresses_deleted += 1

    for addr, d in desired_map.items():
        # A row at this address is owned by another firewall / integration
        # — don't try to create a duplicate (would violate the unique
        # (subnet_id, address) constraint) and don't touch theirs.
        if addr in unclaimable and addr not in current:
            continue
        subnet = _find_subnet_for_ip(subnets, d.address)
        if subnet is None:
            summary.skipped_no_subnet += 1
            continue
        if addr in current:
            row = current[addr]
            changed = False
            # subnet_id is factual — always update.
            if row.subnet_id != subnet.id:
                dirty_subnets.add(row.subnet_id)
                row.subnet_id = subnet.id
                changed = True
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
                if d.mac and (row.mac_address or "") != d.mac:
                    row.mac_address = d.mac
                    changed = True
                if row.auto_from_lease != d.auto_from_lease:
                    row.auto_from_lease = d.auto_from_lease
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
                    mac_address=d.mac,
                    auto_from_lease=d.auto_from_lease,
                    opnsense_router_id=router.id,
                )
            )
            dirty_subnets.add(subnet.id)
            summary.addresses_created += 1

    if dirty_subnets:
        await db.flush()
        for subnet_id in dirty_subnets:
            await _recompute_subnet_utilization(db, subnet_id)


def _warn_on_dhcp_backends(
    router: OPNsenseRouter,
    lease_result: Any | None,
    reservation_result: Any | None,
    summary: ReconcileSummary,
) -> None:
    """Warn when DHCP mirroring is armed but nothing answered.

    This is the #797 case made visible. The operator turned
    ``mirror_dhcp_leases`` / ``mirror_static_mappings`` on, every request
    returned a well-formed response, and the mirror stayed empty forever
    — because on OPNsense 25.7+ the ISC endpoints this client used to be
    the only consumer of simply do not exist. Zero rows from a backend
    that answered is a fact about the firewall; zero rows because no
    backend answered is a fact about our configuration, and only the
    second one warrants telling somebody.

    ``sources_forbidden`` is reported separately because it has a
    different remedy: the backend is there, but the API user needs a
    privilege (the Kea lease endpoints carry their own ACL entries —
    opnsense/core#7770).
    """
    checks = (
        ("DHCP leases", router.mirror_dhcp_leases, lease_result),
        ("static reservations", router.mirror_static_mappings, reservation_result),
    )
    for label, enabled, result in checks:
        if not enabled or result is None:
            continue
        if result.sources_forbidden:
            summary.warnings.append(
                f"{label}: the API user was refused by "
                f"{', '.join(sorted(set(result.sources_forbidden)))} — grant that "
                f"backend's page/lease privileges to the read-only user, or those "
                f"rows will never mirror"
            )
        if not result.sources_found:
            summary.warnings.append(
                f"{label}: no DHCP backend responded (Kea, Dnsmasq and the legacy "
                f"ISC endpoints are all absent, disabled, or not permitted for this "
                f"API user) — nothing can be mirrored while this is true"
            )


# ── Entry point ───────────────────────────────────────────────────────


async def reconcile_router(db: AsyncSession, router: OPNsenseRouter) -> ReconcileSummary:
    summary = ReconcileSummary(ok=False)

    api_secret = ""
    if router.api_secret_encrypted:
        try:
            api_secret = decrypt_str(router.api_secret_encrypted)
        except ValueError as exc:
            summary.error = f"api-secret decrypt failed: {exc}"
            router.last_sync_error = summary.error
            router.last_synced_at = datetime.now(UTC)
            await db.commit()
            return summary
    if not api_secret or not router.api_key:
        summary.error = "no API key/secret configured"
        router.last_sync_error = summary.error
        router.last_synced_at = datetime.now(UTC)
        await db.commit()
        return summary

    try:
        async with OPNsenseClient(
            host=router.host,
            port=router.port,
            api_key=router.api_key,
            api_secret=api_secret,
            verify_tls=router.verify_tls,
            ca_bundle_pem=router.ca_bundle_pem or "",
        ) as client:
            firmware = await client.get_firmware()
            interfaces = await client.list_interfaces()
            vlans = await client.list_vlans()
            lease_result = await client.list_leases() if router.mirror_dhcp_leases else None
            reservation_result = (
                await client.list_reservations() if router.mirror_static_mappings else None
            )
            arp = await client.list_arp() if router.mirror_arp else []
    except OPNsenseClientError as exc:
        summary.error = str(exc)
        router.last_sync_error = summary.error
        router.last_synced_at = datetime.now(UTC)
        await db.commit()
        logger.warning(
            "opnsense_reconcile_fetch_failed", router=str(router.id), error=summary.error
        )
        return summary

    leases = lease_result.leases if lease_result is not None else []
    reservations = reservation_result.reservations if reservation_result is not None else []
    _warn_on_dhcp_backends(router, lease_result, reservation_result, summary)
    if not interfaces:
        # Every mirrored address needs an enclosing subnet, and subnets
        # come only from interfaces — so zero interfaces silently zeroes
        # the whole mirror downstream. (A malformed payload raises in the
        # client; reaching here means the firewall really reported no
        # addressed, enabled interface.)
        summary.warnings.append(
            "no addressed interfaces found — every mirrored address needs an "
            "enclosing subnet, so nothing will be mirrored until at least one "
            "interface reports a static IPv4/IPv6 address"
        )

    summary.firmware_version = firmware.version
    summary.interface_count = len(interfaces)
    summary.lease_count = len(leases)
    summary.reservation_count = len(reservations)
    summary.arp_count = len(arp)

    desired_subnets, desired_addresses = _compute_desired(
        router, interfaces, vlans, leases, reservations, arp
    )

    await _apply_blocks_and_subnets(db, router, desired_subnets, summary)
    await _apply_addresses(db, router, desired_addresses, summary)

    router.last_synced_at = datetime.now(UTC)
    router.last_sync_error = None
    # #797 — persist the non-fatal findings. Cleared to NULL on a clean
    # pass so a resolved warning doesn't linger as a stale amber chip.
    router.last_sync_warning = "\n".join(summary.warnings) if summary.warnings else None
    router.firmware_version = summary.firmware_version
    router.interface_count = summary.interface_count
    router.lease_count = summary.lease_count

    db.add(
        AuditLog(
            user_display_name="system",
            auth_source="system",
            action="opnsense.reconcile",
            resource_type="opnsense_router",
            resource_id=str(router.id),
            resource_display=router.name,
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
                "warnings": summary.warnings,
            },
        )
    )
    await db.commit()
    summary.ok = True
    logger.info(
        "opnsense_reconcile_ok",
        router=str(router.id),
        firmware=summary.firmware_version,
        interfaces=summary.interface_count,
        leases=summary.lease_count,
        reservations=summary.reservation_count,
        arp=summary.arp_count,
        blocks_created=summary.blocks_created,
        subnets_created=summary.subnets_created,
        addresses_created=summary.addresses_created,
        addresses_updated=summary.addresses_updated,
        addresses_deleted=summary.addresses_deleted,
        # #797 — a pass that mirrors nothing used to log as an unqualified
        # success. The warnings are the difference between "nothing to do"
        # and "we asked the wrong endpoints", so they belong on the line an
        # operator greps.
        lease_sources=lease_result.sources_found if lease_result is not None else [],
        warnings=summary.warnings,
    )
    return summary


__all__ = ["ReconcileSummary", "reconcile_router"]
