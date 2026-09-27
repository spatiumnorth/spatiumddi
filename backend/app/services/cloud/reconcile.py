"""Per-endpoint Cloud (AWS / Azure / GCP) reconciler (issue #37, Part A).

For one :class:`CloudEndpoint` row (one cloud account / subscription /
project set):

  1. Decrypt the per-provider credential dict.
  2. Resolve a concrete connector via :func:`get_connector` and pull a
     single normalised :class:`CloudInventory`.
  3. Compute the desired set of IPBlock / Subnet / IPAddress rows.
  4. Load currently-mirrored rows (FK lookup on ``cloud_endpoint_id``).
  5. Apply the diff: create, update, delete.
  6. Persist ``last_synced_at`` / ``last_sync_error`` /
     ``provider_account_id`` / ``network_count`` / ``instance_count`` +
     a discovery snapshot + a summary audit entry.

Parallels the Proxmox reconciler — same ownership-claim, soft-field
``user_modified_at`` lock, prune-unclaimed pass, and audit write. Cloud
specifics:

* **One IPBlock per VPC/VNet CIDR.** A :class:`CloudNetwork` reports its
  address-space CIDR(s) (one or more on AWS/Azure); each lands as a
  ``cloud_endpoint_id``-owned IPBlock under ``ipam_space_id``, named
  ``"<provider>:<network> <cidr>"`` (the CIDR suffix dropped when the
  network has exactly one CIDR).
* **GCP networks have no own CIDR.** GCP VPCs are CIDR-less containers —
  the addressing lives entirely on the subnets. For a network with
  ``cidrs=()`` we create one IPBlock per *distinct subnet CIDR* belonging
  to that network (the block is the subnet's exact CIDR). The subnet then
  nests directly inside its same-CIDR block. This keeps every Subnet row
  enclosed by a block without speculatively inventing a supernet we can't
  derive reliably.
* **Subnets are routed overlays.** Cloud subnets carry no broadcast row
  and the first usable host (``x.x.x.1`` by AWS/Azure/GCP convention) is
  the gateway. They are created with ``kubernetes_semantics=True`` so the
  IPAM tree + UI suppress the LAN-specific gateway / broadcast / network
  placeholder rows, exactly like Kubernetes pod-CIDR / Tailnet subnets.
* **Public + LB IPs are usually out-of-band /32s.** A ``cloud-public`` /
  ``cloud-lb`` row only materialises when an enclosing mirrored subnet
  exists (in ``public_space_id`` when set, else ``ipam_space_id``).
  Public IPs that fall outside every mirrored subnet are counted under
  ``skipped_no_subnet`` — a documented limitation, not an error.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_dict
from app.models.audit import AuditLog
from app.models.cloud import CloudEndpoint
from app.models.ipam import IPAddress, IPBlock, Subnet
from app.services.cloud.base import (
    CloudConnectorError,
    CloudInventory,
    get_connector,
)
from app.services.integration_ownership import owned_by_other_integration, owning_integration

logger = structlog.get_logger(__name__)

_BIGINT_MAX = 2**63 - 1


# ── Desired-state dataclasses ────────────────────────────────────────


@dataclass(frozen=True)
class _DesiredBlock:
    network: str  # CIDR
    name: str
    description: str


@dataclass(frozen=True)
class _DesiredSubnet:
    network: str  # CIDR
    name: str
    description: str
    gateway: str | None = None


@dataclass(frozen=True)
class _DesiredAddress:
    address: str
    status: str  # cloud-instance | cloud-public | cloud-lb
    hostname: str
    description: str
    mac: str | None = None
    # Which space the row belongs in. cloud-public / cloud-lb rows route
    # to the endpoint's ``public_space_id`` when one is configured; every
    # other row (and the fallback) lands in ``ipam_space_id``.
    public: bool = False


@dataclass
class ReconcileSummary:
    ok: bool
    error: str | None = None
    provider_account_id: str | None = None
    network_count: int = 0
    instance_count: int = 0
    blocks_created: int = 0
    blocks_deleted: int = 0
    subnets_created: int = 0
    subnets_updated: int = 0
    subnets_deleted: int = 0
    # Counted when a pre-existing operator-owned subnet at an exact-CIDR
    # match was reused instead of creating a duplicate — mirrors the
    # Proxmox reconciler's issue #177 behaviour.
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


def _lan_total_ips(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> int:
    # Cloud subnets are routed overlays without network / broadcast
    # reservation in IPAM, so the whole range is usable — no -2.
    if isinstance(net, ipaddress.IPv6Network):
        return min(net.num_addresses, _BIGINT_MAX)
    return min(net.num_addresses, _BIGINT_MAX)


def _first_usable_host(cidr: str) -> str | None:
    """First usable host of ``cidr`` (the cloud gateway convention).

    ``10.0.1.0/24 → 10.0.1.1``. For /31 / /32 (and v6 equivalents) where
    there's no distinct host below the network address we just return the
    network address itself. ``None`` on parse failure.
    """
    net = _parse_net(cidr)
    if net is None:
        return None
    if net.num_addresses <= 1:
        return str(net.network_address)
    return str(net.network_address + 1)


def _find_enclosing_operator_block(
    blocks: list[IPBlock], cidr: str, endpoint_id: Any
) -> IPBlock | None:
    """Most-specific block (not owned by this endpoint) that encloses ``cidr``.

    Used at block-creation time to decide whether we even need to create
    an endpoint-owned block — if an operator (or other-integration) block
    already encloses the CIDR we nest under it instead.
    """
    return _find_enclosing_block(blocks, cidr, exclude_endpoint_id=endpoint_id)


def _find_enclosing_block(
    blocks: list[IPBlock], cidr: str, *, exclude_endpoint_id: Any = None
) -> IPBlock | None:
    """Most-specific block that encloses ``cidr``.

    With ``exclude_endpoint_id`` set, blocks owned by that endpoint are
    skipped (the operator/foreign-only view). With it ``None`` every block
    is eligible — that's what the subnet-parent resolver uses so a subnet
    correctly nests under the endpoint's own VPC-CIDR block.
    """
    net = _parse_net(cidr)
    if net is None:
        return None
    best: IPBlock | None = None
    best_prefix = -1
    for b in blocks:
        if exclude_endpoint_id is not None and b.cloud_endpoint_id == exclude_endpoint_id:
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
    endpoint: CloudEndpoint,
    inv: CloudInventory,
) -> tuple[list[_DesiredBlock], list[_DesiredSubnet], list[_DesiredAddress]]:
    """Translate a normalised inventory into desired IPAM rows.

    Returns ``(blocks, subnets, addresses)``. Blocks are the VPC/VNet
    address-space CIDRs (plus the GCP per-subnet-CIDR fallback);
    subnets are the cloud subnets; addresses are instance NIC private
    IPs, public IPs, and load-balancer frontends that land in a
    mirrored subnet.
    """
    blocks: list[_DesiredBlock] = []
    seen_block_cidrs: set[str] = set()

    # Map network_id → its declared CIDRs so the GCP fallback can ask
    # "does this subnet's network own any CIDR of its own?".
    network_by_id = {n.id: n for n in inv.networks}
    network_has_cidr = {n.id: bool(n.cidrs) for n in inv.networks}

    def _add_block(cidr: str, name: str, description: str) -> None:
        net = _parse_net(cidr)
        if net is None:
            return
        key = str(net)
        if key in seen_block_cidrs:
            return
        seen_block_cidrs.add(key)
        blocks.append(_DesiredBlock(network=key, name=name, description=description))

    # VPC/VNet CIDRs → one IPBlock each. Single-CIDR networks omit the
    # CIDR suffix in the name; multi-CIDR networks include it so the two
    # blocks are distinguishable in the tree.
    for n in inv.networks:
        multi = len(n.cidrs) > 1
        for cidr in n.cidrs:
            label = f"{endpoint.provider}:{n.name}"
            if multi:
                label = f"{label} {cidr}"
            region_bit = f" in {n.region}" if n.region else ""
            _add_block(cidr, label, f"{endpoint.provider} VPC/VNet {n.name}{region_bit}")

    # Subnets → one Subnet each, enclosed by the network's block. For a
    # GCP-style CIDR-less network, create a per-subnet-CIDR block first so
    # the subnet has an enclosing block at its own CIDR.
    subnets: list[_DesiredSubnet] = []
    seen_subnet_cidrs: set[str] = set()
    for s in inv.subnets:
        net = _parse_net(s.cidr)
        if net is None:
            continue
        cidr = str(net)
        if cidr in seen_subnet_cidrs:
            continue
        seen_subnet_cidrs.add(cidr)

        parent = network_by_id.get(s.network_id)
        if parent is not None and not network_has_cidr.get(s.network_id, False):
            # CIDR-less network (GCP): place the subnet under a block at
            # its own CIDR. The block won't already exist as a network
            # CIDR because the network had none.
            label = f"{endpoint.provider}:{parent.name}"
            region_bit = f" in {parent.region}" if parent.region else ""
            _add_block(
                cidr,
                label,
                f"{endpoint.provider} VPC/VNet {parent.name}{region_bit} (subnet block)",
            )

        net_name = parent.name if parent is not None else s.network_id
        region_bit = f" in {s.region}" if s.region else ""
        gateway = s.gateway or _first_usable_host(cidr)
        subnets.append(
            _DesiredSubnet(
                network=cidr,
                name=f"{endpoint.provider}:{s.name}",
                description=f"{endpoint.provider} subnet {s.name} in {net_name}{region_bit}",
                gateway=gateway,
            )
        )

    # Instance NIC private IPs → cloud-instance rows. A NIC's public IP,
    # if present, becomes a cloud-public row too (almost always skipped
    # for want of an enclosing subnet — that's expected).
    addresses: list[_DesiredAddress] = []
    for inst in inv.instances:
        desc = (
            f"{endpoint.provider} instance {inst.name} ({'running' if inst.running else 'stopped'})"
        )
        for nic in inst.nics:
            if nic.private_ip:
                addresses.append(
                    _DesiredAddress(
                        address=nic.private_ip,
                        status="cloud-instance",
                        hostname=inst.name,
                        description=desc,
                        mac=nic.mac,
                    )
                )
            if nic.public_ip:
                addresses.append(
                    _DesiredAddress(
                        address=nic.public_ip,
                        status="cloud-public",
                        hostname=inst.name,
                        description=f"{desc} — public IP",
                        public=True,
                    )
                )

    # Standalone public / Elastic IPs → cloud-public rows.
    for pub in inv.public_ips:
        label = pub.name or pub.address
        addresses.append(
            _DesiredAddress(
                address=pub.address,
                status="cloud-public",
                hostname=label,
                description=f"{endpoint.provider} public IP {label}"
                + (" (attached)" if pub.attached else " (unattached)"),
                public=True,
            )
        )

    # Load-balancer frontends → cloud-lb rows (only when mirroring LBs).
    if endpoint.mirror_load_balancers:
        for lb in inv.load_balancers:
            region_bit = f" in {lb.region}" if lb.region else ""
            for fip in lb.frontend_ips:
                addresses.append(
                    _DesiredAddress(
                        address=fip,
                        status="cloud-lb",
                        hostname=lb.name,
                        description=f"{endpoint.provider} load balancer {lb.name}{region_bit}",
                        public=True,
                    )
                )

    return blocks, subnets, addresses


# ── Apply: blocks + subnets ──────────────────────────────────────────


async def _apply_blocks_and_subnets(
    db: AsyncSession,
    endpoint: CloudEndpoint,
    desired_blocks: list[_DesiredBlock],
    desired_subnets: list[_DesiredSubnet],
    summary: ReconcileSummary,
    *,
    allow_delete: bool = True,
) -> None:
    block_rows = (
        (await db.execute(select(IPBlock).where(IPBlock.space_id == endpoint.ipam_space_id)))
        .scalars()
        .all()
    )
    blocks = list(block_rows)
    endpoint_blocks = {str(b.network): b for b in blocks if b.cloud_endpoint_id == endpoint.id}
    existing_networks = {str(b.network): b for b in blocks}

    # Create / keep the endpoint-owned blocks for every desired CIDR that
    # isn't already enclosed by an operator (or other-integration) block.
    # If an enclosing block exists we nest beneath it rather than creating
    # a same-CIDR duplicate.
    desired_block_cidrs: set[str] = set()
    for d in desired_blocks:
        if d.network in existing_networks:
            # Already present (operator-curated, foreign, or ours). If it's
            # ours, keep its metadata fresh; otherwise leave it alone.
            owned = endpoint_blocks.get(d.network)
            if owned is not None:
                desired_block_cidrs.add(d.network)
                if owned.name != d.name:
                    owned.name = d.name
                if owned.description != d.description:
                    owned.description = d.description
            continue
        enclosing = _find_enclosing_operator_block(blocks, d.network, endpoint.id)
        if enclosing is not None:
            # An operator / foreign block already encloses this CIDR — we
            # don't need our own block; subnets nest under the enclosing one.
            continue
        new_block = IPBlock(
            space_id=endpoint.ipam_space_id,
            network=d.network,
            name=d.name,
            description=d.description,
            cloud_endpoint_id=endpoint.id,
        )
        db.add(new_block)
        await db.flush()
        blocks.append(new_block)
        endpoint_blocks[d.network] = new_block
        existing_networks[d.network] = new_block
        desired_block_cidrs.add(d.network)
        summary.blocks_created += 1

    # Classify every subnet in the space into endpoint-owned / operator /
    # foreign — same three-way split the Proxmox reconciler uses.
    all_subnet_rows = (
        (await db.execute(select(Subnet).where(Subnet.space_id == endpoint.ipam_space_id)))
        .scalars()
        .all()
    )
    current_subnets: dict[str, Subnet] = {}
    operator_subnets: dict[str, Subnet] = {}
    foreign_subnets: dict[str, Subnet] = {}
    for s in all_subnet_rows:
        net_key = str(s.network)
        if s.cloud_endpoint_id == endpoint.id:
            current_subnets[net_key] = s
        elif owning_integration(s) is None:
            operator_subnets[net_key] = s
        else:
            foreign_subnets[net_key] = s

    desired_map = {d.network: d for d in desired_subnets}

    # Prune endpoint-owned subnets no longer in the desired set. Skipped on a
    # partial pull (#430) — a failed scope makes "absent" unreliable.
    if allow_delete:
        for net_str, row in current_subnets.items():
            if net_str in desired_map:
                continue
            await db.delete(row)
            summary.subnets_deleted += 1

    for net_str, d in desired_map.items():
        # An operator subnet at this exact CIDR wins — reused untouched.
        if net_str in operator_subnets:
            summary.subnets_matched += 1
            continue
        # Another integration owns this CIDR — don't duplicate, warn.
        if net_str in foreign_subnets:
            summary.warnings.append(
                f"subnet {net_str} already exists, owned by another integration; "
                "not creating duplicate"
            )
            continue

        # Any enclosing block is a valid parent — including the endpoint's
        # own VPC-CIDR block created above. Only when nothing encloses the
        # subnet (e.g. a stray cloud subnet outside every discovered VPC
        # CIDR) do we fall back to a same-CIDR endpoint-owned wrapper.
        parent_block = _find_enclosing_block(blocks, d.network)
        if parent_block is None:
            wrapper = endpoint_blocks.get(d.network)
            if wrapper is None:
                wrapper = IPBlock(
                    space_id=endpoint.ipam_space_id,
                    network=d.network,
                    name=f"{endpoint.provider}:{endpoint.name} {d.network}",
                    description=f"Auto-created for Cloud endpoint {endpoint.name}",
                    cloud_endpoint_id=endpoint.id,
                )
                db.add(wrapper)
                await db.flush()
                blocks.append(wrapper)
                endpoint_blocks[d.network] = wrapper
                desired_block_cidrs.add(d.network)
                summary.blocks_created += 1
            parent_block = wrapper

        net_parsed = _parse_net(d.network)
        expected_total = _lan_total_ips(net_parsed) if net_parsed is not None else 0

        existing = current_subnets.get(net_str)
        if existing is None:
            db.add(
                Subnet(
                    space_id=endpoint.ipam_space_id,
                    block_id=parent_block.id,
                    network=d.network,
                    name=d.name,
                    description=d.description,
                    gateway=d.gateway,
                    cloud_endpoint_id=endpoint.id,
                    kubernetes_semantics=True,  # routed overlay — suppress LAN rows
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
            # Only set the gateway when we know one; never clear an
            # operator-set value back to None on a sync.
            if d.gateway and str(existing.gateway or "") != d.gateway:
                existing.gateway = d.gateway
                changed = True
            if existing.total_ips != expected_total:
                existing.total_ips = expected_total
                changed = True
            if changed:
                summary.subnets_updated += 1

    await db.flush()

    # Drop endpoint-owned blocks that no longer back any subnet. Skipped on a
    # partial pull (#430).
    if allow_delete:
        for net_str, block in endpoint_blocks.items():
            if net_str in desired_block_cidrs:
                continue
            refs = await db.execute(select(Subnet).where(Subnet.block_id == block.id))
            if refs.scalar_one_or_none() is None:
                await db.delete(block)
                summary.blocks_deleted += 1


# ── Apply: addresses ──────────────────────────────────────────────────


async def _apply_addresses(
    db: AsyncSession,
    endpoint: CloudEndpoint,
    desired: list[_DesiredAddress],
    summary: ReconcileSummary,
    *,
    allow_delete: bool = True,
) -> None:
    subnet_rows = (
        (await db.execute(select(Subnet).where(Subnet.cloud_endpoint_id == endpoint.id)))
        .scalars()
        .all()
    )
    # Also consider operator subnets in the same space(s) for IP
    # containment — an instance IP may land in an operator-curated subnet
    # the reconciler reused (subnets_matched). We restrict to the bound
    # space(s) so cross-space overlaps don't mis-bind.
    space_ids = [endpoint.ipam_space_id]
    if endpoint.public_space_id is not None and endpoint.public_space_id != endpoint.ipam_space_id:
        space_ids.append(endpoint.public_space_id)
    all_space_subnets = (
        (await db.execute(select(Subnet).where(Subnet.space_id.in_(space_ids)))).scalars().all()
    )
    subnets = list(all_space_subnets)
    endpoint_subnet_ids = {s.id for s in subnet_rows}

    # Dedupe by address — the same IP reported twice (NIC + public IP, or
    # two LBs sharing a frontend) collapses to the first occurrence.
    desired_map: dict[str, _DesiredAddress] = {}
    for d in desired:
        if d.address in desired_map:
            continue
        desired_map[d.address] = d

    # Phase 1 — claim pre-existing operator-owned rows at the desired
    # addresses, stamping ``user_modified_at`` so their soft fields lock.
    desired_addrs = list(desired_map.keys())
    if desired_addrs:
        existing_rows = (
            (await db.execute(select(IPAddress).where(IPAddress.address.in_(desired_addrs))))
            .scalars()
            .all()
        )
        for row in existing_rows:
            if row.cloud_endpoint_id == endpoint.id:
                continue  # already ours
            if row.cloud_endpoint_id is not None:
                summary.warnings.append(
                    f"address {row.address} owned by another Cloud endpoint; not claiming"
                )
                continue
            if owned_by_other_integration(row, "cloud_endpoint_id"):
                summary.warnings.append(
                    f"address {row.address} owned by another integration; not claiming"
                )
                continue
            # Only claim rows that live in a subnet we mirror — otherwise
            # an unrelated operator IP that happens to share an address
            # string (different space) would be wrongly adopted.
            if row.subnet_id not in {s.id for s in subnets}:
                continue
            row.cloud_endpoint_id = endpoint.id
            if row.user_modified_at is None:
                row.user_modified_at = datetime.now(UTC)
        await db.flush()

    res = await db.execute(select(IPAddress).where(IPAddress.cloud_endpoint_id == endpoint.id))
    current = {str(a.address): a for a in res.scalars().all()}

    dirty_subnets: set[Any] = set(endpoint_subnet_ids)

    # Prune endpoint-owned rows no longer desired (preserve operator-edited
    # rows by releasing the FK instead of deleting). Skipped on a partial
    # pull (#430) — a failed scope makes "no longer desired" unreliable.
    if allow_delete:
        for addr, row in current.items():
            if addr not in desired_map:
                dirty_subnets.add(row.subnet_id)
                if row.user_modified_at is not None:
                    row.cloud_endpoint_id = None
                    summary.addresses_updated += 1
                else:
                    await db.delete(row)
                    summary.addresses_deleted += 1

    for addr, d in desired_map.items():
        subnet = _find_subnet_for_ip(subnets, d.address)
        if subnet is None:
            # No enclosing mirrored subnet — public / LB / out-of-band IP.
            summary.skipped_no_subnet += 1
            continue
        if addr in current:
            row = current[addr]
            changed = False
            # subnet_id is factual — always correct it.
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
                    cloud_endpoint_id=endpoint.id,
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
    inv: CloudInventory,
    desired_subnets: list[_DesiredSubnet],
    desired_addresses: list[_DesiredAddress],
    summary: ReconcileSummary,
) -> dict[str, Any]:
    """Counts + per-instance reason codes for the "Discovery" UI modal.

    Categorises every instance by whether any of its NIC IPs landed in a
    mirrored subnet (``mirrored``) or all were skipped for want of an
    enclosing subnet (``no_subnet``) / the instance had no NIC at all
    (``no_nic``). Mirrors the Proxmox reconciler's diagnostic snapshot.
    """
    subnet_set = set()
    for d in desired_subnets:
        net = _parse_net(d.network)
        if net is not None:
            subnet_set.add(net)

    def _in_a_subnet(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in subnet_set)

    instance_rows: list[dict[str, Any]] = []
    counters = {
        "instances_total": len(inv.instances),
        "instances_running": 0,
        "instances_mirrored": 0,
        "instances_no_subnet": 0,
        "instances_no_nic": 0,
    }
    for inst in inv.instances:
        if inst.running:
            counters["instances_running"] += 1
        nic_count = len(inst.nics)
        mirrored = sum(1 for nic in inst.nics if nic.private_ip and _in_a_subnet(nic.private_ip))

        issue: str | None = None
        hint: str | None = None
        if nic_count == 0:
            issue = "no_nic"
            hint = "This instance has no network interfaces."
            counters["instances_no_nic"] += 1
        elif mirrored > 0:
            counters["instances_mirrored"] += 1
        else:
            issue = "no_subnet"
            hint = (
                "The instance's private IP is not enclosed by any mirrored subnet. "
                "Check that the VPC subnet was discovered in this region."
            )
            counters["instances_no_subnet"] += 1

        instance_rows.append(
            {
                "id": inst.id,
                "name": inst.name,
                "running": inst.running,
                "region": inst.region,
                "nic_count": nic_count,
                "ips_mirrored": mirrored,
                "issue": issue,
                "hint": hint,
            }
        )

    counters["networks_total"] = len(inv.networks)
    counters["subnets_total"] = len(inv.subnets)
    counters["public_ips_total"] = len(inv.public_ips)
    counters["load_balancers_total"] = len(inv.load_balancers)
    counters["addresses_skipped_no_subnet"] = summary.skipped_no_subnet
    counters["desired_subnets"] = len(desired_subnets)
    counters["desired_addresses"] = len(desired_addresses)

    instance_rows.sort(key=lambda r: (r["issue"] is None, r["name"]))
    return {
        "summary": counters,
        "instances": instance_rows,
        "warnings": list(inv.warnings),
        "generated_at": datetime.now(UTC).isoformat(),
    }


# ── Entry point ───────────────────────────────────────────────────────


async def reconcile_endpoint(db: AsyncSession, endpoint: CloudEndpoint) -> ReconcileSummary:
    summary = ReconcileSummary(ok=False)

    if not endpoint.credentials_encrypted:
        summary.error = "credentials not set"
        endpoint.last_sync_error = summary.error
        endpoint.last_synced_at = datetime.now(UTC)
        await db.commit()
        return summary

    try:
        credentials = decrypt_dict(endpoint.credentials_encrypted)
    except ValueError as exc:
        summary.error = f"credential decrypt failed: {exc}"
        endpoint.last_sync_error = summary.error
        endpoint.last_synced_at = datetime.now(UTC)
        await db.commit()
        return summary

    try:
        connector = get_connector(
            endpoint.provider,
            credentials=credentials,
            provider_config=endpoint.provider_config,
            regions=endpoint.regions,
        )
        inv = await connector.fetch_inventory(
            include_stopped=endpoint.mirror_stopped_instances,
            include_load_balancers=endpoint.mirror_load_balancers,
        )
    except CloudConnectorError as exc:
        summary.error = str(exc)
        endpoint.last_sync_error = summary.error
        endpoint.last_synced_at = datetime.now(UTC)
        await db.commit()
        logger.warning(
            "cloud_reconcile_fetch_failed", endpoint=str(endpoint.id), error=summary.error
        )
        return summary

    summary.provider_account_id = inv.account_id
    summary.network_count = len(inv.networks)
    summary.instance_count = len(inv.instances)

    desired_blocks, desired_subnets, desired_addresses = _compute_desired(endpoint, inv)

    # #430 — a partial pull (one or more scopes failed mid-fetch) yields an
    # incomplete desired set. Upsert what we got, but suppress the
    # absence-delete pass so a transient scope failure can't mass-delete the
    # rows for the missing project/region/subscription.
    allow_delete = not inv.failed_scopes
    await _apply_blocks_and_subnets(
        db, endpoint, desired_blocks, desired_subnets, summary, allow_delete=allow_delete
    )
    await _apply_addresses(db, endpoint, desired_addresses, summary, allow_delete=allow_delete)

    summary.warnings.extend(inv.warnings)

    endpoint.last_synced_at = datetime.now(UTC)
    # On a partial pull, record the failed scopes so the operator sees the
    # mirror is incomplete (and the interval backoff treats it as an error)
    # rather than a misleading green "last sync OK".
    if inv.failed_scopes:
        partial_msg = "partial pull — absence-delete skipped for: " + ", ".join(inv.failed_scopes)
        endpoint.last_sync_error = partial_msg
        summary.warnings.append(partial_msg)
    else:
        endpoint.last_sync_error = None
    endpoint.provider_account_id = inv.account_id
    endpoint.network_count = summary.network_count
    endpoint.instance_count = summary.instance_count
    endpoint.last_discovery = _build_discovery_payload(
        inv, desired_subnets, desired_addresses, summary
    )

    db.add(
        AuditLog(
            user_display_name="system",
            auth_source="system",
            action="cloud.reconcile",
            resource_type="cloud_endpoint",
            resource_id=str(endpoint.id),
            resource_display=endpoint.name,
            new_value={
                "provider": endpoint.provider,
                "account_id": inv.account_id,
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
        "cloud_reconcile_ok",
        endpoint=str(endpoint.id),
        provider=endpoint.provider,
        account_id=inv.account_id,
        networks=summary.network_count,
        instances=summary.instance_count,
        blocks_created=summary.blocks_created,
        subnets_created=summary.subnets_created,
        subnets_updated=summary.subnets_updated,
        addresses_created=summary.addresses_created,
        addresses_updated=summary.addresses_updated,
        addresses_deleted=summary.addresses_deleted,
    )
    return summary


__all__ = ["ReconcileSummary", "reconcile_endpoint"]
