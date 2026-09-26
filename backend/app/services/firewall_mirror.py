"""Shared firewall read-only-mirror engine (#606).

The address-object / NAT / interface-subnet / DHCP-lease "shadow IPAM" mirror
is identical across every firewall vendor (PAN-OS #605, Fortinet + Meraki
#606) — only the *owner* differs (which ``FirewallObject`` / IPAM provenance FK
carries the vendor id). #605 shipped this logic inline in
``app.services.panos.reconcile``; #606 lifts it here, parameterized by a
``FirewallOwner``, so all three vendor reconcilers share one implementation and
one place to fix bugs.

Each vendor reconciler:

1. fetches from its own vendor client;
2. maps the vendor's wire dataclasses into the neutral ``MirrorObject`` /
   ``MirrorNat`` / ``MirrorSubnet`` / ``MirrorAddress`` shapes below;
3. calls ``apply_objects`` / ``apply_nat`` / ``apply_subnets`` /
   ``apply_addresses`` with its ``FirewallOwner``;
4. writes its own vendor-specific sync-state columns + audit row.

Ownership guard (NN: a mirror never claims another integration's rows): a row
carrying ANY of ``INTEGRATION_OWNERSHIP_FKS`` other than the current owner's is
off-limits. ``other_ownership_fks(owner)`` returns exactly that guard set. The
FK set lives in ``app.services.integration_ownership``, which every other
integration reconciler uses too (#1135).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress, IPBlock, NATMapping, Subnet
from app.models.panos import FIREWALL_OBJECT_KINDS, FirewallObject
from app.services.integration_ownership import INTEGRATION_OWNERSHIP_FKS

_BIGINT_MAX = 2**63 - 1


@dataclass(frozen=True)
class FirewallOwner:
    """Identifies which vendor integration owns the mirrored rows.

    ``kind`` — block-sync/target kind string (``paloalto`` / ``fortinet`` /
    ``meraki``). ``fk_attr`` — the provenance column on ``FirewallObject`` /
    ``Subnet`` / ``IPAddress`` / ``IPBlock`` / ``NATMapping`` that carries this
    vendor's target id. ``label`` — human label used verbatim in auto-created
    wrapper-block descriptions.
    """

    kind: str
    fk_attr: str
    label: str


PALOALTO_OWNER = FirewallOwner("paloalto", "panos_firewall_id", "Palo Alto firewall")
FORTINET_OWNER = FirewallOwner("fortinet", "fortinet_firewall_id", "FortiGate firewall")
MERAKI_OWNER = FirewallOwner("meraki", "meraki_org_id", "Meraki org")


def other_ownership_fks(owner: FirewallOwner) -> frozenset[str]:
    """The ownership-FK guard set for ``owner`` — every integration FK except
    the owner's own."""
    return INTEGRATION_OWNERSHIP_FKS - {owner.fk_attr}


# ── Neutral mirror shapes (vendor reconcilers map their wire types to these) ─


@dataclass
class MirrorObject:
    name: str
    kind: str  # host | network | range | fqdn | group
    value: str
    description: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class MirrorNat:
    name: str
    kind: str
    internal_ip: str | None
    external_ip: str | None
    description: str


@dataclass
class MirrorSubnet:
    cidr: str
    name: str
    description: str
    gateway: str | None = None


@dataclass
class MirrorAddress:
    address: str
    mac: str | None
    hostname: str
    description: str
    status: str = "dhcp"
    auto_from_lease: bool = True


@dataclass
class MirrorSummary:
    """Convergence counters shared by every vendor reconciler. Vendor-specific
    display fields (``sw_version`` / ``model`` / ``network_count``) ride along
    so a single summary object flows back to the task/router layer."""

    ok: bool = False
    error: str | None = None
    sw_version: str | None = None
    model: str | None = None
    network_count: int = 0
    object_count: int = 0
    nat_rule_count: int = 0
    interface_count: int = 0
    lease_count: int = 0
    objects_created: int = 0
    objects_updated: int = 0
    objects_deleted: int = 0
    nat_created: int = 0
    nat_updated: int = 0
    nat_deleted: int = 0
    subnets_created: int = 0
    subnets_updated: int = 0
    subnets_deleted: int = 0
    subnets_matched: int = 0
    blocks_created: int = 0
    blocks_deleted: int = 0
    addresses_created: int = 0
    addresses_updated: int = 0
    addresses_deleted: int = 0
    skipped_no_subnet: int = 0
    warnings: list[str] = field(default_factory=list)


# ── Parse helpers ────────────────────────────────────────────────────


def parse_net(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(value, strict=False)
    except (ValueError, TypeError):
        return None


def _lan_total_ips(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> int:
    if isinstance(net, ipaddress.IPv6Network):
        return min(net.num_addresses, _BIGINT_MAX)
    if net.prefixlen >= 31:
        return net.num_addresses
    return net.num_addresses - 2


def resolved_cidr_for(kind: str, value: str) -> str | None:
    """Best-effort canonical IP/CIDR for the IPAM drift join (vendor-neutral).

    ``host``/``network`` → the CIDR (``10.0.0.5/32``); ``range`` → the first IP
    as ``/32``; ``fqdn``/``group`` → ``None``.
    """
    value = (value or "").strip()
    if not value:
        return None
    try:
        if kind in ("host", "network"):
            if "/" in value:
                return str(ipaddress.ip_interface(value))
            return f"{ipaddress.ip_address(value)}/32"
        if kind == "range":
            first = value.split("-", 1)[0].strip()
            ipaddress.ip_address(first)
            return f"{first}/32"
    except (ValueError, TypeError):
        return None
    return None


# ── FirewallObject mirror ────────────────────────────────────────────


async def _load_ipam_resolve_maps(
    db: AsyncSession, space_id: Any
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Preload the in-space host→ip_id and cidr→subnet_id maps in two queries so
    the per-object drift resolve is a dict lookup, not an N+1 SELECT storm."""
    ip_rows = (
        await db.execute(
            select(IPAddress.id, IPAddress.address)
            .join(Subnet, IPAddress.subnet_id == Subnet.id)
            .where(Subnet.space_id == space_id)
        )
    ).all()
    ip_by_host = {str(addr): rid for rid, addr in ip_rows}
    subnet_rows = (
        await db.execute(select(Subnet.id, Subnet.network).where(Subnet.space_id == space_id))
    ).all()
    subnet_by_cidr = {str(net): sid for sid, net in subnet_rows}
    return ip_by_host, subnet_by_cidr


def _resolve_object_links(
    resolved_cidr: str | None,
    ip_by_host: dict[str, Any],
    subnet_by_cidr: dict[str, Any],
) -> tuple[Any, Any]:
    """Best-effort link a mirrored object to a live IPAM row using the preloaded
    maps. Returns ``(ip_address_id, subnet_id)`` — either/both may be None."""
    if not resolved_cidr:
        return None, None
    net = parse_net(resolved_cidr)
    if net is None:
        return None, None
    if net.prefixlen in (32, 128):
        ip_id = ip_by_host.get(str(net.network_address))
        if ip_id is not None:
            return ip_id, None
    return None, subnet_by_cidr.get(str(net))


async def apply_objects(
    db: AsyncSession,
    owner: FirewallOwner,
    target_id: Any,
    space_id: Any,
    desired: list[MirrorObject],
    summary: MirrorSummary,
) -> None:
    owner_col = getattr(FirewallObject, owner.fk_attr)
    existing_rows = (
        (await db.execute(select(FirewallObject).where(owner_col == target_id))).scalars().all()
    )
    existing = {r.name: r for r in existing_rows}
    desired_map = {d.name: d for d in desired if d.name}

    for name, row in existing.items():
        if name not in desired_map:
            await db.delete(row)
            summary.objects_deleted += 1

    ip_by_host, subnet_by_cidr = (
        await _load_ipam_resolve_maps(db, space_id) if desired_map else ({}, {})
    )
    for name, d in desired_map.items():
        kind = d.kind if d.kind in FIREWALL_OBJECT_KINDS else "host"
        resolved = resolved_cidr_for(kind, d.value)
        ip_id, subnet_id = _resolve_object_links(resolved, ip_by_host, subnet_by_cidr)
        row = existing.get(name)
        if row is None:
            db.add(
                FirewallObject(
                    name=name,
                    kind=kind,
                    value=d.value,
                    description=d.description,
                    tags=list(d.tags),
                    resolved_cidr=resolved,
                    ip_address_id=ip_id,
                    subnet_id=subnet_id,
                    **{owner.fk_attr: target_id},
                )
            )
            summary.objects_created += 1
        else:
            changed = False
            if row.kind != kind:
                row.kind, changed = kind, True
            if (row.value or "") != d.value:
                row.value, changed = d.value, True
            if (row.description or "") != d.description:
                row.description, changed = d.description, True
            if list(row.tags or []) != list(d.tags):
                row.tags, changed = list(d.tags), True
            if (row.resolved_cidr or None) != resolved:
                row.resolved_cidr, changed = resolved, True
            if row.ip_address_id != ip_id:
                row.ip_address_id, changed = ip_id, True
            if row.subnet_id != subnet_id:
                row.subnet_id, changed = subnet_id, True
            if changed:
                summary.objects_updated += 1


# ── NAT mirror ───────────────────────────────────────────────────────


async def apply_nat(
    db: AsyncSession,
    owner: FirewallOwner,
    target_id: Any,
    target_name: str,
    desired: list[MirrorNat],
    summary: MirrorSummary,
) -> None:
    owner_col = getattr(NATMapping, owner.fk_attr)
    existing_rows = (
        (await db.execute(select(NATMapping).where(owner_col == target_id))).scalars().all()
    )
    existing = {r.name: r for r in existing_rows}
    desired_map: dict[str, MirrorNat] = {}
    for d in desired:
        if d.name and d.name not in desired_map:
            desired_map[d.name] = d

    for name, row in existing.items():
        if name not in desired_map:
            await db.delete(row)
            summary.nat_deleted += 1

    for name, d in desired_map.items():
        # A rule whose endpoints resolve to no bare IPs (named objects / 'any')
        # is a content-free mapping — don't mirror it; drop a stale row if a
        # prior sync created one while the rule still had a literal IP.
        if d.internal_ip is None and d.external_ip is None:
            row = existing.get(name)
            if row is not None:
                await db.delete(row)
                summary.nat_deleted += 1
            continue
        description = d.description or f"NAT rule on {target_name}"
        row = existing.get(name)
        if row is None:
            db.add(
                NATMapping(
                    name=name,
                    kind=d.kind,
                    internal_ip=d.internal_ip,
                    external_ip=d.external_ip,
                    protocol="any",
                    device_label=target_name,
                    description=description,
                    **{owner.fk_attr: target_id},
                )
            )
            summary.nat_created += 1
        else:
            changed = False
            if row.kind != d.kind:
                row.kind, changed = d.kind, True
            if (str(row.internal_ip) if row.internal_ip else None) != d.internal_ip:
                row.internal_ip, changed = d.internal_ip, True
            if (str(row.external_ip) if row.external_ip else None) != d.external_ip:
                row.external_ip, changed = d.external_ip, True
            if (row.description or "") != description:
                row.description, changed = description, True
            if changed:
                summary.nat_updated += 1


# ── Interface / VLAN → subnet mirror (opt-in) ────────────────────────


def _find_subnet_for_ip(subnets: list[Subnet], ip: str) -> Subnet | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    best: Subnet | None = None
    best_prefix = -1
    for s in subnets:
        net = parse_net(str(s.network))
        if net is None:
            continue
        if addr in net and net.prefixlen > best_prefix:
            best, best_prefix = s, net.prefixlen
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


def _find_enclosing_operator_block(blocks: list[IPBlock], cidr: str) -> IPBlock | None:
    """The tightest unowned (operator) block that contains ``cidr`` — used as the
    subnet's parent so we don't create a redundant wrapper."""
    net = parse_net(cidr)
    if net is None:
        return None
    best: IPBlock | None = None
    best_prefix = -1
    for b in blocks:
        bnet = parse_net(str(b.network))
        if bnet is None or type(bnet) is not type(net):
            continue
        if net.subnet_of(bnet) and bnet.prefixlen > best_prefix:  # type: ignore[arg-type]
            best, best_prefix = b, bnet.prefixlen
    return best


async def apply_subnets(
    db: AsyncSession,
    owner: FirewallOwner,
    target_id: Any,
    space_id: Any,
    target_name: str,
    desired_subnets: list[MirrorSubnet],
    summary: MirrorSummary,
) -> None:
    """Mirror firewall interface / VLAN CIDRs as owner-owned subnets. Each subnet
    is parented on the tightest enclosing operator block, or — failing that — a
    per-CIDR wrapper block (``network == cidr``) so the parent always contains
    the subnet. A single shared wrapper would strand subnets in unrelated ranges
    under a wrong-CIDR parent."""
    guard = other_ownership_fks(owner)
    all_subnets = (
        (await db.execute(select(Subnet).where(Subnet.space_id == space_id))).scalars().all()
    )
    fw_subnets = {str(s.network): s for s in all_subnets if getattr(s, owner.fk_attr) == target_id}
    operator_subnets = {
        str(s.network): s
        for s in all_subnets
        if getattr(s, owner.fk_attr) is None and all(getattr(s, fk) is None for fk in guard)
    }
    foreign_subnets = {
        str(s.network): s
        for s in all_subnets
        if getattr(s, owner.fk_attr) is None and str(s.network) not in operator_subnets
    }

    desired: dict[str, MirrorSubnet] = {}
    for ms in desired_subnets:
        if ms.cidr and ms.cidr not in desired:
            desired[ms.cidr] = ms

    blocks = list(
        (await db.execute(select(IPBlock).where(IPBlock.space_id == space_id))).scalars().all()
    )
    operator_blocks = [
        b
        for b in blocks
        if getattr(b, owner.fk_attr) is None and all(getattr(b, fk) is None for fk in guard)
    ]
    fw_wrappers = {str(b.network): b for b in blocks if getattr(b, owner.fk_attr) == target_id}

    # Delete owner-owned subnets no longer present (un-claim if foreign IPs live in).
    for cidr, row in list(fw_subnets.items()):
        if cidr in desired:
            continue
        surviving = await db.scalar(
            select(func.count())
            .select_from(IPAddress)
            .where(IPAddress.subnet_id == row.id)
            .where(getattr(IPAddress, owner.fk_attr).is_(None))
        )
        if surviving:
            setattr(row, owner.fk_attr, None)
            summary.subnets_updated += 1
        else:
            await db.delete(row)
            summary.subnets_deleted += 1

    used_wrapper_cidrs: set[str] = set()
    for cidr, ms in desired.items():
        if cidr in operator_subnets:
            summary.subnets_matched += 1
            continue
        if cidr in foreign_subnets:
            summary.warnings.append(
                f"subnet {cidr} already exists, owned by another integration; not duplicating"
            )
            continue

        parent = _find_enclosing_operator_block(operator_blocks, cidr)
        if parent is None:
            wrapper = fw_wrappers.get(cidr)
            if wrapper is None:
                wrapper = IPBlock(
                    space_id=space_id,
                    network=cidr,
                    name=f"{target_name} {cidr}",
                    description=f"Auto-created for {owner.label} {target_name}",
                    **{owner.fk_attr: target_id},
                )
                db.add(wrapper)
                await db.flush()
                fw_wrappers[cidr] = wrapper
                summary.blocks_created += 1
            used_wrapper_cidrs.add(cidr)
            parent = wrapper

        net = parse_net(cidr)
        total = _lan_total_ips(net) if net is not None else 0
        existing = fw_subnets.get(cidr)
        if existing is None:
            db.add(
                Subnet(
                    space_id=space_id,
                    block_id=parent.id,
                    network=cidr,
                    name=ms.name,
                    description=ms.description,
                    gateway=ms.gateway,
                    total_ips=total,
                    **{owner.fk_attr: target_id},
                )
            )
            summary.subnets_created += 1
        else:
            changed = False
            if existing.block_id != parent.id:
                existing.block_id, changed = parent.id, True
            if existing.name != ms.name:
                existing.name, changed = ms.name, True
            if existing.description != ms.description:
                existing.description, changed = ms.description, True
            if ms.gateway and existing.gateway != ms.gateway:
                existing.gateway, changed = ms.gateway, True
            if existing.total_ips != total:
                existing.total_ips, changed = total, True
            if changed:
                summary.subnets_updated += 1
    await db.flush()

    # Drop owner-owned wrapper blocks that no longer back a subnet.
    for cidr, wrapper in fw_wrappers.items():
        if cidr in used_wrapper_cidrs:
            continue
        refs = await db.scalar(
            select(func.count()).select_from(Subnet).where(Subnet.block_id == wrapper.id)
        )
        if not refs:
            await db.delete(wrapper)
            summary.blocks_deleted += 1


async def apply_addresses(
    db: AsyncSession,
    owner: FirewallOwner,
    target_id: Any,
    space_id: Any,
    desired_addrs: list[MirrorAddress],
    summary: MirrorSummary,
) -> None:
    """Mirror DHCP leases / fixed reservations / clients as owner-owned IP rows.
    Un-claims (rather than deletes) a row an operator has since edited."""
    subnets = list(
        (await db.execute(select(Subnet).where(Subnet.space_id == space_id))).scalars().all()
    )
    current_rows = (
        (await db.execute(select(IPAddress).where(getattr(IPAddress, owner.fk_attr) == target_id)))
        .scalars()
        .all()
    )
    current = {str(a.address): a for a in current_rows}
    desired: dict[str, MirrorAddress] = {}
    for ma in desired_addrs:
        if ma.address and ma.address not in desired:
            desired[ma.address] = ma

    dirty: set[Any] = set()
    for addr, row in current.items():
        if addr not in desired:
            dirty.add(row.subnet_id)
            if row.user_modified_at is not None:
                setattr(row, owner.fk_attr, None)
                summary.addresses_updated += 1
            else:
                await db.delete(row)
                summary.addresses_deleted += 1

    for addr, ma in desired.items():
        subnet = _find_subnet_for_ip(subnets, addr)
        if subnet is None:
            summary.skipped_no_subnet += 1
            continue
        row = current.get(addr)
        if row is None:
            db.add(
                IPAddress(
                    subnet_id=subnet.id,
                    address=addr,
                    status=ma.status,
                    hostname=ma.hostname or "",
                    description=ma.description,
                    mac_address=ma.mac,
                    auto_from_lease=ma.auto_from_lease,
                    **{owner.fk_attr: target_id},
                )
            )
            dirty.add(subnet.id)
            summary.addresses_created += 1
        elif row.user_modified_at is None:
            changed = False
            if row.status != ma.status:
                row.status, changed = ma.status, True
            if (row.hostname or "") != (ma.hostname or ""):
                row.hostname, changed = ma.hostname or "", True
            if (row.description or "") != ma.description:
                row.description, changed = ma.description, True
            if ma.mac and (row.mac_address or "") != ma.mac:
                row.mac_address, changed = ma.mac, True
            if changed:
                dirty.add(subnet.id)
                summary.addresses_updated += 1

    if dirty:
        await db.flush()
        for sid in dirty:
            await _recompute_subnet_utilization(db, sid)


__all__ = [
    "FirewallOwner",
    "INTEGRATION_OWNERSHIP_FKS",
    "MERAKI_OWNER",
    "FORTINET_OWNER",
    "PALOALTO_OWNER",
    "MirrorAddress",
    "MirrorNat",
    "MirrorObject",
    "MirrorSubnet",
    "MirrorSummary",
    "apply_addresses",
    "apply_nat",
    "apply_objects",
    "apply_subnets",
    "other_ownership_fks",
    "parse_net",
    "resolved_cidr_for",
]
