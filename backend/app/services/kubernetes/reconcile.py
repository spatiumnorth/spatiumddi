"""Per-cluster reconciler — Phase 1b.

For one ``KubernetesCluster`` row:

  1. Fetch nodes + services + ingresses (+ pods when ``mirror_pods``
     is on) via the cluster's apiserver.
  2. Compute the desired set of IPBlock / Subnet / IPAddress / DNSRecord
     rows.
  3. Load the currently-mirrored rows for this cluster (FK lookup on
     ``kubernetes_cluster_id``).
  4. Apply the diff: **create** what's desired-not-current, **delete**
     what's current-not-desired (per the "option 2a" choice in the
     design — delete, not orphan), **update** overlapping rows where
     details changed.
  5. Persist the cluster's ``last_synced_at`` / ``last_sync_error`` /
     ``node_count`` + summary audit entry.

Design notes:

* **Smart parent-block detection** — for each CIDR (pod + service)
  we look for an existing *operator-owned* block in the bound space
  that contains the CIDR. If one exists, the auto-created subnet is
  parented under it directly. Only when no enclosing block exists do
  we auto-create a wrapper block (carrying ``kubernetes_cluster_id``
  so it cascades out with the cluster).

* **Subnets are always auto-created** for pod + service CIDRs so pod
  IPs and Service ClusterIPs can actually land somewhere. They carry
  ``kubernetes_semantics=True`` which the IPAM create path reads to
  suppress the LAN-specific network / broadcast / gateway placeholder
  rows (routed overlays — no such thing).

* **Pod mirroring is opt-in** via ``cluster.mirror_pods``. Pods churn
  — a busy cluster can produce thousands of create/delete events per
  day which would noisy-up audit log. Service ClusterIPs are always
  mirrored; they're stable and one per Service.

* No writes to the cluster. SpatiumDDI only reads.
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
from app.models.dns import DNSRecord, DNSZone
from app.models.ipam import IPAddress, IPBlock, Subnet
from app.models.kubernetes import KubernetesCluster
from app.services.integration_ownership import owned_by_other_integration
from app.services.kubernetes.client import (
    KubernetesClient,
    KubernetesClientError,
)

logger = structlog.get_logger(__name__)

# BIGINT clamp for IPv6 ``/64`` or wider — ``Subnet.total_ips`` is BigInteger.
_BIGINT_MAX = 2**63 - 1

# Private-address supernets we auto-create as top-level IPBlocks
# when a cluster's pod / service CIDR falls inside one but no
# enclosing block exists yet. Keeps the IPAM tree tidy: a
# 10.42.0.0/16 pod CIDR lands under 10.0.0.0/8 instead of creating
# its own top-level wrapper. Unowned (no FK) so they persist across
# cluster removal and can be shared with Docker + manual allocations.
# Covers RFC 1918 + RFC 6598 CGNAT (100.64/10) — the latter shows
# up in some k3s and Tailscale-adjacent clusters.
_PRIVATE_SUPERNETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
]


def _k8s_total_ips(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> int:
    """Full address count for a Kubernetes pod / service CIDR.

    Regular LAN subnets exclude 2 addresses (network + broadcast) from
    the usable host count, but pod / service CIDRs are routed overlays
    — every IP in the range is a valid pod IP or ClusterIP — so we
    return ``num_addresses`` unclamped (bar the BIGINT cap for /64+).
    """
    return min(net.num_addresses, _BIGINT_MAX)


async def _recompute_subnet_utilization(db: AsyncSession, subnet_id: Any) -> None:
    """Count allocated addresses on ``subnet_id`` and update the
    cached ``allocated_ips`` + ``utilization_percent`` columns.

    Mirrors ``app.api.v1.ipam.router._update_utilization`` — we copy
    the logic rather than import it to keep the reconciler free of
    circular-import risk with the HTTP router.
    """
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


# ── Desired-state dataclasses ─────────────────────────────────────────


@dataclass(frozen=True)
class _DesiredSubnet:
    """One auto-created Subnet covering an entire pod / service CIDR."""

    network: str
    name: str
    description: str


@dataclass(frozen=True)
class _DesiredAddress:
    """One IPAddress. Subnet lookup happens at apply time — at diff
    time we just key on ``address`` so duplicate IPs across nodes + LB
    services can't collide."""

    address: str
    status: str  # kubernetes-node | kubernetes-lb | kubernetes-service | kubernetes-pod
    hostname: str
    description: str


@dataclass(frozen=True)
class _DesiredRecord:
    """One DNSRecord. Zone lookup happens at apply time by suffix-matching
    the full FQDN against zones in the cluster's bound DNS group."""

    fqdn: str
    record_type: str  # "A" or "CNAME"
    value: str
    # Fixed TTL for k8s-sourced records — ops can't edit them by hand
    # anyway, and a short TTL makes the ingress lifecycle feel fresh
    # without being noisy for resolvers.
    ttl: int = 300


# ── Reconcile summary ─────────────────────────────────────────────────


@dataclass
class ReconcileSummary:
    ok: bool
    error: str | None = None
    cluster_version: str | None = None
    node_count: int = 0
    blocks_created: int = 0
    blocks_deleted: int = 0
    subnets_created: int = 0
    subnets_updated: int = 0
    subnets_deleted: int = 0
    addresses_created: int = 0
    addresses_updated: int = 0
    addresses_deleted: int = 0
    records_created: int = 0
    records_updated: int = 0
    records_deleted: int = 0
    # Desired rows we couldn't place because there's no matching subnet
    # or zone in SpatiumDDI. Non-fatal — surfaced in the logs and the
    # cluster's ``last_sync_error`` so operators can add the missing
    # IPAM block / DNS zone and the next tick will pick them up.
    skipped_no_subnet: int = 0
    skipped_no_zone: int = 0
    # Anything we deliberately skipped because it's out of scope —
    # e.g. an invalid IP, a headless service. Logged only.
    skipped_invalid: int = 0
    warnings: list[str] = field(default_factory=list)


# ── Helpers ───────────────────────────────────────────────────────────


def _private_supernet_of(cidr: str) -> str | None:
    """Return the private-address supernet that strictly contains
    ``cidr`` as a string, or ``None``. Only IPv4 ranges — IPv6 ULA
    detection (fc00::/7) is a future extension.
    """
    net = _parse_net(cidr)
    if net is None or not isinstance(net, ipaddress.IPv4Network):
        return None
    for parent in _PRIVATE_SUPERNETS:
        if net.subnet_of(parent) and net.prefixlen > parent.prefixlen:  # type: ignore[arg-type]
            return str(parent)
    return None


def _parse_net(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(value, strict=False)
    except (ValueError, TypeError):
        return None


def _find_enclosing_operator_block(
    blocks: list[IPBlock], cidr: str, cluster_id: Any
) -> IPBlock | None:
    """Return the smallest block in ``blocks`` that contains ``cidr``
    and is **not** owned by the current cluster (i.e. an operator-
    created block we can nest under). Ignores cluster-owned wrapper
    blocks — those are handled separately.
    """
    net = _parse_net(cidr)
    if net is None:
        return None
    best: IPBlock | None = None
    best_prefix = -1
    for b in blocks:
        if b.kubernetes_cluster_id == cluster_id:
            continue
        bnet = _parse_net(str(b.network))
        if bnet is None or type(bnet) is not type(net):
            continue
        # Same family confirmed → subnet_of accepts the narrowed type.
        if net.subnet_of(bnet) and bnet.prefixlen > best_prefix:  # type: ignore[arg-type]
            best = b
            best_prefix = bnet.prefixlen
    return best


def _find_subnet_for_ip(subnets: list[Subnet], ip: str) -> Subnet | None:
    """Return the most-specific ``Subnet`` in ``subnets`` that contains
    ``ip``, or None. We iterate in-memory after loading all space
    subnets once per reconcile — it's a tiny list and a Python filter
    beats an IN query with per-IP CIDR containment checks.
    """
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


def _find_zone_for_fqdn(zones: list[DNSZone], fqdn: str) -> DNSZone | None:
    """Longest-suffix match of ``fqdn`` against the zones."""
    host = fqdn.rstrip(".").lower()
    best: DNSZone | None = None
    best_len = -1
    for z in zones:
        zname = (z.name or "").rstrip(".").lower()
        if not zname:
            continue
        if host == zname or host.endswith("." + zname):
            if len(zname) > best_len:
                best = z
                best_len = len(zname)
    return best


def _relative_label(fqdn: str, zone: DNSZone) -> str:
    host = fqdn.rstrip(".").lower()
    zname = (zone.name or "").rstrip(".").lower()
    if host == zname:
        return "@"
    suffix = "." + zname
    if host.endswith(suffix):
        return host[: -len(suffix)]
    return host


# ── Desired state computation ─────────────────────────────────────────


def _compute_desired(
    cluster: KubernetesCluster,
    nodes: list[Any],
    services: list[Any],
    lb_services: list[Any],
    pods: list[Any],
    ingresses: list[Any],
) -> tuple[
    list[_DesiredSubnet],
    list[_DesiredAddress],
    list[_DesiredRecord],
]:
    subnets: list[_DesiredSubnet] = []
    if cluster.pod_cidr:
        subnets.append(
            _DesiredSubnet(
                network=cluster.pod_cidr,
                name=f"{cluster.name} pods",
                description=f"Kubernetes pod CIDR for cluster {cluster.name}",
            )
        )
    if cluster.service_cidr:
        subnets.append(
            _DesiredSubnet(
                network=cluster.service_cidr,
                name=f"{cluster.name} services",
                description=f"Kubernetes service CIDR for cluster {cluster.name}",
            )
        )

    addresses: list[_DesiredAddress] = []

    for n in nodes:
        if not n.internal_ip:
            continue
        addresses.append(
            _DesiredAddress(
                address=n.internal_ip,
                status="kubernetes-node",
                hostname=n.name,
                description=f"node {n.name} ({'ready' if n.ready else 'not-ready'})",
            )
        )

    # LB VIPs — surface from status.loadBalancer.ingress, could be a LAN
    # IP (MetalLB, klipper-lb) or a hostname (cloud LB).
    for s in lb_services:
        if not s.ip:
            continue  # hostname-only LBs are Phase 2's problem
        addresses.append(
            _DesiredAddress(
                address=s.ip,
                status="kubernetes-lb",
                hostname=f"{s.name}.{s.namespace}",
                description=f"LoadBalancer service {s.namespace}/{s.name}",
            )
        )

    # Service ClusterIPs — every non-headless Service gets one. Stable
    # for the Service's lifetime so always mirrored (not gated on
    # mirror_pods).
    for s in services:
        addresses.append(
            _DesiredAddress(
                address=s.cluster_ip,
                status="kubernetes-service",
                hostname=f"{s.name}.{s.namespace}",
                description=f"{s.service_type} service {s.namespace}/{s.name}",
            )
        )

    # Pods — opt-in. Same namespace/name hostname shape so the UI can
    # filter to a given workload.
    if cluster.mirror_pods:
        for p in pods:
            addresses.append(
                _DesiredAddress(
                    address=p.pod_ip,
                    status="kubernetes-pod",
                    hostname=f"{p.name}.{p.namespace}",
                    description=f"pod {p.namespace}/{p.name} ({p.phase})",
                )
            )

    records: list[_DesiredRecord] = []
    for ing in ingresses:
        if not ing.hosts:
            continue
        for host in ing.hosts:
            if ing.target_ip:
                records.append(
                    _DesiredRecord(
                        fqdn=host,
                        record_type="A",
                        value=ing.target_ip,
                    )
                )
            elif ing.target_hostname:
                tgt = ing.target_hostname.rstrip(".") + "."
                records.append(
                    _DesiredRecord(
                        fqdn=host,
                        record_type="CNAME",
                        value=tgt,
                    )
                )

    return subnets, addresses, records


# ── Apply: blocks + subnets (resolved together) ──────────────────────


async def _apply_blocks_and_subnets(
    db: AsyncSession,
    cluster: KubernetesCluster,
    desired_subnets: list[_DesiredSubnet],
    summary: ReconcileSummary,
) -> None:
    """Resolve the parent block for each desired subnet, ensure the
    subnet row exists, and clean up cluster-owned wrapper blocks that
    are no longer needed.

    Strategy per desired subnet:
      1. Look for an operator-owned enclosing block (smallest containing
         block that's NOT cluster-owned). If one exists, the subnet's
         parent is that block — no wrapper block needed.
      2. Else look for an existing cluster-owned wrapper block at the
         exact CIDR and reuse it.
      3. Else create a fresh cluster-owned wrapper block at the CIDR.

    After subnets are in place, delete cluster-owned wrapper blocks
    that no longer have any cluster-owned subnets referencing them.
    """
    # Load every block in the space so we can do enclosing lookups.
    block_rows = (
        (await db.execute(select(IPBlock).where(IPBlock.space_id == cluster.ipam_space_id)))
        .scalars()
        .all()
    )
    blocks = list(block_rows)
    cluster_owned_wrappers = {
        str(b.network): b for b in blocks if b.kubernetes_cluster_id == cluster.id
    }

    # Ensure a private-address supernet exists for every desired CIDR
    # that falls in a private range (RFC 1918 or RFC 6598 CGNAT).
    # Auto-created unowned so the block survives cluster removal and
    # can be shared with other integrations or manual allocations.
    existing_networks = {str(b.network): b for b in blocks}
    for d in desired_subnets:
        supernet = _private_supernet_of(d.network)
        if supernet is None or supernet in existing_networks:
            continue
        parent = IPBlock(
            space_id=cluster.ipam_space_id,
            network=supernet,
            name=f"Private {supernet}",
            description=f"Auto-created as the private-address parent for {d.network}",
        )
        db.add(parent)
        await db.flush()
        blocks.append(parent)
        existing_networks[supernet] = parent
        summary.blocks_created += 1

    # Current cluster-owned subnets.
    res = await db.execute(select(Subnet).where(Subnet.kubernetes_cluster_id == cluster.id))
    current_subnets = {str(s.network): s for s in res.scalars().all()}

    desired_map = {d.network: d for d in desired_subnets}

    # Wrapper blocks we decided to keep this pass — anything cluster-
    # owned NOT in here becomes a deletion candidate.
    used_wrapper_cidrs: set[str] = set()

    # Deletes first: current subnets we no longer want.
    for net_str, row in current_subnets.items():
        if net_str not in desired_map:
            await db.delete(row)
            summary.subnets_deleted += 1

    # Creates / updates.
    for net_str, d in desired_map.items():
        parent_block = _find_enclosing_operator_block(blocks, d.network, cluster.id)

        if parent_block is None:
            # No operator block covers this CIDR — need a wrapper.
            wrapper = cluster_owned_wrappers.get(net_str)
            if wrapper is None:
                wrapper = IPBlock(
                    space_id=cluster.ipam_space_id,
                    network=d.network,
                    name=f"{cluster.name} {d.network}",
                    description=f"Auto-created for Kubernetes cluster {cluster.name}",
                    kubernetes_cluster_id=cluster.id,
                )
                db.add(wrapper)
                await db.flush()
                blocks.append(wrapper)
                cluster_owned_wrappers[net_str] = wrapper
                summary.blocks_created += 1
            used_wrapper_cidrs.add(net_str)
            parent_block = wrapper

        expected_total = 0
        net_parsed = _parse_net(d.network)
        if net_parsed is not None:
            expected_total = _k8s_total_ips(net_parsed)

        existing = current_subnets.get(net_str)
        if existing is None:
            db.add(
                Subnet(
                    space_id=cluster.ipam_space_id,
                    block_id=parent_block.id,
                    network=d.network,
                    name=d.name,
                    description=d.description,
                    kubernetes_cluster_id=cluster.id,
                    kubernetes_semantics=True,
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
            if not existing.kubernetes_semantics:
                existing.kubernetes_semantics = True
                changed = True
            # Backfill total_ips on pre-existing rows that were created
            # before this path set it. Pod/service CIDRs don't change
            # shape within a cluster's lifetime, but operator edits to
            # cluster.pod_cidr can change the CIDR → recompute anyway.
            if existing.total_ips != expected_total:
                existing.total_ips = expected_total
                changed = True
            if changed:
                summary.subnets_updated += 1

    await db.flush()

    # Delete cluster-owned wrapper blocks that aren't backing any
    # cluster-owned subnet anymore (e.g. operator added a new enclosing
    # block since the last pass).
    for net_str, wrapper in cluster_owned_wrappers.items():
        if net_str in used_wrapper_cidrs:
            continue
        # Defensive — before deleting, check no subnet still points at
        # this wrapper (pathological state; only cluster-owned subnets
        # should, and we already reparented those).
        refs = await db.execute(select(Subnet).where(Subnet.block_id == wrapper.id))
        if refs.scalar_one_or_none() is None:
            await db.delete(wrapper)
            summary.blocks_deleted += 1


# ── Apply: addresses ──────────────────────────────────────────────────


async def _apply_addresses(
    db: AsyncSession,
    cluster: KubernetesCluster,
    desired: list[_DesiredAddress],
    summary: ReconcileSummary,
) -> None:
    subnet_rows = (
        (await db.execute(select(Subnet).where(Subnet.space_id == cluster.ipam_space_id)))
        .scalars()
        .all()
    )
    subnets = list(subnet_rows)

    desired_map: dict[str, _DesiredAddress] = {}
    for d in desired:
        if d.address in desired_map:
            continue  # first-wins for duplicates
        desired_map[d.address] = d

    # Phase 1 — claim pre-existing operator-owned rows at the desired
    # addresses. See the matching block in services/proxmox/reconcile.py
    # for the full rationale.
    desired_addrs = list(desired_map.keys())
    if desired_addrs:
        existing = (
            (await db.execute(select(IPAddress).where(IPAddress.address.in_(desired_addrs))))
            .scalars()
            .all()
        )
        for row in existing:
            if row.kubernetes_cluster_id == cluster.id:
                continue
            if row.kubernetes_cluster_id is not None:
                summary.warnings.append(
                    f"address {row.address} owned by another Kubernetes cluster; not claiming"
                )
                continue
            if owned_by_other_integration(row, "kubernetes_cluster_id"):
                summary.warnings.append(
                    f"address {row.address} owned by another integration; not claiming"
                )
                continue
            row.kubernetes_cluster_id = cluster.id
            if row.user_modified_at is None:
                row.user_modified_at = datetime.now(UTC)
        await db.flush()

    res = await db.execute(select(IPAddress).where(IPAddress.kubernetes_cluster_id == cluster.id))
    current = {str(a.address): a for a in res.scalars().all()}

    # Subnets whose utilization we'll recompute at the end. We
    # unconditionally include every cluster-owned subnet so the
    # cached counters self-heal on any pass — no-change reconciles
    # still fix stale numbers left by pre-backfill data or out-of-
    # band edits. Non-k8s subnets (e.g. the node LAN) land here
    # only when something actually changed.
    dirty_subnets: set[Any] = {s.id for s in subnets if s.kubernetes_cluster_id == cluster.id}

    for addr, row in current.items():
        if addr not in desired_map:
            dirty_subnets.add(row.subnet_id)
            if row.user_modified_at is not None:
                # Preserve operator-edited rows when the upstream
                # disappears — release the FK rather than delete.
                row.kubernetes_cluster_id = None
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
            if row.subnet_id != subnet.id:
                dirty_subnets.add(row.subnet_id)  # old parent loses one
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
                    kubernetes_cluster_id=cluster.id,
                )
            )
            dirty_subnets.add(subnet.id)
            summary.addresses_created += 1

    # Flush so the COUNT inside recompute sees every in-flight row.
    if dirty_subnets:
        await db.flush()
        for subnet_id in dirty_subnets:
            await _recompute_subnet_utilization(db, subnet_id)


async def _apply_records(
    db: AsyncSession,
    cluster: KubernetesCluster,
    desired: list[_DesiredRecord],
    summary: ReconcileSummary,
) -> None:
    if cluster.dns_group_id is None:
        return

    zone_rows = (
        (await db.execute(select(DNSZone).where(DNSZone.group_id == cluster.dns_group_id)))
        .scalars()
        .all()
    )
    zones = list(zone_rows)

    res = await db.execute(select(DNSRecord).where(DNSRecord.kubernetes_cluster_id == cluster.id))
    current = {a.fqdn.rstrip(".").lower(): a for a in res.scalars().all()}

    desired_map: dict[str, _DesiredRecord] = {}
    for d in desired:
        key = d.fqdn.rstrip(".").lower()
        if key in desired_map:
            continue
        desired_map[key] = d

    for key, row in current.items():
        if key not in desired_map:
            await db.delete(row)
            summary.records_deleted += 1

    for key, d in desired_map.items():
        zone = _find_zone_for_fqdn(zones, d.fqdn)
        if zone is None:
            summary.skipped_no_zone += 1
            continue
        label = _relative_label(d.fqdn, zone)
        full_fqdn = d.fqdn.rstrip(".").lower() + "."
        if key in current:
            row = current[key]
            changed = False
            if row.zone_id != zone.id:
                row.zone_id = zone.id
                changed = True
            if row.name != label:
                row.name = label
                changed = True
            if row.record_type != d.record_type:
                row.record_type = d.record_type
                changed = True
            if row.value != d.value:
                row.value = d.value
                changed = True
            if row.ttl != d.ttl:
                row.ttl = d.ttl
                changed = True
            if row.fqdn != full_fqdn:
                row.fqdn = full_fqdn
                changed = True
            if changed:
                summary.records_updated += 1
        else:
            db.add(
                DNSRecord(
                    zone_id=zone.id,
                    name=label,
                    fqdn=full_fqdn,
                    record_type=d.record_type,
                    value=d.value,
                    ttl=d.ttl,
                    auto_generated=True,
                    kubernetes_cluster_id=cluster.id,
                )
            )
            summary.records_created += 1


# ── Entry point ───────────────────────────────────────────────────────


async def reconcile_cluster(db: AsyncSession, cluster: KubernetesCluster) -> ReconcileSummary:
    """Run one reconcile pass for the given cluster.

    Opens the k8s client, collects state, applies diffs against the
    DB, and updates the cluster's sync state. The full pass runs in a
    single transaction — ``db.commit()`` at the end makes every diff
    land atomically; ``db.rollback()`` on error means partial state
    never persists.
    """
    summary = ReconcileSummary(ok=False)
    try:
        token = decrypt_str(cluster.token_encrypted)
    except ValueError as exc:
        summary.error = f"token decrypt failed: {exc}"
        cluster.last_sync_error = summary.error
        cluster.last_synced_at = datetime.now(UTC)
        await db.commit()
        return summary

    try:
        async with KubernetesClient(
            api_server_url=cluster.api_server_url,
            token=token,
            ca_bundle_pem=cluster.ca_bundle_pem or "",
        ) as client:
            nodes = await client.list_nodes()
            all_services = await client.list_services()
            lb_services = await client.list_loadbalancer_services()
            pods = await client.list_pods() if cluster.mirror_pods else []
            ingresses = await client.list_ingresses()
    except KubernetesClientError as exc:
        summary.error = str(exc)
        cluster.last_sync_error = summary.error
        cluster.last_synced_at = datetime.now(UTC)
        await db.commit()
        logger.warning(
            "k8s_reconcile_fetch_failed",
            cluster=str(cluster.id),
            error=summary.error,
        )
        return summary

    summary.node_count = len(nodes)

    desired_subnets, desired_addresses, desired_records = _compute_desired(
        cluster, nodes, all_services, lb_services, pods, ingresses
    )

    await _apply_blocks_and_subnets(db, cluster, desired_subnets, summary)
    await _apply_addresses(db, cluster, desired_addresses, summary)
    await _apply_records(db, cluster, desired_records, summary)

    cluster.last_synced_at = datetime.now(UTC)
    cluster.last_sync_error = None
    cluster.node_count = summary.node_count

    db.add(
        AuditLog(
            user_display_name="system",
            auth_source="system",
            action="kubernetes.reconcile",
            resource_type="kubernetes_cluster",
            resource_id=str(cluster.id),
            resource_display=cluster.name,
            new_value={
                "blocks": {
                    "created": summary.blocks_created,
                    "deleted": summary.blocks_deleted,
                },
                "subnets": {
                    "created": summary.subnets_created,
                    "updated": summary.subnets_updated,
                    "deleted": summary.subnets_deleted,
                },
                "addresses": {
                    "created": summary.addresses_created,
                    "updated": summary.addresses_updated,
                    "deleted": summary.addresses_deleted,
                    "skipped_no_subnet": summary.skipped_no_subnet,
                },
                "records": {
                    "created": summary.records_created,
                    "updated": summary.records_updated,
                    "deleted": summary.records_deleted,
                    "skipped_no_zone": summary.skipped_no_zone,
                },
            },
        )
    )

    await db.commit()
    summary.ok = True
    logger.info(
        "k8s_reconcile_ok",
        cluster=str(cluster.id),
        nodes=summary.node_count,
        blocks_created=summary.blocks_created,
        blocks_deleted=summary.blocks_deleted,
        subnets_created=summary.subnets_created,
        subnets_updated=summary.subnets_updated,
        subnets_deleted=summary.subnets_deleted,
        addresses_created=summary.addresses_created,
        addresses_updated=summary.addresses_updated,
        addresses_deleted=summary.addresses_deleted,
        records_created=summary.records_created,
        records_updated=summary.records_updated,
        records_deleted=summary.records_deleted,
        skipped_no_subnet=summary.skipped_no_subnet,
        skipped_no_zone=summary.skipped_no_zone,
    )
    return summary


__all__ = ["ReconcileSummary", "reconcile_cluster"]
