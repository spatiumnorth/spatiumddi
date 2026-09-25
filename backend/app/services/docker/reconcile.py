"""Per-host Docker reconciler.

For one ``DockerHost`` row:

  1. Fetch networks + containers from the Docker Engine API.
  2. Compute the desired set of IPBlock / Subnet / IPAddress rows.
  3. Load the currently-mirrored rows for this host (FK lookup on
     ``docker_host_id``).
  4. Apply the diff: create, update, delete.
  5. Persist the host's ``last_synced_at`` / ``last_sync_error`` /
     ``container_count`` + summary audit entry.

Parallels the Kubernetes reconciler. Notable differences:

* **LAN semantics.** Docker bridge networks have a real gateway and
  broadcast — they're actual L2 segments bridged to a veth pair.
  We create subnets without ``kubernetes_semantics`` and stamp the
  network / broadcast / gateway placeholder rows like the IPAM
  router does, so these subnets look "normal" in the UI.
* **Default-network filtering.** Docker's default unconfigured
  ``bridge`` (172.17.0.0/16), ``host``, and ``none`` are skipped
  unless ``include_default_networks=True`` on the host row.
* **Swarm overlay networks.** Cluster-wide, not per-host. Skipped
  in this reconciler — see Phase-3 note in CLAUDE.md.
* **Container mirroring is opt-in** via ``host.mirror_containers``
  (mirrors ``KubernetesCluster.mirror_pods``).
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
from app.models.docker import DockerHost
from app.models.ipam import IPAddress, IPBlock, Subnet
from app.services.docker.client import (
    DockerClient,
    DockerClientError,
)
from app.services.integration_ownership import owned_by_other_integration

logger = structlog.get_logger(__name__)

# Docker-default networks we ignore by default. The first is the
# unconfigured bridge every daemon ships with — usually noise in IPAM.
_DEFAULT_SKIP_NAMES = {"bridge", "host", "none", "docker_gwbridge", "ingress"}

# Private-address supernets we auto-create as top-level IPBlocks
# when a mirrored network falls inside one but no enclosing block
# exists yet. Keeps the IPAM tree tidy: a 172.20.0.0/16 bridge lands
# under 172.16.0.0/12 instead of creating its own top-level wrapper.
# Unowned (no FK) so they persist across integration removal and can
# be shared between Docker + Kubernetes + manual allocations.
# Covers RFC 1918 (10/8, 172.16/12, 192.168/16) plus RFC 6598 CGNAT
# (100.64/10) — the latter isn't strictly RFC 1918 but shows up in
# container networks often enough (Tailscale, k3s service CIDR on
# some distros) that it deserves the same treatment.
_PRIVATE_SUPERNETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
]


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


# Swarm overlay networks we always skip — they're cluster-wide, so
# per-host mirroring creates duplicate IPAM entries on every node.
_SWARM_SKIP_SCOPES = {"swarm", "global"}

_BIGINT_MAX = 2**63 - 1


# ── Desired-state dataclasses ────────────────────────────────────────


@dataclass(frozen=True)
class _DesiredSubnet:
    network: str
    name: str
    description: str
    gateway: str | None = None


@dataclass(frozen=True)
class _DesiredAddress:
    address: str
    status: str  # docker-container | docker-gateway
    hostname: str
    description: str


@dataclass
class ReconcileSummary:
    ok: bool
    error: str | None = None
    engine_version: str | None = None
    container_count: int = 0
    blocks_created: int = 0
    blocks_deleted: int = 0
    subnets_created: int = 0
    subnets_updated: int = 0
    subnets_deleted: int = 0
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
    """Usable-host count matching the IPAM router's ``_total_ips``."""
    if isinstance(net, ipaddress.IPv6Network):
        return min(net.num_addresses, _BIGINT_MAX)
    if net.prefixlen >= 31:
        return net.num_addresses
    return net.num_addresses - 2


def _find_enclosing_operator_block(
    blocks: list[IPBlock], cidr: str, host_id: Any
) -> IPBlock | None:
    """Smallest block containing ``cidr`` that isn't owned by the current
    host. Same logic as the k8s reconciler — operator blocks win over
    auto-created wrappers from this same host so the subnet nests
    under user intent.
    """
    net = _parse_net(cidr)
    if net is None:
        return None
    best: IPBlock | None = None
    best_prefix = -1
    for b in blocks:
        if b.docker_host_id == host_id:
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
    """Mirrors the same helper in the k8s reconciler — copied to keep
    the Docker package free of cross-integration imports.
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


# ── Desired state computation ────────────────────────────────────────


def _compute_desired(
    host: DockerHost,
    networks: list[Any],
    containers: list[Any],
) -> tuple[list[_DesiredSubnet], list[_DesiredAddress]]:
    subnets: list[_DesiredSubnet] = []
    container_status_ok = {"running"}
    if host.include_stopped_containers:
        container_status_ok |= {"created", "paused", "restarting", "exited", "dead"}

    # Map network name → list of (cidr_str, gateway) for subnet lookup
    # when we decide which subnets a container's IPs belong to. We
    # don't strictly need this because ``_find_subnet_for_ip`` works
    # off the Subnet rows in the DB, but we use the gateway data to
    # seed gateway placeholder rows.
    for n in networks:
        if n.scope in _SWARM_SKIP_SCOPES:
            continue
        if n.name in _DEFAULT_SKIP_NAMES and not host.include_default_networks:
            continue
        for cidr, gateway in n.subnets:
            parsed = _parse_net(cidr)
            if parsed is None:
                continue
            subnets.append(
                _DesiredSubnet(
                    network=cidr,
                    name=f"{host.name}/{n.name}",
                    description=f"Docker {n.driver} network {n.name} on {host.name}",
                    gateway=gateway or None,
                )
            )

    addresses: list[_DesiredAddress] = []
    for c in containers:
        if c.state.lower() not in container_status_ok:
            continue
        if c.compose_project and c.compose_service:
            hostname = f"{c.compose_project}.{c.compose_service}"
        else:
            hostname = c.name
        desc = f"{c.image} ({c.status})"
        for _net_name, ip in c.ip_bindings:
            addresses.append(
                _DesiredAddress(
                    address=ip,
                    status="docker-container",
                    hostname=hostname,
                    description=desc,
                )
            )

    # Gateway rows — so the IPAM subnet shows a gateway marker like
    # the operator-created LAN subnets do. Keyed on (gateway_ip,
    # subnet). The reconciler places these as ``reserved`` status
    # matching the IPAM router's create path.
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

    return subnets, addresses


# ── Apply: blocks + subnets ──────────────────────────────────────────


async def _apply_blocks_and_subnets(
    db: AsyncSession,
    host: DockerHost,
    desired_subnets: list[_DesiredSubnet],
    summary: ReconcileSummary,
) -> None:
    block_rows = (
        (await db.execute(select(IPBlock).where(IPBlock.space_id == host.ipam_space_id)))
        .scalars()
        .all()
    )
    blocks = list(block_rows)
    host_owned_wrappers = {str(b.network): b for b in blocks if b.docker_host_id == host.id}

    # Ensure a private-address supernet exists for every desired CIDR
    # that falls in a private range (RFC 1918 or RFC 6598 CGNAT).
    # Auto-created unowned so the block survives host removal and can
    # be shared with other integrations or manual allocations.
    existing_networks = {str(b.network): b for b in blocks}
    for d in desired_subnets:
        supernet = _private_supernet_of(d.network)
        if supernet is None or supernet in existing_networks:
            continue
        parent = IPBlock(
            space_id=host.ipam_space_id,
            network=supernet,
            name=f"Private {supernet}",
            description=f"Auto-created as the private-address parent for {d.network}",
        )
        db.add(parent)
        await db.flush()
        blocks.append(parent)
        existing_networks[supernet] = parent
        summary.blocks_created += 1

    res = await db.execute(select(Subnet).where(Subnet.docker_host_id == host.id))
    current_subnets = {str(s.network): s for s in res.scalars().all()}

    desired_map = {d.network: d for d in desired_subnets}
    used_wrapper_cidrs: set[str] = set()

    for net_str, row in current_subnets.items():
        if net_str not in desired_map:
            await db.delete(row)
            summary.subnets_deleted += 1

    for net_str, d in desired_map.items():
        parent_block = _find_enclosing_operator_block(blocks, d.network, host.id)

        if parent_block is None:
            wrapper = host_owned_wrappers.get(net_str)
            if wrapper is None:
                wrapper = IPBlock(
                    space_id=host.ipam_space_id,
                    network=d.network,
                    name=f"{host.name} {d.network}",
                    description=f"Auto-created for Docker host {host.name}",
                    docker_host_id=host.id,
                )
                db.add(wrapper)
                await db.flush()
                blocks.append(wrapper)
                host_owned_wrappers[net_str] = wrapper
                summary.blocks_created += 1
            used_wrapper_cidrs.add(net_str)
            parent_block = wrapper

        net_parsed = _parse_net(d.network)
        expected_total = _lan_total_ips(net_parsed) if net_parsed is not None else 0

        existing = current_subnets.get(net_str)
        if existing is None:
            db.add(
                Subnet(
                    space_id=host.ipam_space_id,
                    block_id=parent_block.id,
                    network=d.network,
                    name=d.name,
                    description=d.description,
                    gateway=d.gateway,
                    docker_host_id=host.id,
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
            if existing.gateway != d.gateway:
                existing.gateway = d.gateway
                changed = True
            if existing.total_ips != expected_total:
                existing.total_ips = expected_total
                changed = True
            if changed:
                summary.subnets_updated += 1

    await db.flush()

    for net_str, wrapper in host_owned_wrappers.items():
        if net_str in used_wrapper_cidrs:
            continue
        refs = await db.execute(select(Subnet).where(Subnet.block_id == wrapper.id))
        if refs.scalar_one_or_none() is None:
            await db.delete(wrapper)
            summary.blocks_deleted += 1


# ── Apply: addresses ──────────────────────────────────────────────────


async def _apply_addresses(
    db: AsyncSession,
    host: DockerHost,
    desired: list[_DesiredAddress],
    summary: ReconcileSummary,
) -> None:
    subnet_rows = (
        (await db.execute(select(Subnet).where(Subnet.space_id == host.ipam_space_id)))
        .scalars()
        .all()
    )
    subnets = list(subnet_rows)

    desired_map: dict[str, _DesiredAddress] = {}
    for d in desired:
        if d.address in desired_map:
            continue
        desired_map[d.address] = d

    # Phase 1 — claim pre-existing operator-owned rows at the desired
    # addresses. See the matching block in services/proxmox/reconcile.py
    # for the full rationale. Operator rows (no integration FK) are
    # adopted with ``user_modified_at`` stamped so their values stay
    # locked; rows owned by another integration are skipped + warned.
    desired_addrs = list(desired_map.keys())
    if desired_addrs:
        existing = (
            (await db.execute(select(IPAddress).where(IPAddress.address.in_(desired_addrs))))
            .scalars()
            .all()
        )
        for row in existing:
            if row.docker_host_id == host.id:
                continue
            if row.docker_host_id is not None:
                summary.warnings.append(
                    f"address {row.address} owned by another Docker host; not claiming"
                )
                continue
            if owned_by_other_integration(row, "docker_host_id"):
                summary.warnings.append(
                    f"address {row.address} owned by another integration; not claiming"
                )
                continue
            row.docker_host_id = host.id
            if row.user_modified_at is None:
                row.user_modified_at = datetime.now(UTC)
        await db.flush()

    res = await db.execute(select(IPAddress).where(IPAddress.docker_host_id == host.id))
    current = {str(a.address): a for a in res.scalars().all()}

    dirty_subnets: set[Any] = {s.id for s in subnets if s.docker_host_id == host.id}

    for addr, row in current.items():
        if addr not in desired_map:
            dirty_subnets.add(row.subnet_id)
            if row.user_modified_at is not None:
                # Preserve operator-edited rows when the upstream
                # disappears — release the FK rather than delete.
                row.docker_host_id = None
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
                    docker_host_id=host.id,
                )
            )
            dirty_subnets.add(subnet.id)
            summary.addresses_created += 1

    if dirty_subnets:
        await db.flush()
        for subnet_id in dirty_subnets:
            await _recompute_subnet_utilization(db, subnet_id)


# ── Entry point ───────────────────────────────────────────────────────


async def reconcile_host(db: AsyncSession, host: DockerHost) -> ReconcileSummary:
    summary = ReconcileSummary(ok=False)

    client_key_pem = ""
    if host.client_key_encrypted:
        try:
            client_key_pem = decrypt_str(host.client_key_encrypted)
        except ValueError as exc:
            summary.error = f"client-key decrypt failed: {exc}"
            host.last_sync_error = summary.error
            host.last_synced_at = datetime.now(UTC)
            await db.commit()
            return summary

    try:
        async with DockerClient(
            connection_type=host.connection_type,
            endpoint=host.endpoint,
            ca_bundle_pem=host.ca_bundle_pem or "",
            client_cert_pem=host.client_cert_pem or "",
            client_key_pem=client_key_pem,
        ) as client:
            networks = await client.list_networks()
            containers = await client.list_containers(
                include_stopped=host.include_stopped_containers
            )
    except DockerClientError as exc:
        summary.error = str(exc)
        host.last_sync_error = summary.error
        host.last_synced_at = datetime.now(UTC)
        await db.commit()
        logger.warning("docker_reconcile_fetch_failed", host=str(host.id), error=summary.error)
        return summary

    summary.container_count = len(containers)

    # Optionally mirror containers — networks always land, containers
    # gated on mirror_containers. The reconciler writes them anyway
    # via _compute_desired? No — skip here by emptying the list.
    if not host.mirror_containers:
        containers = []

    desired_subnets, desired_addresses = _compute_desired(host, networks, containers)

    await _apply_blocks_and_subnets(db, host, desired_subnets, summary)
    await _apply_addresses(db, host, desired_addresses, summary)

    host.last_synced_at = datetime.now(UTC)
    host.last_sync_error = None
    host.container_count = summary.container_count

    db.add(
        AuditLog(
            user_display_name="system",
            auth_source="system",
            action="docker.reconcile",
            resource_type="docker_host",
            resource_id=str(host.id),
            resource_display=host.name,
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
            },
        )
    )
    await db.commit()
    summary.ok = True
    logger.info(
        "docker_reconcile_ok",
        host=str(host.id),
        containers=summary.container_count,
        blocks_created=summary.blocks_created,
        blocks_deleted=summary.blocks_deleted,
        subnets_created=summary.subnets_created,
        subnets_updated=summary.subnets_updated,
        subnets_deleted=summary.subnets_deleted,
        addresses_created=summary.addresses_created,
        addresses_updated=summary.addresses_updated,
        addresses_deleted=summary.addresses_deleted,
        skipped_no_subnet=summary.skipped_no_subnet,
    )
    return summary


__all__ = ["ReconcileSummary", "reconcile_host"]
