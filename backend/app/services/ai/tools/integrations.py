"""Tier 4 integration target read tools for the Operator Copilot
(issue #101).

Exposes the four read-only integration mirror surfaces — Kubernetes
clusters, Docker hosts, Proxmox endpoints, Tailscale tenants — as
list tools so operators can ask "which clusters are configured?" or
"is the Frankfurt Docker host still syncing?" without falling back
to UI navigation.

Each tool is gated by the matching feature_module
(``integrations.kubernetes`` etc.) so disabling the integration in
Settings → Features removes the tool from the AI surface in lock-step
with the sidebar entry.

Output is intentionally narrow — name / endpoint / enabled state /
last sync timestamp + error / ipam space binding. Credentials, CA
bundles, and any other secret material never enter the response
payload (the underlying models keep them in encrypted columns the
ORM doesn't surface here).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.cloud import CloudEndpoint
from app.models.docker import DockerHost
from app.models.firewall_feed import FirewallFeed
from app.models.fortinet import FortinetFirewall
from app.models.kubernetes import KubernetesCluster
from app.models.meraki import MerakiOrg
from app.models.netbird import NetbirdInstance
from app.models.opnsense import OPNsenseRouter
from app.models.panos import FirewallObject, PANOSFirewall
from app.models.proxmox import ProxmoxNode
from app.models.tailscale import TailscaleTenant
from app.models.unifi import UnifiController
from app.services.ai.tools.base import register_tool


def _common_target_args() -> dict[str, Any]:
    """Field set every list-targets tool exposes — kept consistent so
    the LLM doesn't have to remember per-integration filter shapes."""
    return {
        "search": Field(
            default=None,
            description="Substring match on name / description / endpoint URL.",
        ),
        "enabled": Field(
            default=None,
            description="Filter by ``enabled`` flag. None = both.",
        ),
        "limit": Field(default=50, ge=1, le=500),
    }


# ── list_kubernetes_targets ───────────────────────────────────────────


class ListKubernetesTargetsArgs(BaseModel):
    search: str | None = _common_target_args()["search"]
    enabled: bool | None = _common_target_args()["enabled"]
    limit: int = _common_target_args()["limit"]


@register_tool(
    name="list_kubernetes_targets",
    permission=("read", "kubernetes_cluster"),
    module="integrations.kubernetes",
    description=(
        "List configured Kubernetes clusters that SpatiumDDI mirrors "
        "into IPAM. Each row carries id, name, description, "
        "api_server_url, enabled flag, ipam_space_id, dns_group_id, "
        "pod_cidr / service_cidr, last_synced_at, last_sync_error, "
        "cluster_version, and node_count. Use for 'which clusters are "
        "configured?', 'is cluster X syncing?', or 'when did we last "
        "pull from the prod cluster?'. Credentials are never returned."
    ),
    args_model=ListKubernetesTargetsArgs,
    category="integrations",
)
async def list_kubernetes_targets(
    db: AsyncSession, user: User, args: ListKubernetesTargetsArgs
) -> list[dict[str, Any]]:
    stmt = select(KubernetesCluster)
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(KubernetesCluster.name).like(like),
                func.lower(KubernetesCluster.description).like(like),
                func.lower(KubernetesCluster.api_server_url).like(like),
            )
        )
    if args.enabled is not None:
        stmt = stmt.where(KubernetesCluster.enabled.is_(args.enabled))
    stmt = stmt.order_by(KubernetesCluster.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(r.id),
            "name": r.name,
            "description": r.description,
            "api_server_url": r.api_server_url,
            "enabled": r.enabled,
            "ipam_space_id": str(r.ipam_space_id),
            "dns_group_id": str(r.dns_group_id) if r.dns_group_id else None,
            "pod_cidr": r.pod_cidr,
            "service_cidr": r.service_cidr,
            "sync_interval_seconds": r.sync_interval_seconds,
            "mirror_pods": r.mirror_pods,
            "last_synced_at": r.last_synced_at.isoformat() if r.last_synced_at else None,
            "last_sync_error": r.last_sync_error,
            "cluster_version": r.cluster_version,
            "node_count": r.node_count,
        }
        for r in rows
    ]


# ── list_docker_targets ───────────────────────────────────────────────


class ListDockerTargetsArgs(BaseModel):
    search: str | None = _common_target_args()["search"]
    enabled: bool | None = _common_target_args()["enabled"]
    limit: int = _common_target_args()["limit"]


@register_tool(
    name="list_docker_targets",
    permission=("read", "docker_host"),
    module="integrations.docker",
    description=(
        "List configured Docker hosts that SpatiumDDI mirrors into "
        "IPAM. Each row carries id, name, description, connection_type "
        "(unix / tcp), endpoint, enabled flag, ipam_space_id, "
        "dns_group_id, mirror_containers / include_default_networks / "
        "include_stopped_containers flags, sync_interval_seconds, and "
        "last_synced_at. Use for 'which Docker hosts are configured?' "
        "or 'is the docker integration syncing?'. Credentials never "
        "appear in the response."
    ),
    args_model=ListDockerTargetsArgs,
    category="integrations",
)
async def list_docker_targets(
    db: AsyncSession, user: User, args: ListDockerTargetsArgs
) -> list[dict[str, Any]]:
    stmt = select(DockerHost)
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(DockerHost.name).like(like),
                func.lower(DockerHost.description).like(like),
                func.lower(DockerHost.endpoint).like(like),
            )
        )
    if args.enabled is not None:
        stmt = stmt.where(DockerHost.enabled.is_(args.enabled))
    stmt = stmt.order_by(DockerHost.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(r.id),
            "name": r.name,
            "description": r.description,
            "connection_type": r.connection_type,
            "endpoint": r.endpoint,
            "enabled": r.enabled,
            "ipam_space_id": str(r.ipam_space_id),
            "dns_group_id": str(r.dns_group_id) if r.dns_group_id else None,
            "mirror_containers": r.mirror_containers,
            "include_default_networks": r.include_default_networks,
            "include_stopped_containers": r.include_stopped_containers,
            "sync_interval_seconds": r.sync_interval_seconds,
            "last_synced_at": r.last_synced_at.isoformat() if r.last_synced_at else None,
        }
        for r in rows
    ]


# ── list_proxmox_targets ──────────────────────────────────────────────


class ListProxmoxTargetsArgs(BaseModel):
    search: str | None = _common_target_args()["search"]
    enabled: bool | None = _common_target_args()["enabled"]
    limit: int = _common_target_args()["limit"]


@register_tool(
    name="list_proxmox_targets",
    permission=("read", "proxmox_node"),
    module="integrations.proxmox",
    description=(
        "List configured Proxmox VE endpoints that SpatiumDDI mirrors "
        "into IPAM. Each row carries id, name, description, endpoint, "
        "enabled flag, ipam_space_id, sync_interval_seconds, and "
        "last_synced_at. Use for 'which PVE endpoints are configured?' "
        "or 'is Proxmox syncing?'. API tokens never appear."
    ),
    args_model=ListProxmoxTargetsArgs,
    category="integrations",
)
async def list_proxmox_targets(
    db: AsyncSession, user: User, args: ListProxmoxTargetsArgs
) -> list[dict[str, Any]]:
    stmt = select(ProxmoxNode)
    if args.search:
        like = f"%{args.search.lower()}%"
        cols = [
            func.lower(ProxmoxNode.name).like(like),
            func.lower(ProxmoxNode.description).like(like),
        ]
        # ProxmoxNode may or may not have ``endpoint`` / ``api_url``.
        # Probe for both common attribute names so the tool stays robust
        # if the column gets renamed; the search just narrows further
        # when present.
        for col_name in ("endpoint", "api_url"):
            col = getattr(ProxmoxNode, col_name, None)
            if col is not None:
                cols.append(func.lower(col).like(like))
        stmt = stmt.where(or_(*cols))
    if args.enabled is not None:
        stmt = stmt.where(ProxmoxNode.enabled.is_(args.enabled))
    stmt = stmt.order_by(ProxmoxNode.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    out: list[dict[str, Any]] = []
    for r in rows:
        last_synced = getattr(r, "last_synced_at", None)
        row: dict[str, Any] = {
            "id": str(r.id),
            "name": r.name,
            "description": getattr(r, "description", "") or "",
            "enabled": r.enabled,
            "ipam_space_id": (str(r.ipam_space_id) if getattr(r, "ipam_space_id", None) else None),
            "sync_interval_seconds": getattr(r, "sync_interval_seconds", None),
            "last_synced_at": last_synced.isoformat() if last_synced else None,
        }
        for opt in ("endpoint", "api_url"):
            val = getattr(r, opt, None)
            if val is not None:
                row[opt] = val
        out.append(row)
    return out


# ── list_tailscale_targets ────────────────────────────────────────────


class ListTailscaleTargetsArgs(BaseModel):
    search: str | None = _common_target_args()["search"]
    enabled: bool | None = _common_target_args()["enabled"]
    limit: int = _common_target_args()["limit"]


@register_tool(
    name="list_tailscale_targets",
    permission=("read", "tailscale_tenant"),
    module="integrations.tailscale",
    description=(
        "List configured Tailscale tenants (tailnets) that SpatiumDDI "
        "mirrors into IPAM. Each row carries id, name, description, "
        "enabled flag, ipam_space_id, sync_interval_seconds, and "
        "last_synced_at. Use for 'which tailnets are connected?' or "
        "'is Tailscale syncing?'. PAT tokens never appear."
    ),
    args_model=ListTailscaleTargetsArgs,
    category="integrations",
)
async def list_tailscale_targets(
    db: AsyncSession, user: User, args: ListTailscaleTargetsArgs
) -> list[dict[str, Any]]:
    stmt = select(TailscaleTenant)
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(TailscaleTenant.name).like(like),
                func.lower(TailscaleTenant.description).like(like),
            )
        )
    if args.enabled is not None:
        stmt = stmt.where(TailscaleTenant.enabled.is_(args.enabled))
    stmt = stmt.order_by(TailscaleTenant.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    out: list[dict[str, Any]] = []
    for r in rows:
        last_synced = getattr(r, "last_synced_at", None)
        out.append(
            {
                "id": str(r.id),
                "name": r.name,
                "description": getattr(r, "description", "") or "",
                "enabled": r.enabled,
                "ipam_space_id": (
                    str(r.ipam_space_id) if getattr(r, "ipam_space_id", None) else None
                ),
                "sync_interval_seconds": getattr(r, "sync_interval_seconds", None),
                "last_synced_at": last_synced.isoformat() if last_synced else None,
            }
        )
    return out


# ── list_netbird_targets ──────────────────────────────────────────────


class ListNetbirdTargetsArgs(BaseModel):
    search: str | None = _common_target_args()["search"]
    enabled: bool | None = _common_target_args()["enabled"]
    limit: int = _common_target_args()["limit"]


@register_tool(
    name="list_netbird_targets",
    permission=("read", "netbird_instance"),
    module="integrations.netbird",
    description=(
        "List configured NetBird instances (mesh deployments) that "
        "SpatiumDDI mirrors into IPAM. Each row carries id, name, "
        "description, enabled flag, ipam_space_id, sync_interval_seconds, "
        "and last_synced_at. Use for 'which NetBird meshes are connected?' "
        "or 'is NetBird syncing?'. API tokens never appear."
    ),
    args_model=ListNetbirdTargetsArgs,
    category="integrations",
)
async def list_netbird_targets(
    db: AsyncSession, user: User, args: ListNetbirdTargetsArgs
) -> list[dict[str, Any]]:
    stmt = select(NetbirdInstance)
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(NetbirdInstance.name).like(like),
                func.lower(NetbirdInstance.description).like(like),
            )
        )
    if args.enabled is not None:
        stmt = stmt.where(NetbirdInstance.enabled.is_(args.enabled))
    stmt = stmt.order_by(NetbirdInstance.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    out: list[dict[str, Any]] = []
    for r in rows:
        last_synced = getattr(r, "last_synced_at", None)
        out.append(
            {
                "id": str(r.id),
                "name": r.name,
                "description": getattr(r, "description", "") or "",
                "enabled": r.enabled,
                "ipam_space_id": (
                    str(r.ipam_space_id) if getattr(r, "ipam_space_id", None) else None
                ),
                "sync_interval_seconds": getattr(r, "sync_interval_seconds", None),
                "last_synced_at": last_synced.isoformat() if last_synced else None,
            }
        )
    return out


# ── list_unifi_targets ────────────────────────────────────────────────


class ListUnifiTargetsArgs(BaseModel):
    search: str | None = _common_target_args()["search"]
    enabled: bool | None = _common_target_args()["enabled"]
    limit: int = _common_target_args()["limit"]


@register_tool(
    name="list_unifi_targets",
    permission=("read", "unifi_controller"),
    module="integrations.unifi",
    description=(
        "List configured UniFi controllers that SpatiumDDI mirrors "
        "into IPAM. Each row carries id, name, description, mode "
        "(local|cloud), host, cloud_host_id, enabled, ipam_space_id, "
        "dns_group_id, mirror flags (mirror_networks / mirror_clients "
        "/ mirror_fixed_ips), site_allowlist, sync_interval_seconds, "
        "last_synced_at, last_sync_error, controller_version, "
        "site_count, network_count, client_count. Use for 'which "
        "UniFi controllers are connected?', 'is the cloud controller "
        "syncing?', or 'how many networks does the home controller "
        "expose?'. Credentials never appear."
    ),
    args_model=ListUnifiTargetsArgs,
    category="integrations",
)
async def list_unifi_targets(
    db: AsyncSession, user: User, args: ListUnifiTargetsArgs
) -> list[dict[str, Any]]:
    stmt = select(UnifiController)
    if args.search:
        like = f"%{args.search.lower()}%"
        cols = [
            func.lower(UnifiController.name).like(like),
            func.lower(UnifiController.description).like(like),
        ]
        # ``host`` is nullable for cloud-mode rows; lowercase NULL is
        # NULL, so the LIKE just doesn't match — no need to special-case.
        cols.append(func.lower(func.coalesce(UnifiController.host, "")).like(like))
        cols.append(func.lower(func.coalesce(UnifiController.cloud_host_id, "")).like(like))
        stmt = stmt.where(or_(*cols))
    if args.enabled is not None:
        stmt = stmt.where(UnifiController.enabled.is_(args.enabled))
    stmt = stmt.order_by(UnifiController.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(r.id),
            "name": r.name,
            "description": r.description,
            "mode": r.mode,
            "host": r.host,
            "cloud_host_id": r.cloud_host_id,
            "port": r.port,
            "enabled": r.enabled,
            "ipam_space_id": str(r.ipam_space_id),
            "dns_group_id": str(r.dns_group_id) if r.dns_group_id else None,
            "mirror_networks": r.mirror_networks,
            "mirror_clients": r.mirror_clients,
            "mirror_fixed_ips": r.mirror_fixed_ips,
            "site_allowlist": list(r.site_allowlist or []),
            "include_wired": r.include_wired,
            "include_wireless": r.include_wireless,
            "include_vpn": r.include_vpn,
            "sync_interval_seconds": r.sync_interval_seconds,
            "last_synced_at": r.last_synced_at.isoformat() if r.last_synced_at else None,
            "last_sync_error": r.last_sync_error,
            "controller_version": r.controller_version,
            "site_count": r.site_count,
            "network_count": r.network_count,
            "client_count": r.client_count,
        }
        for r in rows
    ]


# ── list_cloud_targets ────────────────────────────────────────────────


class ListCloudTargetsArgs(BaseModel):
    search: str | None = _common_target_args()["search"]
    enabled: bool | None = _common_target_args()["enabled"]
    limit: int = _common_target_args()["limit"]
    provider: str | None = Field(
        default=None,
        description="Filter by cloud provider: 'aws', 'azure', or 'gcp'.",
    )


@register_tool(
    name="list_cloud_targets",
    permission=("read", "cloud_endpoint"),
    module="integrations.cloud",
    description=(
        "List configured public-cloud accounts (AWS / Azure / GCP) that "
        "SpatiumDDI mirrors into IPAM. Each row carries id, name, "
        "description, provider, enabled flag, regions, ipam_space_id, "
        "public_space_id, dns_group_id, mirror_load_balancers / "
        "mirror_stopped_instances, sync_interval_seconds, last_synced_at, "
        "last_sync_error, provider_account_id, network_count, and "
        "instance_count. Use for 'which cloud accounts are connected?', "
        "'is the AWS prod account syncing?', or 'how many VPCs does the "
        "Azure account expose?'. Credentials never appear."
    ),
    args_model=ListCloudTargetsArgs,
    category="integrations",
)
async def list_cloud_targets(
    db: AsyncSession, user: User, args: ListCloudTargetsArgs
) -> list[dict[str, Any]]:
    stmt = select(CloudEndpoint)
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(CloudEndpoint.name).like(like),
                func.lower(CloudEndpoint.description).like(like),
            )
        )
    if args.enabled is not None:
        stmt = stmt.where(CloudEndpoint.enabled.is_(args.enabled))
    if args.provider:
        stmt = stmt.where(CloudEndpoint.provider == args.provider.strip().lower())
    stmt = stmt.order_by(CloudEndpoint.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(r.id),
            "name": r.name,
            "description": r.description,
            "provider": r.provider,
            "enabled": r.enabled,
            "regions": list(r.regions or []),
            "ipam_space_id": str(r.ipam_space_id),
            "public_space_id": str(r.public_space_id) if r.public_space_id else None,
            "dns_group_id": str(r.dns_group_id) if r.dns_group_id else None,
            "mirror_load_balancers": r.mirror_load_balancers,
            "mirror_stopped_instances": r.mirror_stopped_instances,
            "sync_interval_seconds": r.sync_interval_seconds,
            "last_synced_at": r.last_synced_at.isoformat() if r.last_synced_at else None,
            "last_sync_error": r.last_sync_error,
            "provider_account_id": r.provider_account_id,
            "network_count": r.network_count,
            "instance_count": r.instance_count,
        }
        for r in rows
    ]


# ── list_opnsense_targets ─────────────────────────────────────────────


class ListOPNsenseTargetsArgs(BaseModel):
    search: str | None = _common_target_args()["search"]
    enabled: bool | None = _common_target_args()["enabled"]
    limit: int = _common_target_args()["limit"]


@register_tool(
    name="list_opnsense_targets",
    permission=("read", "opnsense_router"),
    module="integrations.opnsense",
    description=(
        "List configured OPNsense firewalls that SpatiumDDI mirrors "
        "into IPAM. Each row carries id, name, description, endpoint, "
        "enabled flag, ipam_space_id, sync_interval_seconds, "
        "last_synced_at, firmware_version, interface_count, and "
        "lease_count. Use for 'which OPNsense firewalls are configured?' "
        "or 'is OPNsense syncing?'. API keys/secrets never appear."
    ),
    args_model=ListOPNsenseTargetsArgs,
    category="integrations",
)
async def list_opnsense_targets(
    db: AsyncSession, user: User, args: ListOPNsenseTargetsArgs
) -> list[dict[str, Any]]:
    stmt = select(OPNsenseRouter)
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(OPNsenseRouter.name).like(like),
                func.lower(OPNsenseRouter.description).like(like),
                func.lower(OPNsenseRouter.host).like(like),
            )
        )
    if args.enabled is not None:
        stmt = stmt.where(OPNsenseRouter.enabled.is_(args.enabled))
    stmt = stmt.order_by(OPNsenseRouter.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    out: list[dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "id": str(r.id),
                "name": r.name,
                "description": r.description or "",
                "enabled": r.enabled,
                "endpoint": f"https://{r.host}:{r.port}",
                "ipam_space_id": str(r.ipam_space_id),
                "sync_interval_seconds": r.sync_interval_seconds,
                "last_synced_at": r.last_synced_at.isoformat() if r.last_synced_at else None,
                "last_sync_error": r.last_sync_error,
                "firmware_version": r.firmware_version,
                "interface_count": r.interface_count,
                "lease_count": r.lease_count,
            }
        )
    return out


# ── list_panos_targets (#605) ─────────────────────────────────────────


class ListPanosTargetsArgs(BaseModel):
    search: str | None = _common_target_args()["search"]
    enabled: bool | None = _common_target_args()["enabled"]
    limit: int = _common_target_args()["limit"]


@register_tool(
    name="list_panos_targets",
    permission=("read", "panos_firewall"),
    module="integrations.paloalto",
    description=(
        "List configured Palo Alto PAN-OS / Panorama firewalls that "
        "SpatiumDDI mirrors into IPAM (address objects, NAT rules, and "
        "optionally zones/interfaces + DHCP leases). Each row carries id, "
        "name, description, endpoint, enabled flag, whether it is a Panorama "
        "device-group or a standalone vsys, ipam_space_id, "
        "sync_interval_seconds, last_synced_at, sw_version, model, "
        "object_count, nat_rule_count, and whether DAG enforcement "
        "(block_sync) is armed. Use for 'which Palo Alto firewalls are "
        "configured?' or 'is PAN-OS syncing?'. API keys never appear."
    ),
    args_model=ListPanosTargetsArgs,
    category="integrations",
)
async def list_panos_targets(
    db: AsyncSession, user: User, args: ListPanosTargetsArgs
) -> list[dict[str, Any]]:
    stmt = select(PANOSFirewall)
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(PANOSFirewall.name).like(like),
                func.lower(PANOSFirewall.description).like(like),
                func.lower(PANOSFirewall.host).like(like),
            )
        )
    if args.enabled is not None:
        stmt = stmt.where(PANOSFirewall.enabled.is_(args.enabled))
    stmt = stmt.order_by(PANOSFirewall.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(f.id),
            "name": f.name,
            "description": f.description or "",
            "enabled": f.enabled,
            "endpoint": f"https://{f.host}:{f.port}",
            "is_panorama": f.is_panorama,
            "scope": (f"device-group {f.device_group}" if f.is_panorama else f"vsys {f.vsys}"),
            "ipam_space_id": str(f.ipam_space_id),
            "sync_interval_seconds": f.sync_interval_seconds,
            "last_synced_at": f.last_synced_at.isoformat() if f.last_synced_at else None,
            "last_sync_error": f.last_sync_error,
            "sw_version": f.sw_version,
            "model": f.model,
            "object_count": f.object_count,
            "nat_rule_count": f.nat_rule_count,
            "dag_enforcement_armed": f.block_sync_enabled,
        }
        for f in rows
    ]


# ── find_firewall_objects / count_firewall_objects (#605) ─────────────


def _firewall_owner_match(firewall_id: Any) -> Any:
    """A predicate matching a FirewallObject owned by ``firewall_id`` across any
    of the three vendor owner columns (PAN-OS / Fortinet / Meraki)."""
    return or_(
        FirewallObject.panos_firewall_id == firewall_id,
        FirewallObject.fortinet_firewall_id == firewall_id,
        FirewallObject.meraki_org_id == firewall_id,
    )


class FindFirewallObjectsArgs(BaseModel):
    firewall_id: str | None = Field(
        default=None,
        description="Filter to one firewall / org (UUID, any vendor). Omit for all.",
    )
    source_kind: str | None = Field(
        default=None, description="Filter by vendor: paloalto | fortinet | meraki."
    )
    kind: str | None = Field(
        default=None, description="Filter by kind: host | network | range | fqdn | group."
    )
    search: str | None = Field(
        default=None, description="Substring match on the object name / value."
    )
    unlinked_only: bool = Field(
        default=False,
        description=(
            "When true, only objects that resolve to a CIDR/IP but have no "
            "matching IPAM row — the 'firewall object with no IPAM row' drift set."
        ),
    )
    limit: int = Field(default=50, ge=1, le=200)


_SOURCE_KIND_COL = {
    "paloalto": FirewallObject.panos_firewall_id,
    "fortinet": FirewallObject.fortinet_firewall_id,
    "meraki": FirewallObject.meraki_org_id,
}


@register_tool(
    name="find_firewall_objects",
    permission=("read", ("panos_firewall", "fortinet_firewall", "meraki_org")),
    description=(
        "List mirrored firewall address objects / groups from every configured "
        "firewall vendor (Palo Alto #605, Fortinet + Meraki #606) — the 'shadow "
        "IPAM' store. Each row carries source_kind, name, kind (host/network/"
        "range/fqdn/group), value, description, tags, the resolved CIDR, and "
        "whether it links to a live IPAM subnet/address. Use unlinked_only=true "
        "to surface drift ('firewall objects with no IPAM row'). Read-only."
    ),
    args_model=FindFirewallObjectsArgs,
    category="read",
    default_enabled=True,
)
async def find_firewall_objects(
    db: AsyncSession, user: User, args: FindFirewallObjectsArgs
) -> dict[str, Any]:
    import uuid as _uuid  # noqa: PLC0415

    stmt = select(FirewallObject)
    if args.firewall_id:
        try:
            stmt = stmt.where(_firewall_owner_match(_uuid.UUID(args.firewall_id)))
        except ValueError:
            return {"firewall_objects": [], "count": 0, "error": "invalid firewall_id"}
    if args.source_kind:
        col = _SOURCE_KIND_COL.get(args.source_kind)
        if col is None:
            return {"firewall_objects": [], "count": 0, "error": "invalid source_kind"}
        stmt = stmt.where(col.isnot(None))
    if args.kind:
        stmt = stmt.where(FirewallObject.kind == args.kind)
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(FirewallObject.name).like(like),
                func.lower(FirewallObject.value).like(like),
            )
        )
    if args.unlinked_only:
        stmt = (
            stmt.where(FirewallObject.resolved_cidr.isnot(None))
            .where(FirewallObject.ip_address_id.is_(None))
            .where(FirewallObject.subnet_id.is_(None))
        )
    stmt = stmt.order_by(FirewallObject.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return {
        "firewall_objects": [
            {
                "id": str(o.id),
                "source_kind": o.source_kind,
                "firewall_id": str(o.source_id) if o.source_id else None,
                "name": o.name,
                "kind": o.kind,
                "value": o.value,
                "description": o.description or "",
                "tags": list(o.tags or []),
                "resolved_cidr": str(o.resolved_cidr) if o.resolved_cidr else None,
                "linked_to_ipam": o.ip_address_id is not None or o.subnet_id is not None,
            }
            for o in rows
        ],
        "count": len(rows),
    }


class CountFirewallObjectsArgs(BaseModel):
    firewall_id: str | None = Field(
        default=None,
        description="Filter to one firewall / org (UUID, any vendor). Omit for all.",
    )


@register_tool(
    name="count_firewall_objects",
    permission=("read", ("panos_firewall", "fortinet_firewall", "meraki_org")),
    description=(
        "Count mirrored firewall address objects across every vendor (Palo Alto "
        "#605, Fortinet + Meraki #606) grouped by kind, plus the number that "
        "resolve to a CIDR/IP but link no IPAM row (the drift count). Use to "
        "size the shadow-IPAM set. Read-only."
    ),
    args_model=CountFirewallObjectsArgs,
    category="read",
    default_enabled=True,
)
async def count_firewall_objects(
    db: AsyncSession, user: User, args: CountFirewallObjectsArgs
) -> dict[str, Any]:
    import uuid as _uuid  # noqa: PLC0415

    fw_filter = None
    if args.firewall_id:
        try:
            fw_filter = _uuid.UUID(args.firewall_id)
        except ValueError:
            return {"total": 0, "by_kind": {}, "unlinked": 0, "error": "invalid firewall_id"}

    kind_stmt = select(FirewallObject.kind, func.count(FirewallObject.id)).group_by(
        FirewallObject.kind
    )
    if fw_filter is not None:
        kind_stmt = kind_stmt.where(_firewall_owner_match(fw_filter))
    by_kind = {k: int(n) for k, n in (await db.execute(kind_stmt)).all()}

    unlinked_stmt = (
        select(func.count(FirewallObject.id))
        .where(FirewallObject.resolved_cidr.isnot(None))
        .where(FirewallObject.ip_address_id.is_(None))
        .where(FirewallObject.subnet_id.is_(None))
    )
    if fw_filter is not None:
        unlinked_stmt = unlinked_stmt.where(_firewall_owner_match(fw_filter))
    unlinked = int((await db.execute(unlinked_stmt)).scalar_one())

    return {"total": sum(by_kind.values()), "by_kind": by_kind, "unlinked": unlinked}


# ── list_fortinet_targets / list_meraki_targets / list_firewall_feeds (#606) ──


class ListFortinetTargetsArgs(BaseModel):
    search: str | None = _common_target_args()["search"]
    enabled: bool | None = _common_target_args()["enabled"]
    limit: int = _common_target_args()["limit"]


@register_tool(
    name="list_fortinet_targets",
    permission=("read", "fortinet_firewall"),
    module="integrations.fortinet",
    description=(
        "List configured Fortinet FortiGate firewalls that SpatiumDDI mirrors "
        "into IPAM (address objects, VIPs/DNAT, and optionally interfaces + DHCP "
        "leases). Each row carries id, name, description, endpoint, enabled, vdom, "
        "ipam_space_id, sync_interval_seconds, last_synced_at, sw_version, model, "
        "object_count, nat_rule_count. FortiGate enforcement is the credential-free "
        "threat-feed path (see list_firewall_feeds). API tokens never appear."
    ),
    args_model=ListFortinetTargetsArgs,
    category="integrations",
)
async def list_fortinet_targets(
    db: AsyncSession, user: User, args: ListFortinetTargetsArgs
) -> list[dict[str, Any]]:
    stmt = select(FortinetFirewall)
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(FortinetFirewall.name).like(like),
                func.lower(FortinetFirewall.description).like(like),
                func.lower(FortinetFirewall.host).like(like),
            )
        )
    if args.enabled is not None:
        stmt = stmt.where(FortinetFirewall.enabled.is_(args.enabled))
    stmt = stmt.order_by(FortinetFirewall.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(f.id),
            "name": f.name,
            "description": f.description or "",
            "enabled": f.enabled,
            "endpoint": f"https://{f.host}:{f.port}",
            "vdom": f.vdom,
            "ipam_space_id": str(f.ipam_space_id),
            "sync_interval_seconds": f.sync_interval_seconds,
            "last_synced_at": f.last_synced_at.isoformat() if f.last_synced_at else None,
            "last_sync_error": f.last_sync_error,
            "sw_version": f.sw_version,
            "model": f.model,
            "object_count": f.object_count,
            "nat_rule_count": f.nat_rule_count,
        }
        for f in rows
    ]


class ListMerakiTargetsArgs(BaseModel):
    search: str | None = _common_target_args()["search"]
    enabled: bool | None = _common_target_args()["enabled"]
    limit: int = _common_target_args()["limit"]


@register_tool(
    name="list_meraki_targets",
    permission=("read", "meraki_org"),
    module="integrations.meraki",
    description=(
        "List configured Cisco Meraki organizations that SpatiumDDI mirrors into "
        "IPAM (appliance VLANs -> subnets, DHCP fixed-IP reservations, policy "
        "objects, 1:1 NAT / port-forward, and optionally clients). Each row "
        "carries id, name, description, org_id, enabled, ipam_space_id, "
        "sync_interval_seconds, last_synced_at, network_count, object_count, and "
        "whether per-client block enforcement (block_sync) is armed. API keys "
        "never appear."
    ),
    args_model=ListMerakiTargetsArgs,
    category="integrations",
)
async def list_meraki_targets(
    db: AsyncSession, user: User, args: ListMerakiTargetsArgs
) -> list[dict[str, Any]]:
    stmt = select(MerakiOrg)
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(MerakiOrg.name).like(like),
                func.lower(MerakiOrg.description).like(like),
                func.lower(MerakiOrg.org_id).like(like),
            )
        )
    if args.enabled is not None:
        stmt = stmt.where(MerakiOrg.enabled.is_(args.enabled))
    stmt = stmt.order_by(MerakiOrg.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(o.id),
            "name": o.name,
            "description": o.description or "",
            "enabled": o.enabled,
            "org_id": o.org_id,
            "ipam_space_id": str(o.ipam_space_id),
            "sync_interval_seconds": o.sync_interval_seconds,
            "last_synced_at": o.last_synced_at.isoformat() if o.last_synced_at else None,
            "last_sync_error": o.last_sync_error,
            "network_count": o.network_count,
            "object_count": o.object_count,
            "client_block_enforcement_armed": o.block_sync_enabled,
        }
        for o in rows
    ]


class ListFirewallFeedsArgs(BaseModel):
    limit: int = _common_target_args()["limit"]


@register_tool(
    name="list_firewall_feeds",
    permission=("read", "firewall_feed"),
    module="security.firewall_feeds",
    description=(
        "List SpatiumDDI-hosted firewall block-list feeds (#606). A feed-polling "
        "firewall (FortiGate External Threat Feed, Cisco Security Intelligence) "
        "subscribes to a feed's token-scoped URL to enforce the block set with no "
        "write credentials held by SpatiumDDI. Each row carries id, name, "
        "description, enabled, kind, poll_count, and last_polled_at/ip so you can "
        "confirm a firewall is actually consuming the feed. Feed tokens never "
        "appear."
    ),
    args_model=ListFirewallFeedsArgs,
    category="read",
    default_enabled=True,
)
async def list_firewall_feeds(
    db: AsyncSession, user: User, args: ListFirewallFeedsArgs
) -> list[dict[str, Any]]:
    stmt = select(FirewallFeed).order_by(FirewallFeed.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(f.id),
            "name": f.name,
            "description": f.description or "",
            "enabled": f.enabled,
            "kind": f.kind,
            "poll_count": f.poll_count or 0,
            "last_polled_at": f.last_polled_at.isoformat() if f.last_polled_at else None,
            "last_polled_ip": str(f.last_polled_ip) if f.last_polled_ip else None,
        }
        for f in rows
    ]
