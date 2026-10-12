"""Mirrors leave an address another integration owns to its owner (#1677).

Kubernetes, Docker, Tailscale, NetBird and Cloud each warned "owned by
another integration; not claiming" in their claim pass and then inserted
their own row at the same ``(subnet, address)`` anyway. The insert hit
``uq_ip_address_subnet_address`` and nothing from that target synced.
Proxmox had the same gap (#1622). Each test puts a UniFi row at one
address the mirror reports, next to a free one: the sync must succeed,
the UniFi row stays as it was, and the free address still lands.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_dict, encrypt_str
from app.models.cloud import CloudEndpoint
from app.models.docker import DockerHost
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.kubernetes import KubernetesCluster
from app.models.netbird import NetbirdInstance
from app.models.tailscale import TailscaleTenant
from app.models.unifi import UnifiController
from app.services.cloud import reconcile as cloud_reconcile
from app.services.cloud.base import (
    CloudInstance,
    CloudInventory,
    CloudNetwork,
    CloudNic,
    CloudSubnet,
)
from app.services.docker.client import _DockerContainer, _DockerNetwork
from app.services.docker.reconcile import reconcile_host
from app.services.kubernetes.client import _K8sNode
from app.services.kubernetes.reconcile import reconcile_cluster
from app.services.netbird.client import _NetbirdPeer
from app.services.netbird.reconcile import reconcile_instance
from app.services.tailscale.client import _TailscaleDevice
from app.services.tailscale.reconcile import reconcile_tenant

# ── Helpers ──────────────────────────────────────────────────────────


async def _make_space(db: AsyncSession) -> IPSpace:
    space = IPSpace(name=f"owned-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    return space


async def _unifi_row(db: AsyncSession, space: IPSpace, subnet_id: uuid.UUID, address: str):
    controller = UnifiController(name=f"unifi-{uuid.uuid4().hex[:6]}", ipam_space_id=space.id)
    db.add(controller)
    await db.flush()
    row = IPAddress(
        subnet_id=subnet_id,
        address=address,
        status="unifi-client",
        hostname="unifi-client-1",
        unifi_controller_id=controller.id,
    )
    db.add(row)
    await db.commit()
    return row


async def _rows_in(db: AsyncSession, subnet_id: uuid.UUID) -> dict[str, IPAddress]:
    rows = (
        (await db.execute(select(IPAddress).where(IPAddress.subnet_id == subnet_id)))
        .scalars()
        .all()
    )
    return {str(r.address): r for r in rows}


async def _assert_left_alone(db: AsyncSession, row: IPAddress) -> None:
    await db.refresh(row)
    assert row.hostname == "unifi-client-1"
    assert row.unifi_controller_id is not None


class _Ctx:
    """Async context manager stub that returns itself."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


# ── Kubernetes ───────────────────────────────────────────────────────


class _K8sClient(_Ctx):
    def __init__(self, nodes: list[_K8sNode]) -> None:
        self.nodes = nodes

    async def list_nodes(self):
        return self.nodes

    async def list_loadbalancer_services(self):
        return []

    async def list_services(self):
        return []

    async def list_pods(self):
        return []

    async def list_ingresses(self):
        return []


async def _k8s_setup(db: AsyncSession):
    space = await _make_space(db)
    block = IPBlock(space_id=space.id, network="10.0.0.0/24", name="lan")
    db.add(block)
    await db.flush()
    lan = Subnet(
        space_id=space.id, block_id=block.id, network="10.0.0.0/24", name="lan", total_ips=254
    )
    db.add(lan)
    cluster = KubernetesCluster(
        name=f"cluster-{uuid.uuid4().hex[:6]}",
        api_server_url="https://k8s.example.test:6443",
        ca_bundle_pem="",
        token_encrypted=encrypt_str("faketoken"),
        ipam_space_id=space.id,
        pod_cidr="",
        service_cidr="",
    )
    db.add(cluster)
    await db.flush()
    unifi_row = await _unifi_row(db, space, lan.id, "10.0.0.5")
    return space, lan, cluster, unifi_row


def _k8s_client(*nodes: tuple[str, str]):
    fake = _K8sClient([_K8sNode(name=n, internal_ip=ip, ready=True) for n, ip in nodes])
    return patch("app.services.kubernetes.reconcile.KubernetesClient", side_effect=lambda **_: fake)


@pytest.mark.asyncio
async def test_kubernetes_node_ip_owned_by_other_integration(db_session: AsyncSession) -> None:
    _space, lan, cluster, unifi_row = await _k8s_setup(db_session)

    with _k8s_client(("node-a", "10.0.0.5"), ("node-b", "10.0.0.6")):
        summary = await reconcile_cluster(db_session, cluster)

    assert summary.ok, summary.error
    assert any("10.0.0.5 owned by another integration" in w for w in summary.warnings)
    await _assert_left_alone(db_session, unifi_row)
    rows = await _rows_in(db_session, lan.id)
    assert rows["10.0.0.5"].id == unifi_row.id
    assert rows["10.0.0.6"].kubernetes_cluster_id == cluster.id


@pytest.mark.asyncio
async def test_kubernetes_row_not_moved_onto_other_integrations_row(
    db_session: AsyncSession,
) -> None:
    """Our node row sits in a subnet of another space; the cluster's own
    space has a UniFi row at that address. Moving it would collide, so
    the row stays put and the rest of the sync commits."""
    _space, lan, cluster, unifi_row = await _k8s_setup(db_session)
    other_space = await _make_space(db_session)
    other_block = IPBlock(space_id=other_space.id, network="10.0.0.0/24", name="old")
    db_session.add(other_block)
    await db_session.flush()
    old_sub = Subnet(
        space_id=other_space.id,
        block_id=other_block.id,
        network="10.0.0.0/24",
        name="old",
        total_ips=254,
    )
    db_session.add(old_sub)
    await db_session.flush()
    own_row = IPAddress(
        subnet_id=old_sub.id,
        address="10.0.0.5",
        status="kubernetes-node",
        hostname="node-a",
        kubernetes_cluster_id=cluster.id,
    )
    db_session.add(own_row)
    await db_session.commit()

    with _k8s_client(("node-a", "10.0.0.5"), ("node-b", "10.0.0.6")):
        summary = await reconcile_cluster(db_session, cluster)

    assert summary.ok, summary.error
    assert any("10.0.0.5" in w and "not moving" in w for w in summary.warnings)
    await db_session.refresh(own_row)
    assert own_row.subnet_id == old_sub.id
    await _assert_left_alone(db_session, unifi_row)
    rows = await _rows_in(db_session, lan.id)
    assert rows["10.0.0.6"].kubernetes_cluster_id == cluster.id


# ── Docker ───────────────────────────────────────────────────────────


class _DockerClient(_Ctx):
    def __init__(self, containers: list[_DockerContainer]) -> None:
        self.containers = containers

    async def list_networks(self):
        return [
            _DockerNetwork(
                id="net1",
                name="backend",
                driver="bridge",
                scope="local",
                subnets=[("172.20.0.0/16", "172.20.0.1")],
            )
        ]

    async def list_containers(self, *, include_stopped: bool):
        del include_stopped
        return self.containers


def _container(cid: str, ip: str) -> _DockerContainer:
    return _DockerContainer(
        id=cid,
        name=f"app-{cid}",
        image="nginx:latest",
        state="running",
        status="Up 1 hour",
        ip_bindings=[("backend", ip)],
    )


@pytest.mark.asyncio
async def test_docker_container_ip_owned_by_other_integration(db_session: AsyncSession) -> None:
    space = await _make_space(db_session)
    host = DockerHost(
        name=f"docker-{uuid.uuid4().hex[:6]}",
        connection_type="tcp",
        endpoint="docker.example.test:2376",
        ipam_space_id=space.id,
        mirror_containers=True,
        client_key_encrypted=b"",
    )
    db_session.add(host)
    await db_session.commit()

    # First pass creates the network's subnet.
    with patch(
        "app.services.docker.reconcile.DockerClient", side_effect=lambda **_: _DockerClient([])
    ):
        assert (await reconcile_host(db_session, host)).ok
    sub = (
        await db_session.execute(select(Subnet).where(Subnet.docker_host_id == host.id))
    ).scalar_one()
    unifi_row = await _unifi_row(db_session, space, sub.id, "172.20.0.5")

    fake = _DockerClient([_container("c1", "172.20.0.5"), _container("c2", "172.20.0.6")])
    with patch("app.services.docker.reconcile.DockerClient", side_effect=lambda **_: fake):
        summary = await reconcile_host(db_session, host)

    assert summary.ok, summary.error
    assert any("172.20.0.5 owned by another integration" in w for w in summary.warnings)
    await _assert_left_alone(db_session, unifi_row)
    rows = await _rows_in(db_session, sub.id)
    assert rows["172.20.0.5"].id == unifi_row.id
    assert rows["172.20.0.6"].docker_host_id == host.id


# ── Tailscale ────────────────────────────────────────────────────────


class _TailscaleClient(_Ctx):
    def __init__(self, devices: list[_TailscaleDevice]) -> None:
        self.devices = devices

    async def list_devices(self):
        return self.devices


def _ts_device(id_: str, ip: str) -> _TailscaleDevice:
    return _TailscaleDevice(
        id=id_,
        node_id=f"n{id_}",
        name=f"host{id_}.example.ts.net",
        hostname=f"host{id_}",
        addresses=[ip],
        os="linux",
        client_version="1.62.0",
        user="alice@example.com",
        tags=[],
        last_seen=None,
        expires=None,
        key_expiry_disabled=True,
        advertised_routes=[],
        enabled_routes=[],
    )


@pytest.mark.asyncio
async def test_tailscale_device_ip_owned_by_other_integration(db_session: AsyncSession) -> None:
    space = await _make_space(db_session)
    tenant = TailscaleTenant(
        name=f"ts-{uuid.uuid4().hex[:6]}",
        tailnet="-",
        api_key_encrypted=b"x",
        ipam_space_id=space.id,
    )
    db_session.add(tenant)
    await db_session.commit()

    def _run(devices: list[_TailscaleDevice]):
        fake = _TailscaleClient(devices)
        return (
            patch("app.services.tailscale.reconcile.TailscaleClient", side_effect=lambda **_: fake),
            patch("app.services.tailscale.reconcile.decrypt_str", return_value="tskey-api-fake"),
        )

    p1, p2 = _run([])
    with p1, p2:
        assert (await reconcile_tenant(db_session, tenant)).ok
    sub = (
        await db_session.execute(
            select(Subnet).where(
                Subnet.tailscale_tenant_id == tenant.id, Subnet.network == "100.64.0.0/10"
            )
        )
    ).scalar_one()
    unifi_row = await _unifi_row(db_session, space, sub.id, "100.64.0.5")

    p1, p2 = _run([_ts_device("1", "100.64.0.5"), _ts_device("2", "100.64.0.6")])
    with p1, p2:
        summary = await reconcile_tenant(db_session, tenant)

    assert summary.ok, summary.error
    assert any("100.64.0.5 owned by another integration" in w for w in summary.warnings)
    await _assert_left_alone(db_session, unifi_row)
    rows = await _rows_in(db_session, sub.id)
    assert rows["100.64.0.5"].id == unifi_row.id
    assert rows["100.64.0.6"].tailscale_tenant_id == tenant.id


# ── NetBird ──────────────────────────────────────────────────────────


class _NetbirdClient(_Ctx):
    def __init__(self, peers: list[_NetbirdPeer]) -> None:
        self.peers = peers

    async def list_peers(self):
        return self.peers


@pytest.mark.asyncio
async def test_netbird_peer_ip_owned_by_other_integration(db_session: AsyncSession) -> None:
    space = await _make_space(db_session)
    instance = NetbirdInstance(
        name=f"nb-{uuid.uuid4().hex[:6]}",
        api_key_encrypted=b"x",
        ipam_space_id=space.id,
    )
    db_session.add(instance)
    await db_session.commit()

    def _run(peers: list[_NetbirdPeer]):
        fake = _NetbirdClient(peers)
        return (
            patch("app.services.netbird.reconcile.NetbirdClient", side_effect=lambda **_: fake),
            patch("app.services.netbird.reconcile.decrypt_str", return_value="nbp_fake"),
        )

    p1, p2 = _run([])
    with p1, p2:
        assert (await reconcile_instance(db_session, instance)).ok
    sub = (
        await db_session.execute(select(Subnet).where(Subnet.netbird_instance_id == instance.id))
    ).scalar_one()
    unifi_row = await _unifi_row(db_session, space, sub.id, "100.64.0.5")

    p1, p2 = _run(
        [
            _NetbirdPeer(id="p1", name="peer-1", ip="100.64.0.5"),
            _NetbirdPeer(id="p2", name="peer-2", ip="100.64.0.6"),
        ]
    )
    with p1, p2:
        summary = await reconcile_instance(db_session, instance)

    assert summary.ok, summary.error
    assert any("100.64.0.5 owned by another integration" in w for w in summary.warnings)
    await _assert_left_alone(db_session, unifi_row)
    rows = await _rows_in(db_session, sub.id)
    assert rows["100.64.0.5"].id == unifi_row.id
    assert rows["100.64.0.6"].netbird_instance_id == instance.id


# ── Cloud ────────────────────────────────────────────────────────────


class _CloudConnector:
    def __init__(self, ips: list[str]) -> None:
        self.ips = ips

    async def fetch_inventory(self, **_kwargs):
        return CloudInventory(
            account_id="123456789012",
            networks=[
                CloudNetwork(id="vpc-1", name="vpc", cidrs=("10.1.0.0/16",), region="us-east-1")
            ],
            subnets=[
                CloudSubnet(
                    id="subnet-a",
                    name="app-a",
                    network_id="vpc-1",
                    cidr="10.1.1.0/24",
                    region="us-east-1",
                )
            ],
            instances=[
                CloudInstance(
                    id=f"i-{n}",
                    name=f"vm-{n}",
                    running=True,
                    region="us-east-1",
                    nics=(CloudNic(private_ip=ip),),
                )
                for n, ip in enumerate(self.ips)
            ],
        )


@pytest.mark.asyncio
async def test_cloud_instance_ip_owned_by_other_integration(db_session: AsyncSession) -> None:
    space = await _make_space(db_session)
    endpoint = CloudEndpoint(
        name=f"cloud-{uuid.uuid4().hex[:6]}",
        provider="aws",
        credentials_encrypted=encrypt_dict({"access_key_id": "AKIA", "secret_access_key": "s"}),
        provider_config={},
        regions=["us-east-1"],
        ipam_space_id=space.id,
    )
    db_session.add(endpoint)
    await db_session.commit()

    def _run(ips: list[str]):
        fake = _CloudConnector(ips)
        return patch.object(cloud_reconcile, "get_connector", side_effect=lambda *_a, **_k: fake)

    with _run([]):
        assert (await cloud_reconcile.reconcile_endpoint(db_session, endpoint)).ok
    sub = (
        await db_session.execute(select(Subnet).where(Subnet.cloud_endpoint_id == endpoint.id))
    ).scalar_one()
    unifi_row = await _unifi_row(db_session, space, sub.id, "10.1.1.5")

    with _run(["10.1.1.5", "10.1.1.6"]):
        summary = await cloud_reconcile.reconcile_endpoint(db_session, endpoint)

    assert summary.ok, summary.error
    assert any("10.1.1.5 owned by another integration" in w for w in summary.warnings)
    await _assert_left_alone(db_session, unifi_row)
    rows = await _rows_in(db_session, sub.id)
    assert rows["10.1.1.5"].id == unifi_row.id
    assert rows["10.1.1.6"].cloud_endpoint_id == endpoint.id
