"""Tests for the Proxmox reconciler.

Stub ``ProxmoxClient`` so we don't need a real PVE. Validates
bridge → subnet creation, smart parent-block detection, RFC 1918
supernet auto-create, VM/LXC NIC mirroring with runtime + static
fallback, mirror-toggle behaviour, and cascade-delete on endpoint
removal.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.proxmox import ProxmoxNode
from app.services.proxmox.client import (
    _ProxmoxClusterInfo,
    _ProxmoxGuest,
    _ProxmoxNetworkIface,
    _ProxmoxNicDef,
    _ProxmoxNodeInfo,
    _ProxmoxSDNSubnet,
    _ProxmoxSDNVnet,
    _ProxmoxVersion,
)
from app.services.proxmox.reconcile import reconcile_node

# ── Fixtures ─────────────────────────────────────────────────────────


async def _make_space(db: AsyncSession) -> IPSpace:
    space = IPSpace(name=f"proxmox-test-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    return space


async def _make_block(db: AsyncSession, space: IPSpace, network: str) -> IPBlock:
    block = IPBlock(
        space_id=space.id,
        network=network,
        name=f"blk-{uuid.uuid4().hex[:6]}",
    )
    db.add(block)
    await db.flush()
    return block


async def _make_node(
    db: AsyncSession,
    space: IPSpace,
    *,
    mirror_vms: bool = True,
    mirror_lxc: bool = True,
    include_stopped: bool = False,
    infer_vnet_subnets: bool = False,
) -> ProxmoxNode:
    node = ProxmoxNode(
        name=f"pve-{uuid.uuid4().hex[:6]}",
        host="pve.example.test",
        port=8006,
        verify_tls=False,
        token_id="root@pam!spatiumddi",
        token_secret_encrypted=b"",  # reconciler guards on empty decrypt
        ipam_space_id=space.id,
        mirror_vms=mirror_vms,
        mirror_lxc=mirror_lxc,
        include_stopped=include_stopped,
        infer_vnet_subnets=infer_vnet_subnets,
    )
    db.add(node)
    await db.flush()
    return node


class _FakeClient:
    def __init__(
        self,
        *,
        version: _ProxmoxVersion | None = None,
        cluster: _ProxmoxClusterInfo | None = None,
        nodes: list[_ProxmoxNodeInfo] | None = None,
        networks: dict[str, list[_ProxmoxNetworkIface]] | None = None,
        qemu: dict[str, list[_ProxmoxGuest]] | None = None,
        lxc: dict[str, list[_ProxmoxGuest]] | None = None,
        sdn_subnets: list[_ProxmoxSDNSubnet] | None = None,
        sdn_vnets: list[_ProxmoxSDNVnet] | None = None,
        unreadable_guests: list[str] | None = None,
    ) -> None:
        self.version = version or _ProxmoxVersion(version="9.1.9", release="9.1", repoid="xyz")
        self.cluster = cluster or _ProxmoxClusterInfo(cluster_name=None, node_count=1, quorate=None)
        self.nodes = nodes or [_ProxmoxNodeInfo(node="pve01", status="online")]
        self.networks = networks or {}
        self.qemu = qemu or {}
        self.lxc = lxc or {}
        self.sdn_subnets = sdn_subnets or []
        self.sdn_vnets = sdn_vnets or []
        # #1559 — mirrors ProxmoxClient.unreadable_guests.
        self.unreadable_guests = unreadable_guests or []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get_version(self):
        return self.version

    async def get_cluster_info(self):
        return self.cluster

    async def list_nodes(self):
        return self.nodes

    async def list_networks(self, node: str):
        return self.networks.get(node, [])

    async def list_sdn_subnets(self):
        return self.sdn_subnets

    async def list_sdn_vnets(self):
        return self.sdn_vnets

    async def list_qemu(self, node: str, *, include_stopped: bool):
        del include_stopped
        return self.qemu.get(node, [])

    async def list_lxc(self, node: str, *, include_stopped: bool):
        del include_stopped
        return self.lxc.get(node, [])


def _patch_client(fake: _FakeClient):
    def _ctor(**_kwargs):
        return fake

    return patch(
        "app.services.proxmox.reconcile.ProxmoxClient",
        side_effect=_ctor,
    )


# ── Tests ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bridge_with_cidr_creates_subnet_and_host_placeholder(
    db_session: AsyncSession,
) -> None:
    """Plain Linux bridge: subnet is created with NO gateway (the
    bridge IP is the host's own LAN address, not the network gateway
    — which lives upstream on a router). The bridge IP lands as a
    ``reserved`` row labelled with the PVE node name, not a phantom
    "gateway" entry."""
    space = await _make_space(db_session)
    node = await _make_node(db_session, space)
    await db_session.commit()

    fake = _FakeClient(
        networks={
            "pve01": [
                _ProxmoxNetworkIface(
                    node="pve01",
                    iface="vmbr0",
                    iface_type="bridge",
                    cidr="10.0.0.94/24",
                    active=True,
                )
            ]
        }
    )
    with _patch_client(fake):
        summary = await reconcile_node(db_session, node)

    assert summary.ok, summary.error
    assert summary.subnets_created == 1

    sub = (
        await db_session.execute(select(Subnet).where(Subnet.proxmox_node_id == node.id))
    ).scalar_one()
    assert str(sub.network) == "10.0.0.0/24"
    assert sub.gateway is None  # bridges don't imply a gateway
    assert sub.kubernetes_semantics is False

    # Host placeholder — the PVE node's own bridge IP, marked reserved
    # with the PVE node name as hostname.
    host = (
        await db_session.execute(
            select(IPAddress).where(
                IPAddress.proxmox_node_id == node.id, IPAddress.status == "reserved"
            )
        )
    ).scalar_one()
    assert str(host.address) == "10.0.0.94"
    assert host.hostname == "pve01"


@pytest.mark.asyncio
async def test_bridge_does_not_clobber_operator_gateway(
    db_session: AsyncSession,
) -> None:
    """If the operator manually sets the correct upstream gateway on
    a Proxmox-mirrored subnet, subsequent reconciles must NOT clear
    it back to None just because the bridge doesn't declare one."""
    space = await _make_space(db_session)
    node = await _make_node(db_session, space)
    await db_session.commit()

    network = [
        _ProxmoxNetworkIface(
            node="pve01",
            iface="vmbr0",
            iface_type="bridge",
            cidr="10.0.0.94/24",
            active=True,
        )
    ]
    # First sync: subnet created with gateway=None.
    with _patch_client(_FakeClient(networks={"pve01": network})):
        await reconcile_node(db_session, node)
    sub = (
        await db_session.execute(select(Subnet).where(Subnet.proxmox_node_id == node.id))
    ).scalar_one()
    assert sub.gateway is None

    # Operator sets the real upstream gateway in IPAM.
    sub.gateway = "10.0.0.1"
    await db_session.commit()

    # Second sync — no SDN data, just bridges. Operator's gateway must persist.
    with _patch_client(_FakeClient(networks={"pve01": network})):
        await reconcile_node(db_session, node)
    await db_session.refresh(sub)
    assert str(sub.gateway) == "10.0.0.1"


@pytest.mark.asyncio
async def test_sdn_vnet_subnets_create_subnets_without_host_bridge_ip(
    db_session: AsyncSession,
) -> None:
    """The whole point of SDN support: mirror VNet subnets even when
    the PVE host doesn't carry an IP on the backing bridge — the
    typical split-responsibility setup where a physical router is the
    gateway and PVE is pure L2 for the VLAN.
    """
    space = await _make_space(db_session)
    node = await _make_node(db_session, space)
    await db_session.commit()

    fake = _FakeClient(
        # PVE host has vmbr0 with the management IP only; no bridge
        # advertises 10.20.30.0/24 or 10.40.50.0/24.
        networks={
            "pve01": [
                _ProxmoxNetworkIface(
                    node="pve01",
                    iface="vmbr0",
                    iface_type="bridge",
                    cidr="192.168.0.10/24",
                    active=True,
                )
            ]
        },
        sdn_subnets=[
            _ProxmoxSDNSubnet(
                vnet="lab",
                zone="localnetwork",
                cidr="10.20.30.0/24",
                gateway="10.20.30.1",
                snat=False,
                alias="Lab network",
            ),
            _ProxmoxSDNSubnet(
                vnet="dmz",
                zone="evpn1",
                cidr="10.40.50.0/24",
                gateway=None,
                snat=True,
                alias=None,
            ),
        ],
    )
    with _patch_client(fake):
        summary = await reconcile_node(db_session, node)

    assert summary.ok, summary.error
    rows = (
        (await db_session.execute(select(Subnet).where(Subnet.proxmox_node_id == node.id)))
        .scalars()
        .all()
    )
    nets = {str(s.network) for s in rows}
    assert nets == {"10.20.30.0/24", "10.40.50.0/24", "192.168.0.0/24"}

    lab = next(s for s in rows if str(s.network) == "10.20.30.0/24")
    assert lab.name == "vnet:lab"
    assert str(lab.gateway) == "10.20.30.1"


@pytest.mark.asyncio
async def test_sdn_subnet_overrides_bridge_for_same_cidr(
    db_session: AsyncSession,
) -> None:
    """When the same CIDR shows up as both a bridge and an SDN VNet
    subnet, the SDN row wins — it carries the operator's intent (vnet
    label, human alias).
    """
    space = await _make_space(db_session)
    node = await _make_node(db_session, space)
    await db_session.commit()

    fake = _FakeClient(
        networks={
            "pve01": [
                _ProxmoxNetworkIface(
                    node="pve01",
                    iface="vmbr0",
                    iface_type="bridge",
                    cidr="10.0.0.1/24",
                    active=True,
                )
            ]
        },
        sdn_subnets=[
            _ProxmoxSDNSubnet(
                vnet="main",
                zone="localnetwork",
                cidr="10.0.0.0/24",
                gateway="10.0.0.1",
                snat=False,
                alias=None,
            )
        ],
    )
    with _patch_client(fake):
        summary = await reconcile_node(db_session, node)

    assert summary.ok, summary.error
    sub = (
        await db_session.execute(select(Subnet).where(Subnet.proxmox_node_id == node.id))
    ).scalar_one()
    assert sub.name == "vnet:main"


@pytest.mark.asyncio
async def test_bridge_without_cidr_is_skipped(db_session: AsyncSession) -> None:
    """L2-only bridges (no IP on the host) are the common case for VM
    bridges — skipping them keeps IPAM free of empty "subnets"."""
    space = await _make_space(db_session)
    node = await _make_node(db_session, space)
    await db_session.commit()

    fake = _FakeClient(
        networks={
            "pve01": [
                _ProxmoxNetworkIface(
                    node="pve01", iface="vmbr1", iface_type="bridge", cidr=None, active=True
                )
            ]
        }
    )
    with _patch_client(fake):
        summary = await reconcile_node(db_session, node)

    assert summary.ok
    assert summary.subnets_created == 0


@pytest.mark.asyncio
async def test_enclosing_operator_block_skips_wrapper(
    db_session: AsyncSession,
) -> None:
    space = await _make_space(db_session)
    parent = await _make_block(db_session, space, "10.0.0.0/8")
    node = await _make_node(db_session, space)
    await db_session.commit()

    fake = _FakeClient(
        networks={
            "pve01": [
                _ProxmoxNetworkIface(
                    node="pve01",
                    iface="vmbr0",
                    iface_type="bridge",
                    cidr="10.0.0.1/24",
                    active=True,
                )
            ]
        }
    )
    with _patch_client(fake):
        summary = await reconcile_node(db_session, node)

    assert summary.ok
    assert summary.blocks_created == 0

    sub = (
        await db_session.execute(select(Subnet).where(Subnet.proxmox_node_id == node.id))
    ).scalar_one()
    assert sub.block_id == parent.id


@pytest.mark.asyncio
async def test_rfc1918_supernet_auto_created(db_session: AsyncSession) -> None:
    space = await _make_space(db_session)
    node = await _make_node(db_session, space)
    await db_session.commit()

    fake = _FakeClient(
        networks={
            "pve01": [
                _ProxmoxNetworkIface(
                    node="pve01",
                    iface="vmbr0",
                    iface_type="bridge",
                    cidr="192.168.1.1/24",
                    active=True,
                )
            ]
        }
    )
    with _patch_client(fake):
        summary = await reconcile_node(db_session, node)

    assert summary.ok, summary.error
    # A 192.168.0.0/16 parent block exists and is unowned.
    parent = (
        await db_session.execute(
            select(IPBlock).where(IPBlock.space_id == space.id, IPBlock.network == "192.168.0.0/16")
        )
    ).scalar_one()
    assert parent.proxmox_node_id is None


@pytest.mark.asyncio
async def test_match_by_cidr_reuses_operator_subnet(
    db_session: AsyncSession,
) -> None:
    """Issue #177: a pre-existing operator subnet at the exact CIDR
    that Proxmox would otherwise auto-create must be reused — not
    duplicated. The operator's name / description / block linkage are
    preserved, ownership stays NULL, and addresses still mirror into
    the reused subnet.
    """
    space = await _make_space(db_session)
    parent = await _make_block(db_session, space, "10.0.0.0/8")
    node = await _make_node(db_session, space)
    # Operator pre-creates 10.1.40.0/24 with their own naming.
    operator_sub = Subnet(
        space_id=space.id,
        block_id=parent.id,
        network="10.1.40.0/24",
        name="lab-vlan40",
        description="manually curated",
        gateway="10.1.40.1",
        total_ips=254,
    )
    db_session.add(operator_sub)
    await db_session.commit()

    # Proxmox advertises VLAN40 as an SDN VNet at the same CIDR; PVE's
    # host has a vmbr0 on 192.168.0.0/24 that's unrelated.
    vm = _ProxmoxGuest(
        node="pve01",
        vmid=100,
        name="vm-100",
        kind="qemu",
        status="running",
        agent_enabled=True,
        nics=[
            _ProxmoxNicDef(
                slot="net0",
                mac="BC:24:11:E8:4A:3F",
                bridge="VLAN40",
                vlan_tag=None,
                static_cidr=None,
            )
        ],
        runtime_ips_by_mac={"bc:24:11:e8:4a:3f": ["10.1.40.50"]},
    )
    fake = _FakeClient(
        networks={
            "pve01": [
                _ProxmoxNetworkIface(
                    node="pve01",
                    iface="vmbr0",
                    iface_type="bridge",
                    cidr="192.168.0.10/24",
                    active=True,
                )
            ]
        },
        sdn_subnets=[
            _ProxmoxSDNSubnet(
                vnet="VLAN40",
                zone="dc1",
                cidr="10.1.40.0/24",
                gateway="10.1.40.1",
                snat=False,
                alias=None,
            )
        ],
        qemu={"pve01": [vm]},
    )
    with _patch_client(fake):
        summary = await reconcile_node(db_session, node)

    assert summary.ok, summary.error
    assert summary.subnets_matched == 1

    # Exactly one subnet at 10.1.40.0/24 — no duplicate.
    rows = (
        (
            await db_session.execute(
                select(Subnet).where(Subnet.space_id == space.id, Subnet.network == "10.1.40.0/24")
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    only = rows[0]
    # Operator's row untouched: ownership stays NULL, name + description
    # + gateway + block linkage preserved.
    assert only.id == operator_sub.id
    assert only.proxmox_node_id is None
    assert only.name == "lab-vlan40"
    assert only.description == "manually curated"
    assert str(only.gateway) == "10.1.40.1"
    assert only.block_id == parent.id

    # The VM's IP still lands in the reused subnet.
    ip = (
        await db_session.execute(
            select(IPAddress).where(
                IPAddress.proxmox_node_id == node.id,
                IPAddress.status == "proxmox-vm",
            )
        )
    ).scalar_one()
    assert str(ip.address) == "10.1.40.50"
    assert ip.subnet_id == operator_sub.id


@pytest.mark.asyncio
async def test_match_by_cidr_is_idempotent(
    db_session: AsyncSession,
) -> None:
    """Two consecutive reconciles against an operator subnet match
    must report ``subnets_matched=1`` each time and never create the
    duplicate row, even though the first pass left the operator
    subnet unowned (so the node-owned query still returns nothing
    on pass two).
    """
    space = await _make_space(db_session)
    parent = await _make_block(db_session, space, "10.0.0.0/8")
    node = await _make_node(db_session, space)
    operator_sub = Subnet(
        space_id=space.id,
        block_id=parent.id,
        network="10.1.40.0/24",
        name="lab-vlan40",
        total_ips=254,
    )
    db_session.add(operator_sub)
    await db_session.commit()

    fake = _FakeClient(
        sdn_subnets=[
            _ProxmoxSDNSubnet(
                vnet="VLAN40",
                zone="dc1",
                cidr="10.1.40.0/24",
                gateway=None,
                snat=False,
                alias=None,
            )
        ],
    )
    with _patch_client(fake):
        first = await reconcile_node(db_session, node)
    with _patch_client(fake):
        second = await reconcile_node(db_session, node)

    assert first.ok and second.ok
    assert first.subnets_matched == 1
    assert second.subnets_matched == 1
    assert first.subnets_created == 0
    assert second.subnets_created == 0

    rows = (
        (
            await db_session.execute(
                select(Subnet).where(Subnet.space_id == space.id, Subnet.network == "10.1.40.0/24")
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_match_by_cidr_skips_foreign_integration_subnet(
    db_session: AsyncSession,
) -> None:
    """A subnet owned by a different integration (e.g. Kubernetes
    pod CIDR) at the desired CIDR must NOT be duplicated. A warning
    surfaces in ``summary.warnings`` so the operator can resolve the
    overlap deliberately.
    """
    from app.models.kubernetes import KubernetesCluster  # noqa: PLC0415

    space = await _make_space(db_session)
    block = await _make_block(db_session, space, "10.0.0.0/8")
    node = await _make_node(db_session, space)
    # Stand up a fake k8s cluster + a pod-CIDR subnet at 10.1.40.0/24.
    cluster = KubernetesCluster(
        name="k8s-test",
        api_server_url="https://k8s.example.test",
        ipam_space_id=space.id,
        token_encrypted=b"",
    )
    db_session.add(cluster)
    await db_session.flush()
    foreign_sub = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.1.40.0/24",
        name="pod-cidr",
        total_ips=254,
        kubernetes_cluster_id=cluster.id,
        kubernetes_semantics=True,
    )
    db_session.add(foreign_sub)
    await db_session.commit()

    fake = _FakeClient(
        sdn_subnets=[
            _ProxmoxSDNSubnet(
                vnet="VLAN40",
                zone="dc1",
                cidr="10.1.40.0/24",
                gateway=None,
                snat=False,
                alias=None,
            )
        ],
    )
    with _patch_client(fake):
        summary = await reconcile_node(db_session, node)

    assert summary.ok
    assert summary.subnets_created == 0
    assert summary.subnets_matched == 0
    assert any("another integration" in w for w in summary.warnings)

    # Exactly one subnet at the CIDR — the original foreign one.
    rows = (
        (
            await db_session.execute(
                select(Subnet).where(Subnet.space_id == space.id, Subnet.network == "10.1.40.0/24")
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].kubernetes_cluster_id == cluster.id


@pytest.mark.asyncio
async def test_vm_nic_with_runtime_ip_creates_proxmox_vm_row(
    db_session: AsyncSession,
) -> None:
    space = await _make_space(db_session)
    node = await _make_node(db_session, space)
    await db_session.commit()

    vm = _ProxmoxGuest(
        node="pve01",
        vmid=100,
        name="db01",
        kind="qemu",
        status="running",
        agent_enabled=True,
        nics=[
            _ProxmoxNicDef(
                slot="net0",
                mac="BC:24:11:E8:4A:3F",
                bridge="vmbr0",
                vlan_tag=None,
                static_cidr=None,
            )
        ],
        runtime_ips_by_mac={"bc:24:11:e8:4a:3f": ["10.0.0.50"]},
    )
    fake = _FakeClient(
        networks={
            "pve01": [
                _ProxmoxNetworkIface(
                    node="pve01",
                    iface="vmbr0",
                    iface_type="bridge",
                    cidr="10.0.0.1/24",
                    active=True,
                )
            ]
        },
        qemu={"pve01": [vm]},
    )
    with _patch_client(fake):
        summary = await reconcile_node(db_session, node)

    assert summary.ok, summary.error
    assert summary.vm_count == 1

    ip = (
        await db_session.execute(
            select(IPAddress).where(
                IPAddress.proxmox_node_id == node.id,
                IPAddress.status == "proxmox-vm",
            )
        )
    ).scalar_one()
    assert str(ip.address) == "10.0.0.50"
    assert ip.hostname == "db01"
    assert (ip.mac_address or "").lower() == "bc:24:11:e8:4a:3f"


@pytest.mark.asyncio
async def test_vm_falls_back_to_static_cidr_when_agent_unavailable(
    db_session: AsyncSession,
) -> None:
    """If the guest-agent isn't running / installed, runtime_ips_by_mac
    stays empty and the reconciler should fall back to the static_cidr
    from ``ipconfigN``.
    """
    space = await _make_space(db_session)
    node = await _make_node(db_session, space)
    await db_session.commit()

    vm = _ProxmoxGuest(
        node="pve01",
        vmid=101,
        name="app01",
        kind="qemu",
        status="running",
        agent_enabled=False,
        nics=[
            _ProxmoxNicDef(
                slot="net0",
                mac="AA:BB:CC:DD:EE:FF",
                bridge="vmbr0",
                vlan_tag=None,
                static_cidr="10.0.0.77/24",
            )
        ],
    )
    fake = _FakeClient(
        networks={
            "pve01": [
                _ProxmoxNetworkIface(
                    node="pve01",
                    iface="vmbr0",
                    iface_type="bridge",
                    cidr="10.0.0.1/24",
                    active=True,
                )
            ]
        },
        qemu={"pve01": [vm]},
    )
    with _patch_client(fake):
        summary = await reconcile_node(db_session, node)

    assert summary.ok
    ip = (
        await db_session.execute(
            select(IPAddress).where(
                IPAddress.proxmox_node_id == node.id,
                IPAddress.status == "proxmox-vm",
            )
        )
    ).scalar_one()
    assert str(ip.address) == "10.0.0.77"


@pytest.mark.asyncio
async def test_lxc_nic_lands_as_proxmox_lxc(db_session: AsyncSession) -> None:
    space = await _make_space(db_session)
    node = await _make_node(db_session, space)
    await db_session.commit()

    ct = _ProxmoxGuest(
        node="pve01",
        vmid=200,
        name="web-ct",
        kind="lxc",
        status="running",
        agent_enabled=False,
        nics=[
            _ProxmoxNicDef(
                slot="net0",
                mac="DE:AD:BE:EF:00:01",
                bridge="vmbr0",
                vlan_tag=None,
                static_cidr="10.0.0.150/24",
            )
        ],
        runtime_ips_by_mac={"de:ad:be:ef:00:01": ["10.0.0.150"]},
    )
    fake = _FakeClient(
        networks={
            "pve01": [
                _ProxmoxNetworkIface(
                    node="pve01",
                    iface="vmbr0",
                    iface_type="bridge",
                    cidr="10.0.0.1/24",
                    active=True,
                )
            ]
        },
        lxc={"pve01": [ct]},
    )
    with _patch_client(fake):
        summary = await reconcile_node(db_session, node)

    assert summary.ok
    assert summary.lxc_count == 1
    ip = (
        await db_session.execute(
            select(IPAddress).where(
                IPAddress.proxmox_node_id == node.id,
                IPAddress.status == "proxmox-lxc",
            )
        )
    ).scalar_one()
    assert str(ip.address) == "10.0.0.150"
    assert ip.hostname == "web-ct"


@pytest.mark.asyncio
async def test_mirror_vms_off_skips_vms(db_session: AsyncSession) -> None:
    space = await _make_space(db_session)
    node = await _make_node(db_session, space, mirror_vms=False)
    await db_session.commit()

    vm = _ProxmoxGuest(
        node="pve01",
        vmid=100,
        name="db01",
        kind="qemu",
        status="running",
        agent_enabled=True,
        nics=[
            _ProxmoxNicDef(
                slot="net0",
                mac="BC:24:11:E8:4A:3F",
                bridge="vmbr0",
                vlan_tag=None,
                static_cidr=None,
            )
        ],
        runtime_ips_by_mac={"bc:24:11:e8:4a:3f": ["10.0.0.50"]},
    )
    fake = _FakeClient(
        networks={
            "pve01": [
                _ProxmoxNetworkIface(
                    node="pve01",
                    iface="vmbr0",
                    iface_type="bridge",
                    cidr="10.0.0.1/24",
                    active=True,
                )
            ]
        },
        qemu={"pve01": [vm]},
    )
    with _patch_client(fake):
        summary = await reconcile_node(db_session, node)

    assert summary.ok
    assert summary.vm_count == 0
    # Only the gateway row exists — no proxmox-vm rows at all.
    rows = (
        (
            await db_session.execute(
                select(IPAddress).where(
                    IPAddress.proxmox_node_id == node.id,
                    IPAddress.status == "proxmox-vm",
                )
            )
        )
        .scalars()
        .all()
    )
    assert list(rows) == []


@pytest.mark.asyncio
async def test_removed_vm_deletes_its_address(db_session: AsyncSession) -> None:
    """A VM that disappears between reconciles should have its mirrored
    IPAddress row removed — drift-correct."""
    space = await _make_space(db_session)
    node = await _make_node(db_session, space)
    await db_session.commit()

    # First pass: one VM exists.
    net = [
        _ProxmoxNetworkIface(
            node="pve01",
            iface="vmbr0",
            iface_type="bridge",
            cidr="10.0.0.1/24",
            active=True,
        )
    ]
    vm = _ProxmoxGuest(
        node="pve01",
        vmid=100,
        name="db01",
        kind="qemu",
        status="running",
        agent_enabled=True,
        nics=[
            _ProxmoxNicDef(
                slot="net0",
                mac="BC:24:11:E8:4A:3F",
                bridge="vmbr0",
                vlan_tag=None,
                static_cidr=None,
            )
        ],
        runtime_ips_by_mac={"bc:24:11:e8:4a:3f": ["10.0.0.50"]},
    )
    with _patch_client(_FakeClient(networks={"pve01": net}, qemu={"pve01": [vm]})):
        await reconcile_node(db_session, node)

    # Second pass: VM is gone.
    with _patch_client(_FakeClient(networks={"pve01": net}, qemu={"pve01": []})):
        summary = await reconcile_node(db_session, node)

    assert summary.ok
    assert summary.addresses_deleted >= 1
    rows = (
        (
            await db_session.execute(
                select(IPAddress).where(
                    IPAddress.proxmox_node_id == node.id,
                    IPAddress.status == "proxmox-vm",
                )
            )
        )
        .scalars()
        .all()
    )
    assert list(rows) == []


@pytest.mark.asyncio
async def test_unreadable_guest_config_keeps_its_address(db_session: AsyncSession) -> None:
    """#1559 — a guest whose config fetch fails once is unreadable, not
    gone: the address absence-delete must not remove its rows."""
    space = await _make_space(db_session)
    node = await _make_node(db_session, space)
    await db_session.commit()

    net = [
        _ProxmoxNetworkIface(
            node="pve01",
            iface="vmbr0",
            iface_type="bridge",
            cidr="10.0.0.1/24",
            active=True,
        )
    ]
    vm = _ProxmoxGuest(
        node="pve01",
        vmid=100,
        name="db01",
        kind="qemu",
        status="running",
        agent_enabled=True,
        nics=[
            _ProxmoxNicDef(
                slot="net0",
                mac="BC:24:11:E8:4A:3F",
                bridge="vmbr0",
                vlan_tag=None,
                static_cidr=None,
            )
        ],
        runtime_ips_by_mac={"bc:24:11:e8:4a:3f": ["10.0.0.50"]},
    )
    with _patch_client(_FakeClient(networks={"pve01": net}, qemu={"pve01": [vm]})):
        await reconcile_node(db_session, node)

    # Second pass: the guest's config fetch failed — it is absent from
    # the guest list but reported unreadable by the client.
    with _patch_client(
        _FakeClient(
            networks={"pve01": net},
            qemu={"pve01": []},
            unreadable_guests=["pve01/qemu/100"],
        )
    ):
        summary = await reconcile_node(db_session, node)

    assert summary.ok, summary.error
    assert summary.unreadable_guests == 1
    assert summary.addresses_deleted == 0
    assert any("absence-delete skipped" in w for w in summary.warnings)
    rows = (
        (
            await db_session.execute(
                select(IPAddress).where(
                    IPAddress.proxmox_node_id == node.id,
                    IPAddress.status == "proxmox-vm",
                )
            )
        )
        .scalars()
        .all()
    )
    assert [str(r.address) for r in rows] == ["10.0.0.50"]


@pytest.mark.asyncio
async def test_offline_node_with_include_stopped_keeps_guest_addresses(
    db_session: AsyncSession,
) -> None:
    """#1559 — with include_stopped armed, a not-online node's guests
    are part of the desired set; skipping the node must freeze the
    mirror for it, not delete its rows (subnet pass included)."""
    space = await _make_space(db_session)
    node = await _make_node(db_session, space, include_stopped=True)
    await db_session.commit()

    net = [
        _ProxmoxNetworkIface(
            node="pve01",
            iface="vmbr0",
            iface_type="bridge",
            cidr="10.0.0.1/24",
            active=True,
        )
    ]
    vm = _ProxmoxGuest(
        node="pve01",
        vmid=100,
        name="db01",
        kind="qemu",
        status="running",
        agent_enabled=True,
        nics=[
            _ProxmoxNicDef(
                slot="net0",
                mac="BC:24:11:E8:4A:3F",
                bridge="vmbr0",
                vlan_tag=None,
                static_cidr=None,
            )
        ],
        runtime_ips_by_mac={"bc:24:11:e8:4a:3f": ["10.0.0.50"]},
    )
    with _patch_client(_FakeClient(networks={"pve01": net}, qemu={"pve01": [vm]})):
        await reconcile_node(db_session, node)

    # Second pass: the node reports not-online.
    with _patch_client(
        _FakeClient(
            nodes=[_ProxmoxNodeInfo(node="pve01", status="offline")],
            networks={"pve01": net},
            qemu={"pve01": [vm]},
        )
    ):
        summary = await reconcile_node(db_session, node)

    assert summary.ok, summary.error
    assert summary.unreadable_nodes == 1
    assert summary.addresses_deleted == 0
    assert summary.subnets_deleted == 0
    rows = (
        (
            await db_session.execute(
                select(IPAddress).where(
                    IPAddress.proxmox_node_id == node.id,
                    IPAddress.status == "proxmox-vm",
                )
            )
        )
        .scalars()
        .all()
    )
    assert [str(r.address) for r in rows] == ["10.0.0.50"]


@pytest.mark.asyncio
async def test_node_delete_cascades(db_session: AsyncSession) -> None:
    space = await _make_space(db_session)
    node = await _make_node(db_session, space)
    await db_session.commit()

    vm = _ProxmoxGuest(
        node="pve01",
        vmid=100,
        name="db01",
        kind="qemu",
        status="running",
        agent_enabled=True,
        nics=[
            _ProxmoxNicDef(
                slot="net0",
                mac="BC:24:11:E8:4A:3F",
                bridge="vmbr0",
                vlan_tag=None,
                static_cidr=None,
            )
        ],
        runtime_ips_by_mac={"bc:24:11:e8:4a:3f": ["10.0.0.50"]},
    )
    fake = _FakeClient(
        networks={
            "pve01": [
                _ProxmoxNetworkIface(
                    node="pve01",
                    iface="vmbr0",
                    iface_type="bridge",
                    cidr="10.0.0.1/24",
                    active=True,
                )
            ]
        },
        qemu={"pve01": [vm]},
    )
    with _patch_client(fake):
        await reconcile_node(db_session, node)

    node_id = node.id
    await db_session.delete(node)
    await db_session.commit()

    # Every FK'd row is gone. The auto-created RFC 1918 supernet is
    # unowned → survives. Subnet is FK'd to the node → cascades.
    subs = (
        (await db_session.execute(select(Subnet).where(Subnet.proxmox_node_id == node_id)))
        .scalars()
        .all()
    )
    assert list(subs) == []
    addrs = (
        (await db_session.execute(select(IPAddress).where(IPAddress.proxmox_node_id == node_id)))
        .scalars()
        .all()
    )
    assert list(addrs) == []


# ── VNet subnet inference ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_infer_vnet_off_means_no_inference(db_session: AsyncSession) -> None:
    """Toggle defaults off — even with perfect signal we don't invent
    a subnet from guest NICs."""
    space = await _make_space(db_session)
    node = await _make_node(db_session, space)  # infer_vnet_subnets=False
    await db_session.commit()

    vm = _ProxmoxGuest(
        node="pve01",
        vmid=100,
        name="lab-01",
        kind="qemu",
        status="running",
        agent_enabled=True,
        nics=[
            _ProxmoxNicDef(
                slot="net0",
                mac="BC:24:11:E8:4A:3F",
                bridge="VLAN10",
                vlan_tag=None,
                static_cidr="10.10.10.5/24",
                static_gateway="10.10.10.1",
            )
        ],
    )
    fake = _FakeClient(
        qemu={"pve01": [vm]},
        sdn_vnets=[_ProxmoxSDNVnet(vnet="VLAN10", zone="home", alias="Lab", tag=10)],
    )
    with _patch_client(fake):
        summary = await reconcile_node(db_session, node)

    assert summary.ok
    rows = (
        (await db_session.execute(select(Subnet).where(Subnet.proxmox_node_id == node.id)))
        .scalars()
        .all()
    )
    assert list(rows) == []  # no inference → no subnet


@pytest.mark.asyncio
async def test_infer_vnet_static_cidr_creates_subnet(db_session: AsyncSession) -> None:
    """Exact path: a VM NIC on VLAN10 carries a static_cidr — we
    peel off the network portion and stamp a subnet for the VNet."""
    space = await _make_space(db_session)
    node = await _make_node(db_session, space, infer_vnet_subnets=True)
    await db_session.commit()

    vm = _ProxmoxGuest(
        node="pve01",
        vmid=100,
        name="lab-01",
        kind="qemu",
        status="running",
        agent_enabled=True,
        nics=[
            _ProxmoxNicDef(
                slot="net0",
                mac="BC:24:11:E8:4A:3F",
                bridge="VLAN10",
                vlan_tag=None,
                static_cidr="10.10.10.5/24",
                static_gateway="10.10.10.1",
            )
        ],
    )
    fake = _FakeClient(
        qemu={"pve01": [vm]},
        sdn_vnets=[_ProxmoxSDNVnet(vnet="VLAN10", zone="home", alias="Lab", tag=10)],
    )
    with _patch_client(fake):
        summary = await reconcile_node(db_session, node)

    assert summary.ok, summary.error
    sub = (
        await db_session.execute(select(Subnet).where(Subnet.proxmox_node_id == node.id))
    ).scalar_one()
    assert str(sub.network) == "10.10.10.0/24"
    assert sub.name == "vnet:VLAN10"
    assert str(sub.gateway) == "10.10.10.1"


@pytest.mark.asyncio
async def test_infer_vnet_runtime_ip_guesses_slash_24(db_session: AsyncSession) -> None:
    """Speculative path: no static_cidr, just guest-agent IPs. We
    assume /24 around them. Gateway stays None because we can't
    trust any synthesised IP to be the actual router."""
    space = await _make_space(db_session)
    node = await _make_node(db_session, space, infer_vnet_subnets=True)
    await db_session.commit()

    vm = _ProxmoxGuest(
        node="pve01",
        vmid=200,
        name="ads-01",
        kind="qemu",
        status="running",
        agent_enabled=True,
        nics=[
            _ProxmoxNicDef(
                slot="net0",
                mac="BC:24:11:AA:AA:AA",
                bridge="VLAN30",
                vlan_tag=None,
                static_cidr=None,
            )
        ],
        runtime_ips_by_mac={"bc:24:11:aa:aa:aa": ["192.168.30.50"]},
    )
    fake = _FakeClient(
        qemu={"pve01": [vm]},
        sdn_vnets=[_ProxmoxSDNVnet(vnet="VLAN30", zone="home", alias="ads", tag=30)],
    )
    with _patch_client(fake):
        summary = await reconcile_node(db_session, node)

    assert summary.ok, summary.error
    sub = (
        await db_session.execute(select(Subnet).where(Subnet.proxmox_node_id == node.id))
    ).scalar_one()
    assert str(sub.network) == "192.168.30.0/24"
    assert sub.gateway is None
    assert sub.name == "vnet:VLAN30"

    # The guest's runtime IP also lands as a mirrored proxmox-vm row
    # inside the inferred subnet — the inference closes the loop.
    ip = (
        await db_session.execute(
            select(IPAddress).where(
                IPAddress.proxmox_node_id == node.id,
                IPAddress.status == "proxmox-vm",
            )
        )
    ).scalar_one()
    assert str(ip.address) == "192.168.30.50"


@pytest.mark.asyncio
async def test_infer_vnet_skipped_when_declared_subnet_exists(
    db_session: AsyncSession,
) -> None:
    """If PVE has a real declared SDN subnet, the declared row wins
    and inference doesn't run for that VNet."""
    space = await _make_space(db_session)
    node = await _make_node(db_session, space, infer_vnet_subnets=True)
    await db_session.commit()

    vm = _ProxmoxGuest(
        node="pve01",
        vmid=100,
        name="lab-01",
        kind="qemu",
        status="running",
        agent_enabled=True,
        nics=[
            _ProxmoxNicDef(
                slot="net0",
                mac="BC:24:11:E8:4A:3F",
                bridge="VLAN10",
                vlan_tag=None,
                # Guest lies and says /25, but the declared PVE subnet
                # says /24 — declared wins.
                static_cidr="10.10.10.5/25",
            )
        ],
    )
    fake = _FakeClient(
        qemu={"pve01": [vm]},
        sdn_vnets=[_ProxmoxSDNVnet(vnet="VLAN10", zone="home", alias="Lab", tag=10)],
        sdn_subnets=[
            _ProxmoxSDNSubnet(
                vnet="VLAN10",
                zone="home",
                cidr="10.10.10.0/24",
                gateway="10.10.10.1",
                snat=False,
                alias="Lab",
            )
        ],
    )
    with _patch_client(fake):
        summary = await reconcile_node(db_session, node)

    assert summary.ok, summary.error
    rows = (
        (await db_session.execute(select(Subnet).where(Subnet.proxmox_node_id == node.id)))
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert str(rows[0].network) == "10.10.10.0/24"  # declared, not /25


# ── User-edit lock + claim-on-existing ────────────────────────────────


@pytest.mark.asyncio
async def test_pre_existing_operator_row_is_claimed_with_lock(
    db_session: AsyncSession,
) -> None:
    """The user's specific scenario: operator created an IPAM row
    manually (e.g. ``db-prod`` at 10.0.0.50), THEN added Proxmox.
    PVE has a VM at the same IP. First reconcile must adopt the row
    (set proxmox_node_id) but preserve the operator's hostname /
    description."""
    space = await _make_space(db_session)
    node = await _make_node(db_session, space)
    await db_session.commit()

    # Pre-create the IPAM tree the operator would have built.
    block = IPBlock(space_id=space.id, network="10.0.0.0/24", name="lan")
    db_session.add(block)
    await db_session.flush()
    sub = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.0.0.0/24",
        name="lan",
        total_ips=254,
    )
    db_session.add(sub)
    await db_session.flush()
    operator_row = IPAddress(
        subnet_id=sub.id,
        address="10.0.0.50",
        status="allocated",
        hostname="db-prod",
        description="Production database — DO NOT TOUCH",
    )
    db_session.add(operator_row)
    await db_session.commit()

    # Now Proxmox reports the same IP under VM 100 named "vm-100".
    vm = _ProxmoxGuest(
        node="pve01",
        vmid=100,
        name="vm-100",
        kind="qemu",
        status="running",
        agent_enabled=True,
        nics=[
            _ProxmoxNicDef(
                slot="net0",
                mac="BC:24:11:E8:4A:3F",
                bridge="vmbr0",
                vlan_tag=None,
                static_cidr=None,
            )
        ],
        runtime_ips_by_mac={"bc:24:11:e8:4a:3f": ["10.0.0.50"]},
    )
    fake = _FakeClient(
        networks={
            "pve01": [
                _ProxmoxNetworkIface(
                    node="pve01",
                    iface="vmbr0",
                    iface_type="bridge",
                    cidr="10.0.0.1/24",
                    active=True,
                )
            ]
        },
        qemu={"pve01": [vm]},
    )
    with _patch_client(fake):
        summary = await reconcile_node(db_session, node)
    assert summary.ok, summary.error

    await db_session.refresh(operator_row)
    # Row was claimed by Proxmox …
    assert operator_row.proxmox_node_id == node.id
    # … but the operator's values were preserved.
    assert operator_row.hostname == "db-prod"
    assert operator_row.description == "Production database — DO NOT TOUCH"
    assert operator_row.status == "allocated"
    # And user_modified_at is now stamped, locking future reconciles.
    assert operator_row.user_modified_at is not None


@pytest.mark.asyncio
async def test_user_edit_blocks_reconciler_overwrite(
    db_session: AsyncSession,
) -> None:
    """Operator renames a Proxmox-mirrored row from ``vm-100`` to
    ``db-prod`` (stamping user_modified_at via the API path), then
    the reconciler runs again. The rename must stick."""
    space = await _make_space(db_session)
    node = await _make_node(db_session, space)
    await db_session.commit()

    vm = _ProxmoxGuest(
        node="pve01",
        vmid=100,
        name="vm-100",
        kind="qemu",
        status="running",
        agent_enabled=True,
        nics=[
            _ProxmoxNicDef(
                slot="net0",
                mac="BC:24:11:E8:4A:3F",
                bridge="vmbr0",
                vlan_tag=None,
                static_cidr=None,
            )
        ],
        runtime_ips_by_mac={"bc:24:11:e8:4a:3f": ["10.0.0.50"]},
    )
    network = [
        _ProxmoxNetworkIface(
            node="pve01",
            iface="vmbr0",
            iface_type="bridge",
            cidr="10.0.0.1/24",
            active=True,
        )
    ]
    # First sync — creates the row with PVE's name.
    with _patch_client(_FakeClient(networks={"pve01": network}, qemu={"pve01": [vm]})):
        await reconcile_node(db_session, node)
    row = (
        await db_session.execute(
            select(IPAddress).where(
                IPAddress.proxmox_node_id == node.id, IPAddress.status == "proxmox-vm"
            )
        )
    ).scalar_one()
    assert row.hostname == "vm-100"

    # Operator renames the row (simulating the API write path).
    from datetime import UTC as _UTC
    from datetime import datetime as _dt

    row.hostname = "db-prod"
    row.description = "Production DB — keep hands off"
    row.user_modified_at = _dt.now(_UTC)
    await db_session.commit()

    # Second sync — PVE still says "vm-100" but operator's edits hold.
    with _patch_client(_FakeClient(networks={"pve01": network}, qemu={"pve01": [vm]})):
        await reconcile_node(db_session, node)
    await db_session.refresh(row)
    assert row.hostname == "db-prod"
    assert row.description == "Production DB — keep hands off"


@pytest.mark.asyncio
async def test_locked_row_keeps_when_vm_disappears(
    db_session: AsyncSession,
) -> None:
    """If the operator has invested edits in a Proxmox-mirrored row
    and the underlying VM is later deleted from PVE, the row must
    NOT be deleted — the FK is released so it becomes a plain
    operator-managed row."""
    space = await _make_space(db_session)
    node = await _make_node(db_session, space)
    await db_session.commit()

    network = [
        _ProxmoxNetworkIface(
            node="pve01",
            iface="vmbr0",
            iface_type="bridge",
            cidr="10.0.0.1/24",
            active=True,
        )
    ]
    vm = _ProxmoxGuest(
        node="pve01",
        vmid=100,
        name="vm-100",
        kind="qemu",
        status="running",
        agent_enabled=True,
        nics=[
            _ProxmoxNicDef(
                slot="net0",
                mac="BC:24:11:E8:4A:3F",
                bridge="vmbr0",
                vlan_tag=None,
                static_cidr=None,
            )
        ],
        runtime_ips_by_mac={"bc:24:11:e8:4a:3f": ["10.0.0.50"]},
    )
    with _patch_client(_FakeClient(networks={"pve01": network}, qemu={"pve01": [vm]})):
        await reconcile_node(db_session, node)
    row = (
        await db_session.execute(
            select(IPAddress).where(
                IPAddress.proxmox_node_id == node.id, IPAddress.status == "proxmox-vm"
            )
        )
    ).scalar_one()

    # Operator edits the row.
    from datetime import UTC as _UTC
    from datetime import datetime as _dt

    row.hostname = "important-host"
    row.user_modified_at = _dt.now(_UTC)
    row_id = row.id
    await db_session.commit()

    # VM disappears from PVE.
    with _patch_client(_FakeClient(networks={"pve01": network}, qemu={"pve01": []})):
        await reconcile_node(db_session, node)

    survivor = await db_session.get(IPAddress, row_id)
    assert survivor is not None  # not deleted
    assert survivor.proxmox_node_id is None  # un-claimed
    assert survivor.hostname == "important-host"  # operator value preserved


@pytest.mark.asyncio
async def test_unlocked_row_deletes_when_vm_disappears(
    db_session: AsyncSession,
) -> None:
    """Sanity check the inverse — if the row has no operator edits,
    deleting the VM in PVE deletes the IPAM row as before."""
    space = await _make_space(db_session)
    node = await _make_node(db_session, space)
    await db_session.commit()

    network = [
        _ProxmoxNetworkIface(
            node="pve01",
            iface="vmbr0",
            iface_type="bridge",
            cidr="10.0.0.1/24",
            active=True,
        )
    ]
    vm = _ProxmoxGuest(
        node="pve01",
        vmid=100,
        name="vm-100",
        kind="qemu",
        status="running",
        agent_enabled=True,
        nics=[
            _ProxmoxNicDef(
                slot="net0",
                mac="BC:24:11:E8:4A:3F",
                bridge="vmbr0",
                vlan_tag=None,
                static_cidr=None,
            )
        ],
        runtime_ips_by_mac={"bc:24:11:e8:4a:3f": ["10.0.0.50"]},
    )
    with _patch_client(_FakeClient(networks={"pve01": network}, qemu={"pve01": [vm]})):
        await reconcile_node(db_session, node)

    with _patch_client(_FakeClient(networks={"pve01": network}, qemu={"pve01": []})):
        await reconcile_node(db_session, node)

    rows = (
        (await db_session.execute(select(IPAddress).where(IPAddress.status == "proxmox-vm")))
        .scalars()
        .all()
    )
    assert list(rows) == []


async def _make_lan_with_unifi_row(db: AsyncSession, space: IPSpace, address: str):
    """10.0.0.0/24 in ``space`` with a UniFi-owned row at ``address``."""
    from app.models.unifi import UnifiController  # noqa: PLC0415

    controller = UnifiController(name=f"unifi-{uuid.uuid4().hex[:6]}", ipam_space_id=space.id)
    db.add(controller)
    block = IPBlock(space_id=space.id, network="10.0.0.0/24", name="lan")
    db.add(block)
    await db.flush()
    sub = Subnet(
        space_id=space.id, block_id=block.id, network="10.0.0.0/24", name="lan", total_ips=254
    )
    db.add(sub)
    await db.flush()
    row = IPAddress(
        subnet_id=sub.id,
        address=address,
        status="unifi-client",
        hostname="desktop-1",
        unifi_controller_id=controller.id,
    )
    db.add(row)
    await db.flush()
    return sub, row


def _vm(vmid: int, mac: str, ip: str) -> _ProxmoxGuest:
    return _ProxmoxGuest(
        node="pve01",
        vmid=vmid,
        name=f"vm-{vmid}",
        kind="qemu",
        status="running",
        agent_enabled=True,
        nics=[
            _ProxmoxNicDef(slot="net0", mac=mac, bridge="vmbr0", vlan_tag=None, static_cidr=None)
        ],
        runtime_ips_by_mac={mac.lower(): [ip]},
    )


_LAN_BRIDGE = {
    "pve01": [
        _ProxmoxNetworkIface(
            node="pve01", iface="vmbr0", iface_type="bridge", cidr="10.0.0.1/24", active=True
        )
    ]
}


@pytest.mark.asyncio
async def test_address_owned_by_other_integration_is_not_inserted_again(
    db_session: AsyncSession,
) -> None:
    """A VM reports an address UniFi already mirrors. The reconciler
    warns and leaves the UniFi row alone; it must not insert a second
    row at the same (subnet, address) and fail the whole sweep on
    ``uq_ip_address_subnet_address``."""
    space = await _make_space(db_session)
    node = await _make_node(db_session, space)
    sub, unifi_row = await _make_lan_with_unifi_row(db_session, space, "10.0.0.50")
    await db_session.commit()

    fake = _FakeClient(
        networks=_LAN_BRIDGE,
        qemu={
            "pve01": [
                _vm(100, "BC:24:11:E8:4A:3F", "10.0.0.50"),
                _vm(101, "BC:24:11:E8:4A:40", "10.0.0.51"),
            ]
        },
    )
    with _patch_client(fake):
        summary = await reconcile_node(db_session, node)
    assert summary.ok, summary.error
    assert any("10.0.0.50 owned by another integration" in w for w in summary.warnings)

    await db_session.refresh(unifi_row)
    assert unifi_row.proxmox_node_id is None
    assert unifi_row.hostname == "desktop-1"
    rows = (
        (await db_session.execute(select(IPAddress).where(IPAddress.subnet_id == sub.id)))
        .scalars()
        .all()
    )
    by_addr = {str(r.address): r for r in rows}
    assert by_addr["10.0.0.50"].id == unifi_row.id
    # The rest of the sweep still landed.
    assert by_addr["10.0.0.51"].proxmox_node_id == node.id


@pytest.mark.asyncio
async def test_own_row_is_not_moved_onto_another_integrations_row(
    db_session: AsyncSession,
) -> None:
    """Our row for a VM sits in a subnet that no longer encloses it for
    this node, and the subnet that does already has a UniFi row at the
    address. The move would collide; the row stays put and the sweep
    still commits."""
    space = await _make_space(db_session)
    node = await _make_node(db_session, space)
    _sub, unifi_row = await _make_lan_with_unifi_row(db_session, space, "10.0.0.50")
    other_space = await _make_space(db_session)
    other_block = await _make_block(db_session, other_space, "10.0.0.0/24")
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
        address="10.0.0.50",
        status="proxmox-vm",
        hostname="vm-100",
        proxmox_node_id=node.id,
    )
    db_session.add(own_row)
    await db_session.commit()

    fake = _FakeClient(
        networks=_LAN_BRIDGE, qemu={"pve01": [_vm(100, "BC:24:11:E8:4A:3F", "10.0.0.50")]}
    )
    with _patch_client(fake):
        summary = await reconcile_node(db_session, node)
    assert summary.ok, summary.error
    assert any("not moving" in w for w in summary.warnings)

    await db_session.refresh(own_row)
    await db_session.refresh(unifi_row)
    assert own_row.subnet_id == old_sub.id
    assert unifi_row.proxmox_node_id is None
