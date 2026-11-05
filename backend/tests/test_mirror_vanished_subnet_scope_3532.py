"""#3532 — a mirrored subnet whose upstream network is gone must not take
an operator's DHCP scope with it.

``dhcp_scope.subnet_id`` is ON DELETE CASCADE, so a reconciler that
hard-deleted a vanished network's subnet also hard-deleted any scope on it
(pools and reservations too), live or in the Trash, with no audit row.
Every mirror now retires such a subnet through
``integration_ownership.retire_vanished_subnet``: un-claimed and kept when
it carries operator content, deleted otherwise, audited either way. Driven
here through the Docker reconciler, the path the issue reproduced.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.dhcp import DHCPPool, DHCPScope, DHCPServerGroup, DHCPStaticAssignment
from app.models.dns import DNSRecord
from app.models.docker import DockerHost
from app.models.ipam import IPAddress, IPBlock, Subnet
from app.services.docker.client import _DockerContainer, _DockerNetwork
from app.services.docker.reconcile import reconcile_host
from app.services.fortinet.client import _FortiInterface
from app.services.fortinet.reconcile import reconcile_firewall
from app.services.integration_ownership import release_outside_space
from app.services.kubernetes.reconcile import reconcile_cluster
from app.services.soft_delete import apply_soft_delete, collect_soft_delete_batch, restore_batch
from tests.test_docker_reconcile import (
    _engine,
    _FakeClient,
    _make_block,
    _make_host,
    _make_space,
    _patch_client,
)
from tests.test_fortinet_reconcile import _FakeClient as _FortiClient
from tests.test_fortinet_reconcile import _make_fw
from tests.test_fortinet_reconcile import _patch as _forti_patch
from tests.test_kubernetes_reconcile import _FakeClient as _K8sClient
from tests.test_kubernetes_reconcile import _make_cluster
from tests.test_kubernetes_reconcile import _patch_client as _k8s_patch
from tests.test_subnet_trash_retracts_dns_1906 import _dns

_INC = {"include_deleted": True}


async def _mirror(db: AsyncSession, cidrs: list[str]):
    space = await _make_space(db)
    host = await _make_host(db, space)
    await db.commit()
    nets = [(f"n{i}", cidr, cidr.rsplit(".", 1)[0] + ".1") for i, cidr in enumerate(cidrs)]
    with _patch_client(_engine(nets, [])):
        summary = await reconcile_host(db, host)
    assert summary.ok, summary.error
    subnets = {}
    for cidr in cidrs:
        [row] = (
            (
                await db.execute(
                    select(Subnet).where(Subnet.space_id == space.id, Subnet.network == cidr)
                )
            )
            .scalars()
            .all()
        )
        assert row.docker_host_id == host.id
        subnets[cidr] = row.id
    return space, host, subnets


async def _scope(db: AsyncSession, subnet_id: uuid.UUID, base: str, *, trashed: bool):
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    scope = DHCPScope(group_id=group.id, subnet_id=subnet_id, name="op", address_family="ipv4")
    db.add(scope)
    await db.flush()
    pool = DHCPPool(
        scope_id=scope.id, start_ip=f"{base}.100", end_ip=f"{base}.200", pool_type="dynamic"
    )
    static = DHCPStaticAssignment(
        scope_id=scope.id, ip_address=f"{base}.10", mac_address="aa:bb:cc:dd:ee:01"
    )
    db.add_all([pool, static])
    await db.flush()
    if trashed:
        now = datetime.now(UTC)
        for row in (scope, pool, static):
            row.deleted_at = now
    ids = (scope.id, pool.id, static.id)
    await db.commit()
    return ids


async def _exists(db: AsyncSession, model, row_id) -> bool:
    return (
        await db.scalar(select(model.id).where(model.id == row_id).execution_options(**_INC))
    ) is not None


async def _subnet_audit(db: AsyncSession, subnet_id) -> list[AuditLog]:
    res = await db.execute(
        select(AuditLog).where(
            AuditLog.resource_type == "subnet", AuditLog.resource_id == str(subnet_id)
        )
    )
    return list(res.scalars().all())


@pytest.mark.asyncio
@pytest.mark.parametrize("trashed", [False, True], ids=["live", "trashed"])
async def test_vanished_network_keeps_a_subnet_with_a_scope(
    db_session: AsyncSession, trashed: bool
) -> None:
    space, host, subnets = await _mirror(db_session, ["198.19.217.0/24"])
    sid = subnets["198.19.217.0/24"]
    scope_id, pool_id, static_id = await _scope(db_session, sid, "198.19.217", trashed=trashed)

    await db_session.refresh(host)
    with _patch_client(_engine([], [])):
        summary = await reconcile_host(db_session, host)
    assert summary.ok, summary.error
    assert summary.subnets_deleted == 0
    assert summary.subnets_updated == 1

    db_session.expire_all()
    row = await db_session.scalar(select(Subnet).where(Subnet.id == sid))
    assert row is not None, "the subnet was deleted with its DHCP scope"
    assert row.docker_host_id is None
    assert row.deleted_at is None
    for model, rid in (
        (DHCPScope, scope_id),
        (DHCPPool, pool_id),
        (DHCPStaticAssignment, static_id),
    ):
        assert await _exists(db_session, model, rid), model.__name__

    [audit] = await _subnet_audit(db_session, sid)
    assert audit.action == "update"
    assert audit.user_id is None
    assert audit.changed_fields == ["docker_host_id"]
    assert audit.new_value["outcome"] == "released"
    assert audit.new_value["reason"] == "source network gone"
    assert "dhcp_scope" in audit.new_value["kept_for"]
    assert any("198.19.217.0/24" in w for w in summary.warnings)

    # Idempotent (#9): the released subnet is no longer the host's, so the
    # next sync neither touches it nor audits it again.
    await db_session.refresh(host)
    with _patch_client(_engine([], [])):
        again = await reconcile_host(db_session, host)
    assert again.ok, again.error
    assert (again.subnets_updated, again.subnets_deleted) == (0, 0)
    db_session.expire_all()
    assert len(await _subnet_audit(db_session, sid)) == 1


@pytest.mark.asyncio
async def test_vanished_network_without_operator_state_is_still_deleted(
    db_session: AsyncSession,
) -> None:
    space, host, subnets = await _mirror(db_session, ["198.19.218.0/24"])
    sid = subnets["198.19.218.0/24"]

    await db_session.refresh(host)
    with _patch_client(_engine([], [])):
        summary = await reconcile_host(db_session, host)
    assert summary.ok, summary.error
    assert summary.subnets_deleted == 1
    assert summary.subnets_updated == 0

    db_session.expire_all()
    assert not await _exists(db_session, Subnet, sid)
    [audit] = await _subnet_audit(db_session, sid)
    assert audit.action == "delete"
    assert audit.old_value["integration"] == "docker"
    assert audit.old_value["network"] == "198.19.218.0/24"


@pytest.mark.asyncio
@pytest.mark.parametrize("trashed", [False, True], ids=["live", "trashed"])
async def test_firewall_mirror_keeps_a_vanished_interface_subnet_with_a_scope(
    db_session: AsyncSession, trashed: bool
) -> None:
    """The shared firewall engine (Palo Alto, Fortinet, Meraki), via FortiGate."""
    space = await _make_space(db_session)
    fw = await _make_fw(db_session, space, mirror_interfaces=True)
    await db_session.commit()
    ifaces = [
        _FortiInterface(name="port1", cidr="10.30.0.0/24", address="10.30.0.1", zone="lan"),
        _FortiInterface(name="port2", cidr="10.30.1.0/24", address="10.30.1.1", zone="lan"),
    ]
    with _forti_patch(_FortiClient(interfaces=ifaces)):
        summary = await reconcile_firewall(db_session, fw)
    assert summary.ok, summary.error
    sid = await db_session.scalar(select(Subnet.id).where(Subnet.network == "10.30.1.0/24"))
    scope_id, pool_id, static_id = await _scope(db_session, sid, "10.30.1", trashed=trashed)

    await db_session.refresh(fw)
    with _forti_patch(_FortiClient(interfaces=ifaces[:1])):
        summary = await reconcile_firewall(db_session, fw)
    assert summary.ok, summary.error
    assert summary.subnets_deleted == 0

    db_session.expire_all()
    row = await db_session.scalar(select(Subnet).where(Subnet.id == sid))
    assert row is not None, "the interface subnet was deleted with its DHCP scope"
    assert row.fortinet_firewall_id is None
    for model, rid in (
        (DHCPScope, scope_id),
        (DHCPPool, pool_id),
        (DHCPStaticAssignment, static_id),
    ):
        assert await _exists(db_session, model, rid), model.__name__
    [audit] = await _subnet_audit(db_session, sid)
    assert audit.new_value["integration"] == "fortinet"
    assert audit.new_value["outcome"] == "released"


@pytest.mark.asyncio
@pytest.mark.parametrize("trashed", [False, True], ids=["live", "trashed"])
async def test_kubernetes_keeps_a_dropped_cidr_subnet_with_a_scope(
    db_session: AsyncSession, trashed: bool
) -> None:
    space = await _make_space(db_session)
    cluster = await _make_cluster(db_session, space)
    await db_session.commit()
    with _k8s_patch(_K8sClient()):
        assert (await reconcile_cluster(db_session, cluster)).error is None
    sid = await db_session.scalar(select(Subnet.id).where(Subnet.network == "10.96.0.0/12"))
    scope_id, pool_id, static_id = await _scope(db_session, sid, "10.96.0", trashed=trashed)

    await db_session.refresh(cluster)
    cluster.service_cidr = ""
    await db_session.commit()
    with _k8s_patch(_K8sClient()):
        summary = await reconcile_cluster(db_session, cluster)
    assert summary.error is None, summary.error
    assert summary.subnets_deleted == 0

    db_session.expire_all()
    row = await db_session.scalar(select(Subnet).where(Subnet.id == sid))
    assert row is not None, "the service-CIDR subnet was deleted with its DHCP scope"
    assert row.kubernetes_cluster_id is None
    for model, rid in (
        (DHCPScope, scope_id),
        (DHCPPool, pool_id),
        (DHCPStaticAssignment, static_id),
    ):
        assert await _exists(db_session, model, rid), model.__name__
    [audit] = await _subnet_audit(db_session, sid)
    assert audit.new_value["integration"] == "kubernetes"


@pytest.mark.asyncio
async def test_release_outside_space_counts_a_trashed_scope(db_session: AsyncSession) -> None:
    """#2577's re-target release must see a scope in the Trash too: its
    ``exists()`` on ``dhcp_scope`` sits in the WHERE of a ``select(Subnet)``,
    which the global soft-delete filter does not scope to ``dhcp_scope``."""
    old = await _make_space(db_session)
    new = await _make_space(db_session)
    host = DockerHost(
        name=f"d-{uuid.uuid4().hex[:6]}",
        connection_type="tcp",
        endpoint="docker.example.test:2376",
        ipam_space_id=new.id,
        client_key_encrypted=b"",
    )
    db_session.add(host)
    await db_session.flush()
    block = IPBlock(space_id=old.id, network="10.31.0.0/16", name="b")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(
        space_id=old.id,
        block_id=block.id,
        network="10.31.1.0/24",
        name="s",
        docker_host_id=host.id,
    )
    db_session.add(subnet)
    await db_session.flush()
    sid = subnet.id
    scope_id, _pool_id, _static_id = await _scope(db_session, sid, "10.31.1", trashed=True)

    out = await release_outside_space(db_session, "docker_host_id", host.id, new.id)
    await db_session.commit()
    assert (out.subnets_deleted, out.subnets_unclaimed) == (0, 1)
    db_session.expire_all()
    assert await _exists(db_session, Subnet, sid)
    assert await _exists(db_session, DHCPScope, scope_id)


@pytest.mark.asyncio
async def test_retired_subnet_audit_does_not_take_the_chain_lock_before_a_zone_write(
    db_session: AsyncSession,
) -> None:
    """#3503: the vanished subnet's audit row must not be flushed (taking the
    audit-chain lock) before the same sync's address absence-delete bumps a
    zone serial. The conftest lock-order guard fails this test if it is."""
    net_a = _DockerNetwork(
        id="na",
        name="a",
        driver="bridge",
        scope="local",
        subnets=[("172.31.0.0/24", "172.31.0.1")],
    )
    net_b = _DockerNetwork(
        id="nb",
        name="b",
        driver="bridge",
        scope="local",
        subnets=[("172.31.1.0/24", "172.31.1.1")],
    )
    web = _DockerContainer(
        id="c1",
        name="web",
        image="nginx",
        state="running",
        status="Up",
        ip_bindings=[("a", "172.31.0.5")],
    )
    _grp, _server, zone = await _dns(db_session)
    space = await _make_space(db_session)
    await _make_block(db_session, space, "172.16.0.0/12")
    host = await _make_host(db_session, space, mirror_containers=True)
    await db_session.commit()
    with _patch_client(_FakeClient(networks=[net_a, net_b], containers=[web])):
        assert (await reconcile_host(db_session, host)).ok
    addr_id = await db_session.scalar(
        select(IPAddress.id).where(
            IPAddress.docker_host_id == host.id, IPAddress.address == "172.31.0.5"
        )
    )
    db_session.add(
        DNSRecord(
            zone_id=zone.id,
            name="web",
            fqdn=f"web.{zone.name}",
            record_type="A",
            value="172.31.0.5",
            auto_generated=True,
            ip_address_id=addr_id,
        )
    )
    await db_session.commit()

    # Network b vanishes (its subnet is retired and audited) and the container
    # on network a goes (its address is absence-deleted, its record retracted).
    await db_session.refresh(host)
    with _patch_client(_FakeClient(networks=[net_a], containers=[])):
        summary = await reconcile_host(db_session, host)
    assert summary.ok, summary.error
    assert (summary.subnets_deleted, summary.addresses_deleted) == (1, 1)
    db_session.expire_all()
    [audit] = await _subnet_audit(
        db_session,
        await db_session.scalar(
            select(AuditLog.resource_id).where(
                AuditLog.resource_type == "subnet", AuditLog.resource_display == "172.31.1.0/24"
            )
        ),
    )
    assert audit.action == "delete"


@pytest.mark.asyncio
async def test_release_outside_space_audit_does_not_take_the_chain_lock_before_a_zone_write(
    db_session: AsyncSession,
) -> None:
    """#3556: ``release_outside_space`` runs mid-sync. Its audit row must not
    be flushed (taking the audit-chain lock) before the same sync's address
    absence-delete bumps a zone serial. The conftest lock-order guard fails
    this test if it is."""
    net_a = _DockerNetwork(
        id="na",
        name="a",
        driver="bridge",
        scope="local",
        subnets=[("172.31.0.0/24", "172.31.0.1")],
    )
    web = _DockerContainer(
        id="c1",
        name="web",
        image="nginx",
        state="running",
        status="Up",
        ip_bindings=[("a", "172.31.0.5")],
    )
    _grp, _server, zone = await _dns(db_session)
    space = await _make_space(db_session)
    old = await _make_space(db_session)
    await _make_block(db_session, space, "172.16.0.0/12")
    host = await _make_host(db_session, space, mirror_containers=True)
    await db_session.commit()
    with _patch_client(_FakeClient(networks=[net_a], containers=[web])):
        assert (await reconcile_host(db_session, host)).ok
    addr_id = await db_session.scalar(
        select(IPAddress.id).where(
            IPAddress.docker_host_id == host.id, IPAddress.address == "172.31.0.5"
        )
    )
    db_session.add(
        DNSRecord(
            zone_id=zone.id,
            name="web",
            fqdn=f"web.{zone.name}",
            record_type="A",
            value="172.31.0.5",
            auto_generated=True,
            ip_address_id=addr_id,
        )
    )
    # A pure mirror subnet left behind in a space the host no longer targets.
    block = IPBlock(space_id=old.id, network="10.77.0.0/16", name="b")
    db_session.add(block)
    await db_session.flush()
    db_session.add(
        Subnet(
            space_id=old.id,
            block_id=block.id,
            network="10.77.1.0/24",
            name="stray",
            docker_host_id=host.id,
        )
    )
    await db_session.commit()

    # The container goes: its address is absence-deleted, its record retracted.
    await db_session.refresh(host)
    with _patch_client(_FakeClient(networks=[net_a], containers=[])):
        summary = await reconcile_host(db_session, host)
    assert summary.ok, summary.error
    assert summary.released.subnets_deleted == 1
    assert summary.addresses_deleted == 1
    db_session.expire_all()
    assert (
        await db_session.scalar(
            select(AuditLog.id).where(AuditLog.action == "integration.release_outside_space")
        )
        is not None
    )


async def _trashed_wrapper(db: AsyncSession, cidr: str):
    """A mirrored subnet trashed (as the Trash does it), then its network gone."""
    space, host, subnets = await _mirror(db, [cidr])
    sid = subnets[cidr]
    subnet = await db.get(Subnet, sid)
    wrapper_id = subnet.block_id
    wrapper = await db.get(IPBlock, wrapper_id)
    assert wrapper.docker_host_id == host.id
    batch = await collect_soft_delete_batch(db, subnet)
    await apply_soft_delete(db, batch, None)
    await db.commit()
    await db.refresh(host)
    with _patch_client(_engine([], [])):
        summary = await reconcile_host(db, host)
    return space.id, host, sid, wrapper_id, batch.batch_id, summary


async def _block_row(db: AsyncSession, block_id):
    return (
        await db.execute(
            select(IPBlock.id, IPBlock.docker_host_id)
            .where(IPBlock.id == block_id)
            .execution_options(**_INC)
        )
    ).one_or_none()


@pytest.mark.asyncio
async def test_wrapper_block_holding_only_a_trashed_subnet_is_kept_not_deleted(
    db_session: AsyncSession,
) -> None:
    """#3556: the wrapper-block pass saw no live subnet and deleted the block,
    which the trashed subnet's RESTRICT FK refused: every sync tick failed.
    The block is kept, still the host's, with nothing written."""
    _space_id, host, sid, wrapper_id, _b, summary = await _trashed_wrapper(
        db_session, "203.0.113.0/24"
    )
    assert summary.ok, summary.error
    assert summary.blocks_deleted == 0
    assert any("Trash" in w for w in summary.warnings)
    host_id = host.id
    db_session.expire_all()
    assert await _block_row(db_session, wrapper_id) == (wrapper_id, host_id)
    assert await _exists(db_session, Subnet, sid)

    # Idempotent: the next tick is clean too.
    await db_session.refresh(host)
    with _patch_client(_engine([], [])):
        assert (await reconcile_host(db_session, host)).ok
    assert await _block_row(db_session, wrapper_id) == (wrapper_id, host_id)


@pytest.mark.asyncio
async def test_kept_wrapper_is_reused_when_the_network_returns_and_goes_after_purge(
    db_session: AsyncSession,
) -> None:
    """#3556: a released (un-owned) wrapper would be mirrored into as an
    operator block when the network returned, and never be deleted again: an
    orphaned "Auto-created" block once the Trash entry was purged. Kept owned,
    it is the host's wrapper again, and goes once nothing is under it."""
    cidr = "203.0.113.0/24"
    space_id, host, sid, wrapper_id, _b, summary = await _trashed_wrapper(db_session, cidr)
    assert summary.ok, summary.error
    host_id = host.id

    # The network comes back: mirrored into the same wrapper, no second block.
    for _ in range(2):
        await db_session.refresh(host)
        with _patch_client(_engine([("n0", cidr, "203.0.113.1")], [])):
            back = await reconcile_host(db_session, host)
        assert back.ok, back.error
        assert back.blocks_created == 0
    db_session.expire_all()
    assert (
        await db_session.execute(
            select(IPBlock.id, IPBlock.docker_host_id).where(IPBlock.space_id == space_id)
        )
    ).all() == [(wrapper_id, host_id)]
    live = await db_session.scalar(
        select(Subnet.block_id).where(Subnet.space_id == space_id, Subnet.docker_host_id == host_id)
    )
    assert live == wrapper_id

    # It goes again, and the trashed subnet is purged: the wrapper goes with it.
    await db_session.refresh(host)
    with _patch_client(_engine([], [])):
        assert (await reconcile_host(db_session, host)).ok
    trashed = await db_session.scalar(
        select(Subnet).where(Subnet.id == sid).execution_options(**_INC)
    )
    await db_session.delete(trashed)
    await db_session.commit()
    await db_session.refresh(host)
    with _patch_client(_engine([], [])):
        gone = await reconcile_host(db_session, host)
    assert gone.ok, gone.error
    assert gone.blocks_deleted == 1
    assert await _block_row(db_session, wrapper_id) is None


@pytest.mark.asyncio
async def test_trashed_subnet_restores_into_the_kept_wrapper(db_session: AsyncSession) -> None:
    _space_id, host, sid, wrapper_id, batch_id, summary = await _trashed_wrapper(
        db_session, "203.0.113.0/24"
    )
    assert summary.ok, summary.error
    result = await restore_batch(db_session, batch_id)
    assert not result.conflicts
    await db_session.commit()
    db_session.expire_all()
    row = await db_session.scalar(select(Subnet).where(Subnet.id == sid))
    assert row is not None and row.block_id == wrapper_id


@pytest.mark.asyncio
@pytest.mark.parametrize("trashed", [False, True], ids=["live", "trashed"])
async def test_wrapper_with_a_child_block_is_not_deleted_into_it(
    db_session: AsyncSession, trashed: bool
) -> None:
    """``ip_block.parent_block_id`` is CASCADE: deleting the wrapper silently
    destroyed an operator's block under it (#3556, #3492)."""
    space, host, subnets = await _mirror(db_session, ["198.18.40.0/24"])
    sid = subnets["198.18.40.0/24"]
    subnet = await db_session.get(Subnet, sid)
    wrapper_id = subnet.block_id
    child = IPBlock(
        space_id=space.id,
        parent_block_id=wrapper_id,
        network="198.18.40.128/25",
        name="operator",
        deleted_at=datetime.now(UTC) if trashed else None,
    )
    db_session.add(child)
    await db_session.commit()
    child_id = child.id

    await db_session.refresh(host)
    with _patch_client(_engine([], [])):
        summary = await reconcile_host(db_session, host)
    assert summary.ok, summary.error
    assert summary.blocks_deleted == 0
    db_session.expire_all()
    assert await _exists(db_session, IPBlock, child_id)
    assert await _exists(db_session, IPBlock, wrapper_id)
