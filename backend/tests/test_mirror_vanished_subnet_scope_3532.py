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
from app.models.ipam import Subnet
from app.services.docker.reconcile import reconcile_host
from tests.test_docker_reconcile import _engine, _make_host, _make_space, _patch_client

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
