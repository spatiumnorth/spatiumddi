"""#3596 — an unchanged upstream must not rewrite mirrored subnets.

``Subnet.gateway`` is an INET column and loads as an ``ipaddress`` object,
while the integrations hold the gateway as a string, so a bare ``!=`` was
always true: every sync rewrote (moving ``modified_at``) and counted every
gateway-carrying subnet as updated.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPSpace, Subnet
from app.services.docker.client import _DockerNetwork
from app.services.docker.reconcile import reconcile_host
from app.services.fortinet.client import _FortiInterface
from app.services.fortinet.reconcile import reconcile_firewall
from app.services.integration_ownership import gateway_changed
from tests.test_docker_reconcile import _FakeClient as _DockerFake
from tests.test_docker_reconcile import _make_host as _make_docker_host
from tests.test_docker_reconcile import _patch_client as _patch_docker
from tests.test_fortinet_reconcile import _FakeClient as _FortiFake
from tests.test_fortinet_reconcile import _make_fw
from tests.test_fortinet_reconcile import _patch as _patch_forti

_OLD = datetime(2020, 1, 1, tzinfo=UTC)


async def _space(db: AsyncSession) -> IPSpace:
    space = IPSpace(name=f"noop-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    return space


async def _pin_old(db: AsyncSession, fk_attr: str, owner_id: uuid.UUID) -> None:
    await db.execute(
        update(Subnet).where(getattr(Subnet, fk_attr) == owner_id).values(modified_at=_OLD)
    )
    await db.commit()


async def _subnet(db: AsyncSession, fk_attr: str, owner_id: uuid.UUID) -> Subnet:
    return (
        await db.execute(
            select(Subnet)
            .where(getattr(Subnet, fk_attr) == owner_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


def _net(gw: str) -> _DockerFake:
    return _DockerFake(
        networks=[
            _DockerNetwork(
                id="n1",
                name="backend",
                driver="bridge",
                scope="local",
                subnets=[("172.20.0.0/16", gw)],
            )
        ]
    )


@pytest.mark.asyncio
async def test_docker_unchanged_second_sync_is_a_noop(db_session: AsyncSession) -> None:
    space = await _space(db_session)
    host = await _make_docker_host(db_session, space)
    await db_session.commit()
    with _patch_docker(_net("172.20.0.1")):
        first = await reconcile_host(db_session, host)
    assert first.ok and first.subnets_created == 1
    await db_session.commit()
    await _pin_old(db_session, "docker_host_id", host.id)

    with _patch_docker(_net("172.20.0.1")):
        second = await reconcile_host(db_session, host)
    assert second.ok, second.error
    assert second.subnets_updated == 0
    await db_session.commit()
    sub = await _subnet(db_session, "docker_host_id", host.id)
    assert sub.modified_at == _OLD


@pytest.mark.asyncio
async def test_docker_gateway_change_still_updates(db_session: AsyncSession) -> None:
    space = await _space(db_session)
    host = await _make_docker_host(db_session, space)
    await db_session.commit()
    with _patch_docker(_net("172.20.0.1")):
        await reconcile_host(db_session, host)
    await db_session.commit()
    await _pin_old(db_session, "docker_host_id", host.id)

    with _patch_docker(_net("172.20.0.254")):
        second = await reconcile_host(db_session, host)
    assert second.subnets_updated == 1
    await db_session.commit()
    sub = await _subnet(db_session, "docker_host_id", host.id)
    assert str(sub.gateway) == "172.20.0.254"
    assert sub.modified_at > _OLD + timedelta(days=1)


def _forti(addr: str) -> _FortiFake:
    return _FortiFake(
        interfaces=[_FortiInterface(name="port1", cidr="10.0.0.0/24", address=addr, zone="lan")]
    )


@pytest.mark.asyncio
async def test_fortinet_unchanged_second_sync_is_a_noop(db_session: AsyncSession) -> None:
    space = await _space(db_session)
    fw = await _make_fw(db_session, space, mirror_interfaces=True)
    await db_session.commit()
    with _patch_forti(_forti("10.0.0.1")):
        first = await reconcile_firewall(db_session, fw)
    assert first.ok and first.subnets_created == 1
    await db_session.commit()
    await _pin_old(db_session, "fortinet_firewall_id", fw.id)

    with _patch_forti(_forti("10.0.0.1")):
        second = await reconcile_firewall(db_session, fw)
    assert second.ok, second.error
    assert second.subnets_updated == 0
    await db_session.commit()
    sub = await _subnet(db_session, "fortinet_firewall_id", fw.id)
    assert sub.modified_at == _OLD


@pytest.mark.asyncio
async def test_fortinet_gateway_change_still_updates(db_session: AsyncSession) -> None:
    space = await _space(db_session)
    fw = await _make_fw(db_session, space, mirror_interfaces=True)
    await db_session.commit()
    with _patch_forti(_forti("10.0.0.1")):
        await reconcile_firewall(db_session, fw)
    await db_session.commit()
    await _pin_old(db_session, "fortinet_firewall_id", fw.id)

    with _patch_forti(_forti("10.0.0.2")):
        second = await reconcile_firewall(db_session, fw)
    assert second.subnets_updated == 1
    await db_session.commit()
    sub = await _subnet(db_session, "fortinet_firewall_id", fw.id)
    assert str(sub.gateway) == "10.0.0.2"
    assert sub.modified_at > _OLD + timedelta(days=1)


def test_gateway_changed_compares_addresses_not_spellings() -> None:
    import ipaddress

    assert not gateway_changed(ipaddress.ip_address("10.0.0.1"), "10.0.0.1")
    assert not gateway_changed("10.0.0.1", "10.0.0.1")
    assert gateway_changed(ipaddress.ip_address("10.0.0.1"), "10.0.0.2")
    assert gateway_changed(None, "10.0.0.2")
    assert not gateway_changed(ipaddress.ip_address("10.0.0.1"), None)
    assert not gateway_changed(ipaddress.ip_address("2001:db8::1"), "2001:0db8:0:0:0:0:0:1")
