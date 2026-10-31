"""spatiumddi#3200 — integration mirrors retract an address's DNS records before deleting it.

A reconciler's absence-delete, and a subnet delete that cascades to its
addresses, used to leave the live auto-generated A record behind: the FK went
NULL and the name kept being served with no owner. They now go through
``retract_address_dns``, the path an IPAM permanent delete uses (RFC 2136 delete
op per server, agent wake after commit).
"""

from __future__ import annotations

import asyncio
import pathlib
import re
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSRecordOp
from app.models.ipam import IPAddress, Subnet
from app.services.docker.client import _DockerContainer, _DockerNetwork
from app.services.docker.reconcile import reconcile_host
from app.services.integration_ownership import release_integration_rows
from tests.test_docker_reconcile import (
    _FakeClient,
    _make_block,
    _make_host,
    _make_space,
    _patch_client,
)
from tests.test_subnet_trash_retracts_dns_1906 import _dns

_NET = _DockerNetwork(
    id="net1",
    name="backend",
    driver="bridge",
    scope="local",
    subnets=[("172.31.0.0/24", "172.31.0.1")],
)
_WEB = _DockerContainer(
    id="c1",
    name="web",
    image="nginx",
    state="running",
    status="Up",
    ip_bindings=[("backend", "172.31.0.5")],
)


async def _mirrored(db: AsyncSession):  # type: ignore[no-untyped-def]
    """A Docker host mirroring one container whose address has an auto A record."""
    _grp, server, zone = await _dns(db)
    space = await _make_space(db)
    await _make_block(db, space, "172.16.0.0/12")
    host = await _make_host(db, space, mirror_containers=True)
    await db.commit()
    with _patch_client(_FakeClient(networks=[_NET], containers=[_WEB])):
        assert (await reconcile_host(db, host)).ok
    addr = (
        (await db.execute(select(IPAddress).where(IPAddress.docker_host_id == host.id)))
        .scalars()
        .all()
    )
    web = next(a for a in addr if str(a.address) == "172.31.0.5")
    rec = DNSRecord(
        zone_id=zone.id,
        name="web",
        fqdn=f"web.{zone.name}",
        record_type="A",
        value="172.31.0.5",
        auto_generated=True,
        ip_address_id=web.id,
    )
    db.add(rec)
    await db.commit()
    return server, zone, host, web, rec


async def _records(db: AsyncSession, zone_id: uuid.UUID) -> list[str]:
    rows = (
        await db.execute(
            select(DNSRecord.name)
            .where(DNSRecord.zone_id == zone_id)
            .execution_options(populate_existing=True)
        )
    ).scalars()
    return sorted(rows)


async def _delete_ops(db: AsyncSession, server) -> list[str]:  # type: ignore[no-untyped-def]
    rows = (
        (await db.execute(select(DNSRecordOp).where(DNSRecordOp.server_id == server.id)))
        .scalars()
        .all()
    )
    return [o.record["name"] for o in rows if o.op == "delete"]


@pytest.mark.asyncio
async def test_absence_delete_retracts_the_live_record(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    woken: list[str] = []

    async def _publish(*channels: str) -> None:
        woken.extend(channels)

    monkeypatch.setattr("app.core.agent_wake.publish_wake", _publish)
    server, zone, host, _web, rec = await _mirrored(db_session)
    assert await _records(db_session, zone.id) == ["web"]

    # The container is gone upstream: the reconciler absence-deletes its address.
    with _patch_client(_FakeClient(networks=[_NET], containers=[])):
        summary = await reconcile_host(db_session, host)
    assert summary.ok and summary.addresses_deleted == 1

    assert await _records(db_session, zone.id) == []
    assert await _delete_ops(db_session, server) == ["web"]
    await asyncio.sleep(0.1)
    assert len(woken) == 1 and woken[0].endswith(str(zone.group_id))


@pytest.mark.asyncio
async def test_subnet_delete_retracts_the_records_of_its_cascaded_addresses(
    db_session: AsyncSession,
) -> None:
    server, zone, host, _web, _rec = await _mirrored(db_session)
    # The whole network is gone upstream: the subnet (and the address with it) goes.
    with _patch_client(_FakeClient(networks=[], containers=[])):
        summary = await reconcile_host(db_session, host)
    assert summary.ok and summary.subnets_deleted == 1
    assert await _records(db_session, zone.id) == []
    assert await _delete_ops(db_session, server) == ["web"]


@pytest.mark.asyncio
async def test_target_delete_does_not_orphan_a_record(db_session: AsyncSession) -> None:
    """Deleting the target already keeps any address carrying a DNS record
    (live or trashed) un-claimed, so the cascade never nulls a record's owner.
    Pinned here so narrowing that test cannot reintroduce the orphan."""
    server, zone, host, web, rec = await _mirrored(db_session)
    zone_id, web_id, subnet_id = zone.id, web.id, web.subnet_id
    # A second mirrored address whose only record is trashed.
    other = IPAddress(
        subnet_id=subnet_id, address="172.31.0.9", status="allocated", docker_host_id=host.id
    )
    db_session.add(other)
    await db_session.flush()
    from datetime import UTC, datetime

    trashed = DNSRecord(
        zone_id=zone_id,
        name="gone",
        fqdn="gone.example.",
        record_type="A",
        value="172.31.0.9",
        auto_generated=True,
        ip_address_id=other.id,
        deleted_at=datetime.now(UTC),
    )
    db_session.add(trashed)
    await db_session.commit()
    host_id = host.id

    await release_integration_rows(
        db_session, own_fk="docker_host_id", target_id=host_id, target_name="d"
    )
    await db_session.delete(host)
    await db_session.commit()
    db_session.expire_all()

    survivors = (
        (
            await db_session.execute(
                select(DNSRecord)
                .where(DNSRecord.zone_id == zone_id, DNSRecord.auto_generated.is_(True))
                .execution_options(include_deleted=True)
            )
        )
        .scalars()
        .all()
    )
    for r in survivors:
        assert r.ip_address_id is not None, f"{r.name} left with no owner"
    assert await _records(db_session, zone_id) == ["web"]
    assert (await db_session.get(IPAddress, web_id)) is not None
    assert (await db_session.get(Subnet, subnet_id)) is not None


def test_every_reconciler_retracts_before_deleting_addresses() -> None:
    """Guard: a module that deletes mirrored addresses calls the shared helper."""
    root = pathlib.Path(__file__).resolve().parents[1] / "app" / "services"
    files = [*root.glob("*/reconcile.py"), root / "firewall_mirror.py"]
    assert len(files) >= 9
    for path in files:
        text = path.read_text()
        if re.search(r"summary\.(addresses|subnets)_deleted \+= 1", text):
            assert (
                "retract_address_dns(" in text
            ), f"{path.name} deletes addresses without retracting"
