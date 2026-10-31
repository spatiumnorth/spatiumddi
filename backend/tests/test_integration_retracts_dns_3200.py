"""spatiumddi#3200 — integration mirrors retract an address's DNS records before deleting it.

A reconciler's absence-delete, and a subnet delete that cascades to its
addresses, used to leave the live auto-generated A record behind: the FK went
NULL and the name kept being served with no owner. They now go through
``retract_address_dns``, the path an IPAM permanent delete uses (RFC 2136 delete
op per server, agent wake after commit).
"""

from __future__ import annotations

import ast
import asyncio
import pathlib
import uuid
from typing import Any

import pytest
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSRecordOp, DNSZone
from app.models.ipam import IPAddress, Subnet
from app.services.dns.record_ops import retract_address_dns
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
from tests.test_subnet_trash_retracts_dns_1906 import _dns, _RecordingDriver

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


async def _mirrored(db: AsyncSession, driver: str = "bind9"):  # type: ignore[no-untyped-def]
    """A Docker host mirroring one container whose address has an auto A record."""
    _grp, server, zone = await _dns(db, driver=driver)
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


def _wakes(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    woken: list[str] = []

    async def _publish(*channels: str) -> None:
        woken.extend(channels)

    monkeypatch.setattr("app.core.agent_wake.publish_wake", _publish)
    return woken


@pytest.mark.asyncio
async def test_an_agentless_primary_gets_the_a_and_ptr_deletes(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same pipeline an IPAM delete uses: a Windows DNS primary is told
    directly (after commit), and the PTR in the reverse zone goes too."""
    rec_driver = _RecordingDriver()
    monkeypatch.setattr("app.services.dns.record_ops.get_driver", lambda _name: rec_driver)
    _server, zone, host, web, _rec = await _mirrored(db_session, driver="windows_dns")
    rev = DNSZone(
        group_id=zone.group_id,
        name="0.31.172.in-addr.arpa.",
        zone_type="primary",
        kind="reverse",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db_session.add(rev)
    await db_session.flush()
    db_session.add(
        DNSRecord(
            zone_id=rev.id,
            name="5",
            fqdn="5.0.31.172.in-addr.arpa.",
            record_type="PTR",
            value=f"web.{zone.name}",
            auto_generated=True,
            ip_address_id=web.id,
        )
    )
    await db_session.commit()
    rec_driver.changes.clear()

    with _patch_client(_FakeClient(networks=[_NET], containers=[])):
        assert (await reconcile_host(db_session, host)).addresses_deleted == 1

    assert sorted(rec_driver.changes) == [("delete", "5", "PTR"), ("delete", "web", "A")]
    assert await _records(db_session, zone.id) == []
    assert await _records(db_session, rev.id) == []


@pytest.mark.asyncio
async def test_the_wake_waits_for_the_root_commit(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not at a SAVEPOINT release (the ops are not visible yet), and never for
    a transaction that rolled back."""
    woken = _wakes(monkeypatch)
    _server, zone, _host, web, _rec = await _mirrored(db_session)
    web_id, group_id = web.id, zone.group_id

    # Rolled back: nothing is published, then or at the next commit.
    assert await retract_address_dns(db_session, [web_id]) == 1
    await db_session.rollback()
    await db_session.commit()
    await asyncio.sleep(0.1)
    assert woken == []

    async with db_session.begin_nested():
        assert await retract_address_dns(db_session, [web_id]) == 1
    await asyncio.sleep(0.1)
    assert woken == []  # the savepoint released; the root has not committed
    await db_session.commit()
    await asyncio.sleep(0.1)
    assert len(woken) == 1 and woken[0].endswith(str(group_id))


@pytest.mark.asyncio
async def test_an_absence_sweep_retracts_in_constant_queries(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One retraction per sweep, not one per address: dropping eight
    containers costs the same DNS queries as dropping one."""
    _wakes(monkeypatch)

    async def _sweep(n: int) -> int:
        _grp, _server, zone = await _dns(db_session)
        space = await _make_space(db_session)
        await _make_block(db_session, space, "172.16.0.0/12")
        host = await _make_host(db_session, space, mirror_containers=True)
        await db_session.commit()
        containers = [
            _DockerContainer(
                id=f"c{i}",
                name=f"web{i}",
                image="nginx",
                state="running",
                status="Up",
                ip_bindings=[("backend", f"172.31.0.{10 + i}")],
            )
            for i in range(n)
        ]
        with _patch_client(_FakeClient(networks=[_NET], containers=containers)):
            assert (await reconcile_host(db_session, host)).ok
        for a in (
            (await db_session.execute(select(IPAddress).where(IPAddress.docker_host_id == host.id)))
            .scalars()
            .all()
        ):
            if str(a.address) == "172.31.0.1":
                continue
            db_session.add(
                DNSRecord(
                    zone_id=zone.id,
                    name=f"h{a.address}".replace(".", "-"),
                    fqdn=f"h.{zone.name}",
                    record_type="A",
                    value=str(a.address),
                    auto_generated=True,
                    ip_address_id=a.id,
                )
            )
        await db_session.commit()

        seen: list[str] = []

        def _count(_c: Any, _cur: Any, statement: str, *_a: Any) -> None:
            if "dns_record" in statement:
                seen.append(statement)

        engine = db_session.bind.sync_engine  # type: ignore[union-attr]
        event.listen(engine, "before_cursor_execute", _count)
        try:
            with _patch_client(_FakeClient(networks=[_NET], containers=[])):
                summary = await reconcile_host(db_session, host)
        finally:
            event.remove(engine, "before_cursor_execute", _count)
        assert summary.addresses_deleted == n
        assert await _records(db_session, zone.id) == []
        await db_session.delete(host)
        await db_session.commit()
        return len(seen)

    assert await _sweep(1) == await _sweep(8)


_GUARDED = ("addresses_deleted", "subnets_deleted")


def _deletes_without_retracting(path: pathlib.Path) -> tuple[int, list[str]]:
    """Every function that counts an address or subnet delete must call
    ``retract_address_dns``. Returns (functions checked, offenders)."""
    checked, bad = 0, []
    for fn in ast.walk(ast.parse(path.read_text())):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        counts = any(
            isinstance(n, ast.AugAssign)
            and isinstance(n.target, ast.Attribute)
            and n.target.attr in _GUARDED
            for n in ast.walk(fn)
        )
        if not counts:
            continue
        checked += 1
        calls = any(
            isinstance(n, ast.Call)
            and getattr(n.func, "id", getattr(n.func, "attr", None)) == "retract_address_dns"
            for n in ast.walk(fn)
        )
        if not calls:
            bad.append(f"{path.name}:{fn.name}")
    return checked, bad


def test_every_reconciler_retracts_before_deleting_addresses() -> None:
    """Guard: each function of an integration mirror that deletes addresses or
    subnets (it bumps ``addresses_deleted`` / ``subnets_deleted``) calls the
    shared helper. Per function, so a second delete path in a module that
    already has one is still caught."""
    root = pathlib.Path(__file__).resolve().parents[1] / "app" / "services"
    files = [*root.glob("*/reconcile.py"), root / "firewall_mirror.py"]
    checked, bad = 0, []
    for path in files:
        n, offenders = _deletes_without_retracting(path)
        checked += n
        bad += offenders
    # An address delete path in each of the nine mirrors, a subnet one in
    # seven: a rename of the counters must not leave this guard checking
    # nothing.
    assert checked >= 16, checked
    assert bad == [], f"deletes addresses without retract_address_dns: {bad}"


def test_the_guard_catches_a_function_that_deletes_without_retracting(
    tmp_path: pathlib.Path,
) -> None:
    src = tmp_path / "reconcile.py"
    src.write_text(
        "async def ok(db, rows, summary):\n"
        "    await retract_address_dns(db, [r.id for r in rows])\n"
        "    summary.addresses_deleted += 1\n"
        "async def bad(db, row, summary):\n"
        "    await db.delete(row)\n"
        "    summary.subnets_deleted += 1\n"
    )
    assert _deletes_without_retracting(src) == (2, ["reconcile.py:bad"])
