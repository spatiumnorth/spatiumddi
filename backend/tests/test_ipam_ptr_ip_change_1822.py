"""Changing an address's IP inside one reverse zone retracts the old PTR (#1822).

``_sync_dns_record`` rewrote the PTR row in place and queued one ``update`` at
the NEW name. An ``update`` replaces the RRset at its own name, so the old PTR
stayed served: until the next structural render on an agent engine, forever on
an agentless driver. A rename is a ``delete`` of the old name followed by a
``create`` of the new one (#1773 does the same for the record PUT); a
value-only change stays one ``update``.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns.base import RecordChangeResult
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.dns import record_ops

FWD = "z1822.example."
REV = "2.0.192.in-addr.arpa."
REV3 = "3.0.192.in-addr.arpa."


def _zone(grp: DNSServerGroup, name: str, kind: str) -> DNSZone:
    return DNSZone(
        group_id=grp.id,
        name=name,
        zone_type="primary",
        kind=kind,
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )


async def _setup(db: AsyncSession, driver: str = "technitium", network: str = "192.0.2.0/24"):
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver=driver,
        host="10.0.0.1",
        name="ns1",
        is_primary=True,
        is_enabled=True,
        agent_id=uuid.uuid4() if driver == "technitium" else None,
    )
    fwd, rev, rev3 = (
        _zone(grp, FWD, "forward"),
        _zone(grp, REV, "reverse"),
        _zone(grp, REV3, "reverse"),
    )
    db.add_all([server, fwd, rev, rev3])
    await db.flush()
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=network, name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network=network,
        name="s",
        dns_zone_id=str(fwd.id),
        dns_group_ids=[str(grp.id)],
        dns_inherit_settings=False,
    )
    db.add(subnet)
    await db.flush()
    ip = IPAddress(subnet_id=subnet.id, address="192.0.2.10", status="allocated", hostname="web")
    db.add(ip)
    await db.flush()
    owner = f"web.{FWD.rstrip('.')}"
    a = DNSRecord(
        zone_id=fwd.id,
        name="web",
        fqdn=f"{owner}.",
        record_type="A",
        value="192.0.2.10",
        ttl=300,
        auto_generated=True,
        ip_address_id=ip.id,
    )
    ptr = DNSRecord(
        zone_id=rev.id,
        name="10",
        fqdn=f"10.{REV}",
        record_type="PTR",
        value=f"{owner}.",
        ttl=300,
        auto_generated=True,
        ip_address_id=ip.id,
    )
    db.add_all([a, ptr])
    await db.flush()
    ip.dns_record_id = a.id
    ip.forward_zone_id = fwd.id
    ip.reverse_zone_id = rev.id
    await db.flush()
    return server, ip, subnet, ptr


async def _ptr_ops(db: AsyncSession, zone_name: str = REV) -> list[tuple[str, str, str]]:
    rows = (
        await db.execute(
            select(DNSRecordOp)
            .where(DNSRecordOp.zone_name == zone_name)
            .order_by(DNSRecordOp.created_at, DNSRecordOp.seq)
        )
    ).scalars()
    return [(o.op, o.record["name"], o.record["value"]) for o in rows if o.record["type"] == "PTR"]


@pytest.mark.parametrize("batched", [False, True])
async def test_ip_change_in_the_same_zone_deletes_the_old_ptr_then_creates(db_session, batched):
    from app.api.v1.ipam.router import _batched_dns_ops, _sync_dns_record

    _server, ip, subnet, ptr = await _setup(db_session)
    ip.address = "192.0.2.20"
    if batched:
        async with _batched_dns_ops(db_session):
            await _sync_dns_record(db_session, ip, subnet, action="update")
    else:
        await _sync_dns_record(db_session, ip, subnet, action="update")
    await db_session.flush()
    owner = f"web.{FWD}"
    assert await _ptr_ops(db_session) == [
        ("delete", "10", owner),
        ("create", "20", owner),
    ]
    await db_session.refresh(ptr)
    assert ptr.name == "20"


async def test_hostname_only_change_stays_one_update(db_session):
    from app.api.v1.ipam.router import _sync_dns_record

    _server, ip, subnet, _ptr = await _setup(db_session)
    ip.hostname = "api"
    await _sync_dns_record(db_session, ip, subnet, action="update")
    await db_session.flush()
    ops = await _ptr_ops(db_session)
    # The renamed A's delete re-asserts the PTR first (#1800); the PTR itself
    # is then updated in place: no delete, no second name.
    assert ops[-1] == ("update", "10", f"api.{FWD}"), ops
    assert [o for o in ops if o[0] == "delete" or o[1] != "10"] == [], ops


async def test_hostname_and_ip_change_ends_with_the_old_ptr_deleted(db_session):
    from app.api.v1.ipam.router import _sync_dns_record

    # The renamed A's delete re-asserts the old PTR (#1800); the IP-change
    # delete queued after it is a deliberate retraction nothing re-asserts.
    _server, ip, subnet, _ptr = await _setup(db_session)
    ip.hostname = "api"
    ip.address = "192.0.2.20"
    await _sync_dns_record(db_session, ip, subnet, action="update")
    await db_session.flush()
    ops = await _ptr_ops(db_session)
    assert [o for o in ops if o[1] == "10"][-1][0] == "delete", ops
    assert ops[-1] == ("create", "20", f"api.{FWD}"), ops


async def test_cross_zone_change_is_unchanged(db_session):
    from app.api.v1.ipam.router import _sync_dns_record

    _server, ip, subnet, _ptr = await _setup(db_session, network="192.0.2.0/23")
    ip.address = "192.0.3.5"
    await _sync_dns_record(db_session, ip, subnet, action="update")
    await db_session.flush()
    owner = f"web.{FWD}"
    assert await _ptr_ops(db_session, REV) == [("delete", "10", owner)]
    assert await _ptr_ops(db_session, REV3) == [("create", "5", owner)]


async def test_agentless_gets_both_ops_in_one_driver_call_in_order(db_session, monkeypatch):
    from app.api.v1.ipam.router import _sync_dns_record

    _server, ip, subnet, _ptr = await _setup(db_session, driver="technitium_api")
    batches: list[list[tuple[str, str, str]]] = []

    class Fake:
        async def apply_record_changes(self, server: Any, changes: list[Any]) -> list[Any]:
            batches.append([(c.op, c.record.name, c.record.record_type) for c in changes])
            return [RecordChangeResult(ok=True, change=c) for c in changes]

        async def apply_record_change(self, server: Any, change: Any) -> None:
            batches.append([(change.op, change.record.name, change.record.record_type)])

    monkeypatch.setattr(record_ops, "get_driver", lambda name: Fake())
    ip.address = "192.0.2.20"
    await _sync_dns_record(db_session, ip, subnet, action="update")
    await db_session.commit()  # #1539 — the provider is written by the commit
    ptr_batches = [b for b in batches if any(t == "PTR" for _o, _n, t in b)]
    assert ptr_batches == [[("delete", "10", "PTR"), ("create", "20", "PTR")]], batches


def _members(record: dict[str, Any]) -> list[str]:
    return [m["value"] for m in (record.get("rrset") or {}).get("members", [])]


async def test_technitium_hostname_rename_converges_on_the_new_target(db_session):
    """#1800's re-assert queues a transient PTR create of the OLD target when
    the renamed A is deleted (Technitium takes the PTR with it); the PTR update
    queued after it carries the NEW target. Both are whole-RRset writes, so the
    server ends on the new target alone, and a failed create is superseded by
    the update rather than retried after it."""
    from datetime import UTC, datetime

    from app.api.v1.ipam.router import _sync_dns_record

    _server, ip, subnet, _ptr = await _setup(db_session)
    ip.hostname = "api"
    await _sync_dns_record(db_session, ip, subnet, action="update")
    await db_session.flush()
    rows = (
        (
            await db_session.execute(
                select(DNSRecordOp)
                .where(DNSRecordOp.zone_name == REV)
                .order_by(DNSRecordOp.created_at, DNSRecordOp.seq)
            )
        )
        .scalars()
        .all()
    )
    assert [(o.op, _members(o.record)) for o in rows] == [
        ("create", [f"web.{FWD}"]),
        ("update", [f"api.{FWD}"]),
    ]
    create = rows[0]
    create.state = "in_flight"
    await record_ops.fail_attempts(db_session, [(create, "boom")], now=datetime.now(UTC))
    assert create.state == "superseded"
    assert create.superseded_by == rows[1].id


async def test_technitium_api_hostname_rename_ends_on_the_new_target(db_session, monkeypatch):
    from app.api.v1.ipam.router import _sync_dns_record

    _server, ip, subnet, _ptr = await _setup(db_session, driver="technitium_api")
    calls: list[tuple[str, str, list[str]]] = []

    class Fake:
        async def apply_record_changes(self, server: Any, changes: list[Any]) -> list[Any]:
            for c in changes:
                await self.apply_record_change(server, c)
            return [RecordChangeResult(ok=True, change=c) for c in changes]

        async def apply_record_change(self, server: Any, change: Any) -> None:
            if change.record.record_type == "PTR":
                members = [m.value for m in change.rrset.members] if change.rrset else []
                calls.append((change.op, change.record.name, members))

    monkeypatch.setattr(record_ops, "get_driver", lambda name: Fake())
    ip.hostname = "api"
    await _sync_dns_record(db_session, ip, subnet, action="update")
    await db_session.commit()  # #1539 — the provider is written by the commit
    # Every PTR write lands at the one name, and the last carries only the new
    # target: no second value survives at 10.
    assert {n for _o, n, _m in calls} == {"10"}, calls
    assert calls[-1] == ("update", "10", [f"api.{FWD}"]), calls
