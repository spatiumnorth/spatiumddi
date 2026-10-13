"""An A/AAAA delete op must not strand a PTR SpatiumDDI still owns (#1800).

Technitium's web API deletes the matching PTR with the A/AAAA when the
reverse zone is on the same server (``WebServiceZonesApi.DeleteRecord``,
v15.4.0). The structural reconcile re-asserts owned PTRs (#1799); the record-op
path did not. The control plane now queues a PTR ``create`` after the delete,
decided against the database (not the agent's cached bundle, which can still
carry a PTR a delete op already removed).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.services.dns import record_ops
from app.services.dns.agent_config import page_pending_ops
from app.services.dns.record_ops import (
    enqueue_record_op,
    enqueue_record_ops_batch,
    enqueue_record_ops_bulk,
)

FWD = "z1800.example."
REV = "2.0.192.in-addr.arpa."
OWNER = "web.z1800.example"


async def _group(
    db: AsyncSession, driver: str = "technitium", servers: int = 2
) -> tuple[list[DNSServer], DNSZone, DNSZone]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    rows = [
        DNSServer(
            group_id=grp.id,
            driver=driver,
            host=f"10.0.0.{i + 1}",
            name=f"ns{i + 1}",
            is_primary=i == 0,
            is_enabled=True,
            agent_id=uuid.uuid4() if driver == "technitium" else None,
        )
        for i in range(servers)
    ]
    fwd = DNSZone(
        group_id=grp.id,
        name=FWD,
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    rev = DNSZone(
        group_id=grp.id,
        name=REV,
        zone_type="primary",
        kind="reverse",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add_all([*rows, fwd, rev])
    await db.flush()
    return rows, fwd, rev


async def _ptr(
    db: AsyncSession, rev: DNSZone, last: int = 10, value: str = f"{OWNER}.", live: bool = True
) -> DNSRecord:
    rec = DNSRecord(
        zone_id=rev.id,
        name=str(last),
        fqdn=f"{last}.{REV}",
        record_type="PTR",
        value=value,
        ttl=300,
        auto_generated=True,
    )
    if not live:
        rec.deleted_at = datetime.now(UTC)
    db.add(rec)
    await db.flush()
    return rec


def _a_delete(last: int = 10, name: str = "web") -> dict[str, Any]:
    return {
        "name": name,
        "type": "A",
        "value": f"192.0.2.{last}",
        "ttl": 300,
    }


async def _shipped(db: AsyncSession, server: DNSServer) -> list[tuple[str, str, str]]:
    page, _ = await page_pending_ops(db, server)
    return [(p["op"], p["zone_name"], p["record"]["type"]) for p in page]


EXPECTED = [("delete", FWD, "A"), ("create", REV, "PTR")]


async def test_a_delete_op_is_followed_by_a_ptr_create_on_every_server(db_session):
    servers, fwd, rev = await _group(db_session)
    await _ptr(db_session, rev)
    await enqueue_record_op(db_session, fwd, "delete", _a_delete())
    for s in servers:
        assert await _shipped(db_session, s) == EXPECTED, s.name


async def test_the_reassert_carries_the_ptr_value_and_name(db_session):
    servers, fwd, rev = await _group(db_session, servers=1)
    await _ptr(db_session, rev)
    await enqueue_record_op(db_session, fwd, "delete", _a_delete())
    ops = (
        (await db_session.execute(select(DNSRecordOp).where(DNSRecordOp.op == "create")))
        .scalars()
        .all()
    )
    assert len(ops) == 1
    rec = ops[0].record
    assert (rec["name"], rec["type"], rec["value"]) == ("10", "PTR", f"{OWNER}.")


async def test_ipv6_delete_reasserts_too(db_session):
    servers, fwd, _ = await _group(db_session, servers=1)
    rev6 = DNSZone(
        group_id=fwd.group_id,
        name="8.b.d.0.1.0.0.2.ip6.arpa.",
        zone_type="primary",
        kind="reverse",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db_session.add(rev6)
    await db_session.flush()
    import ipaddress

    ip = ipaddress.ip_address("2001:db8::1")
    ptr = DNSRecord(
        zone_id=rev6.id,
        name=ip.reverse_pointer[: -len("8.b.d.0.1.0.0.2.ip6.arpa") - 1],
        fqdn=ip.reverse_pointer + ".",
        record_type="PTR",
        value=f"{OWNER}.",
        ttl=300,
    )
    db_session.add(ptr)
    await db_session.flush()
    await enqueue_record_op(
        db_session,
        fwd,
        "delete",
        {"name": "web", "type": "AAAA", "value": "2001:db8::1", "ttl": 300},
    )
    assert await _shipped(db_session, servers[0]) == [
        ("delete", FWD, "AAAA"),
        ("create", rev6.name, "PTR"),
    ]


async def test_a_ptr_deleted_earlier_is_not_resurrected(db_session):
    """The stale-bundle hazard: the PTR was deliberately removed."""
    servers, fwd, rev = await _group(db_session)
    await _ptr(db_session, rev, live=False)
    await enqueue_record_op(db_session, fwd, "delete", _a_delete())
    for s in servers:
        assert await _shipped(db_session, s) == [("delete", FWD, "A")]


async def test_a_ptr_whose_delete_is_already_queued_is_not_resurrected(db_session):
    servers, fwd, rev = await _group(db_session)
    ptr = await _ptr(db_session, rev)  # row still live; its delete is queued
    await enqueue_record_op(
        db_session,
        rev,
        "delete",
        {"name": "10", "type": "PTR", "value": ptr.value, "ttl": 300, "record_id": str(ptr.id)},
    )
    await enqueue_record_op(db_session, fwd, "delete", _a_delete())
    for s in servers:
        got = await _shipped(db_session, s)
        assert ("create", REV, "PTR") not in got, got


async def test_a_ptr_pointing_elsewhere_is_left_alone(db_session):
    """Technitium only removes a PTR whose target is the deleted owner."""
    servers, fwd, rev = await _group(db_session)
    await _ptr(db_session, rev, value="other.z1800.example.")
    await enqueue_record_op(db_session, fwd, "delete", _a_delete())
    assert await _shipped(db_session, servers[0]) == [("delete", FWD, "A")]


async def test_no_managed_reverse_zone_means_nothing_to_reassert(db_session):
    servers, fwd, rev = await _group(db_session)
    await enqueue_record_op(db_session, fwd, "delete", _a_delete())
    assert await _shipped(db_session, servers[0]) == [("delete", FWD, "A")]


async def test_create_and_update_do_not_reassert(db_session):
    """add overwrite=true and records/update never touch the PTR upstream."""
    servers, fwd, rev = await _group(db_session)
    await _ptr(db_session, rev)
    await enqueue_record_op(db_session, fwd, "update", _a_delete())
    await enqueue_record_op(db_session, fwd, "create", _a_delete())
    assert [o for o, _, _ in await _shipped(db_session, servers[0])] == ["update", "create"]


async def test_other_drivers_are_untouched(db_session):
    servers, fwd, rev = await _group(db_session, driver="bind9")
    await _ptr(db_session, rev)
    await enqueue_record_op(db_session, fwd, "delete", _a_delete())
    assert await _shipped(db_session, servers[0]) == [("delete", FWD, "A")]


@pytest.mark.parametrize("entry", ["batch", "bulk"])
async def test_batch_and_bulk_deletes_reassert_only_owned_ptrs(db_session, entry):
    servers, fwd, rev = await _group(db_session)
    await _ptr(db_session, rev, 10)
    await _ptr(db_session, rev, 11, live=False)
    ops = [
        {"op": "delete", "record": _a_delete(10, "web")},
        {"op": "delete", "record": _a_delete(11, "gone")},
    ]
    if entry == "batch":
        await enqueue_record_ops_batch(db_session, fwd, ops)
    else:
        await enqueue_record_ops_bulk(db_session, fwd, ops)
    for s in servers:
        got = await _shipped(db_session, s)
        assert got == [("delete", FWD, "A"), ("delete", FWD, "A"), ("create", REV, "PTR")], got


async def test_agentless_technitium_api_applies_the_reassert_after_the_delete(
    db_session, monkeypatch
):
    servers, fwd, rev = await _group(db_session, driver="technitium_api", servers=1)
    await _ptr(db_session, rev)
    calls: list[tuple[str, str, str]] = []

    from app.drivers.dns.base import DNSDriver

    class Fake:
        apply_record_changes = DNSDriver.apply_record_changes

        async def apply_record_change(self, server, change):
            calls.append((change.op, change.zone_name, change.record.record_type))

    monkeypatch.setattr(record_ops, "get_driver", lambda name: Fake())
    await enqueue_record_op(db_session, fwd, "delete", _a_delete())
    assert calls == [("delete", FWD, "A"), ("create", REV, "PTR")]


# ── The IPAM address delete retracts the A AND the PTR (validation) ─────
#
# The scariest regression: a deleted address whose PTR the re-assert brings
# back. ``_sync_dns_record(action="delete")`` enqueues one delete per record,
# in whatever order the rows come back, and only drops each row after its op
# is queued — so when the A goes first, its PTR row is still live and no PTR
# delete is queued yet, and the re-assert does queue a create. That is safe
# only because the PTR's own delete is queued after it: what each server ends
# on is the LAST op for the PTR RRset.


async def _ipam_address(
    db: AsyncSession, fwd: DNSZone, rev: DNSZone, *, ptr_first: bool
) -> tuple[Any, Any]:
    from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet

    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="192.0.2.0/24", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="192.0.2.0/24",
        name="s",
        dns_zone_id=str(fwd.id),
        dns_inherit_settings=False,
    )
    db.add(subnet)
    await db.flush()
    ip = IPAddress(subnet_id=subnet.id, address="192.0.2.10", status="allocated", hostname="web")
    db.add(ip)
    await db.flush()
    a = DNSRecord(
        zone_id=fwd.id,
        name="web",
        fqdn=f"{OWNER}.",
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
        value=f"{OWNER}.",
        ttl=300,
        auto_generated=True,
        ip_address_id=ip.id,
    )
    for rec in (ptr, a) if ptr_first else (a, ptr):
        db.add(rec)
        await db.flush()
    return ip, subnet


async def _last_ptr_op(db: AsyncSession, server: DNSServer) -> str | None:
    rows = (
        await db.execute(
            select(DNSRecordOp.op)
            .where(DNSRecordOp.server_id == server.id, DNSRecordOp.zone_name == REV)
            .order_by(DNSRecordOp.created_at, DNSRecordOp.seq)
        )
    ).all()
    return rows[-1][0] if rows else None


@pytest.mark.parametrize("ptr_first", [False, True])
@pytest.mark.parametrize("batched", [False, True])
async def test_an_ipam_address_delete_leaves_the_ptr_deleted(db_session, ptr_first, batched):
    from app.api.v1.ipam.router import _batched_dns_ops, _sync_dns_record

    servers, fwd, rev = await _group(db_session)
    ip, subnet = await _ipam_address(db_session, fwd, rev, ptr_first=ptr_first)
    if batched:
        async with _batched_dns_ops(db_session):
            await _sync_dns_record(db_session, ip, subnet, action="delete")
    else:
        await _sync_dns_record(db_session, ip, subnet, action="delete")
    await db_session.flush()
    for s in servers:
        assert await _last_ptr_op(db_session, s) == "delete", s.name
    # The PTR is retracted first, so no create is queued that its delete undoes.
    creates = (
        await db_session.execute(select(DNSRecordOp.id).where(DNSRecordOp.op == "create"))
    ).all()
    assert creates == []


@pytest.mark.parametrize("ptr_first", [False, True])
async def test_an_agentless_ipam_address_delete_ends_on_the_ptr_delete(
    db_session, monkeypatch, ptr_first
):
    from app.api.v1.ipam.router import _sync_dns_record
    from app.drivers.dns.base import DNSDriver

    servers, fwd, rev = await _group(db_session, driver="technitium_api", servers=1)
    ip, subnet = await _ipam_address(db_session, fwd, rev, ptr_first=ptr_first)
    calls: list[tuple[str, str, str]] = []

    class Fake:
        apply_record_changes = DNSDriver.apply_record_changes

        async def apply_record_change(self, server, change):
            calls.append((change.op, change.zone_name, change.record.record_type))

    monkeypatch.setattr(record_ops, "get_driver", lambda name: Fake())
    await _sync_dns_record(db_session, ip, subnet, action="delete")
    ptr_calls = [c for c in calls if c[2] == "PTR"]
    assert ptr_calls and ptr_calls[-1][0] == "delete", calls


async def test_a_subnet_purge_retracts_the_ptr_without_a_reassert(db_session):
    servers, fwd, rev = await _group(db_session)
    _, subnet = await _ipam_address(db_session, fwd, rev, ptr_first=False)
    await record_ops.retract_address_records(db_session, [subnet.id])
    await db_session.flush()
    for s in servers:
        assert await _last_ptr_op(db_session, s) == "delete", s.name
    creates = (
        await db_session.execute(select(DNSRecordOp.id).where(DNSRecordOp.op == "create"))
    ).all()
    assert creates == []


# ── A retried A delete lands after the re-assert (validation) ───────────


async def _retry_a_delete_after_the_ptr_create(db: AsyncSession, server: DNSServer) -> DNSRecordOp:
    """First page: the A delete fails, the PTR create applies. Second page: the
    A delete's retry applies — after the create, so Technitium took the PTR."""
    page, _ = await page_pending_ops(db, server)
    acks = []
    for p in page:
        ok = p["record"]["type"] == "PTR"
        acks.append(
            {
                "op_id": p["op_id"],
                "result": "ok" if ok else "error",
                "message": None if ok else "boom",
                "dispatch": p["dispatch"],
            }
        )
    await record_ops.apply_acks(db, server.id, acks)
    a_op = (
        (await db.execute(select(DNSRecordOp).where(DNSRecordOp.zone_name == FWD))).scalars().one()
    )
    assert a_op.state == "pending"
    a_op.next_attempt_at = None
    await db.flush()
    page, _ = await page_pending_ops(db, server)
    assert [p["op_id"] for p in page] == [str(a_op.id)]
    await record_ops.apply_acks(
        db,
        server.id,
        [{"op_id": page[0]["op_id"], "result": "ok", "dispatch": page[0]["dispatch"]}],
    )
    return a_op


async def test_a_retried_a_delete_reasserts_the_ptr_again(db_session):
    servers, fwd, rev = await _group(db_session, servers=1)
    await _ptr(db_session, rev)
    await enqueue_record_op(db_session, fwd, "delete", _a_delete())
    a_op = await _retry_a_delete_after_the_ptr_create(db_session, servers[0])
    again = (
        (
            await db_session.execute(
                select(DNSRecordOp).where(
                    DNSRecordOp.zone_name == REV,
                    DNSRecordOp.op == "create",
                    DNSRecordOp.state == "pending",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(again) == 1
    assert (again[0].created_at, again[0].seq) > (a_op.created_at, a_op.seq)


async def test_a_retried_a_delete_does_not_resurrect_a_ptr_deleted_since(db_session):
    servers, fwd, rev = await _group(db_session, servers=1)
    ptr = await _ptr(db_session, rev)
    await enqueue_record_op(db_session, fwd, "delete", _a_delete())
    ptr.deleted_at = datetime.now(UTC)
    await db_session.flush()
    await _retry_a_delete_after_the_ptr_create(db_session, servers[0])
    pending = (
        await db_session.execute(
            select(DNSRecordOp.id).where(
                DNSRecordOp.zone_name == REV, DNSRecordOp.state == "pending"
            )
        )
    ).all()
    assert pending == []
