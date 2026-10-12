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
