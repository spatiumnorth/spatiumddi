"""Bulk IPAM→DNS sync batches the create path per zone (issue #341).

The delete branch of ``_apply_dns_sync`` already groups stale records by zone
and fires one ``enqueue_record_ops_batch`` per zone (one WinRM round trip for
an agentless Windows-DNS primary). The create/update branch used to loop
``_sync_dns_record`` per IP, each enqueuing singularly — N WinRM round trips.

These tests pin the fix: the bulk create path now routes every op through the
batch enqueue (one call per zone, carrying all the IPs' ops) and never touches
the singular ``enqueue_record_op``.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ipam.router import (
    DnsSyncCommitRequest,
    _apply_dns_sync,
    _batched_dns_ops,
    _enqueue_dns_op,
)
from app.models.dns import DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet

CIDR = "10.50.0.0/24"


async def _fixture(db: AsyncSession) -> tuple[Subnet, DNSZone, list[IPAddress]]:
    space = IPSpace(name=f"s-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=CIDR, name="b")
    db.add(block)
    await db.flush()
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    zone = DNSZone(
        group_id=grp.id,
        name="example.com.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.com.",
        admin_email="admin.example.com.",
    )
    db.add(zone)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network=CIDR,
        name="s",
        # Pin the zone on the subnet itself — _resolve_effective_dns only
        # consults subnet.dns_zone_id when inherit is off.
        dns_inherit_settings=False,
        dns_zone_id=str(zone.id),
    )
    db.add(subnet)
    await db.flush()
    ips = [
        IPAddress(
            subnet_id=subnet.id, address=f"10.50.0.{n}", hostname=f"host{n}", status="allocated"
        )
        for n in (10, 11, 12)
    ]
    db.add_all(ips)
    await db.flush()
    return subnet, zone, ips


async def test_bulk_sync_create_batches_per_zone(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    subnet, zone, ips = await _fixture(db_session)
    await db_session.commit()

    batch_calls: list[tuple[uuid.UUID, int]] = []
    singular_calls: list[Any] = []

    async def fake_batch(db: Any, z: Any, ops: list[dict[str, Any]]) -> list[Any]:
        batch_calls.append((z.id, len(ops)))
        return [object()] * len(ops)

    async def fake_singular(
        db: Any, z: Any, op: str, record: dict, target_serial: Any = None
    ) -> Any:
        singular_calls.append((z.id, op))
        return None

    monkeypatch.setattr("app.services.dns.record_ops.enqueue_record_ops_batch", fake_batch)
    monkeypatch.setattr("app.services.dns.record_ops.enqueue_record_op", fake_singular)

    body = DnsSyncCommitRequest(create_for_ip_ids=[ip.id for ip in ips])
    created, _updated, _deleted, errors = await _apply_dns_sync(db_session, body)

    assert created == 3, errors
    # The bulk create path must NEVER fall back to the singular per-op enqueue.
    assert singular_calls == []
    # The forward zone received exactly one batched call carrying all 3 creates
    # (not three separate calls) — this is the round-trip saving.
    fwd = [c for zid, c in batch_calls if zid == zone.id]
    assert fwd == [3], batch_calls
    # Any zone touched (forward + an auto-created reverse) is batched, never per-IP.
    assert all(c == 3 for _zid, c in batch_calls), batch_calls


async def test_enqueue_dns_op_inline_without_batch_context(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Outside a ``_batched_dns_ops`` block the singular path is unchanged —
    # single-IP callers (allocate one IP, edit one IP) keep enqueuing inline.
    _subnet, zone, _ips = await _fixture(db_session)
    await db_session.commit()

    singular_calls: list[Any] = []
    batch_calls: list[Any] = []

    async def fake_singular(
        db: Any, z: Any, op: str, record: dict, target_serial: Any = None
    ) -> Any:
        singular_calls.append((z.id, op, record["type"]))
        return None

    async def fake_batch(db: Any, z: Any, ops: list[dict[str, Any]]) -> list[Any]:
        batch_calls.append((z.id, len(ops)))
        return [object()] * len(ops)

    monkeypatch.setattr("app.services.dns.record_ops.enqueue_record_op", fake_singular)
    monkeypatch.setattr("app.services.dns.record_ops.enqueue_record_ops_batch", fake_batch)

    await _enqueue_dns_op(db_session, zone, "create", "h", "A", "10.50.0.10", None)
    assert singular_calls == [(zone.id, "create", "A")]
    assert batch_calls == []


async def test_batched_dns_ops_groups_and_flushes(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Two zones, three ops — flush groups by zone, one batch per zone, order
    # preserved.
    _subnet, zone_a, _ips = await _fixture(db_session)
    grp_b = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp_b)
    await db_session.flush()
    zone_b = DNSZone(
        group_id=grp_b.id,
        name="b.example.com.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.b.example.com.",
        admin_email="admin.b.example.com.",
    )
    db_session.add(zone_b)
    await db_session.commit()

    batch_calls: list[tuple[uuid.UUID, int]] = []

    async def fake_batch(db: Any, z: Any, ops: list[dict[str, Any]]) -> list[Any]:
        batch_calls.append((z.id, len(ops)))
        return [object()] * len(ops)

    monkeypatch.setattr("app.services.dns.record_ops.enqueue_record_ops_batch", fake_batch)

    async with _batched_dns_ops(db_session):
        await _enqueue_dns_op(db_session, zone_a, "create", "h1", "A", "10.50.0.10", None)
        await _enqueue_dns_op(db_session, zone_b, "create", "h2", "A", "10.60.0.10", None)
        await _enqueue_dns_op(db_session, zone_a, "create", "h3", "A", "10.50.0.11", None)

    assert batch_calls == [(zone_a.id, 2), (zone_b.id, 1)]


async def test_batched_failed_op_unstamps_dns_record_id(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    # #1536 — in batch mode ``_enqueue_dns_op`` returns None, so the #428
    # guard in ``_sync_dns_record`` never fired: a failed agentless create
    # left ``dns_record_id`` stamped (DDNS would never retry) and the sync
    # counted the IP as created. The flush must un-stamp and the sync must
    # count the failure as an error instead.
    _subnet, zone, ips = await _fixture(db_session)
    await db_session.commit()

    async def fake_batch(db: Any, z: Any, ops: list[dict[str, Any]]) -> list[Any]:
        return [SimpleNamespace(state="failed", last_error="provider boom") for _ in ops]

    monkeypatch.setattr("app.services.dns.record_ops.enqueue_record_ops_batch", fake_batch)

    async with _batched_dns_ops(db_session) as results:
        ip = ips[0]
        stamped = uuid.uuid4()
        ip.dns_record_id = stamped
        await _enqueue_dns_op(
            db_session,
            zone,
            "create",
            "host10",
            "A",
            "10.50.0.10",
            None,
            ip=ip,
            stamped_record_id=stamped,
        )

    assert ip.dns_record_id is None, "failed batched op must un-stamp (#428)"
    assert len(results) == 1
    assert results[0]["op_row"].state == "failed"
    assert results[0]["ip"] is ip


async def test_apply_dns_sync_counts_batched_failures_as_errors(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    subnet, zone, ips = await _fixture(db_session)
    await db_session.commit()

    async def fake_batch(db: Any, z: Any, ops: list[dict[str, Any]]) -> list[Any]:
        return [SimpleNamespace(state="failed", last_error="provider boom") for _ in ops]

    monkeypatch.setattr("app.services.dns.record_ops.enqueue_record_ops_batch", fake_batch)

    body = DnsSyncCommitRequest(create_for_ip_ids=[ip.id for ip in ips])
    created, _updated, _deleted, errors = await _apply_dns_sync(db_session, body)

    assert created == 0, errors
    assert any("DNS create failed" in e for e in errors), errors
    assert all(ip.dns_record_id is None for ip in ips)


async def test_batched_applied_op_keeps_stamp(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The un-stamp must only fire on ``failed`` — an applied op keeps the
    # stamp (and agent ``pending`` ops keep it too: they self-heal).
    _subnet, zone, ips = await _fixture(db_session)
    await db_session.commit()

    async def fake_batch(db: Any, z: Any, ops: list[dict[str, Any]]) -> list[Any]:
        return [SimpleNamespace(state="applied", last_error=None) for _ in ops]

    monkeypatch.setattr("app.services.dns.record_ops.enqueue_record_ops_batch", fake_batch)

    ip = ips[0]
    stamped = uuid.uuid4()
    ip.dns_record_id = stamped
    async with _batched_dns_ops(db_session):
        await _enqueue_dns_op(
            db_session,
            zone,
            "create",
            "host10",
            "A",
            "10.50.0.10",
            None,
            ip=ip,
            stamped_record_id=stamped,
        )

    assert ip.dns_record_id == stamped
