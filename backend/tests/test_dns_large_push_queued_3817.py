"""A large zone's agentless push is queued, not sent inside the request (#3817)."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns.base import RecordChangeResult
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.services.dns.pull_from_server import (
    INLINE_PUSH_MAX_RECORDS,
    restore_zone_records_to_server,
)


class _Driver:
    def __init__(self) -> None:
        self.calls = 0
        self.changes = 0

    def capabilities(self) -> dict[str, Any]:
        return {"record_types": ["A"]}

    async def pull_zone_records(self, server: Any, zone_name: str, *, tsig: Any = None) -> Any:
        return []

    async def apply_record_changes(self, server: Any, changes: list[Any]) -> list[Any]:
        self.calls += 1
        self.changes += len(changes)
        return [RecordChangeResult(ok=True, change=c) for c in changes]


async def _zone(db: AsyncSession, n: int) -> tuple[DNSServer, DNSZone]:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    srv = DNSServer(
        group_id=group.id,
        name="ns1",
        driver="technitium_api",
        host="10.0.0.1",
        port=5380,
        is_enabled=True,
        is_primary=True,
    )
    zone = DNSZone(group_id=group.id, name="example.com.", zone_type="primary", kind="forward")
    db.add_all([srv, zone])
    await db.flush()
    db.add_all(
        DNSRecord(
            zone_id=zone.id,
            name=f"h{i}",
            fqdn=f"h{i}.example.com.",
            record_type="A",
            value=f"192.0.2.{i % 250 + 1}",
            ttl=300,
        )
        for i in range(n)
    )
    await db.flush()
    return srv, zone


async def test_large_zone_is_queued_one_op_per_record(db_session: AsyncSession) -> None:
    n = INLINE_PUSH_MAX_RECORDS + 5
    srv, zone = await _zone(db_session, n)
    driver = _Driver()

    res = await restore_zone_records_to_server(db_session, srv, driver, zone)

    assert driver.calls == 0
    assert res.queued_for_agent is True
    assert (res.candidates, res.pushed, res.push_errors) == (n, n, [])
    ops = (await db_session.execute(select(DNSRecordOp))).scalars().all()
    assert len(ops) == n
    assert {o.server_id for o in ops} == {srv.id}
    assert {o.state for o in ops} == {"pending"}


async def test_small_zone_still_pushes_inline(db_session: AsyncSession) -> None:
    srv, zone = await _zone(db_session, 3)
    driver = _Driver()

    res = await restore_zone_records_to_server(db_session, srv, driver, zone)

    assert (driver.calls, driver.changes) == (1, 3)
    assert res.queued_for_agent is False
    assert res.pushed == 3
    assert (await db_session.execute(select(DNSRecordOp))).scalars().all() == []


async def test_repeat_does_not_queue_duplicates(db_session: AsyncSession) -> None:
    n = INLINE_PUSH_MAX_RECORDS + 1
    srv, zone = await _zone(db_session, n)
    driver = _Driver()
    await restore_zone_records_to_server(db_session, srv, driver, zone)
    await restore_zone_records_to_server(db_session, srv, driver, zone)
    ops = (await db_session.execute(select(DNSRecordOp))).scalars().all()
    assert len(ops) == n
