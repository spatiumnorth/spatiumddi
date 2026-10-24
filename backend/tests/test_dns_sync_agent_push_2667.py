"""Sync with Servers on an agent-managed BIND9 server queues ops (#2667).

The control plane has no RFC 2136 path to an agent-managed server; the push
phase used to call the driver and report an error per record.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns.base import RecordChangeResult
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.services.dns import pull_from_server as pfs
from app.services.dns.pull_from_server import sync_zone_with_server


class _AgentBind9:
    def capabilities(self) -> dict[str, Any]:
        return {"record_types": ["A"]}

    async def pull_zone_records(self, server: Any, zone_name: str, *, tsig: Any = None) -> Any:
        return []

    async def apply_record_changes(self, server: Any, changes: list[Any]) -> list[Any]:
        return [
            RecordChangeResult(ok=False, change=c, error="no TSIG key configured") for c in changes
        ]


async def _setup(db: AsyncSession) -> tuple[DNSServer, DNSZone]:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    srv = DNSServer(
        group_id=group.id,
        name="bind",
        driver="bind9",
        host="10.0.0.1",
        port=53,
        is_enabled=True,
        is_primary=True,
    )
    zone = DNSZone(group_id=group.id, name="example.com.", zone_type="primary", kind="forward")
    db.add_all([srv, zone])
    await db.flush()
    db.add(
        DNSRecord(
            zone_id=zone.id,
            name="www",
            fqdn="www.example.com.",
            record_type="A",
            value="192.0.2.5",
            ttl=300,
        )
    )
    await db.flush()
    return srv, zone


async def test_agent_managed_push_is_queued_not_an_error(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    srv, zone = await _setup(db_session)
    monkeypatch.setattr(pfs, "get_driver", lambda name: _AgentBind9())

    res = await sync_zone_with_server(db_session, zone, apply=True)
    assert res.push.push_errors == []
    assert res.push.queued_for_agent is True
    assert res.push.pushed == 1
    ops = (
        (await db_session.execute(select(DNSRecordOp).where(DNSRecordOp.server_id == srv.id)))
        .scalars()
        .all()
    )
    assert len(ops) == 1 and ops[0].op == "create" and ops[0].state == "pending"
    assert ops[0].record["name"] == "www" and ops[0].record["value"] == "192.0.2.5"

    # A second Sync before the agent drains does not queue a duplicate.
    await sync_zone_with_server(db_session, zone, apply=True)
    ops = (
        (await db_session.execute(select(DNSRecordOp).where(DNSRecordOp.server_id == srv.id)))
        .scalars()
        .all()
    )
    assert len(ops) == 1


async def test_preview_queues_nothing(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    srv, zone = await _setup(db_session)
    monkeypatch.setattr(pfs, "get_driver", lambda name: _AgentBind9())
    await sync_zone_with_server(db_session, zone, apply=False)
    ops = (await db_session.execute(select(DNSRecordOp))).scalars().all()
    assert ops == []
