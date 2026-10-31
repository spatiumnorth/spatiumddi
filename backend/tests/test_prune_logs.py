"""Tests for the nightly sweep, which since #2185 only retires agent ingest receipts.

The agent-shipped log tables are time-partitioned and their retention is a
partition drop (``test_log_partitions_2185.py``); the sweep no longer deletes
from them.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent_ingest import AgentIngestReceipt
from app.models.dhcp import DHCPServer
from app.models.dns import DNSServer, DNSServerGroup
from app.models.dns_rpz_hit import DNSRPZHit
from app.models.logs import DHCPLogEntry, DNSQueryLogEntry
from app.services.agents.ingest_receipt import RECEIPT_RETENTION_DAYS
from app.services.logs.partitions import DEFAULT_RETENTION_HOURS, RPZ_HIT_RETENTION_DAYS
from app.tasks import prune_logs
from app.tasks.prune_logs import FAILED, _sweep_with_session


async def _make_dns_server(db: AsyncSession) -> DNSServer:
    grp = DNSServerGroup(name=f"grp-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    s = DNSServer(
        group_id=grp.id,
        name=f"dns-{uuid.uuid4().hex[:6]}",
        host="127.0.0.1",
        driver="bind9",
    )
    db.add(s)
    await db.flush()
    return s


async def _make_dhcp_server(db: AsyncSession) -> DHCPServer:
    s = DHCPServer(
        name=f"dhcp-{uuid.uuid4().hex[:6]}",
        host="127.0.0.1",
        driver="kea",
    )
    db.add(s)
    await db.flush()
    return s


async def _count(db: AsyncSession, model: type) -> int:
    return await db.scalar(select(func.count()).select_from(model)) or 0


@pytest.mark.asyncio
async def test_sweep_retires_old_receipts_and_reports_the_windows(db_session: AsyncSession) -> None:
    server = await _make_dns_server(db_session)
    old = datetime.now(UTC) - timedelta(days=RECEIPT_RETENTION_DAYS + 5)
    for _ in range(2):
        db_session.add(
            AgentIngestReceipt(
                server_id=server.id,
                stream="dns.query_log",
                batch_id=uuid.uuid4().hex,
                received_at=old,
            )
        )
    await db_session.commit()

    result = await _sweep_with_session(db_session)

    assert result["agent_ingest_receipt_removed"] == 2
    assert result["failed_tables"] == []
    assert result["retention_hours"] == DEFAULT_RETENTION_HOURS
    assert result["rpz_retention_days"] == RPZ_HIT_RETENTION_DAYS
    assert result["receipt_retention_days"] == RECEIPT_RETENTION_DAYS
    assert await _count(db_session, AgentIngestReceipt) == 0


@pytest.mark.asyncio
async def test_sweep_leaves_the_log_tables_to_the_partition_drop(db_session: AsyncSession) -> None:
    dns = await _make_dns_server(db_session)
    dhcp = await _make_dhcp_server(db_session)
    old = datetime.now(UTC) - timedelta(days=20)
    db_session.add(DNSQueryLogEntry(server_id=dns.id, ts=old, qname="o.example", raw="o"))
    db_session.add(DHCPLogEntry(server_id=dhcp.id, ts=old, raw="o"))
    db_session.add(
        DNSRPZHit(server_id=dns.id, ts=old, qname="o.example", trigger="qname", policy="NXDOMAIN")
    )
    await db_session.commit()

    await _sweep_with_session(db_session)

    assert await _count(db_session, DNSQueryLogEntry) == 1
    assert await _count(db_session, DHCPLogEntry) == 1
    assert await _count(db_session, DNSRPZHit) == 1


@pytest.mark.asyncio
async def test_failed_receipt_prune_is_reported_not_raised(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def boom(_db: AsyncSession) -> int:
        raise RuntimeError("canceling statement: timeout")

    monkeypatch.setattr(prune_logs, "prune_receipts", boom)

    result = await _sweep_with_session(db_session)

    assert result["agent_ingest_receipt_removed"] == FAILED
    assert result["failed_tables"] == ["agent_ingest_receipt"]
