"""Tests for the log retention sweep."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPServer
from app.models.dns import DNSServer, DNSServerGroup
from app.models.dns_rpz_hit import DNSRPZHit
from app.models.logs import DHCPLogEntry, DNSQueryLogEntry
from app.tasks.prune_logs import DEFAULT_RETENTION_HOURS, _sweep_with_session


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


@pytest.mark.asyncio
async def test_prune_drops_old_dns_keeps_recent(db_session: AsyncSession) -> None:
    server = await _make_dns_server(db_session)
    now = datetime.now(UTC)
    # One row well past the cutoff, one inside the window.
    db_session.add(
        DNSQueryLogEntry(
            server_id=server.id,
            ts=now - timedelta(hours=DEFAULT_RETENTION_HOURS + 5),
            qname="old.example",
            raw="old",
        )
    )
    db_session.add(
        DNSQueryLogEntry(
            server_id=server.id,
            ts=now - timedelta(minutes=10),
            qname="new.example",
            raw="new",
        )
    )
    await db_session.commit()

    result = await _sweep_with_session(db_session)
    assert result["dns_query_log_removed"] >= 1
    assert result["retention_hours"] == DEFAULT_RETENTION_HOURS

    remaining = (
        await db_session.scalar(
            select(func.count())
            .select_from(DNSQueryLogEntry)
            .where(DNSQueryLogEntry.server_id == server.id)
        )
        or 0
    )
    assert remaining == 1


@pytest.mark.asyncio
async def test_prune_drops_old_dhcp_keeps_recent(db_session: AsyncSession) -> None:
    server = await _make_dhcp_server(db_session)
    now = datetime.now(UTC)
    db_session.add(
        DHCPLogEntry(
            server_id=server.id,
            ts=now - timedelta(hours=DEFAULT_RETENTION_HOURS + 1),
            severity="INFO",
            code="DHCP4_LEASE_ALLOC",
            raw="old",
        )
    )
    db_session.add(
        DHCPLogEntry(
            server_id=server.id,
            ts=now - timedelta(minutes=5),
            severity="INFO",
            code="DHCP4_LEASE_ALLOC",
            raw="new",
        )
    )
    await db_session.commit()

    result = await _sweep_with_session(db_session)
    assert result["dhcp_log_removed"] >= 1

    remaining = (
        await db_session.scalar(
            select(func.count())
            .select_from(DHCPLogEntry)
            .where(DHCPLogEntry.server_id == server.id)
        )
        or 0
    )
    assert remaining == 1


async def _seed_old_rows(db: AsyncSession) -> tuple[uuid.UUID, uuid.UUID]:
    dns = await _make_dns_server(db)
    dhcp = await _make_dhcp_server(db)
    old = datetime.now(UTC) - timedelta(days=60)
    db.add(DNSQueryLogEntry(server_id=dns.id, ts=old, qname="o.example", raw="o"))
    db.add(DHCPLogEntry(server_id=dhcp.id, ts=old, raw="o"))
    db.add(
        DNSRPZHit(server_id=dns.id, ts=old, qname="o.example", trigger="qname", policy="NXDOMAIN")
    )
    await db.commit()
    return dns.id, dhcp.id


async def _count(db: AsyncSession, model: type, server_id: uuid.UUID) -> int:
    return (
        await db.scalar(
            select(func.count()).select_from(model).where(model.server_id == server_id)  # type: ignore[attr-defined]
        )
        or 0
    )


@pytest.mark.asyncio
async def test_prune_all_tables_commit_independently(db_session: AsyncSession) -> None:
    dns_id, dhcp_id = await _seed_old_rows(db_session)
    result = await _sweep_with_session(db_session)
    assert result["failed_tables"] == []
    assert result["dns_query_log_removed"] >= 1
    assert result["dhcp_log_removed"] >= 1
    assert await _count(db_session, DNSQueryLogEntry, dns_id) == 0
    assert await _count(db_session, DHCPLogEntry, dhcp_id) == 0


@pytest.mark.asyncio
async def test_failed_dns_delete_does_not_roll_back_other_tables(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    dns_id, dhcp_id = await _seed_old_rows(db_session)
    real_execute = db_session.execute

    async def flaky(stmt, *a, **kw):  # type: ignore[no-untyped-def]
        if str(stmt).startswith("DELETE FROM dns_query_log_entry"):
            raise OperationalError("DELETE", {}, Exception("canceling statement: timeout"))
        return await real_execute(stmt, *a, **kw)

    monkeypatch.setattr(db_session, "execute", flaky)
    result = await _sweep_with_session(db_session)
    monkeypatch.undo()

    assert result["dns_query_log_removed"] == -1
    assert result["failed_tables"] == ["dns_query_log"]
    assert result["dhcp_log_removed"] >= 1
    # The DNS rows survive for the next run; the DHCP delete was committed.
    assert await _count(db_session, DNSQueryLogEntry, dns_id) == 1
    assert await _count(db_session, DHCPLogEntry, dhcp_id) == 0
    assert result["dns_rpz_hit_removed"] >= 1
    assert await _count(db_session, DNSRPZHit, dns_id) == 0
