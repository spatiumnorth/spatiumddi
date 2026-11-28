"""#4173 — deleting a DNS server keeps client history and runs in a worker.

``DELETE /dns/groups/{g}/servers/{s}`` used to cascade the server's query log,
RPZ hits and metrics inside the request (over a minute on a 1.2M-row log) and
erased what clients had asked. Now the request marks the server ``removing``
and answers 202; ``remove_server_with_session`` (the worker task) detaches
the history rows, deletes the operational rows in batches and the server last.

Pinned on stored state and HTTP answers, not on the code path.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.dns import DNSServer
from app.models.dns_rpz_hit import DNSRPZHit
from app.models.logs import DNSQueryLogEntry
from app.models.metrics import DNSMetricSample
from app.services.dns.agent_token import hash_token, mint_agent_token
from app.tasks import dns_server_removal
from app.tasks.dns_server_removal import remove_server_with_session
from tests.test_dns_server_group_move import _auth, _group, _server, _superadmin

_NOW = datetime(2026, 11, 1, tzinfo=UTC)


@pytest.fixture
def enqueued(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []
    monkeypatch.setattr(
        dns_server_removal.remove_dns_server, "delay", lambda sid: calls.append(sid), raising=False
    )
    return calls


async def _seed_history(db: AsyncSession, server: DNSServer, n_logs: int = 7) -> None:
    for i in range(n_logs):
        db.add(
            DNSQueryLogEntry(
                server_id=server.id,
                # Half predate the column: no stored name.
                server_name=server.name if i % 2 == 0 else None,
                ts=_NOW + timedelta(seconds=i),
                client_ip="192.0.2.5",
                qname=f"q{i}.example.",
                qtype="A",
                raw="x",
            )
        )
    for i in range(3):
        db.add(
            DNSRPZHit(
                server_id=server.id,
                ts=_NOW + timedelta(seconds=i),
                client_ip="192.0.2.5",
                qname=f"bad{i}.example.",
                trigger="QNAME",
                policy="NXDOMAIN",
                raw="x",
            )
        )
    for i in range(5):
        db.add(DNSMetricSample(server_id=server.id, bucket_at=_NOW + timedelta(minutes=i)))
    await db.flush()


async def _count(db: AsyncSession, model: Any, *where: Any) -> int:
    return int(
        (await db.execute(select(func.count()).select_from(model).where(*where))).scalar_one()
    )


@pytest.mark.asyncio
async def test_delete_answers_202_marks_removing_and_enqueues(
    client: AsyncClient, db_session: AsyncSession, enqueued: list[str]
) -> None:
    token = await _superadmin(db_session, "root4173a")
    grp = await _group(db_session, "g4173a")
    srv = await _server(db_session, grp, "ns1", is_primary=True)
    other = await _server(db_session, grp, "ns2")
    await db_session.commit()
    sid, gid, oid = srv.id, grp.id, other.id

    resp = await client.delete(f"/api/v1/dns/groups/{gid}/servers/{sid}", headers=_auth(token))
    assert resp.status_code == 202, resp.text
    assert resp.json()["removing"] is True
    assert enqueued == [str(sid)]

    db_session.expire_all()
    row = await db_session.get(DNSServer, sid)
    assert row is not None and row.removing_at is not None
    # The primary flag moved before the row is gone: two primaries 500s the poll.
    assert row.is_primary is False
    assert (await db_session.get(DNSServer, oid)).is_primary is True  # type: ignore[union-attr]
    listed = await client.get(f"/api/v1/dns/groups/{gid}/servers", headers=_auth(token))
    assert {s["id"]: s["removing"] for s in listed.json()} == {str(sid): True, str(oid): False}
    audits = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.action == "delete", AuditLog.resource_id == str(sid)
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(audits) == 1

    # Asking again re-enqueues (the recovery for a lost enqueue); no second audit row.
    again = await client.delete(f"/api/v1/dns/groups/{gid}/servers/{sid}", headers=_auth(token))
    assert again.status_code == 202
    assert enqueued == [str(sid), str(sid)]
    assert await _count(db_session, AuditLog, AuditLog.resource_id == str(sid)) == 1


@pytest.mark.asyncio
async def test_a_removing_servers_agent_is_refused(
    client: AsyncClient, db_session: AsyncSession, enqueued: list[str]
) -> None:
    token = await _superadmin(db_session, "root4173b")
    grp = await _group(db_session, "g4173b")
    srv = await _server(db_session, grp, "ns1", agent_id=uuid.uuid4())
    agent_token, _ = mint_agent_token(str(srv.id), str(srv.agent_id), "fp")
    srv.agent_jwt_hash = hash_token(agent_token)
    await db_session.commit()
    agent = {"Authorization": f"Bearer {agent_token}"}

    gone = await client.post(
        "/api/v1/dns/agents/heartbeat", headers=agent, json={"agent_id": str(srv.agent_id)}
    )
    assert gone.status_code != 404, gone.text  # live server: the token is accepted

    resp = await client.delete(
        f"/api/v1/dns/groups/{grp.id}/servers/{srv.id}", headers=_auth(token)
    )
    assert resp.status_code == 202
    refused = await client.post(
        "/api/v1/dns/agents/heartbeat", headers=agent, json={"agent_id": str(srv.agent_id)}
    )
    assert refused.status_code == 404


@pytest.mark.asyncio
async def test_task_detaches_history_and_deletes_operational_rows_in_batches(
    db_session: AsyncSession,
) -> None:
    grp = await _group(db_session, "g4173c")
    srv = await _server(db_session, grp, "retired-ns")
    keep = await _server(db_session, grp, "kept-ns")
    await _seed_history(db_session, srv)
    await _seed_history(db_session, keep, n_logs=2)
    await db_session.commit()
    sid, kid = srv.id, keep.id

    # Not marked: the task refuses to remove a server nobody asked to delete.
    assert (await remove_server_with_session(db_session, sid, batch_size=2))["status"] == (
        "not_removing"
    )
    assert await _count(db_session, DNSQueryLogEntry, DNSQueryLogEntry.server_id == sid) == 7

    srv.removing_at = datetime.now(UTC)
    await db_session.commit()
    result = await remove_server_with_session(db_session, sid, batch_size=2)
    assert result["status"] == "removed"
    assert result["rows"]["dns_query_log_entry"] == 7
    assert result["rows"]["dns_metric_sample"] == 5

    db_session.expire_all()
    assert await db_session.get(DNSServer, sid) is None
    # History survives, detached, still attributable.
    orphans = (
        (
            await db_session.execute(
                select(DNSQueryLogEntry).where(DNSQueryLogEntry.server_id.is_(None))
            )
        )
        .scalars()
        .all()
    )
    assert len(orphans) == 7
    assert {o.server_name for o in orphans} == {"retired-ns"}  # legacy rows stamped too
    rpz = (
        (await db_session.execute(select(DNSRPZHit).where(DNSRPZHit.server_id.is_(None))))
        .scalars()
        .all()
    )
    assert len(rpz) == 3 and {r.server_name for r in rpz} == {"retired-ns"}
    # Counters go with the server; the other server's rows are untouched.
    assert await _count(db_session, DNSMetricSample, DNSMetricSample.server_id == sid) == 0
    assert await _count(db_session, DNSMetricSample, DNSMetricSample.server_id == kid) == 5
    assert await _count(db_session, DNSQueryLogEntry, DNSQueryLogEntry.server_id == kid) == 2

    # Idempotent: a retry after completion is a no-op.
    assert (await remove_server_with_session(db_session, sid))["status"] == "gone"


@pytest.mark.asyncio
async def test_logs_readers_cope_with_a_deleted_server(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root4173d")
    grp = await _group(db_session, "g4173d")
    srv = await _server(db_session, grp, "retired-ns")
    live = await _server(db_session, grp, "live-ns")
    await _seed_history(db_session, srv, n_logs=3)
    db_session.add(
        DNSQueryLogEntry(
            server_id=live.id, server_name="live-ns", ts=_NOW, qname="l.example.", raw="x"
        )
    )
    srv.removing_at = datetime.now(UTC)
    await db_session.commit()
    gid = grp.id
    await remove_server_with_session(db_session, srv.id)

    allq = await client.post(
        "/api/v1/logs/dns-queries", json={"max_events": 50}, headers=_auth(token)
    )
    assert allq.status_code == 200, allq.text
    rows = allq.json()["events"]
    assert len(rows) == 4
    detached = [r for r in rows if r["server_id"] is None]
    assert len(detached) == 3
    assert {r["server_name"] for r in detached} == {"retired-ns"}
    assert [r["server_name"] for r in rows if r["server_id"] is not None] == ["live-ns"]

    # A read narrowed to a group names live servers only.
    scoped = await client.post(
        "/api/v1/logs/dns-queries", json={"group_id": str(gid)}, headers=_auth(token)
    )
    assert len(scoped.json()["events"]) == 1

    stats = await client.post("/api/v1/logs/dns-queries/analytics", json={}, headers=_auth(token))
    assert stats.status_code == 200, stats.text
    assert stats.json()["total_queries"] == 4
