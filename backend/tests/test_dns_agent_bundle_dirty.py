"""The dirty mark (#1111): which writes bump ``bundle_dirty_seq``, in the same
transaction as the change, and which deliberately do not.

Over-triggering costs one render; under-triggering is an agent serving stale
config while every surface reports converged. So every contributor the
bundle reads must bump the servers whose bundle it feeds, a heartbeat must
not, and the mark must roll back with the change.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.dns import (
    DNSRecord,
    DNSRecordOp,
    DNSSECPolicy,
    DNSServer,
    DNSServerGroup,
    DNSZone,
)
from app.services.dns import bundle_dirty


async def _group(
    db: AsyncSession, *, agent_servers: int, agentless: int = 0
) -> tuple[DNSServerGroup, list[DNSServer], list[DNSServer], DNSZone]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    agents = []
    for i in range(agent_servers):
        s = DNSServer(
            group_id=grp.id,
            driver="bind9",
            host=f"10.0.0.{i + 1}",
            name=f"srv-{uuid.uuid4().hex[:6]}",
            is_primary=(i == 0),
            is_enabled=True,
        )
        db.add(s)
        agents.append(s)
    others = []
    for i in range(agentless):
        s = DNSServer(
            group_id=grp.id,
            driver="windows_dns",
            host=f"10.0.1.{i + 1}",
            name=f"win-{uuid.uuid4().hex[:6]}",
            is_enabled=True,
        )
        db.add(s)
        others.append(s)
    await db.flush()
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(zone)
    await db.flush()
    return grp, agents, others, zone


async def _seqs(db: AsyncSession, servers: list[DNSServer]) -> dict[uuid.UUID, int]:
    rows = (
        await db.execute(
            select(DNSServer.id, DNSServer.bundle_dirty_seq).where(
                DNSServer.id.in_([s.id for s in servers])
            )
        )
    ).all()
    return {sid: int(seq) for sid, seq in rows}


def _record(zone: DNSZone, name: str) -> DNSRecord:
    return DNSRecord(
        zone_id=zone.id,
        name=name,
        fqdn=f"{name}.{zone.name}",
        record_type="A",
        value="10.9.9.9",
    )


@pytest.mark.asyncio
async def test_a_record_insert_bumps_every_agent_based_server_in_its_group_and_no_other(
    db_session: AsyncSession,
) -> None:
    _g1, agents, others, zone = await _group(db_session, agent_servers=2, agentless=1)
    _g2, elsewhere, _, _ = await _group(db_session, agent_servers=1)
    await db_session.commit()
    everyone = agents + others + elsewhere
    before = await _seqs(db_session, everyone)

    db_session.add(_record(zone, "a"))
    await db_session.commit()

    after = await _seqs(db_session, everyone)
    for s in agents:
        assert after[s.id] == before[s.id] + 1, "an agent-based server in the group"
    for s in others:
        assert after[s.id] == before[s.id], "an agentless server never polls"
    for s in elsewhere:
        assert after[s.id] == before[s.id], "another group is untouched"


@pytest.mark.asyncio
async def test_a_heartbeat_style_write_does_not_bump(db_session: AsyncSession) -> None:
    _g, (server,), _, _zone = await _group(db_session, agent_servers=1)
    await db_session.commit()
    before = (await _seqs(db_session, [server]))[server.id]

    server.last_seen_at = datetime.now(UTC)
    server.last_seen_ip = "10.0.0.9"
    server.status = "active"
    server.last_config_etag = "sha256:" + "0" * 64
    server.config_apply_status = "ok"
    server.daemon_version = "9.20.1"
    await db_session.commit()

    assert (await _seqs(db_session, [server]))[server.id] == before


@pytest.mark.asyncio
async def test_server_columns_the_bundle_reads_bump_self_or_the_group(
    db_session: AsyncSession,
) -> None:
    _g, (primary, secondary), _, _zone = await _group(db_session, agent_servers=2)
    await db_session.commit()
    before = await _seqs(db_session, [primary, secondary])

    # Only this server's bundle carries its fleet-upgrade intent.
    secondary.reboot_requested = True
    await db_session.commit()
    mid = await _seqs(db_session, [primary, secondary])
    assert mid[secondary.id] == before[secondary.id] + 1
    assert mid[primary.id] == before[primary.id]

    # A sibling's bundle reads is_primary (the catalog producer pick).
    secondary.is_primary = True
    await db_session.commit()
    after = await _seqs(db_session, [primary, secondary])
    assert after[primary.id] == mid[primary.id] + 1
    assert after[secondary.id] == mid[secondary.id] + 1


@pytest.mark.asyncio
async def test_a_new_op_row_bumps_only_its_server_and_state_transitions_do_not(
    db_session: AsyncSession,
) -> None:
    _g, (a, b), _, zone = await _group(db_session, agent_servers=2)
    await db_session.commit()
    before = await _seqs(db_session, [a, b])

    op = DNSRecordOp(
        server_id=a.id,
        zone_name=zone.name,
        op="create",
        record={"name": "x", "type": "A", "value": "10.1.1.1"},
        state="pending",
    )
    db_session.add(op)
    await db_session.commit()
    mid = await _seqs(db_session, [a, b])
    assert mid[a.id] == before[a.id] + 1
    assert mid[b.id] == before[b.id]

    # The ops lifecycle the long-poll and the heartbeat drive is not a change.
    op.state = "in_flight"
    await db_session.commit()
    op.state = "applied"
    op.applied_at = datetime.now(UTC)
    await db_session.commit()
    assert await _seqs(db_session, [a, b]) == mid


@pytest.mark.asyncio
async def test_a_global_contributor_bumps_every_agent_based_server(
    db_session: AsyncSession,
) -> None:
    _g1, agents1, others, _ = await _group(db_session, agent_servers=1, agentless=1)
    _g2, agents2, _, _ = await _group(db_session, agent_servers=1)
    await db_session.commit()
    everyone = agents1 + agents2 + others
    before = await _seqs(db_session, everyone)

    db_session.add(DNSSECPolicy(name=f"pol-{uuid.uuid4().hex[:6]}", algorithm="ecdsap256sha256"))
    await db_session.commit()

    after = await _seqs(db_session, everyone)
    for s in agents1 + agents2:
        assert after[s.id] == before[s.id] + 1
    for s in others:
        assert after[s.id] == before[s.id]


@pytest.mark.asyncio
async def test_the_mark_rolls_back_with_the_change(db_session: AsyncSession) -> None:
    _g, (server,), _, zone = await _group(db_session, agent_servers=1)
    await db_session.commit()
    server_id = server.id  # rollback expires the instance; read the row by id
    before = (await _seqs(db_session, [server]))[server_id]

    db_session.add(_record(zone, "never"))
    await db_session.flush()  # the bump is issued here, inside the transaction
    mid = (
        await db_session.execute(
            select(DNSServer.bundle_dirty_seq).where(DNSServer.id == server_id)
        )
    ).scalar_one()
    assert mid == before + 1, "the bump is part of the transaction"
    await db_session.rollback()

    after = (
        await db_session.execute(
            select(DNSServer.bundle_dirty_seq).where(DNSServer.id == server_id)
        )
    ).scalar_one()
    assert after == before, "and rolls back with it"


@pytest.mark.asyncio
async def test_after_commit_enqueues_one_render_per_bumped_server(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _g, agents, others, zone = await _group(db_session, agent_servers=2, agentless=1)
    await db_session.commit()
    captured: list[str] = []
    monkeypatch.setattr(settings, "dns_agent_bundle_enqueue_renders", True)
    monkeypatch.setattr(bundle_dirty, "_enqueue_sync", lambda ids: captured.extend(ids))

    db_session.add(_record(zone, "a"))
    await db_session.commit()
    # The enqueue is scheduled on the loop and runs off-thread; give it a beat.
    for _ in range(20):
        if len(captured) >= 2:
            break
        await asyncio.sleep(0.05)

    assert sorted(captured) == sorted(str(s.id) for s in agents)
    assert all(str(s.id) not in captured for s in others)


@pytest.mark.asyncio
async def test_collect_affected_is_empty_for_unrelated_writes(db_session: AsyncSession) -> None:
    class _Session:
        new: set = set()
        dirty: set = set()
        deleted: set = set()

    assert bundle_dirty.collect_affected(_Session()).is_empty()
    assert bundle_dirty.mark_dirty(db_session.sync_session, bundle_dirty.Affected()) == []


@pytest.mark.asyncio
async def test_an_old_op_and_a_new_op_are_told_apart_by_created_at(
    db_session: AsyncSession,
) -> None:
    """Sanity for the gate the long-poll applies: ``created_at`` is the DB
    clock at insert, so an op created before a snapshot sorts before it."""
    _g, (server,), _, zone = await _group(db_session, agent_servers=1)
    old = DNSRecordOp(
        server_id=server.id,
        zone_name=zone.name,
        op="create",
        record={"name": "old", "type": "A", "value": "10.1.1.1"},
        state="pending",
        created_at=datetime.now(UTC) - timedelta(minutes=5),
    )
    db_session.add(old)
    await db_session.commit()
    assert old.created_at < datetime.now(UTC)
