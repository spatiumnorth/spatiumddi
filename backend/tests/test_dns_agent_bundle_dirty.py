"""The dirty mark (#1111): which writes bump ``bundle_dirty_seq``, in the same
transaction as the change, and which deliberately do not.

Over-triggering costs one render; under-triggering is an agent serving stale
config while every surface reports converged. So every contributor the
bundle reads must bump the servers whose bundle it feeds, a heartbeat must
not, and the mark must roll back with the change.
"""

from __future__ import annotations

import ast
import asyncio
import os
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import (
    DNSPool,
    DNSPoolMember,
    DNSRecord,
    DNSRecordOp,
    DNSSECPolicy,
    DNSServer,
    DNSServerGroup,
    DNSZone,
    DNSZoneUpdateAcl,
)
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.models.ownership import Site
from app.models.settings import PlatformSettings
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
    await db_session.flush()
    mid = (
        await db_session.execute(
            select(DNSServer.bundle_dirty_seq).where(DNSServer.id == server_id)
        )
    ).scalar_one()
    # The bump waits for the commit (it is a row lock on every server it
    # names — tests/test_dns_agent_bundle_mark_locks.py): after the flush the
    # change is in the transaction and the mark is only collected.
    assert mid == before, "a flush collects the mark; the commit issues it"
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


# ── The worker process carries the listener (review of #1122) ──────────────


def test_the_worker_process_installs_the_listener() -> None:
    """The listener is installed by importing ``bundle_dirty``. This suite
    imports ``app.main`` (conftest), so every test above runs with it
    installed whatever the worker does — which is how the worker running
    WITHOUT it went unnoticed: pool failover, ACME DNS-01, lease-expiry
    DDNS and IPAM auto-sync all write from Celery tasks. So probe the
    worker's own import graph in a fresh interpreter: import the Celery app
    and every module in its ``include`` list, exactly as ``celery worker``
    does at startup, and ask whether the listener module is loaded."""
    probe = (
        "import sys\n"
        "from app.celery_app import celery_app\n"
        "celery_app.loader.import_default_modules()\n"
        "assert 'app.main' not in sys.modules, 'probe must not load the api'\n"
        "print('LOADED' if 'app.services.dns.bundle_dirty' in sys.modules else 'MISSING')\n"
    )
    proc = subprocess.run(  # noqa: S603 — fixed argv, our own interpreter
        [sys.executable, "-c", probe],
        cwd=Path(__file__).resolve().parents[1],
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        timeout=120,
    )
    # A probe that could not run is not the negative outcome; say which.
    assert proc.returncode == 0, f"worker import probe failed to run:\n{proc.stderr[-2000:]}"
    assert proc.stdout.strip().splitlines()[-1] == "LOADED", (
        "a Celery worker does not install the bundle dirty-mark listener; "
        "import it from app.celery_app"
    )


def test_install_is_idempotent() -> None:
    bundle_dirty.install()
    bundle_dirty.install()
    assert bundle_dirty.installed()


# ── Writes the bundle never reads do not mark ──────────────────────────────


async def _pool(db: AsyncSession, zone: DNSZone) -> tuple[DNSPool, DNSPoolMember]:
    pool = DNSPool(group_id=zone.group_id, zone_id=zone.id, name="p", record_name="svc")
    db.add(pool)
    await db.flush()
    member = DNSPoolMember(pool_id=pool.id, address="10.9.9.9")
    db.add(member)
    await db.flush()
    return pool, member


@pytest.mark.asyncio
async def test_a_pool_health_check_tick_does_not_mark(db_session: AsyncSession) -> None:
    """The 30 s health check stamps the pool and every member. A pool is a
    platform-wide contributor, so marking on those stamps would re-render
    every server in the install every tick — and a stale bundle is never
    served, so at a million rows that is an agent that receives nothing."""
    _g, agents, _, zone = await _group(db_session, agent_servers=2)
    pool, member = await _pool(db_session, zone)
    await db_session.commit()
    before = await _seqs(db_session, agents)

    now = datetime.now(UTC)
    pool.last_checked_at = now
    pool.next_check_at = now + timedelta(seconds=30)
    member.last_check_at = now
    member.consecutive_successes = (member.consecutive_successes or 0) + 1
    member.last_check_state = "healthy"
    await db_session.commit()

    assert await _seqs(db_session, agents) == before


@pytest.mark.asyncio
async def test_a_pool_members_geo_scope_change_marks(db_session: AsyncSession) -> None:
    _g, agents, _, zone = await _group(db_session, agent_servers=1)
    _pool_row, member = await _pool(db_session, zone)
    await db_session.commit()
    before = await _seqs(db_session, agents)

    member.serving_cidrs = ["203.0.113.0/24"]
    await db_session.commit()

    after = await _seqs(db_session, agents)
    assert all(after[s.id] == before[s.id] + 1 for s in agents)


@pytest.mark.asyncio
async def test_platform_settings_mark_only_on_what_snmp_and_ntp_render(
    db_session: AsyncSession,
) -> None:
    _g, agents, _, _zone = await _group(db_session, agent_servers=1)
    ps = await db_session.get(PlatformSettings, 1)
    if ps is None:
        ps = PlatformSettings(id=1)
        db_session.add(ps)
    await db_session.commit()
    before = await _seqs(db_session, agents)

    # A beat task's run stamp — the Windows lease pull writes this every 15 s.
    ps.dhcp_pull_leases_last_run_at = datetime.now(UTC)
    await db_session.commit()
    assert await _seqs(db_session, agents) == before

    ps.ntp_pool_servers = ["time.example.net"]
    await db_session.commit()
    after = await _seqs(db_session, agents)
    assert all(after[s.id] == before[s.id] + 1 for s in agents)


def test_snmp_and_ntp_renderers_read_only_prefixed_platform_settings_columns() -> None:
    """``_RENDERED_PREFIXES`` lets a PlatformSettings write mark only when a
    ``snmp_`` / ``ntp_`` column changes, on the grounds that
    ``snmp_bundle`` / ``ntp_bundle`` read nothing else. Scan both renderers
    so a new setting they read under another name fails here instead of
    being served stale."""
    columns = {c.key for c in PlatformSettings.__mapper__.column_attrs} - {"id"}
    root = Path(__file__).resolve().parents[1] / "app" / "services" / "appliance"
    read: set[str] = set()
    for name in ("snmp.py", "ntp.py"):
        tree = ast.parse((root / name).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in columns:
                read.add(node.attr)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value in columns:
                    read.add(node.value)
    assert read, "the scan found no PlatformSettings column at all — it is not scanning"
    prefixes = bundle_dirty._RENDERED_PREFIXES[PlatformSettings]
    assert sorted(c for c in read if not c.startswith(prefixes)) == []


@pytest.mark.asyncio
async def test_the_dnssec_state_stamp_and_a_same_value_write_do_not_mark(
    db_session: AsyncSession,
) -> None:
    """Every BIND9 agent posts /dnssec-state after each structural reload,
    which stamps ``dnssec_synced_at`` on each signed zone; and
    ``session.dirty`` holds any object an attribute was assigned on, even
    to the value it already had."""
    _g, agents, _, zone = await _group(db_session, agent_servers=1)
    await db_session.commit()
    before = await _seqs(db_session, agents)

    zone.dnssec_synced_at = datetime.now(UTC)
    zone.primary_ns = zone.primary_ns
    await db_session.commit()

    assert await _seqs(db_session, agents) == before


@pytest.mark.asyncio
async def test_a_record_moved_between_zones_marks_both_groups(db_session: AsyncSession) -> None:
    _g1, (a,), _, zone1 = await _group(db_session, agent_servers=1)
    _g2, (b,), _, zone2 = await _group(db_session, agent_servers=1)
    rec = _record(zone1, "moving")
    db_session.add(rec)
    await db_session.commit()
    before = await _seqs(db_session, [a, b])

    rec.zone_id = zone2.id
    await db_session.commit()

    after = await _seqs(db_session, [a, b])
    assert after[a.id] == before[a.id] + 1, "the zone it left re-renders without it"
    assert after[b.id] == before[b.id] + 1


# ── Geo steering inputs ─────────────────────────────────────────────────────


async def _site_subnet(db: AsyncSession) -> tuple[Site, Subnet]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.20.0.0/16", name="b")
    db.add(block)
    await db.flush()
    site = Site(name=f"DC-{uuid.uuid4().hex[:6]}")
    db.add(site)
    await db.flush()
    subnet = Subnet(
        space_id=space.id, block_id=block.id, network="10.20.30.0/24", name="lan", site_id=site.id
    )
    db.add(subnet)
    await db.flush()
    return site, subnet


@pytest.mark.asyncio
async def test_a_site_linked_subnet_change_marks_groups_whose_pools_use_the_site(
    db_session: AsyncSession,
) -> None:
    """``pool_geo`` resolves a member's Site to its live subnets' CIDRs, so a
    subnet joining or leaving a Site moves the rendered ``match-clients``."""
    _g, (geo_server,), _, zone = await _group(db_session, agent_servers=1)
    _g2, (bystander,), _, _ = await _group(db_session, agent_servers=1)
    site, subnet = await _site_subnet(db_session)
    _pool_row, member = await _pool(db_session, zone)
    member.site_id = site.id
    await db_session.commit()
    before = await _seqs(db_session, [geo_server, bystander])

    subnet.site_id = None
    await db_session.commit()

    after = await _seqs(db_session, [geo_server, bystander])
    assert after[geo_server.id] == before[geo_server.id] + 1
    assert after[bystander.id] == before[bystander.id], "no pool there uses the site"

    # A subnet write that touches none of site / network / soft-delete —
    # utilisation, description — is not a geo input.
    subnet.description = "renamed"
    await db_session.commit()
    assert await _seqs(db_session, [geo_server, bystander]) == after


# ── Core writes mark through the helper ─────────────────────────────────────


@pytest.mark.asyncio
async def test_mark_bundles_dirty_covers_a_core_write_and_enqueues_it(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _g, agents, _, zone = await _group(db_session, agent_servers=2)
    rec = _record(zone, "core")
    db_session.add(rec)
    await db_session.commit()
    before = await _seqs(db_session, agents)
    captured: list[str] = []
    monkeypatch.setattr(settings, "dns_agent_bundle_enqueue_renders", True)
    monkeypatch.setattr(bundle_dirty, "_enqueue_sync", lambda ids: captured.extend(ids))

    await db_session.execute(sa_delete(DNSRecord).where(DNSRecord.id == rec.id))
    await bundle_dirty.mark_bundles_dirty(db_session, zone_ids=[zone.id])
    await db_session.commit()
    for _ in range(20):
        if len(captured) >= 2:
            break
        await asyncio.sleep(0.05)

    after = await _seqs(db_session, agents)
    assert all(after[s.id] == before[s.id] + 1 for s in agents)
    assert sorted(captured) == sorted(str(s.id) for s in agents)


@pytest.mark.asyncio
async def test_clearing_a_zones_update_acl_marks_its_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The ACL replace deletes the old rows with a Core statement. Cleared to
    an empty list it writes nothing else, so without an explicit mark the
    agents kept serving the revoked ``allow-update``."""
    grp, (server,), _, zone = await _group(db_session, agent_servers=1)
    db_session.add(DNSZoneUpdateAcl(zone_id=zone.id, seq=0, match_kind="ip", ip_cidr="10.0.0.5/32"))
    admin = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@t.io",
        display_name="sa",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db_session.add(admin)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {create_access_token(str(admin.id))}"}
    before = (await _seqs(db_session, [server]))[server.id]

    r = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/update-acl",
        headers=headers,
        json={"entries": []},
    )
    assert r.status_code == 200, r.text

    assert (await _seqs(db_session, [server]))[server.id] == before + 1


@pytest.mark.asyncio
async def test_a_rolled_back_savepoint_keeps_the_outer_transactions_mark_and_render(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A savepoint that rolls back must not drop what the OUTER transaction
    marked: SQLAlchemy dispatches ``after_rollback`` for a nested rollback too,
    and a listener that clears its state there loses the outer change's render
    enqueue (and, once the mark itself is deferred to commit, the mark)."""
    _g, (server,), _, zone = await _group(db_session, agent_servers=1)
    await db_session.commit()
    server_id = server.id
    before = (await _seqs(db_session, [server]))[server_id]
    captured: list[str] = []
    monkeypatch.setattr(settings, "dns_agent_bundle_enqueue_renders", True)
    monkeypatch.setattr(bundle_dirty, "_enqueue_sync", lambda ids: captured.extend(ids))

    db_session.add(_record(zone, "outer"))
    await db_session.flush()
    with pytest.raises(RuntimeError):
        async with db_session.begin_nested():
            db_session.add(_record(zone, "inner"))
            await db_session.flush()
            raise RuntimeError("the savepoint's work fails")
    await db_session.commit()
    for _ in range(20):
        if captured:
            break
        await asyncio.sleep(0.05)

    after = (
        await db_session.execute(
            select(DNSServer.bundle_dirty_seq).where(DNSServer.id == server_id)
        )
    ).scalar_one()
    assert after >= before + 1, "the outer change is marked"
    assert captured == [str(server_id)], (
        "the outer change's render was not enqueued after its commit: the "
        f"savepoint's rollback cleared it (captured {captured!r})"
    )


@pytest.mark.asyncio
async def test_a_released_savepoint_enqueues_nothing_until_the_outer_commit(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SQLAlchemy dispatches ``after_commit`` when a savepoint is RELEASED,
    while the outer transaction and its bump are still uncommitted. A render
    enqueued there reads the old sequence and finds nothing to do, and the
    real commit then had nothing left to enqueue."""
    _g, (server,), _, zone = await _group(db_session, agent_servers=1)
    await db_session.commit()
    server_id = server.id
    captured: list[str] = []
    monkeypatch.setattr(settings, "dns_agent_bundle_enqueue_renders", True)
    monkeypatch.setattr(bundle_dirty, "_enqueue_sync", lambda ids: captured.extend(ids))

    async with db_session.begin_nested():
        db_session.add(_record(zone, "released"))
    for _ in range(10):
        await asyncio.sleep(0.05)
    assert captured == [], (
        "the render was enqueued when the savepoint was released, before the "
        f"outer transaction committed the change (captured {captured!r})"
    )

    await db_session.commit()
    for _ in range(20):
        if captured:
            break
        await asyncio.sleep(0.05)
    assert captured == [
        str(server_id)
    ], f"the outer commit enqueued {captured!r}, want the server's render"
