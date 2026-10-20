"""A render that keeps dying with its worker is surfaced and held (#2227).

The OOM killer runs no ``finally`` and the render records nothing. The broker
redelivers the task of a worker process that died
(``task_reject_on_worker_lost``) and the 30 s sweep re-enqueues every server
whose bundle is behind, so a render the worker cannot survive killed one
worker process after another — seven workers, every 5 - 15 minutes, in the
scale lab — while the server row said nothing about why.

Each render now raises a per-server count before it runs and clears it when it
returns or raises. A count left at ``ABANDONED_RENDER_LIMIT`` means that many
renders died mid-flight: the next one records the reason on the server row
(what the ``agent_bundle_render_failed`` alert reads) and holds the server for
``ABANDONED_HOLD``; then one render is let through again.

Real Redis (``settings.redis_url``) and real worker processes killed with
SIGKILL; every test works on its own key names.
"""

from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import sys
import time
import uuid

import pytest
import pytest_asyncio
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.redis_client import make_async_redis
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.services.dns.agent_bundle_store import RENDER_STATUS_FAILED, RENDER_STATUS_OK
from app.tasks import agent_bundles

LEASE = 1


async def _agent(db: AsyncSession) -> DNSServer:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver="bind9",
        host="10.0.0.1",
        name=f"srv-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
    )
    db.add(server)
    await db.flush()
    zone = DNSZone(group_id=grp.id, name=f"z{uuid.uuid4().hex[:6]}.example.")
    db.add(zone)
    await db.flush()
    db.add(
        DNSRecord(
            zone_id=zone.id, name="h", fqdn=f"h.{zone.name}", record_type="A", value="10.0.0.9"
        )
    )
    await db.flush()
    return server


@pytest_asyncio.fixture
async def redis_keys(monkeypatch: pytest.MonkeyPatch):
    client = make_async_redis(settings.redis_url, socket_connect_timeout=0.5)
    try:
        await client.ping()
    except Exception:  # noqa: BLE001
        await client.aclose()
        pytest.skip(f"no Redis at {settings.redis_url}")
    tag = uuid.uuid4().hex[:8]
    keys = {
        "slot": f"spatium:test:{tag}:render-slot",
        "lock": f"spatium:test:{tag}:render:",
        "dirty": f"spatium:test:{tag}:dirty:",
        "attempts": f"spatium:test:{tag}:attempts:",
        "hold": f"spatium:test:{tag}:hold:",
    }
    monkeypatch.setattr(agent_bundles, "RENDER_SLOT_KEY", keys["slot"])
    monkeypatch.setattr(agent_bundles, "RENDER_LOCK_PREFIX", keys["lock"])
    monkeypatch.setattr(agent_bundles, "RENDER_DIRTY_PREFIX", keys["dirty"])
    monkeypatch.setattr(
        agent_bundles, "RENDER_WAITING_KEY", f"spatium:test:{tag}:waiting", raising=False
    )
    # One fleet slot: these tests are about what a held slot does to others.
    if "dns_agent_bundle_render_slots" in type(settings).model_fields:
        monkeypatch.setattr(settings, "dns_agent_bundle_render_slots", 1)
    monkeypatch.setattr(agent_bundles, "RENDER_ATTEMPTS_PREFIX", keys["attempts"], raising=False)
    monkeypatch.setattr(agent_bundles, "RENDER_HOLD_PREFIX", keys["hold"], raising=False)
    monkeypatch.setattr(settings, "dns_agent_bundle_render_lease_seconds", LEASE)
    try:
        yield client, keys
    finally:
        async for key in client.scan_iter(match=f"spatium:test:{tag}:*"):
            await client.delete(key)
        await client.aclose()


# A worker process whose render never ends: it takes the keys, starts the
# render, and is SIGKILLed in the middle of it, as the OOM killer would.
_DOOMED_RENDER = r"""
import asyncio, os, sys
from app.tasks import agent_bundles

async def _hang(server_id):
    await asyncio.sleep(300)

agent_bundles._render_once = _hang
agent_bundles.RENDER_SLOT_KEY = os.environ["T_SLOT"]
agent_bundles.RENDER_LOCK_PREFIX = os.environ["T_LOCK"]
agent_bundles.RENDER_DIRTY_PREFIX = os.environ["T_DIRTY"]
agent_bundles.RENDER_ATTEMPTS_PREFIX = os.environ["T_ATTEMPTS"]
agent_bundles.RENDER_HOLD_PREFIX = os.environ["T_HOLD"]
asyncio.run(agent_bundles._run(sys.argv[1]))
"""


async def _kill_mid_render(client, keys: dict[str, str], server_id: str) -> None:  # noqa: ANN001
    """Run one render of ``server_id`` in a worker process and SIGKILL it once
    the render has started; then wait for its lease to lapse, as a
    redelivered task would find it."""
    before = int(await client.get(keys["attempts"] + server_id) or 0)
    env = {
        **os.environ,
        "T_SLOT": keys["slot"],
        "T_LOCK": keys["lock"],
        "T_DIRTY": keys["dirty"],
        "T_ATTEMPTS": keys["attempts"],
        "T_HOLD": keys["hold"],
        "DNS_AGENT_BUNDLE_RENDER_LEASE_SECONDS": str(LEASE),
    }
    proc = subprocess.Popen(  # noqa: S603 — this interpreter, a fixed script
        [sys.executable, "-c", _DOOMED_RENDER, server_id],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 60
        while int(await client.get(keys["attempts"] + server_id) or 0) <= before:
            assert proc.poll() is None, proc.stderr.read().decode()[-2000:] if proc.stderr else ""
            assert time.monotonic() < deadline, "the doomed render never started"
            await asyncio.sleep(0.05)
        os.kill(proc.pid, signal.SIGKILL)
        proc.wait(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
    deadline = time.monotonic() + LEASE + 10
    while await client.get(keys["lock"] + server_id) is not None:
        assert time.monotonic() < deadline, "the dead render's lock outlived its lease"
        await asyncio.sleep(0.1)


async def _row(db: AsyncSession, server_id: uuid.UUID) -> DNSServer:
    db.expunge_all()
    row = await db.get(DNSServer, server_id)
    assert row is not None
    return row


@pytest.mark.asyncio
async def test_renders_killed_mid_flight_are_surfaced_held_and_retried_once(
    db_session: AsyncSession, redis_keys, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, keys = redis_keys
    server = await _agent(db_session)
    await db_session.commit()
    sid = str(server.id)

    for _ in range(agent_bundles.ABANDONED_RENDER_LIMIT):
        await _kill_mid_render(client, keys, sid)
    assert int(await client.get(keys["attempts"] + sid)) == agent_bundles.ABANDONED_RENDER_LIMIT

    rendered: list[uuid.UUID] = []
    real = agent_bundles._render_once

    async def _spy(server_id):  # noqa: ANN001
        rendered.append(server_id)
        return await real(server_id)

    monkeypatch.setattr(agent_bundles, "_render_once", _spy)

    # The redelivered task: it does not start a third render that would die
    # like the others. It says why on the server row and holds the server.
    outcome = await agent_bundles._run(sid)
    assert outcome["status"] == "abandoned", outcome
    assert rendered == []
    row = await _row(db_session, server.id)
    assert row.bundle_render_status == RENDER_STATUS_FAILED
    assert row.bundle_render_error and "never finished" in row.bundle_render_error
    assert "out of memory" in row.bundle_render_error
    hold_ttl = await client.ttl(keys["hold"] + sid)
    assert 0 < hold_ttl <= int(agent_bundles.ABANDONED_HOLD.total_seconds())
    # The keys are free for every other server meanwhile.
    assert await client.get(keys["slot"]) is None
    assert await client.get(keys["lock"] + sid) is None

    # Every change and every sweep tick during the hold costs nothing.
    assert (await agent_bundles._run(sid))["status"] == "on_hold"
    assert rendered == []

    # The hold lapses: one render is let through, and this one finishes.
    await client.delete(keys["hold"] + sid)
    outcome = await agent_bundles._run(sid)
    assert outcome["status"] == "stored", outcome
    assert rendered == [server.id]
    assert await client.get(keys["attempts"] + sid) is None
    row = await _row(db_session, server.id)
    assert row.bundle_render_status == RENDER_STATUS_OK
    assert row.bundle_render_error is None


@pytest.mark.asyncio
async def test_after_a_hold_one_more_death_holds_again(
    db_session: AsyncSession, redis_keys
) -> None:
    """The render let through after a hold dies too: the next request holds
    again at once, rather than spending ``ABANDONED_RENDER_LIMIT`` more worker
    processes first."""
    client, keys = redis_keys
    server = await _agent(db_session)
    await db_session.commit()
    sid = str(server.id)
    for _ in range(agent_bundles.ABANDONED_RENDER_LIMIT):
        await _kill_mid_render(client, keys, sid)
    assert (await agent_bundles._run(sid))["status"] == "abandoned"
    await client.delete(keys["hold"] + sid)

    await _kill_mid_render(client, keys, sid)
    assert (await agent_bundles._run(sid))["status"] == "abandoned"


@pytest.mark.asyncio
async def test_a_held_server_that_then_renders_is_healthy_again(
    db_session: AsyncSession, redis_keys
) -> None:
    """The render let through after a hold succeeds: the count is cleared and
    the row reads ok, so a later single death is retried like any other — a
    server that recovered is not left one death from the next hold."""
    client, keys = redis_keys
    server = await _agent(db_session)
    await db_session.commit()
    sid = str(server.id)
    for _ in range(agent_bundles.ABANDONED_RENDER_LIMIT):
        await _kill_mid_render(client, keys, sid)
    assert (await agent_bundles._run(sid))["status"] == "abandoned"
    assert (await agent_bundles._run(sid))["status"] == "on_hold"
    await client.delete(keys["hold"] + sid)  # the hold lapses

    outcome = await agent_bundles._run(sid)
    assert outcome["status"] == "stored", outcome
    assert await client.get(keys["attempts"] + sid) is None
    assert (await _row(db_session, server.id)).bundle_render_status == RENDER_STATUS_OK

    await _kill_mid_render(client, keys, sid)
    await db_session.execute(
        update(DNSServer)
        .where(DNSServer.id == server.id)
        .values(bundle_dirty_seq=DNSServer.bundle_dirty_seq + 1)
    )
    await db_session.commit()
    outcome = await agent_bundles._run(sid)
    assert outcome["status"] == "stored", outcome


@pytest.mark.asyncio
async def test_one_killed_render_is_simply_retried(db_session: AsyncSession, redis_keys) -> None:
    """A single death may not be the render's fault (a neighbouring task took
    the memory): the next render runs."""
    client, keys = redis_keys
    server = await _agent(db_session)
    await db_session.commit()
    sid = str(server.id)
    await _kill_mid_render(client, keys, sid)

    outcome = await agent_bundles._run(sid)
    assert outcome["status"] == "stored", outcome
    assert await client.get(keys["attempts"] + sid) is None
    assert await client.get(keys["hold"] + sid) is None


@pytest.mark.asyncio
async def test_a_render_that_raises_is_a_failure_not_an_abandoned_render(
    db_session: AsyncSession, redis_keys, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative control: a render that raises finished — its own error is
    recorded and it is retried as before, however often it happens. Only a
    process killed mid-render leaves the count raised."""
    client, keys = redis_keys
    server = await _agent(db_session)
    await db_session.commit()
    sid = str(server.id)

    async def _boom(db, srv, *, rendered_by):  # noqa: ANN001
        raise RuntimeError("records query cancelled")

    monkeypatch.setattr(agent_bundles, "render_and_store", _boom)
    for _ in range(agent_bundles.ABANDONED_RENDER_LIMIT + 2):
        with pytest.raises(RuntimeError):
            await agent_bundles._run(sid)
        assert await client.get(keys["attempts"] + sid) is None
    assert await client.get(keys["hold"] + sid) is None
    row = await _row(db_session, server.id)
    assert row.bundle_render_status == RENDER_STATUS_FAILED
    assert row.bundle_render_error == "RuntimeError: records query cancelled"


@pytest.mark.asyncio
async def test_without_redis_the_render_still_runs(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The count is advisory, like the lock: Redis down means render anyway."""
    server = await _agent(db_session)
    await db_session.commit()
    monkeypatch.setattr(settings, "redis_url", "redis://127.0.0.1:1/0")
    outcome = await agent_bundles._run(str(server.id))
    assert outcome["status"] == "stored", outcome
