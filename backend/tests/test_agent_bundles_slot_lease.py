"""The render task's Redis keys (#1111, review item B): the fleet-wide render
slot and the per-server lock.

* A render killed mid-flight (an OOM kill never runs ``finally``) must not
  hold the fleet slot — and with it every server's render — for long: the
  keys are a short lease the holder renews while it renders, not a 15-minute
  TTL.
* A holder must never release a key it no longer owns: after a lease ran
  out and another render took the key, an unconditional ``DELETE`` would
  free it under that render and let a third one start beside it.
* A render deferred because the slot is taken keeps its server's lock, so
  the duplicates the sweep and every further mark enqueue while it waits
  coalesce into it instead of each starting a retry chain of its own.

Real Redis (``settings.redis_url``); every test works on its own key names so
parallel workers never share the one global slot.
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
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.redis_client import make_async_redis
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.tasks import agent_bundles


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
    db.add(
        DNSRecord(
            zone_id=zone.id, name="h", fqdn=f"h.{zone.name}", record_type="A", value="10.0.0.9"
        )
    )
    await db.flush()
    return server


def _set_lease(monkeypatch: pytest.MonkeyPatch, seconds: int) -> None:
    """The render lease, where the build has one (a build without it holds the
    keys for its fixed TTL, which is what the tests below catch)."""
    if "dns_agent_bundle_render_lease_seconds" in type(settings).model_fields:
        monkeypatch.setattr(settings, "dns_agent_bundle_render_lease_seconds", seconds)


@pytest_asyncio.fixture
async def redis_keys(monkeypatch: pytest.MonkeyPatch):
    """A reachable Redis and this test's own key names."""
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
        "waiting": f"spatium:test:{tag}:waiting",
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
    # #2227's per-server counters, kept out of the real key space too (absent
    # from builds before it).
    monkeypatch.setattr(
        agent_bundles, "RENDER_ATTEMPTS_PREFIX", f"spatium:test:{tag}:attempts:", raising=False
    )
    monkeypatch.setattr(
        agent_bundles, "RENDER_HOLD_PREFIX", f"spatium:test:{tag}:hold:", raising=False
    )
    try:
        yield client, keys
    finally:
        async for key in client.scan_iter(match=f"spatium:test:{tag}:*"):
            await client.delete(key)
        await client.aclose()


@pytest.mark.asyncio
async def test_a_deferred_render_keeps_its_server_lock_so_duplicates_coalesce(
    db_session: AsyncSession, redis_keys
) -> None:
    client, keys = redis_keys
    server = await _agent(db_session)
    await db_session.commit()
    # Another server's render holds the fleet slot.
    assert await client.set(keys["slot"], "someone-else", ex=60)

    first = await agent_bundles._run(str(server.id))
    second = await agent_bundles._run(str(server.id))  # the sweep's duplicate, 30 s later

    assert first["status"] == "deferred", first
    assert second["status"] == "coalesced", (
        "a second request for a server whose render is already waiting for the "
        f"slot started a retry chain of its own ({second}); each sweep tick and "
        "each further mark adds another while one long render holds the slot"
    )


@pytest.mark.asyncio
async def test_a_deferred_render_comes_back_with_its_lock_and_renders_when_the_slot_frees(
    db_session: AsyncSession, redis_keys, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The task re-enqueues a deferred render ONCE, carrying the token its
    server's lock holds, and that retry renders once the slot is free."""
    client, keys = redis_keys
    server = await _agent(db_session)
    await db_session.commit()
    lock_key = keys["lock"] + str(server.id)
    requeued: list[dict] = []
    monkeypatch.setattr(
        agent_bundles.render_dns_bundle,
        "apply_async",
        lambda *a, **kw: requeued.append(kw),
    )
    assert await client.set(keys["slot"], "someone-else", ex=60)

    first = await asyncio.to_thread(agent_bundles.render_dns_bundle.run, str(server.id))
    dup = await asyncio.to_thread(agent_bundles.render_dns_bundle.run, str(server.id))
    assert first["status"] == "deferred" and dup["status"] == "coalesced", (first, dup)
    assert len(requeued) == 1, f"one retry chain per waiting server, got {requeued!r}"
    token = requeued[0]["kwargs"]["lock_token"]
    assert (await client.get(lock_key)) == token.encode(), "the lock waits with the retry"

    await client.delete(keys["slot"])
    retry = await asyncio.to_thread(
        agent_bundles.render_dns_bundle.run, str(server.id), lock_token=token
    )
    assert retry["status"] == "stored", retry
    assert await client.get(lock_key) is None, "released after the render"
    assert len(requeued) == 1


@pytest.mark.asyncio
async def test_a_render_never_releases_a_slot_it_no_longer_holds(
    db_session: AsyncSession, redis_keys, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R1's slot runs out mid-render and R2 takes it; R1 finishing must leave
    R2's slot alone."""
    client, keys = redis_keys
    s1 = await _agent(db_session)
    s2 = await _agent(db_session)
    await db_session.commit()
    real = agent_bundles._render_once
    entered = {s1.id: asyncio.Event(), s2.id: asyncio.Event()}
    gate = {s1.id: asyncio.Event(), s2.id: asyncio.Event()}

    async def _gated(server_id):  # noqa: ANN001
        entered[server_id].set()
        await gate[server_id].wait()
        return await real(server_id)

    monkeypatch.setattr(agent_bundles, "_render_once", _gated)
    r1 = asyncio.create_task(agent_bundles._run(str(s1.id)))
    await asyncio.wait_for(entered[s1.id].wait(), 10)
    await client.delete(keys["slot"])  # R1's slot lease ran out
    r2 = asyncio.create_task(agent_bundles._run(str(s2.id)))
    await asyncio.wait_for(entered[s2.id].wait(), 10)
    holder = await client.get(keys["slot"])
    assert holder is not None, "R2 took the slot"

    gate[s1.id].set()
    await asyncio.wait_for(r1, 30)
    after = await client.get(keys["slot"])
    gate[s2.id].set()
    await asyncio.wait_for(r2, 30)
    assert after == holder, (
        "R1 released the fleet slot R2 was rendering under (slot "
        f"{holder!r} -> {after!r}): a third render could now start beside R2"
    )


@pytest.mark.asyncio
async def test_a_render_never_releases_a_server_lock_it_no_longer_holds(
    db_session: AsyncSession, redis_keys, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same for the per-server lock: two renders of ONE server at once is
    what the lock exists to prevent."""
    client, keys = redis_keys
    server = await _agent(db_session)
    await db_session.commit()
    lock_key = keys["lock"] + str(server.id)
    real = agent_bundles._render_once
    calls: list[asyncio.Event] = []
    gates: list[asyncio.Event] = []

    async def _gated(server_id):  # noqa: ANN001
        entered, gate = asyncio.Event(), asyncio.Event()
        calls.append(entered)
        gates.append(gate)
        entered.set()
        await gate.wait()
        return await real(server_id)

    monkeypatch.setattr(agent_bundles, "_render_once", _gated)
    r1 = asyncio.create_task(agent_bundles._run(str(server.id)))
    for _ in range(100):
        if calls:
            break
        await asyncio.sleep(0.05)
    await client.delete(lock_key, keys["slot"])  # both leases ran out
    r2 = asyncio.create_task(agent_bundles._run(str(server.id)))
    for _ in range(100):
        if len(calls) >= 2:
            break
        await asyncio.sleep(0.05)
    assert len(calls) == 2, "R2 started rendering the same server"
    holder = await client.get(lock_key)

    gates[0].set()
    await asyncio.wait_for(r1, 30)
    after = await client.get(lock_key)
    for g in gates[1:]:
        g.set()
    await asyncio.wait_for(r2, 30)
    assert holder is not None and after == holder, (
        "R1 released the server lock R2 was rendering under (lock "
        f"{holder!r} -> {after!r}): a third render of the same server could "
        "start beside R2"
    )


_KILLED_HOLDER = r"""
import asyncio, os, sys
from app.tasks import agent_bundles

async def _hang(server_id):
    await asyncio.sleep(300)

agent_bundles._render_once = _hang
agent_bundles.RENDER_SLOT_KEY = os.environ["T_SLOT"]
agent_bundles.RENDER_LOCK_PREFIX = os.environ["T_LOCK"]
agent_bundles.RENDER_DIRTY_PREFIX = os.environ["T_DIRTY"]
asyncio.run(agent_bundles._run(sys.argv[1]))
"""


@pytest.mark.asyncio
async def test_a_killed_render_frees_the_fleet_slot_within_one_lease(
    db_session: AsyncSession, redis_keys, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A worker process SIGKILLed mid-render (the OOM killer) never runs its
    ``finally``. Its keys must expire within one lease, not after the render
    ceiling, or every server's render is deferred until they do."""
    client, keys = redis_keys
    lease = 2
    _set_lease(monkeypatch, lease)
    victim = await _agent(db_session)
    other = await _agent(db_session)
    await db_session.commit()

    env = {
        **os.environ,
        "T_SLOT": keys["slot"],
        "T_LOCK": keys["lock"],
        "T_DIRTY": keys["dirty"],
        "DNS_AGENT_BUNDLE_RENDER_LEASE_SECONDS": str(lease),
    }
    proc = subprocess.Popen(  # noqa: S603 — this interpreter, a fixed script
        [sys.executable, "-c", _KILLED_HOLDER, str(victim.id)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and not await client.get(keys["slot"]):
            assert proc.poll() is None, proc.stderr.read().decode()[-2000:] if proc.stderr else ""
            await asyncio.sleep(0.1)
        assert await client.get(keys["slot"]), "the doomed render never took the slot"
        os.kill(proc.pid, signal.SIGKILL)
        proc.wait(timeout=10)
        ttl_after_kill = await client.ttl(keys["slot"])

        deadline = time.monotonic() + lease + 6
        outcome: dict = {}
        token = None
        while time.monotonic() < deadline:
            # Retry the way the task does: a deferred render comes back with
            # the token its server's lock holds.
            if token:
                outcome = await agent_bundles._run(str(other.id), lock_token=token)
            else:
                outcome = await agent_bundles._run(str(other.id))
            if outcome.get("status") != "deferred":
                break
            token = outcome.get("lock_token")
            await asyncio.sleep(0.5)
        assert outcome.get("status") == "stored", (
            f"{lease + 6}s after the render holding the fleet slot was SIGKILLed, "
            f"another server's render is still {outcome.get('status')!r}: the dead "
            f"holder's slot had {ttl_after_kill}s left to live when it died, and "
            "every server's render waits for it"
        )
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)


@pytest.mark.asyncio
async def test_a_render_longer_than_its_lease_keeps_the_slot(
    db_session: AsyncSession, redis_keys, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lease is renewed while the render runs: a render several leases long
    still owns the slot at the end, and nothing else rendered meanwhile."""
    client, keys = redis_keys
    lease = 1
    _set_lease(monkeypatch, lease)
    slow = await _agent(db_session)
    other = await _agent(db_session)
    await db_session.commit()
    real = agent_bundles._render_once

    async def _slow(server_id):  # noqa: ANN001
        if server_id == slow.id:
            await asyncio.sleep(3.5 * lease)
        return await real(server_id)

    monkeypatch.setattr(agent_bundles, "_render_once", _slow)
    task = asyncio.create_task(agent_bundles._run(str(slow.id)))
    await asyncio.sleep(2.5 * lease)
    assert await client.get(keys["slot"]), "the slot lapsed under a render still running"
    assert (await agent_bundles._run(str(other.id)))["status"] == "deferred"
    result = await asyncio.wait_for(task, 30)
    assert result["status"] == "stored", result


# ── #2227: more than one slot, and a holder that hands its slot on ────────────


@pytest.mark.asyncio
async def test_two_slots_let_two_servers_render_at_once(
    db_session: AsyncSession, redis_keys, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With two slots a second server renders beside a long one; a third
    waits."""
    client, keys = redis_keys
    monkeypatch.setattr(settings, "dns_agent_bundle_render_slots", 2)
    slow = await _agent(db_session)
    second = await _agent(db_session)
    third = await _agent(db_session)
    await db_session.commit()
    real = agent_bundles._render_once
    gate, entered = asyncio.Event(), asyncio.Event()

    async def _held(server_id):  # noqa: ANN001
        if server_id == slow.id:
            entered.set()
            await gate.wait()
        return await real(server_id)

    monkeypatch.setattr(agent_bundles, "_render_once", _held)
    task = asyncio.create_task(agent_bundles._run(str(slow.id)))
    await asyncio.wait_for(entered.wait(), 10)
    # The second slot is free: another server renders now.
    assert await client.get(keys["slot"]) is not None
    blocker = asyncio.create_task(agent_bundles._run(str(second.id)))
    result = await asyncio.wait_for(blocker, 30)
    assert result["status"] == "stored", result
    # Both slots taken (the slow one, and a stand-in): the next one waits.
    assert await client.set(keys["slot"] + ":1", "someone-else", ex=60)
    assert (await agent_bundles._run(str(third.id)))["status"] == "deferred"
    gate.set()
    assert (await asyncio.wait_for(task, 30))["status"] == "stored"


@pytest.mark.asyncio
async def test_a_holder_with_more_to_render_hands_its_slot_to_a_waiting_server(
    db_session: AsyncSession, redis_keys, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A server that changed again while it rendered used to render again,
    up to 50 times, while every other server waited for the one slot. With a
    render waiting it hands the slot on and comes back through the queue,
    keeping its server's lock so duplicates still coalesce into it."""
    client, keys = redis_keys
    busy = await _agent(db_session)
    other = await _agent(db_session)
    await db_session.commit()
    busy_lock = keys["lock"] + str(busy.id)
    real = agent_bundles._render_once
    entered, gate = asyncio.Event(), asyncio.Event()
    renders: list[uuid.UUID] = []

    async def _storm(server_id):  # noqa: ANN001
        renders.append(server_id)
        if server_id == busy.id:
            entered.set()
            await gate.wait()
            # A change landed while it rendered.
            await client.set(keys["dirty"] + str(busy.id), "1", ex=60)
        return await real(server_id)

    monkeypatch.setattr(agent_bundles, "_render_once", _storm)
    task = asyncio.create_task(agent_bundles._run(str(busy.id)))
    await asyncio.wait_for(entered.wait(), 10)
    waiting = await agent_bundles._run(str(other.id))
    assert waiting["status"] == "deferred", waiting
    gate.set()
    result = await asyncio.wait_for(task, 30)

    assert result["status"] == "handed_on", result
    assert renders.count(busy.id) == 1, "it rendered again while another server waited"
    assert await client.get(keys["slot"]) is None, "the slot was handed on"
    token = result["lock_token"]
    assert (await client.get(busy_lock)) == token.encode(), "its lock waits with the retry"

    # The waiting server takes the slot; the busy one comes back after it
    # (the storm over, nobody waiting).
    monkeypatch.setattr(agent_bundles, "_render_once", real)
    other_back = await agent_bundles._run(str(other.id), lock_token=waiting["lock_token"])
    assert other_back["status"] == "stored", other_back
    await client.delete(keys["waiting"])
    back = await agent_bundles._run(str(busy.id), lock_token=token)
    assert back["status"] in ("stored", "current"), back
    assert await client.get(busy_lock) is None


def test_a_handed_on_render_comes_back_after_the_waiters_next_try(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The task re-enqueues a render that handed its slot on, carrying its
    lock token, LATER than a deferred render's retry: re-enqueued at once it
    took back the slot it had just freed before the waiter (retrying every
    ``SLOT_RETRY_SECONDS``) came round, so nothing was handed to anyone."""
    sid = str(uuid.uuid4())

    async def _handed(server_id, lock_token=None):  # noqa: ANN001
        return {"status": "handed_on", "lock_token": "tok", "renders": 1}

    requeued: list[dict] = []
    monkeypatch.setattr(agent_bundles, "_run", _handed)
    monkeypatch.setattr(
        agent_bundles.render_dns_bundle, "apply_async", lambda *a, **kw: requeued.append(kw)
    )
    agent_bundles.render_dns_bundle.run(sid)
    assert requeued == [
        {
            "args": [sid],
            "kwargs": {"lock_token": "tok"},
            "countdown": agent_bundles.HANDED_ON_RETRY_SECONDS,
            "retry": False,
            "queue": "bundles",
        }
    ], requeued
    assert agent_bundles.HANDED_ON_RETRY_SECONDS > agent_bundles.SLOT_RETRY_SECONDS


@pytest.mark.asyncio
async def test_with_nobody_waiting_a_holder_renders_again(
    db_session: AsyncSession, redis_keys, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative control: with no render waiting, the holder still renders its
    server again in place, as before."""
    client, keys = redis_keys
    server = await _agent(db_session)
    await db_session.commit()
    real = agent_bundles._render_once
    calls = 0

    async def _dirty_once(server_id):  # noqa: ANN001
        nonlocal calls
        calls += 1
        if calls == 1:
            await client.set(keys["dirty"] + str(server.id), "1", ex=60)
        return await real(server_id)

    monkeypatch.setattr(agent_bundles, "_render_once", _dirty_once)
    result = await agent_bundles._run(str(server.id))
    assert result["renders"] == 2, result
    assert result["status"] in ("stored", "current"), result
