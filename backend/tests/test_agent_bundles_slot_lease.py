"""The render task's Redis keys (#1111, review item B): the fleet-wide render
slot and the per-server lock.

* A holder must never release a key it no longer owns: after a lease ran
  out and another render took the key, an unconditional ``DELETE`` would
  free it under that render and let a third one start beside it.

Real Redis (``settings.redis_url``); every test works on its own key names so
parallel workers never share the one global slot.
"""

from __future__ import annotations

import asyncio
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
    }
    monkeypatch.setattr(agent_bundles, "RENDER_SLOT_KEY", keys["slot"])
    monkeypatch.setattr(agent_bundles, "RENDER_LOCK_PREFIX", keys["lock"])
    monkeypatch.setattr(agent_bundles, "RENDER_DIRTY_PREFIX", keys["dirty"])
    try:
        yield client, keys
    finally:
        async for key in client.scan_iter(match=f"spatium:test:{tag}:*"):
            await client.delete(key)
        await client.aclose()


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
