"""The worker side of #1111: the render task's coalescing and the
render-missing sweep. Redis is advisory — with no Redis the task renders
anyway; with one, a second request for a server already rendering sets the
dirty flag and returns, and the holder renders once more.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.redis_client import make_async_redis
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.services.dns import agent_bundle_store as store
from app.tasks import agent_bundles


async def _agent(
    db: AsyncSession, records: int = 3, *, driver: str = "bind9"
) -> tuple[DNSServer, DNSZone]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver=driver,
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
    db.add_all(
        DNSRecord(
            zone_id=zone.id,
            name=f"h{i}",
            fqdn=f"h{i}.{zone.name}",
            record_type="A",
            value=f"10.0.0.{i}",
        )
        for i in range(records)
    )
    await db.flush()
    return server, zone


async def _redis_available(url: str) -> bool:
    client = make_async_redis(url, socket_connect_timeout=0.5)
    try:
        await client.ping()
        return True
    except Exception:  # noqa: BLE001
        return False
    finally:
        try:
            await client.aclose()
        except Exception:  # noqa: BLE001
            pass


@pytest.mark.asyncio
async def test_the_task_renders_without_redis(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "redis_url", "redis://127.0.0.1:1/0")  # nothing listens
    server, _zone = await _agent(db_session)
    await db_session.commit()

    result = await agent_bundles._run(str(server.id))
    assert result["status"] == "stored", result
    assert result["renders"] == 1
    await db_session.refresh(server)
    assert store.is_current(server)
    assert server.bundle_render_count == 1

    # Current already: nothing to do.
    again = await agent_bundles._run(str(server.id))
    assert again["status"] == "current"
    await db_session.refresh(server)
    assert server.bundle_render_count == 1


@pytest.mark.asyncio
async def test_the_task_skips_agentless_disabled_and_missing_servers(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "redis_url", "redis://127.0.0.1:1/0")
    win, _ = await _agent(db_session, driver="windows_dns")
    off, _ = await _agent(db_session)
    off.is_enabled = False
    await db_session.commit()
    assert (await agent_bundles._run(str(win.id)))["status"] == "skipped"
    assert (await agent_bundles._run(str(off.id)))["status"] == "skipped"
    assert (await agent_bundles._run(str(uuid.uuid4())))["status"] == "gone"


@pytest.mark.asyncio
async def test_a_failing_render_is_recorded_and_raised(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "redis_url", "redis://127.0.0.1:1/0")
    server, _zone = await _agent(db_session)
    await db_session.commit()

    async def _boom(db, server, *, rendered_by):  # noqa: ANN001
        raise RuntimeError("synthetic")

    monkeypatch.setattr(agent_bundles, "render_and_store", _boom)
    with pytest.raises(RuntimeError):
        await agent_bundles._run(str(server.id))
    await db_session.refresh(server)
    assert server.bundle_render_status == store.RENDER_STATUS_FAILED
    assert "synthetic" in (server.bundle_render_error or "")


@pytest.mark.asyncio
async def test_the_sweep_enqueues_stale_agent_based_servers_only(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "redis_url", "redis://127.0.0.1:1/0")
    stale, _ = await _agent(db_session)
    fresh, _ = await _agent(db_session)
    win, _ = await _agent(db_session, driver="windows_dns")
    await db_session.commit()
    assert (await agent_bundles._run(str(fresh.id)))["status"] == "stored"

    captured: list[str] = []
    monkeypatch.setattr(
        agent_bundles, "enqueue_render", lambda sid: (captured.append(sid), True)[1]
    )
    result = await agent_bundles._sweep()
    assert result == {"stale": 1, "enqueued": 1}
    assert captured == [str(stale.id)]
    assert str(win.id) not in captured and str(fresh.id) not in captured


@pytest.mark.asyncio
async def test_with_redis_a_concurrent_request_coalesces_and_the_holder_renders_again(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = settings.redis_url
    if not await _redis_available(url):
        pytest.skip(f"no Redis at {url}")
    monkeypatch.setattr(settings, "redis_url", url)
    server, zone = await _agent(db_session)
    await db_session.commit()
    lock_key = agent_bundles.RENDER_LOCK_PREFIX + str(server.id)
    dirty_key = agent_bundles.RENDER_DIRTY_PREFIX + str(server.id)
    client = make_async_redis(url)
    try:
        await client.delete(lock_key, dirty_key, agent_bundles.RENDER_SLOT_KEY)
        # Someone else holds the lock: this request only leaves the flag.
        assert await client.set(lock_key, "1", nx=True, ex=60)
        assert (await agent_bundles._run(str(server.id)))["status"] == "coalesced"
        assert await client.get(dirty_key)
        await client.delete(lock_key)

        # The holder path: a change lands mid-render → one more render, not N.
        real_render = agent_bundles._render_once
        calls: list[int] = []

        async def _render_then_dirty(server_id):  # noqa: ANN001
            calls.append(1)
            if len(calls) == 1:
                # simulate a change committed while rendering
                await client.set(dirty_key, "1", ex=60)
            return await real_render(server_id)

        monkeypatch.setattr(agent_bundles, "_render_once", _render_then_dirty)
        result = await agent_bundles._run(str(server.id))
        assert result["renders"] == 2, result
        assert not await client.get(lock_key)
        assert not await client.get(agent_bundles.RENDER_SLOT_KEY)
    finally:
        await client.delete(lock_key, dirty_key, agent_bundles.RENDER_SLOT_KEY)
        await client.aclose()


@pytest.mark.asyncio
async def test_the_sweep_re_renders_a_bundle_from_an_older_renderer_revision(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1185: a new release re-renders only when the renderer revision moved,
    and an older process's sweep leaves a newer render alone."""
    monkeypatch.setattr(settings, "redis_url", "redis://127.0.0.1:1/0")
    server, _ = await _agent(db_session)
    await db_session.commit()
    assert (await agent_bundles._run(str(server.id)))["status"] == "stored"

    captured: list[str] = []
    monkeypatch.setattr(
        agent_bundles, "enqueue_render", lambda sid: (captured.append(sid), True)[1]
    )
    assert (await agent_bundles._sweep())["stale"] == 0

    monkeypatch.setattr(settings, "version", "next-release")
    assert (await agent_bundles._sweep())["stale"] == 0, "same renderer, nothing to redo"

    old = store.RENDERER_REVISION
    monkeypatch.setattr(store, "RENDERER_REVISION", old + 1)
    assert (await agent_bundles._sweep())["stale"] == 1
    assert captured == [str(server.id)]
    assert (await agent_bundles._run(str(server.id)))["status"] == "stored"

    monkeypatch.setattr(store, "RENDERER_REVISION", old)
    assert (await agent_bundles._sweep())["stale"] == 0, "an older sweep keeps a newer render"


@pytest.mark.asyncio
async def test_a_server_deleted_mid_render_ends_the_render_as_gone(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The render reads the server and its zones, the server is deleted
    (another session commits it), and the store's INSERT then violates the
    bundle's FK. That is not a failed render: nothing is left to render for.
    It used to log ``dns_agent_bundle_render_failed`` and raise out of the
    task (a Celery task failure) whenever a server was dropped while its
    render ran — six times in half an hour of the api deep tier on a rig."""
    from app.services.dns import agent_bundle_render

    monkeypatch.setattr(settings, "redis_url", "redis://127.0.0.1:1/0")
    server, _zone = await _agent(db_session)
    await db_session.commit()
    server_id = server.id
    real_store = agent_bundle_render.bundle_store.store

    async def _delete_then_store(db, srv, **kw):  # noqa: ANN001
        from sqlalchemy import delete as sa_delete

        from app.db import task_session

        async with task_session() as other:
            await other.execute(sa_delete(DNSServer).where(DNSServer.id == server_id))
            await other.commit()
        return await real_store(db, srv, **kw)

    monkeypatch.setattr(agent_bundle_render.bundle_store, "store", _delete_then_store)
    result = await agent_bundles._run(str(server_id))
    assert result["status"] == "gone", result
