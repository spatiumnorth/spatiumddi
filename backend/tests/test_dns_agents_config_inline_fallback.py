"""The long-poll's inline fallback at scale (#1111, review item C).

With ``dns_agent_bundle_inline_fallback`` on, every poll that finds its
bundle stale renders it in the api. At 1.09 M records that render cannot fit
the api's 30 s ``command_timeout``, so each attempt fails the poll. These pin
what such a failure must not do to the worker path that would have served
the agent anyway.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns import agents as agents_api
from app.config import settings
from app.core.http_etag import etag_matches
from app.core.redis_client import make_async_redis
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.services.dns import agent_bundle_store as store
from app.services.dns.agent_bundle_render import render_and_store
from app.services.dns.agent_token import mint_agent_token
from app.tasks import agent_bundles

CONFIG_URL = "/api/v1/dns/agents/config"
# Read defensively so the bound's tests exercise a build without the bound
# (the unbounded fallback fails them on behaviour, not on a missing name).
INLINE_LOCK_PREFIX = getattr(agents_api, "_INLINE_LOCK_PREFIX", "spatium:bundle:inline:")
INLINE_BACKOFF_PREFIX = getattr(
    agents_api, "_INLINE_BACKOFF_PREFIX", "spatium:bundle:inline-backoff:"
)


def _set_bound(monkeypatch: pytest.MonkeyPatch, seconds: int) -> None:
    if "dns_agent_bundle_inline_fallback_after_seconds" in type(settings).model_fields:
        monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback_after_seconds", seconds)


async def _agent(db: AsyncSession) -> tuple[DNSServer, dict[str, str]]:
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
        agent_id=uuid.uuid4(),
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
    token, _exp = mint_agent_token(str(server.id), str(server.agent_id), "fp")
    return server, {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_a_failed_inline_render_does_not_hold_the_sweep_off_the_worker_render(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The api's inline attempt timed out; the worker must still be asked.

    The sweep leaves a server whose last render FAILED within the last 5
    minutes to the explicit enqueue, so that it does not spin on a render
    the worker keeps failing. Recording the api's timed-out inline attempt as
    that failure stamps the row on every poll, and the sweep never re-enqueues
    the worker's render of the server for as long as its agent keeps
    polling: a lost or crashed worker render is then never retried.
    """
    monkeypatch.setattr(agents_api, "LONGPOLL_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback", True)
    _set_bound(monkeypatch, 0)
    server, headers = await _agent(db_session)
    await db_session.commit()
    server_id = str(server.id)  # the handler's rollback expires the instance

    async def _timed_out(db, server, *, rendered_by):  # noqa: ANN001
        # What asyncpg's 30 s command_timeout raises out of the records query.
        raise TimeoutError()

    monkeypatch.setattr(agents_api, "render_and_store", _timed_out)
    # No bundle is served either way; whether the poll then fails or holds on
    # the worker is not what this pins.
    polled = await client.get(CONFIG_URL, headers=headers)
    assert polled.status_code != 200, polled.text

    captured: list[str] = []
    monkeypatch.setattr(
        agent_bundles, "enqueue_render", lambda sid: (captured.append(sid), True)[1]
    )
    await agent_bundles._sweep()
    assert server_id in captured, (
        "the api's timed-out inline attempt was recorded as the server's render "
        "failure, and the sweep backs off failed servers for 5 minutes: the "
        "worker's render of a stale bundle is not re-enqueued while the agent "
        "keeps polling"
    )


# ── The bound (#1111 review item C) ─────────────────────────────────────────


async def _stored_then_marked(db: AsyncSession) -> tuple[DNSServer, dict[str, str]]:
    """A server whose worker-rendered bundle has just gone stale: rendered and
    stored, then one record added (the mark sets ``bundle_dirty_at``)."""
    server, headers = await _agent(db)
    await db.commit()
    await render_and_store(db, server, rendered_by=store.RENDERED_BY_WORKER)
    await db.commit()
    zone_id = (
        await db.execute(
            text("select id from dns_zone where group_id = :g"), {"g": server.group_id}
        )
    ).scalar_one()
    db.add(
        DNSRecord(zone_id=zone_id, name="late", fqdn="late.x.", record_type="A", value="10.0.0.8")
    )
    await db.commit()
    await db.refresh(server)
    assert server.bundle_dirty_at is not None and not store.is_current(server)
    return server, headers


def _count_inline(monkeypatch: pytest.MonkeyPatch, *, fail: bool = False) -> list[int]:
    calls: list[int] = []
    real = agents_api.render_and_store

    async def _counted(db, server, *, rendered_by):  # noqa: ANN001
        calls.append(1)
        if fail:
            raise TimeoutError()
        return await real(db, server, rendered_by=rendered_by)

    monkeypatch.setattr(agents_api, "render_and_store", _counted)
    return calls


@pytest_asyncio.fixture
async def redis_ok() -> AsyncIterator[object]:
    client = make_async_redis(settings.redis_url, socket_connect_timeout=0.5)
    try:
        await client.ping()
    except Exception:  # noqa: BLE001
        await client.aclose()
        pytest.skip(f"no Redis at {settings.redis_url}")
    try:
        yield client
    finally:
        await client.aclose()


@pytest.fixture
def bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agents_api, "LONGPOLL_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback", True)
    _set_bound(monkeypatch, 120)

    async def _no_enqueue(ids):  # noqa: ANN001
        return None

    monkeypatch.setattr(agents_api, "enqueue_renders", _no_enqueue)


@pytest.mark.asyncio
async def test_a_bundle_stale_for_less_than_the_bound_is_left_to_the_worker(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    bounded: None,
    redis_ok: object,
) -> None:
    """During a change storm every bundle is stale almost all the time, and
    the worker renders it within seconds: the api must not build it too.
    Meanwhile the agent gets the worker's newest render (the long-poll serves
    the newest stored bundle, not only a current one)."""
    server, headers = await _stored_then_marked(db_session)
    stored_etag = server.bundle_etag
    calls = _count_inline(monkeypatch)
    polled = await client.get(CONFIG_URL, headers=headers)
    assert polled.status_code == 200, polled.text
    assert etag_matches(polled.headers["etag"], stored_etag)
    assert calls == [], "the api built a bundle the worker had just been asked for"


@pytest.mark.asyncio
async def test_a_bundle_stale_past_the_bound_is_built_inline(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    bounded: None,
    redis_ok: object,
) -> None:
    """No render has landed for longer than the bound: the worker is not
    keeping up (or not consuming ``bundles``), and the api serves the agent."""
    server, headers = await _stored_then_marked(db_session)
    await db_session.execute(
        text(
            "update dns_server set bundle_dirty_at = now() - interval '200 seconds' "
            "where id = :s"
        ),
        {"s": server.id},
    )
    await db_session.commit()
    calls = _count_inline(monkeypatch)
    polled = await client.get(CONFIG_URL, headers=headers)
    assert polled.status_code == 200, polled.text
    assert calls == [1]
    await db_session.refresh(server)
    assert server.bundle_rendered_by == store.RENDERED_BY_API


@pytest.mark.asyncio
async def test_a_server_that_never_had_a_bundle_is_built_inline_at_once(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    bounded: None,
    redis_ok: object,
) -> None:
    """No bundle at all: nothing is being raced. A new server (marked by its
    own creation) and a server from before stored bundles (never marked) are
    both built on their first poll."""
    fresh, headers = await _agent(db_session)
    await db_session.commit()
    await db_session.refresh(fresh)
    assert fresh.bundle_dirty_at is not None and fresh.bundle_watermark is None
    calls = _count_inline(monkeypatch)
    polled = await client.get(CONFIG_URL, headers=headers)
    assert polled.status_code == 200, polled.text
    assert calls == [1]

    legacy, legacy_headers = await _agent(db_session)
    await db_session.commit()
    await db_session.execute(
        text(
            "update dns_server set bundle_dirty_at = null, bundle_watermark = null, "
            "bundle_dirty_seq = 0 where id = :s"
        ),
        {"s": legacy.id},
    )
    await db_session.commit()
    polled = await client.get(CONFIG_URL, headers=legacy_headers)
    assert polled.status_code == 200, polled.text
    assert calls == [1, 1]


@pytest.mark.asyncio
async def test_a_bundle_from_an_older_renderer_with_nothing_changed_waits_for_the_sweep(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    bounded: None,
    redis_ok: object,
) -> None:
    """An upgrade to a release with a newer renderer revision (#1185): each
    server is re-rendered once by the worker's sweep, not by every polling
    api."""
    server, headers = await _agent(db_session)
    await db_session.commit()
    await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    monkeypatch.setattr(store, "RENDERER_REVISION", store.RENDERER_REVISION + 1)
    calls = _count_inline(monkeypatch)
    polled = await client.get(CONFIG_URL, headers=headers)
    assert polled.status_code == 304, polled.text
    assert calls == []


@pytest.mark.asyncio
async def test_one_inline_attempt_per_server_at_a_time(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    bounded: None,
    redis_ok: object,
) -> None:
    """Another replica is building this server's bundle: this one waits."""
    server, headers = await _stored_then_marked(db_session)
    await db_session.execute(
        text(
            "update dns_server set bundle_dirty_at = now() - interval '200 seconds' "
            "where id = :s"
        ),
        {"s": server.id},
    )
    await db_session.commit()
    lock_key = INLINE_LOCK_PREFIX + str(server.id)
    stored_etag = server.bundle_etag
    rc = redis_ok
    await rc.set(lock_key, "another-replica", ex=60)  # type: ignore[attr-defined]
    try:
        calls = _count_inline(monkeypatch)
        polled = await client.get(CONFIG_URL, headers=headers)
        assert polled.status_code == 200, polled.text
        assert etag_matches(polled.headers["etag"], stored_etag)
        assert calls == []
    finally:
        await rc.delete(lock_key)  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_a_failed_inline_attempt_backs_off_every_replica(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    bounded: None,
    redis_ok: object,
) -> None:
    """At a million records each attempt costs a 30 s query and fails: one
    per backoff window, not one per poll."""
    server, headers = await _stored_then_marked(db_session)
    await db_session.execute(
        text(
            "update dns_server set bundle_dirty_at = now() - interval '200 seconds' "
            "where id = :s"
        ),
        {"s": server.id},
    )
    await db_session.commit()
    server_id = str(server.id)
    stored_etag = server.bundle_etag
    backoff_key = INLINE_BACKOFF_PREFIX + server_id
    rc = redis_ok
    try:
        calls = _count_inline(monkeypatch, fail=True)
        first = await client.get(CONFIG_URL, headers=headers)
        second = await client.get(CONFIG_URL, headers=headers)
        # Both polls get the worker's newest render.
        assert first.status_code == 200 and second.status_code == 200
        assert etag_matches(first.headers["etag"], stored_etag)
        assert etag_matches(second.headers["etag"], stored_etag)
        assert calls == [1], f"{len(calls)} inline attempts across two polls, want 1"
        assert await rc.ttl(backoff_key) > 0  # type: ignore[attr-defined]
    finally:
        await rc.delete(backoff_key)  # type: ignore[attr-defined]
