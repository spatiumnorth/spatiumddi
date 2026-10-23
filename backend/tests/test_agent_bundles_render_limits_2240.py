"""#2240: the render's time limits follow the data, and more than one render
may run at once.

* At ~2M records (1M devices) every render of a server's bundle was killed at
  the fixed ``time_limit=960``. The limits travel in each task message, so
  every publish sets them from the group's record count
  (``render_time_limits``), and a render whose message is too short for the
  group as it is now republishes itself sized for it instead of starting.
* One fleet-wide render slot queued seven servers' full renders behind each
  other for hours. ``dns_agent_bundle_render_slots`` gives N slots; slot 0
  keeps the old key, so one slot behaves exactly as before.

The first half needs neither Postgres nor Redis; the rest uses the suite's
database and, where it says so, a real Redis on its own key names.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from app import db as app_db
from app.config import settings
from app.core.redis_client import make_async_redis
from app.core.task_attempts import DELIVERY_KEY_PREFIX
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.tasks import agent_bundles

# ── The formula ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "records,expected",
    [
        (None, (900, 960)),
        (0, (900, 960)),
        (100_000, (900, 960)),  # 120 + 150 = 270 s: the floor
        (520_000, (900, 960)),  # 120 + 780 = 900 s: the floor's edge
        (600_000, (1020, 1080)),
        (1_000_000, (1620, 1680)),
        (2_000_000, (3120, 3180)),  # the scale lab's 2M records
        (100_000_000, (21600, 21660)),  # the 6 h ceiling
    ],
)
def test_render_time_limits_scale_with_the_record_count(records, expected) -> None:
    assert agent_bundles.render_time_limits(records) == expected


def test_the_task_default_is_the_floor() -> None:
    task = agent_bundles.render_dns_bundle
    assert (task.soft_time_limit, task.time_limit) == agent_bundles.render_time_limits(None)
    assert agent_bundles.DIRTY_FLAG_SECONDS >= agent_bundles.render_time_limits(10**12)[1]


def _capture_publish(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    published: list[dict[str, Any]] = []
    monkeypatch.setattr(
        agent_bundles.render_dns_bundle, "apply_async", lambda *a, **kw: published.append(kw)
    )
    return published


def test_enqueue_render_puts_the_limits_in_the_message(monkeypatch: pytest.MonkeyPatch) -> None:
    published = _capture_publish(monkeypatch)
    assert agent_bundles.enqueue_render("srv-a", records=2_000_000)
    assert agent_bundles.enqueue_render("srv-b")
    big, unknown = published
    assert (big["soft_time_limit"], big["time_limit"]) == (3120, 3180)
    assert (unknown["soft_time_limit"], unknown["time_limit"]) == (900, 960)
    for message in published:
        assert message["queue"] == "bundles" and message["retry"] is False
        assert "kwargs" not in message and "countdown" not in message


def test_enqueue_render_reports_a_broker_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def _down(*_a, **_kw):  # noqa: ANN002, ANN003
        raise ConnectionError("broker down")

    monkeypatch.setattr(agent_bundles.render_dns_bundle, "apply_async", _down)
    assert agent_bundles.enqueue_render("srv", records=10) is False


class _Req:
    def __init__(self, timelimit: Any) -> None:
        self.timelimit = timelimit


class _Task:
    def __init__(self, timelimit: Any) -> None:
        self.request = _Req(timelimit)


@pytest.mark.parametrize(
    "timelimit,expected",
    [
        (None, (900, 960)),  # a direct call
        ((None, None), (900, 960)),  # a message from before #2240
        ([3180, 3120], (3120, 3180)),  # Celery's header is [hard, soft]
        ((None, 3120), (3120, 3180)),
    ],
)
def test_the_running_message_limits_are_read_from_its_request(timelimit, expected) -> None:
    assert agent_bundles._message_limits(_Task(timelimit)) == expected


def _run_task_with(
    monkeypatch: pytest.MonkeyPatch, outcome: dict[str, Any], timelimit: Any
) -> tuple[dict[str, Any], list[dict[str, Any]], list[int | None]]:
    published = _capture_publish(monkeypatch)
    seen: list[int | None] = []

    async def _fake_run(server_id, lock_token=None, soft_limit=None):  # noqa: ANN001
        seen.append(soft_limit)
        return dict(outcome)

    monkeypatch.setattr(agent_bundles, "_run", _fake_run)
    task = agent_bundles.render_dns_bundle
    task.push_request(timelimit=timelimit)
    try:
        result = task.run("srv")
    finally:
        task.pop_request()
    return result, published, seen


def test_a_deferred_retry_keeps_the_limits_of_its_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, published, seen = _run_task_with(
        monkeypatch, {"status": "deferred", "lock_token": "tok"}, [3180, 3120]
    )
    assert seen == [3120], "the render ran under its message's soft limit"
    assert result["status"] == "deferred"
    (retry,) = published
    assert retry["kwargs"] == {"lock_token": "tok"}
    assert retry["countdown"] == agent_bundles.SLOT_RETRY_SECONDS
    assert (retry["soft_time_limit"], retry["time_limit"]) == (3120, 3180), (
        "a render deferred for a slot came back at the 960 s default and was "
        "killed the moment it rendered"
    )


def test_a_render_too_big_for_its_message_republishes_itself_sized_for_the_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, published, seen = _run_task_with(
        monkeypatch,
        {"status": "resize", "records": 2_000_000, "lock_token": "tok", "renders": 0},
        None,
    )
    assert seen == [900]
    (again,) = published
    assert again["kwargs"] == {"lock_token": "tok"}, "the server's lock goes with it"
    assert "countdown" not in again
    # 2M counted, sized for 2.5M (the headroom): 120 + 3750 = 3870 s.
    assert (again["soft_time_limit"], again["time_limit"]) == (3870, 3930)
    assert result["resized_to"] == 3870


# ── The slots, on an in-memory Redis ────────────────────────────────────────


class _FakeRedis:
    """The few commands ``_acquire`` and ``_release`` use, without expiry."""

    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    async def set(self, key, value, nx=False, px=None, ex=None):  # noqa: ANN001, ARG002
        if nx and key in self.data:
            return None
        self.data[key] = value
        return True

    async def get(self, key):  # noqa: ANN001
        return self.data.get(key)

    async def delete(self, *keys):  # noqa: ANN002
        for key in keys:
            self.data.pop(key, None)

    async def eval(self, script, _numkeys, key, value, *_rest):  # noqa: ANN001, ANN002
        if self.data.get(key) != value:
            return 0
        if script == agent_bundles._RELEASE_IF_OWNER:
            del self.data[key]
        return 1


async def _take(client: _FakeRedis, server: str) -> tuple[str, list[str], str]:
    token = uuid.uuid4().hex
    value = f"{server}:{token}"
    status, keys = await agent_bundles._acquire(
        client,
        lock_key=f"lock:{server}",
        dirty_key=f"dirty:{server}",
        token=token,
        slot_value=value,
        lease_ms=60_000,
        resumed=False,
    )
    return status, keys, value


@pytest.mark.asyncio
async def test_one_slot_is_the_original_key_and_nothing_else(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "dns_agent_bundle_render_slots", 1)
    client = _FakeRedis()
    status, keys, value = await _take(client, "a")
    assert (status, keys) == ("held", ["spatium:bundle:render-slot"])
    assert set(client.data) == {
        "lock:a",
        "spatium:bundle:render-slot",
    }, "one slot must take exactly the keys it always took"
    assert (await _take(client, "b"))[:2] == ("deferred", [])
    assert client.data["spatium:bundle:render-slot"] == value


@pytest.mark.asyncio
async def test_n_slots_let_n_renders_run_and_each_releases_its_own(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "dns_agent_bundle_render_slots", 3)
    client = _FakeRedis()
    taken = [await _take(client, s) for s in ("a", "b", "c")]
    assert [t[:2] for t in taken] == [
        ("held", ["spatium:bundle:render-slot"]),
        ("held", ["spatium:bundle:render-slot:1"]),
        ("held", ["spatium:bundle:render-slot:2"]),
    ]
    assert (await _take(client, "d"))[:2] == ("deferred", [])

    # b finishes: it frees slot 1 and nobody else's.
    _status, b_keys, b_value = taken[1]
    for key in b_keys:
        await agent_bundles._release(client, key, b_value)
    assert "spatium:bundle:render-slot:1" not in client.data
    assert client.data["spatium:bundle:render-slot"] == taken[0][2]
    assert client.data["spatium:bundle:render-slot:2"] == taken[2][2]
    # ... and a release by a holder whose lease ran out frees nothing.
    await agent_bundles._release(client, "spatium:bundle:render-slot", b_value)
    assert client.data["spatium:bundle:render-slot"] == taken[0][2]

    status, keys, _value = await _take(client, "e")
    assert (status, keys) == ("held", ["spatium:bundle:render-slot:1"])


@pytest.mark.parametrize("slots,expected", [(0, 1), (-3, 1), (1, 1), (4, 4)])
def test_the_slot_count_is_at_least_one(
    monkeypatch: pytest.MonkeyPatch, slots: int, expected: int
) -> None:
    monkeypatch.setattr(settings, "dns_agent_bundle_render_slots", slots)
    keys = agent_bundles._slot_keys()
    assert len(keys) == expected and keys[0] == agent_bundles.RENDER_SLOT_KEY


# ── Against the database ────────────────────────────────────────────────────


async def _group(db: AsyncSession, records: int = 3) -> DNSServerGroup:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
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
    return grp


async def _server(db: AsyncSession, grp: DNSServerGroup) -> DNSServer:
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
    return server


@pytest.mark.asyncio
async def test_the_render_session_statement_bound_follows_the_soft_limit(
    monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession  # noqa: ARG001
) -> None:
    seen: list[float] = []
    real = app_db.create_async_engine

    def spy(*a, **kw):  # noqa: ANN002, ANN003
        seen.append(kw["connect_args"]["command_timeout"])
        return real(*a, **kw)

    monkeypatch.setattr(app_db, "create_async_engine", spy)
    assert (await agent_bundles._render_once(uuid.uuid4()))["status"] == "gone"
    assert (await agent_bundles._render_once(uuid.uuid4(), 3120))["status"] == "gone"
    assert seen == [settings.task_db_long_command_timeout, 3120]


@pytest.mark.asyncio
async def test_a_render_whose_limit_is_too_short_for_the_group_does_not_start(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    grp = await _group(db_session, records=3)
    server = await _server(db_session, grp)
    await db_session.commit()
    # Three records "take" 120 + 3000 s here.
    monkeypatch.setattr(agent_bundles, "RENDER_SECONDS_PER_1000_RECORDS", 1_000_000.0)

    short = await agent_bundles._render_once(server.id, 900)
    assert short == {"status": "resize", "records": 3, "soft_time_limit": 900}
    await db_session.refresh(server)
    assert server.bundle_watermark is None, "nothing rendered under the short limit"
    assert server.bundle_render_status is None, "a resize is not a failure"

    sized = await agent_bundles._render_once(server.id, 3120)
    assert sized["status"] == "stored", sized
    assert sized["records"] == 3


@pytest.mark.asyncio
async def test_the_sweep_sizes_each_request_from_its_groups_stored_bundles(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "redis_url", "redis://127.0.0.1:1/0")  # nothing listens
    grp = await _group(db_session, records=4)
    rendered = await _server(db_session, grp)
    joined = await _server(db_session, grp)  # a server added to the group: no bundle yet
    lonely = await _server(db_session, await _group(db_session, records=1))
    await db_session.commit()
    assert (await agent_bundles._run(str(rendered.id)))["status"] == "stored"

    async with app_db.task_session() as db:
        known = await agent_bundles.known_records(db, [rendered.id, joined.id, lonely.id])
    assert known == {rendered.id: 4, joined.id: 4}

    captured: dict[str, int | None] = {}

    def _capture(sid: str, records: int | None = None) -> bool:
        captured[sid] = records
        return True

    monkeypatch.setattr(agent_bundles, "enqueue_render", _capture)
    await agent_bundles._sweep()
    assert captured.get(str(joined.id)) == 4, captured
    assert str(lonely.id) in captured and captured[str(lonely.id)] is None
    assert str(rendered.id) not in captured


# ── Against a real Redis ────────────────────────────────────────────────────


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
async def test_a_second_slot_renders_beside_the_first_and_leaves_it_alone(
    db_session: AsyncSession, redis_keys, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, keys = redis_keys
    monkeypatch.setattr(settings, "dns_agent_bundle_render_slots", 2)
    server = await _server(db_session, await _group(db_session))
    await db_session.commit()
    assert await client.set(keys["slot"], "someone-else", ex=60)

    result = await agent_bundles._run(str(server.id))
    assert (
        result["status"] == "stored"
    ), f"with two slots and one taken, the render was {result.get('status')!r}"
    assert await client.get(keys["slot"]) == b"someone-else", "slot 0 is not its to free"
    assert await client.get(keys["slot"] + ":1") is None, "it released the slot it took"
    assert await client.get(keys["lock"] + str(server.id)) is None

    other = await _server(db_session, await _group(db_session))
    await db_session.commit()
    assert await client.set(keys["slot"] + ":1", "a-third", ex=60)
    assert (await agent_bundles._run(str(other.id)))["status"] == "deferred"


@pytest.mark.asyncio
async def test_a_resized_render_keeps_its_lock_frees_its_slot_and_renders_on_return(
    db_session: AsyncSession, redis_keys, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, keys = redis_keys
    server = await _server(db_session, await _group(db_session, records=3))
    await db_session.commit()
    lock_key = keys["lock"] + str(server.id)
    monkeypatch.setattr(agent_bundles, "RENDER_SECONDS_PER_1000_RECORDS", 1_000_000.0)
    published = _capture_publish(monkeypatch)

    def _task(timelimit: Any = None, **kwargs: Any) -> dict[str, Any]:
        # A thread of its own: the task body runs ``asyncio.run``, and
        # Celery's request stack is per thread.
        task = agent_bundles.render_dns_bundle
        task.push_request(timelimit=timelimit)
        try:
            return task.run(str(server.id), **kwargs)
        finally:
            task.pop_request()

    first = await asyncio.to_thread(_task)
    assert first["status"] == "resize" and first["renders"] == 0, first
    (again,) = published
    token = again["kwargs"]["lock_token"]
    # 3 records x 1.25 -> 4 -> 120 + 4000 s.
    assert (again["soft_time_limit"], again["time_limit"]) == (4120, 4180)
    assert await client.get(lock_key) == token.encode(), "the lock waits for the retry"
    assert await client.get(keys["slot"]) is None, "the slot is free for others meanwhile"
    # A duplicate meanwhile coalesces into the retry.
    assert (await agent_bundles._run(str(server.id)))["status"] == "coalesced"

    retry = await asyncio.to_thread(
        _task, [again["time_limit"], again["soft_time_limit"]], lock_token=token
    )
    assert retry["status"] == "stored", retry
    assert len(published) == 1, "sized once, it did not go round again"
    assert await client.get(lock_key) is None and await client.get(keys["slot"]) is None


# ── With the delivery bound (#2271) ─────────────────────────────────────────
#
# Main bounds how often one render message may be delivered, counting on the
# message's task id (``_run_bounded``); this PR renders each message under the
# limits it carries. A redelivery is the same message, so it carries both.


@pytest.mark.parametrize(
    "outcome",
    [
        {"status": "deferred", "lock_token": "tok"},
        {"status": "resize", "records": 3, "lock_token": "tok", "renders": 0},
    ],
)
def test_a_deferral_or_a_resize_goes_out_as_a_new_message(
    monkeypatch: pytest.MonkeyPatch, outcome: dict[str, Any]
) -> None:
    """A render waiting for a slot is republished every couple of seconds.
    Sent again as the same message (its task id, as ``self.retry`` would),
    each wait would count as a lost worker and the bound would abandon a
    render that never started. Each republish is a new message instead, so
    Celery gives it an id, and a delivery count, of its own."""
    published = _capture_publish(monkeypatch)
    counted: list[str | None] = []
    seen: list[int | None] = []

    async def _count(task_name: str, task_id: str | None) -> int:
        counted.append(task_id)
        return 1

    async def _fake_run(server_id, lock_token=None, soft_limit=None):  # noqa: ANN001
        seen.append(soft_limit)
        return dict(outcome)

    monkeypatch.setattr(agent_bundles, "count_delivery", _count)
    monkeypatch.setattr(agent_bundles, "_run", _fake_run)
    task = agent_bundles.render_dns_bundle
    task.push_request(id="message-1", timelimit=[3180, 3120])
    try:
        task.run("srv")
    finally:
        task.pop_request()
    assert counted == ["message-1"], "the task counts its own message's deliveries"
    assert seen == [3120], "and renders under its own message's soft limit"
    (again,) = published
    assert "task_id" not in again, "a republish reused the message's id"


@pytest.mark.asyncio
async def test_a_redelivered_message_renders_under_its_limits_until_the_bound(
    db_session: AsyncSession, redis_keys, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every delivery up to ``MAX_RENDER_DELIVERIES`` renders under the
    message's soft limit; the next renders nothing, republishes nothing and
    records why on the server."""
    client, keys = redis_keys
    server = await _server(db_session, await _group(db_session, records=3))
    await db_session.commit()
    # Three records "take" 120 + 3000 s here: a delivery that lost its
    # message's 3120 s would resize instead of rendering.
    monkeypatch.setattr(agent_bundles, "RENDER_SECONDS_PER_1000_RECORDS", 1_000_000.0)
    published = _capture_publish(monkeypatch)
    renders: list[int] = []  # one entry per render started

    async def _lost(db, srv, *, rendered_by):  # noqa: ANN001, ARG001
        renders.append(1)
        raise MemoryError("simulated: the worker is lost mid-render")

    monkeypatch.setattr(agent_bundles, "render_and_store", _lost)
    task_id = uuid.uuid4().hex

    def _deliver() -> dict[str, Any]:
        # The same message each time: its id and its limits.
        task = agent_bundles.render_dns_bundle
        task.push_request(id=task_id, timelimit=[3180, 3120])
        try:
            return task.run(str(server.id))
        finally:
            task.pop_request()

    try:
        for n in range(1, agent_bundles.MAX_RENDER_DELIVERIES + 1):
            with pytest.raises(MemoryError):
                await asyncio.to_thread(_deliver)
            assert len(renders) == n, f"delivery {n} did not render under its 3120 s"
        last = await asyncio.to_thread(_deliver)
        assert last["status"] == "abandoned", last
        assert len(renders) == agent_bundles.MAX_RENDER_DELIVERIES, "no further render"
        assert published == [], "nothing was deferred, resized or republished"
        await db_session.refresh(server)
        assert server.bundle_render_status == agent_bundles.RENDER_STATUS_FAILED
        assert "delivered" in (server.bundle_render_error or "")
        assert await client.get(keys["lock"] + str(server.id)) is None
        assert await client.get(keys["slot"]) is None
    finally:
        await client.delete(f"{DELIVERY_KEY_PREFIX}{agent_bundles.TASK_RENDER}:{task_id}")
