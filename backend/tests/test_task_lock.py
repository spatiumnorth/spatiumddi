"""#4163 — a redelivered late-ack message must not run a second copy."""

from __future__ import annotations

import threading
import time
import uuid
from types import SimpleNamespace
from typing import Any

import pytest

from app.core import task_lock
from app.core.task_lock import single_flight


class FakeRedis:
    """Just enough of redis-py for the guard: SET NX EX, and the two Lua
    scripts (matched by their text), with real TTL expiry."""

    def __init__(self, store: dict[str, tuple[str, float]] | None = None) -> None:
        self.store = store if store is not None else {}
        self.extends = 0

    def _live(self, key: str) -> str | None:
        item = self.store.get(key)
        if item is None or item[1] <= time.monotonic():
            self.store.pop(key, None)
            return None
        return item[0]

    def set(self, key: str, value: str, nx: bool = False, ex: int | None = None) -> bool:
        if nx and self._live(key) is not None:
            return False
        self.store[key] = (value, time.monotonic() + (ex or 10**6))
        return True

    def eval(self, script: str, numkeys: int, key: str, token: str, *rest: Any) -> int:
        if self._live(key) != token:
            return 0
        if script == task_lock._EXTEND_LUA:
            self.extends += 1
            self.store[key] = (token, time.monotonic() + float(rest[0]))
            return 1
        del self.store[key]
        return 1

    def close(self) -> None:
        pass


def _self(task_id: str | None = None) -> Any:
    return SimpleNamespace(name="t.task", request=SimpleNamespace(id=task_id or uuid.uuid4().hex))


@pytest.fixture
def redis(monkeypatch: pytest.MonkeyPatch) -> FakeRedis:
    fake = FakeRedis()
    monkeypatch.setattr(task_lock, "make_sync_redis", lambda *a, **k: fake)
    return fake


def test_concurrent_duplicate_is_noop(redis: FakeRedis) -> None:
    runs: list[str] = []
    started, release = threading.Event(), threading.Event()

    @single_flight(lambda scan: scan)
    def body(self: Any, scan: str) -> str:
        runs.append(scan)
        started.set()
        release.wait(5)
        return "ran"

    first: list[Any] = []
    t = threading.Thread(target=lambda: first.append(body(_self("a"), "scan-1")))
    t.start()
    assert started.wait(5)
    # The redelivery has a different worker but the same natural key.
    assert body(_self("b"), "scan-1") == {"status": "duplicate_skipped"}
    release.set()
    t.join(5)
    assert first == ["ran"]
    assert runs == ["scan-1"]


def test_lock_extended_past_ttl(redis: FakeRedis) -> None:
    @single_flight(lambda scan: scan, ttl=1, heartbeat=0.2)
    def body(self: Any, scan: str) -> str:
        time.sleep(1.6)  # longer than the TTL
        assert body_second(_self("b"), scan) == {"status": "duplicate_skipped"}
        return "ran"

    @single_flight(lambda scan: scan, ttl=1, heartbeat=0.2)
    def body_second(self: Any, scan: str) -> str:  # pragma: no cover - must not run
        raise AssertionError("duplicate ran")

    assert body(_self("a"), "scan-2") == "ran"
    assert redis.extends >= 2


def test_redis_down_runs_task(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: Any, **k: Any) -> Any:
        raise ConnectionError("redis down")

    monkeypatch.setattr(task_lock, "make_sync_redis", boom)

    @single_flight(lambda scan: scan)
    def body(self: Any, scan: str) -> str:
        return "ran"

    assert body(_self(), "x") == "ran"


def test_redelivery_after_finish_runs_and_lock_released(redis: FakeRedis) -> None:
    @single_flight(lambda scan: scan)
    def body(self: Any, scan: str) -> str:
        return "ran"

    assert body(_self("a"), "s") == "ran"
    assert redis.store == {}
    assert body(_self("a"), "s") == "ran"


def test_lock_released_when_task_raises(redis: FakeRedis) -> None:
    @single_flight()
    def body(self: Any) -> None:
        raise RuntimeError("x")

    with pytest.raises(RuntimeError):
        body(_self("tid"))
    assert redis.store == {}


def test_default_key_is_task_id(redis: FakeRedis) -> None:
    @single_flight()
    def body(self: Any) -> str:
        return "ran"

    redis.set(f"{task_lock.LOCK_KEY_PREFIX}t.task:same", "other", nx=True, ex=60)
    assert body(_self("same")) == {"status": "duplicate_skipped"}
    assert body(_self("different")) == "ran"


def test_nmap_task_is_guarded(redis: FakeRedis, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.tasks import nmap

    calls: list[uuid.UUID] = []

    async def fake_run(scan_id: uuid.UUID) -> None:
        calls.append(scan_id)

    monkeypatch.setattr(nmap, "run_scan", fake_run)
    sid = str(uuid.uuid4())
    redis.set(f"{task_lock.LOCK_KEY_PREFIX}app.tasks.nmap.run_scan:{sid}", "live", nx=True, ex=60)
    nmap.run_scan_task.apply(args=(sid,)).get()
    assert calls == []
    other = str(uuid.uuid4())
    nmap.run_scan_task.apply(args=(other,)).get()
    assert calls == [uuid.UUID(other)]
