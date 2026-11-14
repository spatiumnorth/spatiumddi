"""#3851 — a version hand-off whose 5 s hop was lost with its worker is
re-driven off the hop heartbeat, not after the 900 s grace."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from redis.exceptions import RedisError

from app.services.appliance import k8s
from app.services.upgrades import orchestrator, shared_tags

T0 = 1_000_000.0
OLD = "2026.10.01-1"


class FakeRedis:
    """Key store with TTLs against a settable clock."""

    def __init__(self) -> None:
        self.d: dict[str, tuple[str, float | None]] = {}
        self.clock = T0
        self.broken = False

    def get(self, k: str) -> str | None:
        if self.broken:
            raise RedisError("down")
        v = self.d.get(k)
        if v is None or (v[1] is not None and v[1] <= self.clock):
            return None
        return v[0]

    def set(self, k: str, v: str, nx: bool = False, ex: int | None = None) -> bool:
        if self.broken:
            raise RedisError("down")
        if nx and self.get(k) is not None:
            return False
        self.d[k] = (v, None if ex is None else self.clock + ex)
        return True

    def delete(self, k: str) -> int:
        return 1 if self.d.pop(k, None) is not None else 0


def _progress(marker: bool | None = True) -> dict[str, Any]:
    at = datetime.fromtimestamp(T0, UTC).isoformat()
    flip: dict[str, Any] = {"handed_off_at": at}
    if marker is not None:
        flip["hop_heartbeat"] = marker
    return {
        "events": [{"event": "drive_version_handoff", "at": at}],
        shared_tags.PROGRESS_KEY: {"from_tag": OLD, "flip": flip},
    }


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> tuple[FakeRedis, list[Any]]:
    from app.core import redis_client as rc
    from app.services.upgrades import mutex
    from app.tasks import upgrade_orchestrator as t

    r = FakeRedis()
    monkeypatch.setattr(rc, "make_sync_redis", lambda *a, **kw: r)
    monkeypatch.setattr(k8s, "get_config", object)
    monkeypatch.setattr(mutex, "read_state_strict", lambda: type("S", (), {"held": False})())
    calls: list[Any] = []
    monkeypatch.setattr(
        t.drive_upgrade_run, "apply_async", lambda **kw: calls.append(kw), raising=False
    )
    return r, calls


def _sweep(r: FakeRedis, rid: uuid.UUID, at: float, progress: dict[str, Any]) -> list[str]:
    from app.tasks import upgrade_orchestrator as t

    r.clock = at
    return t.resume_orphaned_runs_sync([(rid, progress)], r, now=at)


def test_lost_hop_is_redriven_exactly_once_within_two_minutes(
    env: tuple[FakeRedis, list[Any]],
) -> None:
    r, calls = env
    rid = uuid.uuid4()
    p = _progress()
    # The holder passed the hop on at T0+20 and was then killed: no more writes.
    r.clock = T0 + 20
    orchestrator.touch_hop_heartbeat(rid)
    assert _sweep(r, rid, T0 + 30, p) == []  # key live: in transit
    assert _sweep(r, rid, T0 + 70, p) == []  # expired (65 s): first sighting
    assert _sweep(r, rid, T0 + 100, p) == []  # too soon after the sighting
    assert _sweep(r, rid, T0 + 130, p) == [str(rid)]  # second sighting
    assert _sweep(r, rid, T0 + 190, p) == []  # cooldown (SET NX)
    assert len(calls) == 1
    assert calls[0]["kwargs"] == {"avoid_version": OLD}


def test_live_heartbeat_keeps_the_run_in_transit(env: tuple[FakeRedis, list[Any]]) -> None:
    r, calls = env
    rid = uuid.uuid4()
    p = _progress()
    for i in range(1, 120):  # a healthy chain, 5 s hops, for 10 minutes
        r.clock = T0 + 5 * i
        orchestrator.touch_hop_heartbeat(rid)
        assert _sweep(r, rid, T0 + 5 * i, p) == []
    assert calls == []


def test_late_duplicate_hop_after_redrive_is_harmless(env: tuple[FakeRedis, list[Any]]) -> None:
    """A stray copy re-heartbeating after the re-drive only keeps the run in
    transit; it can never produce a second re-drive."""
    r, calls = env
    rid = uuid.uuid4()
    p = _progress()
    _sweep(r, rid, T0 + 70, p)
    assert _sweep(r, rid, T0 + 130, p) == [str(rid)]
    r.clock = T0 + 135
    orchestrator.touch_hop_heartbeat(rid)  # the stray copy hops
    assert _sweep(r, rid, T0 + 140, p) == []
    assert len(calls) == 1


def test_unreadable_heartbeat_is_in_transit(env: tuple[FakeRedis, list[Any]]) -> None:
    from app.tasks import upgrade_orchestrator as t

    r, _ = env
    r.broken = True
    assert t._redrive_kwargs(_progress(), T0 + 300, r, uuid.uuid4()) is None


def test_no_redis_client_is_the_legacy_path() -> None:
    from app.tasks import upgrade_orchestrator as t

    assert t._redrive_kwargs(_progress(), T0 + 300) is None


@pytest.mark.parametrize("marker", [None, False])
def test_unmarked_run_keeps_the_900s_grace(
    env: tuple[FakeRedis, list[Any]], marker: bool | None
) -> None:
    from app.tasks import upgrade_orchestrator as t

    r, _ = env
    rid = uuid.uuid4()
    p = _progress(marker)
    assert t._redrive_kwargs(p, T0 + 300, r, rid) is None  # key absent, still in transit
    assert t._redrive_kwargs(p, T0 + t._VERSION_HANDOFF_GRACE_S + 1, r, rid) == {
        "avoid_version": OLD
    }


def test_pass_on_writes_the_heartbeat_before_publishing(
    env: tuple[FakeRedis, list[Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.config import settings
    from app.tasks import upgrade_orchestrator as t

    r, calls = env
    monkeypatch.setattr(settings, "version", OLD)
    rid = str(uuid.uuid4())
    order: list[str] = []
    monkeypatch.setattr(
        t.drive_upgrade_run, "apply_async", lambda **kw: order.append("publish"), raising=False
    )
    real_set = r.set
    monkeypatch.setattr(r, "set", lambda *a, **kw: order.append("beat") or real_set(*a, **kw))
    out = t.drive_upgrade_run.run(rid, avoid_version=OLD, hops=3)
    assert out["state"] == "passed_on"
    assert order == ["beat", "publish"]
    assert r.get(orchestrator.hop_heartbeat_key(rid)) is not None


def test_heartbeat_write_failure_does_not_break_the_pass_on(
    env: tuple[FakeRedis, list[Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.config import settings
    from app.tasks import upgrade_orchestrator as t

    r, calls = env
    r.broken = True
    monkeypatch.setattr(settings, "version", OLD)
    out = t.drive_upgrade_run.run(str(uuid.uuid4()), avoid_version=OLD, hops=1)
    assert out["state"] == "passed_on" and len(calls) == 1
    assert orchestrator.touch_hop_heartbeat(uuid.uuid4()) is False


def test_beat_start_enqueues_the_orphan_sweep(monkeypatch: pytest.MonkeyPatch) -> None:
    """The shared-tag flip recreates beat mid hand-off; its first scheduled
    sweep is a full interval away, so one is queued as beat starts."""
    from celery.signals import beat_init

    from app import celery_app as ca

    assert any(
        getattr(r(), "__name__", "") == "_queue_orphan_sweep_at_start"
        for _, r in beat_init.receivers
    )
    sent: list[str] = []
    monkeypatch.setattr(ca.celery_app, "send_task", lambda name, *a, **kw: sent.append(name))
    ca._queue_orphan_sweep_at_start()
    assert sent == ["app.tasks.upgrade_orchestrator.resume_orphaned_runs"]


def test_beat_start_sweep_failing_to_queue_never_blocks_beat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app import celery_app as ca

    def boom(*a: Any, **kw: Any) -> None:
        raise RuntimeError("broker down")

    monkeypatch.setattr(ca.celery_app, "send_task", boom)
    ca._queue_orphan_sweep_at_start()  # must not raise


def test_sighting_before_a_beat_restart_counts_after_it(
    env: tuple[FakeRedis, list[Any]],
) -> None:
    """The first sighting is in Redis, not in the beat process: a sweep run
    by the restarted beat at start is the second sighting and re-drives."""
    from app.tasks import upgrade_orchestrator as t

    r, calls = env
    rid = uuid.uuid4()
    p = _progress()
    assert _sweep(r, rid, T0 + 70, p) == []  # old beat: first sighting
    # old beat killed; ~200 s with no sweep; the new beat's start-up sweep:
    r.clock = T0 + 270
    assert t.resume_orphaned_runs_sync([(rid, p)], r, now=T0 + 270) == [str(rid)]
    assert len(calls) == 1
