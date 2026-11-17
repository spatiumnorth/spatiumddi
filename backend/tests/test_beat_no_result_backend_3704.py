"""#3704 — sending a task must not SUBSCRIBE to its result channel.

The Redis result backend SUBSCRIBEd each sent task's result channel, and each
``AsyncResult``'s ``__del__`` UNSUBSCRIBEd it, on a pub/sub connection that is
only read by a caller blocked in ``.get()``. Nothing here calls ``.get()``, so
redis-py kept every channel (``PubSub.channels`` +
``pending_unsubscribe_channels``) for the life of the process: beat grew
~40 MiB/day until its 256Mi limit OOM-killed it, and the api leaked the same
way at its own dispatch rate.

These tests drive the real send paths (``send_task``, ``Task.delay`` and
beat's ``Scheduler.apply_async``) with only the broker publish stubbed, and
record what the backend asks redis-py's PubSub to do.
"""

from __future__ import annotations

import contextlib
import gc
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from celery.backends.redis import RedisBackend
from celery.beat import PersistentScheduler

from app.celery_app import celery_app


@pytest.fixture()
def redis_client(monkeypatch: pytest.MonkeyPatch) -> mock.MagicMock:
    backend = celery_app.backend
    assert isinstance(backend, RedisBackend)
    consumer = backend.result_consumer
    monkeypatch.setattr(consumer, "_pubsub", None)
    monkeypatch.setattr(consumer, "subscribed_to", set())

    client = mock.MagicMock(name="Redis")
    client.pubsub.return_value = mock.MagicMock(name="PubSub")
    # ``client`` is a cached_property on the backend; shadow it per test.
    monkeypatch.setitem(backend.__dict__, "client", client)

    # Stub only the broker publish, so the rest of send_task runs for real.
    @contextlib.contextmanager
    def _producer(*_a: Any, **_kw: Any) -> Iterator[mock.MagicMock]:
        yield mock.MagicMock(name="Producer")

    monkeypatch.setattr(celery_app, "producer_or_acquire", _producer)
    monkeypatch.setattr(celery_app.amqp, "send_task_message", mock.MagicMock())
    return client


def _assert_no_pubsub_traffic(client: mock.MagicMock) -> None:
    gc.collect()  # run every dropped AsyncResult's __del__
    pubsub = client.pubsub.return_value
    assert pubsub.subscribe.call_count == 0
    assert pubsub.unsubscribe.call_count == 0
    assert celery_app.backend.result_consumer.subscribed_to == set()


def test_send_task_does_not_subscribe_to_the_result(redis_client: mock.MagicMock) -> None:
    for _ in range(50):
        celery_app.send_task("app.tasks.update_check.check_github_release")
    _assert_no_pubsub_traffic(redis_client)


def test_task_delay_from_the_api_does_not_subscribe(redis_client: mock.MagicMock) -> None:
    from app.tasks.dhcp_fingerprint import lookup_fingerprint_task

    for _ in range(50):
        lookup_fingerprint_task.delay("00:11:22:33:44:55", "server")
    _assert_no_pubsub_traffic(redis_client)


def test_beat_sends_do_not_subscribe(redis_client: mock.MagicMock, tmp_path: Path) -> None:
    sched = PersistentScheduler(app=celery_app, schedule_filename=str(tmp_path / "sched"))
    try:
        name = next(n for n in celery_app.conf.beat_schedule if n in sched.schedule)
        for _ in range(50):
            sched.apply_async(sched.schedule[name], advance=False)
        _assert_no_pubsub_traffic(redis_client)
        # The backend is still Redis (it autoexpires), so beat adds no
        # celery.backend_cleanup entry of its own.
        assert "celery.backend_cleanup" not in sched.schedule
    finally:
        sched.close()


def test_results_are_still_stored_by_the_redis_backend() -> None:
    # Only the send-time subscribe is gone; the backend workers store results
    # in, and the api reads task state from, is unchanged.
    assert isinstance(celery_app.backend, RedisBackend)
    assert celery_app.conf.task_ignore_result is False
