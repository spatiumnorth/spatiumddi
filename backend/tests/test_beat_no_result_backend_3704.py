"""#3704 — celery beat leaked ~40 MiB/day through the Redis result backend.

Every beat send returns an ``AsyncResult`` whose ``__del__`` UNSUBSCRIBEs a
pub/sub channel nothing in beat reads, and redis-py keeps each one in
``pending_unsubscribe_channels``. Beat never needs a result, so its scheduler
runs with the backend disabled; the worker's backend is untouched.
"""

from __future__ import annotations

from celery.backends.base import DisabledBackend
from celery.backends.redis import RedisBackend

from app.celery_app import NoResultBackendScheduler, celery_app


def test_beat_is_configured_with_the_scheduler() -> None:
    assert celery_app.conf.beat_scheduler == "app.celery_app:NoResultBackendScheduler"


def test_beat_scheduler_drops_the_result_backend(tmp_path) -> None:
    original = celery_app.backend
    assert isinstance(original, RedisBackend)  # what a worker keeps

    sched = NoResultBackendScheduler(app=celery_app, schedule_filename=str(tmp_path / "sched"))
    try:
        assert isinstance(celery_app.backend, DisabledBackend)
        # DisabledBackend does not autoexpire; the swap must come after the
        # schedule is built or beat would add a daily backend_cleanup entry.
        assert "celery.backend_cleanup" not in sched.schedule
        # A send's AsyncResult going away must not touch redis.
        celery_app.AsyncResult("not-a-real-task-id").__del__()
    finally:
        sched.close()
        celery_app._backend = original
