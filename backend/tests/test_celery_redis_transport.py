"""Celery's Redis transport must time out and keepalive dead peers (#1669).

kombu leaves socket_timeout / socket_connect_timeout / socket_keepalive unset,
so a Redis master lost with its node left every worker deaf until its liveness
probe killed it, and the warm shutdown blocked on the dead socket.
"""

from __future__ import annotations

import socket

from app.celery_app import (
    DNS_LOOKUP_STALL_S,
    REDIS_RESULT_CONNECT_TIMEOUT_S,
    REDIS_RESULT_SOCKET_TIMEOUT_S,
    REDIS_RESULT_STORE_RETRIES,
    REDIS_SENTINEL_CONNECT_TIMEOUT_S,
    REDIS_SENTINEL_SOCKET_TIMEOUT_S,
    REDIS_SOCKET_CONNECT_TIMEOUT_S,
    REDIS_SOCKET_TIMEOUT_S,
    WORKER_TERMINATION_GRACE_S,
    build_redis_transport_options,
    celery_app,
)
from app.services.upgrades.per_node import DEFAULT_DRAIN_TIMEOUT_S

# kombu 5.6.2 Transport.brpop_timeout: Channel.close() reads an outstanding
# BRPOP reply without polling, and a live server answers within this.
_KOMBU_BRPOP_TIMEOUT_S = 1


def test_socket_timeout_exceeds_brpop_block():
    assert REDIS_SOCKET_TIMEOUT_S > _KOMBU_BRPOP_TIMEOUT_S * 2
    assert REDIS_SOCKET_CONNECT_TIMEOUT_S < REDIS_SOCKET_TIMEOUT_S


def test_sentinel_options_cover_broker_and_sentinel_queries():
    o = build_redis_transport_options("sentinel://s:26379", "mymaster", "pw")
    assert o["master_name"] == "mymaster"
    assert o["socket_timeout"] == REDIS_SOCKET_TIMEOUT_S
    assert o["socket_connect_timeout"] == REDIS_SOCKET_CONNECT_TIMEOUT_S
    sk = o["sentinel_kwargs"]
    assert sk["socket_timeout"] == REDIS_SENTINEL_SOCKET_TIMEOUT_S
    assert sk["socket_connect_timeout"] == REDIS_SENTINEL_CONNECT_TIMEOUT_S
    for d in (o, sk):
        assert d["socket_keepalive"] is True
    assert sk["password"] == "pw"


def test_sentinel_without_password_still_gets_timeouts():
    o = build_redis_transport_options("sentinel://s:26379", "m", None)
    assert "password" not in o["sentinel_kwargs"]
    assert o["sentinel_kwargs"]["socket_timeout"] == REDIS_SENTINEL_SOCKET_TIMEOUT_S


def test_plain_redis_gets_timeouts_but_no_master():
    o = build_redis_transport_options("redis://r:6379/1", "m", None)
    assert o["socket_timeout"] == REDIS_SOCKET_TIMEOUT_S
    assert "master_name" not in o and "sentinel_kwargs" not in o


def test_keepalive_options_are_linux_constants_when_defined():
    o = build_redis_transport_options("redis://r:6379/1", "m", None)
    ka = o["socket_keepalive_options"]
    if hasattr(socket, "TCP_KEEPIDLE"):
        assert ka[socket.TCP_KEEPIDLE] == 10
        assert ka[socket.TCP_KEEPCNT] == 3


def test_unix_socket_broker_gets_nothing():
    assert build_redis_transport_options("unix:///x.sock", "m", None) == {}


def test_app_conf_carries_options_in_this_deployment():
    # The default test URL is redis://, so the broker carries timeouts and the
    # result backend inherits the redis_socket_* settings celery reads.
    assert celery_app.conf.broker_transport_options["socket_timeout"] == REDIS_SOCKET_TIMEOUT_S
    assert celery_app.conf.redis_socket_timeout == REDIS_RESULT_SOCKET_TIMEOUT_S
    assert celery_app.conf.redis_socket_keepalive is True


def test_redis_py_applies_the_keepalive_options_to_a_real_socket():
    # The options are only useful if redis-py accepts them in the form passed
    # and they land on the socket; ``_connect`` opens the TCP connection
    # without the RESP handshake, so a bare listener is enough.
    from redis.connection import Connection

    o = build_redis_transport_options("redis://r:6379/1", "m", None)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    conn = Connection(
        host="127.0.0.1",
        port=listener.getsockname()[1],
        socket_connect_timeout=o["socket_connect_timeout"],
        socket_keepalive=o["socket_keepalive"],
        socket_keepalive_options=o["socket_keepalive_options"],
    )
    sock = conn._connect()
    try:
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 1
        if hasattr(socket, "TCP_KEEPIDLE"):
            assert sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE) == 10
        if hasattr(socket, "TCP_USER_TIMEOUT"):
            assert sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT) == 25_000
    finally:
        sock.close()
        listener.close()


def test_sentinel_kwargs_reach_the_sentinel_clients():
    # redis-py builds one client per Sentinel from sentinel_kwargs verbatim,
    # so the timeouts must be IN sentinel_kwargs to bound a Sentinel query.
    from redis.sentinel import Sentinel

    o = build_redis_transport_options("sentinel://s:26379", "m", "pw")
    s = Sentinel([("s", 26379)], sentinel_kwargs=o["sentinel_kwargs"])
    kw = s.sentinels[0].connection_pool.connection_kwargs
    assert kw["socket_timeout"] == REDIS_SENTINEL_SOCKET_TIMEOUT_S
    assert kw["socket_connect_timeout"] == REDIS_SENTINEL_CONNECT_TIMEOUT_S
    assert kw["socket_keepalive"] is True
    assert kw["password"] == "pw"


def test_sentinel_lookups_are_not_retried_inside_redis_py():
    # redis-py's default for a pool-less client (3 retries, nested around the
    # command AND its connect) made one lookup against an unreachable Sentinel
    # take ~100 s, holding a warm shutdown past its grace period.
    from redis.sentinel import Sentinel

    o = build_redis_transport_options("sentinel://s:26379", "m", None)
    assert o["sentinel_kwargs"]["retry"].get_retries() == 0
    s = Sentinel([("s", 26379)], sentinel_kwargs=o["sentinel_kwargs"])
    assert s.sentinels[0].connection_pool.connection_kwargs["retry"].get_retries() == 0
    # the broker's own (master) connections are untouched by it
    assert "retry" not in o


def test_result_writes_retry_a_bounded_number_of_times():
    assert celery_app.conf.result_backend_always_retry is True
    assert celery_app.conf.result_backend_max_retries == REDIS_RESULT_STORE_RETRIES
    assert celery_app.conf.redis_socket_timeout == REDIS_RESULT_SOCKET_TIMEOUT_S
    assert celery_app.conf.redis_socket_connect_timeout == REDIS_RESULT_CONNECT_TIMEOUT_S


def test_worst_case_result_write_fits_a_warm_shutdown():
    # With no master, a failing write costs the stale socket's read, then per
    # retry one Sentinel lookup + one connect + the max backoff. On a warm
    # shutdown it happens twice (pool child, then the parent's on_failure),
    # beside Channel.close()'s two broker reads; all inside the pod's grace.
    # Each retry can also stall once in getaddrinfo (#1754): the reconnect to
    # the lost node's Sentinel. No socket timeout bounds it; the worker pod's
    # resolver options (timeout:2 attempts:2, x2 search candidates) cap it.
    backoff_s = celery_app.conf.result_backend_max_sleep_between_retries_ms / 1000

    def shutdown_s(lookup_stall_s: float) -> float:
        write = REDIS_RESULT_SOCKET_TIMEOUT_S + REDIS_RESULT_STORE_RETRIES * (
            REDIS_SENTINEL_SOCKET_TIMEOUT_S
            + REDIS_RESULT_CONNECT_TIMEOUT_S
            + backoff_s
            + lookup_stall_s
        )
        return 2 * write + 2 * REDIS_SOCKET_TIMEOUT_S

    assert DNS_LOOKUP_STALL_S == 8
    # margin for the rest of a warm shutdown (pool join, signal handling)
    assert shutdown_s(DNS_LOOKUP_STALL_S) + 5 < WORKER_TERMINATION_GRACE_S
    # With glibc's default options (timeout:5 attempts:2, the ~20 s lookups the
    # #1717 walk measured) the same estimate does not fit: the pod's resolver
    # options, not the grace alone, are what make the number hold.
    assert shutdown_s(5 * 2 * 2) > WORKER_TERMINATION_GRACE_S
    # The upgrade orchestrator's drain waits for a terminating worker pod to
    # be gone, so the grace must leave it room.
    assert WORKER_TERMINATION_GRACE_S + 20 <= DEFAULT_DRAIN_TIMEOUT_S


def test_worker_uses_the_capped_reconnect_consumer(monkeypatch):
    from celery.utils.imports import symbol_by_name
    from celery.worker.consumer import Consumer
    from kombu.utils.functional import fxrange

    from app.celery_app import CONSUMER_RECONNECT_INTERVAL_MAX_S, SpatiumConsumer

    assert symbol_by_name(celery_app.conf.worker_consumer) is SpatiumConsumer

    seen: dict = {}

    class FakeConn:
        def ensure_connection(self, *args, **kwargs):
            seen["args"], seen["kwargs"] = args, kwargs
            return self

    monkeypatch.setattr(Consumer, "ensure_connected", lambda self, conn: conn)
    consumer = object.__new__(SpatiumConsumer)
    conn = consumer.ensure_connected(FakeConn())
    # celery calls it as ensure_connection(errback, max_retries, callback=...)
    conn.ensure_connection("errback", 100, callback="cb")
    kw = seen["kwargs"]
    assert seen["args"] == ("errback", 100) and kw["callback"] == "cb"
    # kombu's retry_over_time sleeps through exactly this range
    waits = fxrange(
        kw["interval_start"],
        kw["interval_max"] + kw["interval_start"],
        kw["interval_step"],
        repeatlast=True,
    )
    first = [next(waits) for _ in range(6)]
    assert max(first) == CONSUMER_RECONNECT_INTERVAL_MAX_S
    assert first[0] <= first[1] and first[-1] == CONSUMER_RECONNECT_INTERVAL_MAX_S


def _raise_from(filename: str) -> AttributeError:
    code = compile("def f():\n    None.client\n", filename, "exec")
    ns: dict = {}
    exec(code, ns)
    try:
        ns["f"]()
    except AttributeError as exc:
        return exc
    raise AssertionError("unreachable")


def test_broker_failure_classification():
    from kombu.exceptions import EncodeError, OperationalError
    from redis.exceptions import ConnectionError as RedisConnectionError
    from redis.exceptions import TimeoutError as RedisTimeoutError

    from app.celery_app import _is_broker_failure

    assert _is_broker_failure(OperationalError("No master found"))
    assert _is_broker_failure(RedisConnectionError("x"))
    assert _is_broker_failure(RedisTimeoutError("x"))
    # kombu's closed-channel publish bug, seen on the ddi-pg walk
    assert _is_broker_failure(_raise_from("/x/site-packages/kombu/transport/redis.py"))
    # anything else must keep celery's drop, or a bad message loops forever
    assert not _is_broker_failure(_raise_from("/app/app/tasks/foo.py"))
    assert not _is_broker_failure(EncodeError("unserialisable"))
    assert not _is_broker_failure(None)


def test_every_task_uses_the_requeueing_base():
    from app.celery_app import SpatiumTask

    celery_app.loader.import_default_modules()
    names = [n for n in celery_app.tasks if n.startswith("app.")]
    assert names
    assert all(isinstance(celery_app.tasks[n], SpatiumTask) for n in names)


def test_retry_rejected_by_the_broker_is_requeued(monkeypatch):
    import pytest
    from celery import Task
    from celery.exceptions import Reject
    from kombu.exceptions import EncodeError, OperationalError

    import app.tasks.event_outbox  # noqa: F401 — registers the task; don't rely on test order
    from app.celery_app import SpatiumTask

    task = celery_app.tasks["app.tasks.event_outbox.process_event_outbox"]

    def broker_down(self, *a, **kw):
        raise Reject(OperationalError("No master found"), requeue=False)

    monkeypatch.setattr(Task, "retry", broker_down)
    with pytest.raises(Reject) as info:
        SpatiumTask.retry(task)
    assert info.value.requeue is True

    def bad_payload(self, *a, **kw):
        raise Reject(EncodeError("nope"), requeue=False)

    monkeypatch.setattr(Task, "retry", bad_payload)
    with pytest.raises(Reject) as info:
        SpatiumTask.retry(task)
    assert info.value.requeue is False
