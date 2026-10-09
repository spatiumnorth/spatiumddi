"""Celery's Redis transport must time out and keepalive dead peers (#1669).

kombu leaves socket_timeout / socket_connect_timeout / socket_keepalive unset,
so a Redis master lost with its node left every worker deaf until its liveness
probe killed it, and the warm shutdown blocked on the dead socket.
"""

from __future__ import annotations

import socket

from app.celery_app import (
    REDIS_SOCKET_CONNECT_TIMEOUT_S,
    REDIS_SOCKET_TIMEOUT_S,
    build_redis_transport_options,
    celery_app,
)

# kombu 5.6.2 Transport.brpop_timeout: the synchronous path blocks this long
# on the socket for every idle BRPOP.
_KOMBU_BRPOP_TIMEOUT_S = 1


def test_socket_timeout_exceeds_brpop_block():
    assert REDIS_SOCKET_TIMEOUT_S > _KOMBU_BRPOP_TIMEOUT_S * 2
    assert REDIS_SOCKET_CONNECT_TIMEOUT_S < REDIS_SOCKET_TIMEOUT_S


def test_sentinel_options_cover_broker_and_sentinel_queries():
    o = build_redis_transport_options("sentinel://s:26379", "mymaster", "pw")
    assert o["master_name"] == "mymaster"
    for d in (o, o["sentinel_kwargs"]):
        assert d["socket_timeout"] == REDIS_SOCKET_TIMEOUT_S
        assert d["socket_connect_timeout"] == REDIS_SOCKET_CONNECT_TIMEOUT_S
        assert d["socket_keepalive"] is True
    assert o["sentinel_kwargs"]["password"] == "pw"


def test_sentinel_without_password_still_gets_timeouts():
    o = build_redis_transport_options("sentinel://s:26379", "m", None)
    assert "password" not in o["sentinel_kwargs"]
    assert o["sentinel_kwargs"]["socket_timeout"] == REDIS_SOCKET_TIMEOUT_S


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
    assert celery_app.conf.redis_socket_timeout == REDIS_SOCKET_TIMEOUT_S
    assert celery_app.conf.redis_socket_keepalive is True
