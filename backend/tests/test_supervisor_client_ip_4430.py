"""#4430 — the supervisor's source address behind the api pod's TLS sidecar.

The sidecar reaches the app over the pod's loopback, so a supervisor that came
in over TLS would otherwise be recorded as 127.0.0.1. ``X-Forwarded-For`` is
believed from a loopback peer only; from anyone else it is spoofable input.
"""

from __future__ import annotations

import pytest
from starlette.requests import Request

from app.api.v1.appliance.supervisor import _client_ip


def _request(peer: str | None, xff: str | None = None) -> Request:
    headers = [(b"x-forwarded-for", xff.encode())] if xff is not None else []
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": headers,
            "client": (peer, 40000) if peer is not None else None,
        }
    )


@pytest.mark.parametrize("loopback", ["127.0.0.1", "::1"])
def test_sidecar_forwarded_address_is_used_from_loopback(loopback: str) -> None:
    assert _client_ip(_request(loopback, "10.1.2.3")) == "10.1.2.3"


def test_only_the_first_forwarded_address_counts() -> None:
    assert _client_ip(_request("127.0.0.1", "10.1.2.3, 10.9.9.9")) == "10.1.2.3"


def test_loopback_without_the_header_is_the_peer() -> None:
    assert _client_ip(_request("127.0.0.1")) == "127.0.0.1"


def test_forwarded_header_from_any_other_peer_is_ignored() -> None:
    assert _client_ip(_request("10.42.0.9", "203.0.113.7")) == "10.42.0.9"


def test_no_client_is_none() -> None:
    assert _client_ip(_request(None)) is None
