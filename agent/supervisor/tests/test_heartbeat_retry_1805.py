"""#1805 — a heartbeat that never reached the control plane is re-sent within
seconds, not after the whole interval.

A member's hard loss makes heartbeats fail for a few seconds to a minute: a
lookup routed to the lost node's DNS, a connection to its api pod, the api
Service empty while the api waits for Redis. Each failure used to cost the
full 30 s interval on top, so two in a row put a healthy seed past the 90 s
after which the demote guard calls it unhealthy (the issue's 2-minute stall).
"""

from __future__ import annotations

import types
import uuid
from pathlib import Path

import httpx
import pytest
import structlog

from spatium_supervisor import appliance_state as st
from spatium_supervisor import heartbeat as hb


def test_held_heartbeat_rearms_after_the_floor() -> None:
    assert hb.next_heartbeat_delay(True, 0, 30.0, 2.0) == 2.0


def test_unheld_answer_waits_the_interval() -> None:
    assert hb.next_heartbeat_delay(False, 0, 30.0, 2.0) == 30.0


def test_failed_heartbeat_is_resent_after_5s_doubling_up_to_the_interval() -> None:
    delays = [hb.next_heartbeat_delay(None, n, 30.0, 2.0) for n in range(1, 7)]
    assert delays == [5.0, 10.0, 20.0, 30.0, 30.0, 30.0]


def test_failed_retry_never_exceeds_a_short_interval() -> None:
    assert hb.next_heartbeat_delay(None, 1, 3.0, 2.0) == 3.0


def test_two_failures_in_a_row_stay_well_inside_the_demote_guard() -> None:
    # The issue's sequence: the in-flight heartbeat fails (its connection or
    # lookup went to the lost node), the next is refused while the api waits for
    # Redis, the third lands. The added wait is 5 + 10 s, not 30 + 30 s.
    waited = sum(hb.next_heartbeat_delay(None, n, 30.0, 2.0) for n in (1, 2))
    assert waited == 15.0


def _quiet_heartbeat(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(st, "collect", dict)
    monkeypatch.setattr(st, "detect_deployment_kind", lambda: "docker")
    monkeypatch.setattr(st, "read_firewall_state", dict)
    monkeypatch.setattr(hb, "probe_port_conflicts", dict)
    monkeypatch.setattr(hb, "_capabilities_payload", dict)
    monkeypatch.setattr(hb, "_effective_control_plane_url", lambda cfg: "http://cp.invalid")
    monkeypatch.setattr(hb, "load_cert", lambda d: None)


@pytest.mark.parametrize(
    "error",
    [
        httpx.ConnectError("[Errno -3] Try again"),
        httpx.ConnectError("[Errno 111] Connection refused"),
        httpx.ReadTimeout("timed out"),
    ],
)
def test_transport_error_returns_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, error: httpx.HTTPError
) -> None:
    _quiet_heartbeat(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        error.request = request
        raise error

    cfg = types.SimpleNamespace(heartbeat_interval_seconds=30, state_dir=tmp_path)
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        held = hb.heartbeat_once(
            cfg, uuid.uuid4(), "tok", None, client, structlog.get_logger()  # type: ignore[arg-type]
        )
    assert held is None
