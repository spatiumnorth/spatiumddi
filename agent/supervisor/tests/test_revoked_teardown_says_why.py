"""A revoked node's teardown that took nothing down says why (#1884).

The heartbeat tears a revoked node's role release down on every rejected
heartbeat once it reads ``revoked``. The teardown takes the kubeapi ``/readyz``
probe first, and a member whose peers had already fenced it out could reach no
kubeapi: the teardown returned ``idle`` and the heartbeat logged nothing,
because it logged only a teardown that stopped something. A teardown that takes
nothing down now logs ``supervisor.heartbeat.revoked_teardown_incomplete`` with
its state and reason, and is tried again on the next revoked heartbeat.
"""

from __future__ import annotations

import types
import uuid
from pathlib import Path

import httpx
import pytest
import structlog
from structlog.testing import capture_logs

from spatium_supervisor import appliance_state, approval_state, heartbeat, service_lifecycle

READYZ_MISS = "kubeapi /readyz not ok"


def _revoked_heartbeats(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, teardown: service_lifecycle.LifecycleResult
) -> list[dict]:
    """REVOCATION_STRIKE_LIMIT rejected heartbeats of an appliance whose
    teardown returns ``teardown``; the events they logged."""
    monkeypatch.setattr(appliance_state, "collect", dict)
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
    monkeypatch.setattr(appliance_state, "read_firewall_state", dict)
    monkeypatch.setattr(heartbeat, "probe_port_conflicts", dict)
    monkeypatch.setattr(heartbeat, "_capabilities_payload", dict)
    monkeypatch.setattr(heartbeat, "_effective_control_plane_url", lambda cfg: "http://cp.invalid")
    monkeypatch.setattr(heartbeat, "load_cert", lambda d: None)
    monkeypatch.setattr(heartbeat, "tear_down_supervised_services", lambda: teardown)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={"detail": "Appliance revoked."},
            headers={heartbeat.REVOCATION_HEADER: "revoked"},
        )

    cfg = types.SimpleNamespace(heartbeat_interval_seconds=0, state_dir=tmp_path)
    with (
        capture_logs() as logs,
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
    ):
        for _ in range(approval_state.REVOCATION_STRIKE_LIMIT):
            heartbeat.heartbeat_once(
                cfg, uuid.uuid4(), "tok", None, client, structlog.get_logger()  # type: ignore[arg-type]
            )
    assert approval_state.read_state(tmp_path) == "revoked"
    return logs


def test_a_revoked_teardown_that_could_not_reach_the_kubeapi_says_why(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """REGRESSION (#1884): the teardown's ``idle`` was logged nowhere."""
    logs = _revoked_heartbeats(
        monkeypatch, tmp_path, service_lifecycle.LifecycleResult(state="idle", reason=READYZ_MISS)
    )
    said = [e for e in logs if e["event"] == "supervisor.heartbeat.revoked_teardown_incomplete"]
    assert len(said) == 1
    assert said[0]["state"] == "idle"
    assert said[0]["reason"] == READYZ_MISS
    assert said[0]["transition"] is True
    assert not any(e["event"] == "supervisor.heartbeat.revoked_teardown" for e in logs)


def test_a_revoked_teardown_that_ran_is_logged_as_before(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    logs = _revoked_heartbeats(
        monkeypatch,
        tmp_path,
        service_lifecycle.LifecycleResult(state="ready", stopped=("dhcp-kea", "dns-bind9")),
    )
    ran = [e for e in logs if e["event"] == "supervisor.heartbeat.revoked_teardown"]
    assert len(ran) == 1 and ran[0]["stopped"] == ["dhcp-kea", "dns-bind9"]
    assert not any(
        e["event"] == "supervisor.heartbeat.revoked_teardown_incomplete" for e in logs
    )
