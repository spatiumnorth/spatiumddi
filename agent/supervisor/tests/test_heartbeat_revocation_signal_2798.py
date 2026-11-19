"""Only the control plane's explicit revocation answer tears role services down (#2798).

A supervisor used to count every 403 AND every 404 on its heartbeat as a
revocation strike. Switching appliance registration off answered every
heartbeat 404, so two of them revoked every appliance and took DNS and DHCP
down. Now a strike is a 403 carrying ``X-Spatium-Revocation`` (or, from a
control plane predating the header, one of the two 403 details it answered
for a revoked or missing row). A 404, or an unmarked 403, is logged and the
node keeps serving its last applied roles.
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

# The wire contract with backend/app/api/v1/appliance/supervisor.py
# (``REVOCATION_HEADER``), spelled out so a rename on either side fails here.
_HEADER = "X-Spatium-Revocation"

# Well past the strike limit, so a refusal that counted would have revoked.
_TICKS = approval_state.REVOCATION_STRIKE_LIMIT + 3


def _drive(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, response: httpx.Response
) -> tuple[list[dict], list[int]]:
    """``_TICKS`` heartbeats of an approved appliance node, each answered
    ``response``. Returns the logged events and one entry per teardown."""
    monkeypatch.setattr(appliance_state, "collect", dict)
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
    monkeypatch.setattr(appliance_state, "read_firewall_state", dict)
    monkeypatch.setattr(heartbeat, "probe_port_conflicts", dict)
    monkeypatch.setattr(heartbeat, "_capabilities_payload", dict)
    monkeypatch.setattr(heartbeat, "_effective_control_plane_url", lambda cfg: "http://cp.invalid")
    monkeypatch.setattr(heartbeat, "load_cert", lambda d: None)
    teardowns: list[int] = []

    def _teardown() -> service_lifecycle.LifecycleResult:
        teardowns.append(1)
        return service_lifecycle.LifecycleResult(state="ready", stopped=("dhcp-kea", "dns-bind9"))

    monkeypatch.setattr(heartbeat, "tear_down_supervised_services", _teardown)
    approval_state.record_success(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            response.status_code, content=response.content, headers=response.headers
        )

    cfg = types.SimpleNamespace(heartbeat_interval_seconds=0, state_dir=tmp_path)
    with (
        capture_logs() as logs,
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
    ):
        for _ in range(_TICKS):
            heartbeat.heartbeat_once(
                cfg, uuid.uuid4(), "tok", None, client, structlog.get_logger()  # type: ignore[arg-type]
            )
    return logs, teardowns


def _events(logs: list[dict], name: str) -> list[dict]:
    return [e for e in logs if e["event"] == name]


@pytest.mark.parametrize(
    "response",
    [
        # What a control plane answered with registration switched off.
        httpx.Response(404, json={"detail": "Not found."}),
        # A proxy, or a router that is not mounted.
        httpx.Response(404, text="<html>404</html>"),
        # A 403 the control plane did not mark (a WAF, a cert-subject mismatch).
        httpx.Response(403, json={"detail": "Cert subject mismatch."}),
        httpx.Response(403, text="Forbidden"),
    ],
    ids=["registration-off-404", "proxy-404", "unmarked-403", "plain-403"],
)
def test_a_refusal_that_is_not_a_revocation_keeps_the_node_serving(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, response: httpx.Response
) -> None:
    """REGRESSION (#2798): two 404s revoked the node and tore DNS + DHCP down."""
    logs, teardowns = _drive(monkeypatch, tmp_path, response)

    assert approval_state.read_state(tmp_path) == "approved"
    assert teardowns == []
    assert not _events(logs, "supervisor.heartbeat.rejected")
    refused = _events(logs, "supervisor.heartbeat.refused_not_revocation")
    assert len(refused) == _TICKS
    assert refused[0]["status_code"] == response.status_code


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        (
            httpx.Response(
                403,
                json={"detail": "Appliance has been revoked."},
                headers={_HEADER: "revoked"},
            ),
            "revoked",
        ),
        (
            httpx.Response(
                403,
                json={"detail": "Invalid appliance or session."},
                headers={_HEADER: "unknown"},
            ),
            "unknown",
        ),
        # A control plane from before the header: its two revocation details.
        (
            httpx.Response(
                403,
                json={
                    "detail": "Appliance has been revoked. Re-authorize on the Fleet page to restore."
                },
            ),
            "revoked",
        ),
        (httpx.Response(403, json={"detail": "Invalid appliance or session."}), "unknown"),
    ],
    ids=["marked-revoked", "marked-unknown", "legacy-revoked", "legacy-deleted"],
)
def test_the_explicit_revocation_still_tears_down(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, response: httpx.Response, reason: str
) -> None:
    logs, teardowns = _drive(monkeypatch, tmp_path, response)

    assert approval_state.read_state(tmp_path) == "revoked"
    # Once per heartbeat from the strike that crossed the limit onwards.
    assert len(teardowns) == _TICKS - approval_state.REVOCATION_STRIKE_LIMIT + 1
    rejected = _events(logs, "supervisor.heartbeat.rejected")
    assert len(rejected) == _TICKS
    assert all(e["revocation"] == reason for e in rejected)
    assert not _events(logs, "supervisor.heartbeat.refused_not_revocation")


def test_revocation_reason_never_reads_a_404_as_one() -> None:
    assert heartbeat.REVOCATION_HEADER == _HEADER
    marked_404 = httpx.Response(404, headers={_HEADER: "revoked"})
    assert heartbeat.revocation_reason(marked_404) is None
    assert heartbeat.revocation_reason(httpx.Response(200, json={})) is None
