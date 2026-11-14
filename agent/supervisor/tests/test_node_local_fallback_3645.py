"""#3645 — a node with no ready api pod must not lose a heartbeat interval.

The node-local Service drops traffic (no refusal) while its node has no ready
api pod, so the node-local attempt gets a short connect timeout and the
heartbeat falls back in the same call. A member with no ``CONTROL_PLANE_URL``
(the seed) falls back to the cluster-wide api Service.
"""

from __future__ import annotations

import types
import uuid
from pathlib import Path

import httpx
import pytest
import structlog

from spatium_supervisor import appliance_state, heartbeat

_LOCAL = heartbeat._IN_CLUSTER_NODE_LOCAL_URL
_CLUSTER = heartbeat._IN_CLUSTER_CONTROL_PLANE_URL


@pytest.fixture(autouse=True)
def _member(monkeypatch: pytest.MonkeyPatch) -> None:
    heartbeat._local_api.update(failures=0, last_failure=0.0, fallback_logged=False)
    monkeypatch.setattr(appliance_state, "detect_appliance_variant", lambda: "control-plane")
    monkeypatch.setattr(appliance_state, "read_cluster_join_state", lambda: (None, None))
    monkeypatch.setattr(appliance_state, "collect", dict)
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
    monkeypatch.setattr(appliance_state, "read_firewall_state", dict)
    monkeypatch.setattr(heartbeat, "probe_port_conflicts", dict)
    monkeypatch.setattr(heartbeat, "_capabilities_payload", dict)
    monkeypatch.setattr(heartbeat, "load_cert", lambda d: None)


def _run(
    tmp_path: Path, control_plane_url: str, local_error: Exception | None
) -> tuple[list[tuple[str, float | None]], bool | None]:
    """One heartbeat; returns (host-prefix, connect timeout) per request."""
    seen: list[tuple[str, float | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((str(request.url)[: len(_LOCAL)], request.extensions["timeout"]["connect"]))
        if "-api-local" in request.url.host and local_error is not None:
            raise local_error
        return httpx.Response(200, json={})

    cfg = types.SimpleNamespace(
        heartbeat_interval_seconds=0,
        state_dir=tmp_path,
        control_plane_url=control_plane_url,
        hostname="n",
    )
    with httpx.Client(
        transport=httpx.MockTransport(handler)
    ) as client, pytest.MonkeyPatch.context() as mp:
        # the fallback gets its own client in production; here it is the mock
        mp.setattr(heartbeat, "_fallback_client", lambda cfg, url: client)
        held = heartbeat.heartbeat_once(
            cfg, uuid.uuid4(), "tok", None, client, structlog.get_logger()  # type: ignore[arg-type]
        )
    return seen, held


def test_node_local_attempt_has_a_short_connect_timeout(tmp_path: Path) -> None:
    seen, _ = _run(tmp_path, "https://10.0.0.5", None)
    assert seen[0][0] == _LOCAL
    assert seen[0][1] == heartbeat._LOCAL_API_CONNECT_TIMEOUT_S
    assert heartbeat._LOCAL_API_CONNECT_TIMEOUT_S <= 5


def test_first_connect_timeout_falls_back_in_the_same_call(tmp_path: Path) -> None:
    seen, _ = _run(tmp_path, "https://10.0.0.5", httpx.ConnectTimeout("dropped"))
    assert [u[:20] for u, _ in seen] == [_LOCAL[:20], "https://10.0.0.5/api/"[:20]]
    assert heartbeat._local_api["failures"] == 1
    # the fallback keeps the normal (long) connect timeout
    assert seen[1][1] != heartbeat._LOCAL_API_CONNECT_TIMEOUT_S


def test_seed_without_control_plane_url_falls_back_to_the_cluster_service(
    tmp_path: Path,
) -> None:
    seen, _ = _run(tmp_path, "", httpx.ConnectError("refused"))
    assert len(seen) == 2
    assert _CLUSTER.startswith(seen[1][0][:40]) and "-api-local" not in seen[1][0]


def test_read_timeout_is_not_a_fallback(tmp_path: Path) -> None:
    # an api pod took the request: the long poll, not a missing endpoint
    seen, held = _run(tmp_path, "https://10.0.0.5", httpx.ReadTimeout("held"))
    assert len(seen) == 1 and held is None
    assert heartbeat._local_api["failures"] == 0


def test_restore_is_one_cooldown_after_the_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = types.SimpleNamespace(control_plane_url="https://10.0.0.5")
    heartbeat.note_local_api_result(_LOCAL, False)
    assert heartbeat._effective_control_plane_url(cfg) == "https://10.0.0.5"  # type: ignore[arg-type]
    heartbeat._local_api["last_failure"] -= heartbeat._LOCAL_API_RETRY_S + 1
    assert heartbeat._effective_control_plane_url(cfg) == _LOCAL  # type: ignore[arg-type]
    heartbeat.note_local_api_result(_LOCAL, True)
    assert heartbeat._local_api["failures"] == 0
