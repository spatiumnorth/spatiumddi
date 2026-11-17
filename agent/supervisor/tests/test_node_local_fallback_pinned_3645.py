"""#3645 — the same-call fallback verifies with the current pin.

The heartbeat client is built for the node-local Service (plain http inside
the cluster), so it carries no pin. The fallback attempt after a node-local
failure must use the client an ordinary heartbeat to that https URL would
use: built from the pin file as it is now, never the default trust store.
These run against a REAL local TLS server, because the property is OpenSSL's.
"""

from __future__ import annotations

import types
import uuid
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import structlog

from spatium_supervisor import appliance_state, cp_tls, heartbeat

from .test_cp_tls import SwappableServer, _leaf


class _NodeLocalDown(httpx.BaseTransport):
    """What the client cp_tls builds for the node-local URL does: the local
    Service drops traffic, anything else goes out with the default trust
    store (no pin on this client)."""

    def __init__(self) -> None:
        self._inner = httpx.HTTPTransport()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if "-api-local" in request.url.host:
            raise httpx.ConnectTimeout("dropped")
        return self._inner.handle_request(request)


@pytest.fixture(autouse=True)
def _member(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv("SPATIUM_INSECURE_SKIP_TLS_VERIFY", raising=False)
    monkeypatch.setattr(cp_tls, "_redirects", {})
    heartbeat._local_api.update(failures=0, last_failure=0.0, fallback_logged=False)
    monkeypatch.setattr(appliance_state, "detect_appliance_variant", lambda: "control-plane")
    monkeypatch.setattr(appliance_state, "read_cluster_join_state", lambda: (None, None))
    monkeypatch.setattr(appliance_state, "collect", dict)
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
    monkeypatch.setattr(appliance_state, "read_firewall_state", dict)
    monkeypatch.setattr(heartbeat, "probe_port_conflicts", dict)
    monkeypatch.setattr(heartbeat, "_capabilities_payload", dict)
    monkeypatch.setattr(heartbeat, "load_cert", lambda d: None)
    yield
    heartbeat._local_api.update(failures=0, last_failure=0.0, fallback_logged=False)


@pytest.fixture
def server(tmp_path: Path) -> Iterator[SwappableServer]:
    srv = SwappableServer(tmp_path, _leaf("control-plane.example"))
    yield srv
    srv.close()


def _beat(state_dir: Path, url: str) -> bool | None:
    cfg = types.SimpleNamespace(
        heartbeat_interval_seconds=0, state_dir=state_dir, control_plane_url=url, hostname="n"
    )
    with httpx.Client(transport=_NodeLocalDown()) as client:
        return heartbeat.heartbeat_once(
            cfg, uuid.uuid4(), "tok", None, client, structlog.get_logger()  # type: ignore[arg-type]
        )


def _posts(server: SwappableServer) -> list[str]:
    return [p for p in server.requests if p != cp_tls.PIN_SET_PATH]


def test_same_call_fallback_verifies_against_the_current_pin(
    server: SwappableServer, tmp_path: Path
) -> None:
    state = tmp_path / "state"
    cp_tls._save_pins(state, server.current_pem())
    assert _beat(state, server.url) is not None
    assert len(_posts(server)) == 1  # accepted in the same call


def test_same_call_fallback_follows_a_repin(server: SwappableServer, tmp_path: Path) -> None:
    state = tmp_path / "state"
    cp_tls._save_pins(state, _leaf("retired.example").pem)
    cp_tls._save_pins(state, server.current_pem())  # the repin, after this process started
    assert _beat(state, server.url) is not None
    assert len(_posts(server)) == 1


def test_same_call_fallback_refuses_a_certificate_that_is_not_the_pin(
    server: SwappableServer, tmp_path: Path
) -> None:
    state = tmp_path / "state"
    cp_tls._save_pins(state, _leaf("someone-else.example").pem)
    assert _beat(state, server.url) is None
    assert _posts(server) == []  # no request completed over the unpinned certificate


def test_same_call_fallback_with_nothing_pinned_sends_nothing(
    server: SwappableServer, tmp_path: Path
) -> None:
    state = tmp_path / "state"
    assert _beat(state, server.url) is None
    assert server.requests == []
    assert cp_tls.load_pins(state) is None
