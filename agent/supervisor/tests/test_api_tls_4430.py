"""#4430 — the supervisor reaches the in-cluster api over TLS.

A member heartbeats the node-local Service on 8443 (the api pod's TLS
sidecar), verified against the pinned certificate. Plain http survives only as
the rolling-upgrade fallback: until the first TLS heartbeat succeeds, an api
that has no listener yet (a pod from before ``api.tlsListener``) is reached
over http, and after it no failure of the TLS attempt ever downgrades.
"""

from __future__ import annotations

import types
import uuid
from pathlib import Path

import httpx
import pytest
import structlog

from spatium_supervisor import appliance_state, cp_tls, heartbeat

_TLS_LOCAL = heartbeat._IN_CLUSTER_NODE_LOCAL_TLS_URL
_HTTP_LOCAL = heartbeat._IN_CLUSTER_NODE_LOCAL_URL
_TLS_CLUSTER = heartbeat._IN_CLUSTER_CONTROL_PLANE_TLS_URL
_MARKER = heartbeat._API_TLS_SEEN


@pytest.fixture(autouse=True)
def _member(monkeypatch: pytest.MonkeyPatch) -> None:
    # leave the upgrade window the shared conftest holds the other tests in
    monkeypatch.setitem(heartbeat._api_tls, "http_until", 0.0)
    heartbeat._local_api.update(failures=0, last_failure=0.0, fallback_logged=False)
    monkeypatch.setattr(appliance_state, "detect_appliance_variant", lambda: "control-plane")
    monkeypatch.setattr(appliance_state, "read_cluster_join_state", lambda: (None, None))
    monkeypatch.setattr(appliance_state, "collect", dict)
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
    monkeypatch.setattr(appliance_state, "read_firewall_state", dict)
    monkeypatch.setattr(heartbeat, "probe_port_conflicts", dict)
    monkeypatch.setattr(heartbeat, "_capabilities_payload", dict)
    monkeypatch.setattr(heartbeat, "load_cert", lambda d: None)


def _cfg(tmp_path: Path, url: str = "https://10.0.0.5") -> types.SimpleNamespace:
    return types.SimpleNamespace(
        heartbeat_interval_seconds=0, state_dir=tmp_path, control_plane_url=url, hostname="n"
    )


def _beat(
    cfg: types.SimpleNamespace, fail: dict[str, Exception]
) -> tuple[list[str], bool | None]:
    """One heartbeat. ``fail`` maps a URL prefix to the error raised for it."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        seen.append(url.split("/api/")[0])
        for prefix, exc in fail.items():
            if url.startswith(prefix):
                raise exc
        return httpx.Response(200, json={})

    with httpx.Client(
        transport=httpx.MockTransport(handler)
    ) as client, pytest.MonkeyPatch.context() as mp:
        mp.setattr(heartbeat, "_fallback_client", lambda cfg, url: client)
        held = heartbeat.heartbeat_once(
            cfg, uuid.uuid4(), "tok", None, client, structlog.get_logger()  # type: ignore[arg-type]
        )
    return seen, held


def test_member_targets_the_node_local_service_over_tls(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    assert heartbeat._effective_control_plane_url(cfg) == _TLS_LOCAL  # type: ignore[arg-type]
    assert _TLS_LOCAL.startswith("https://") and _TLS_LOCAL.endswith(":8443")


def test_successful_tls_heartbeat_ends_the_upgrade_window(tmp_path: Path) -> None:
    seen, _ = _beat(_cfg(tmp_path), {})
    assert seen == [_TLS_LOCAL]
    assert (tmp_path / "tls" / _MARKER).exists()


def test_api_without_a_listener_is_reached_over_http_in_the_same_call(
    tmp_path: Path,
) -> None:
    cfg = _cfg(tmp_path)
    seen, held = _beat(cfg, {_TLS_LOCAL: httpx.ConnectError("refused")})
    assert seen == [_TLS_LOCAL, _HTTP_LOCAL] and held is not None
    # not a node without an api pod: the Service is not marked down, no marker written
    assert heartbeat._local_api["failures"] == 0
    assert not (tmp_path / "tls" / _MARKER).exists()
    # and the next heartbeats stay on http without paying the connect timeout again
    seen, _ = _beat(cfg, {_TLS_LOCAL: httpx.ConnectError("refused")})
    assert seen == [_HTTP_LOCAL]


def test_tls_is_retried_once_the_window_backoff_passes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = _cfg(tmp_path)
    _beat(cfg, {_TLS_LOCAL: httpx.ConnectTimeout("dropped")})
    monkeypatch.setitem(heartbeat._api_tls, "http_until", 0.0)  # the 5 min have passed
    seen, _ = _beat(cfg, {})  # the api pod on this node has been rolled
    assert seen == [_TLS_LOCAL]
    assert (tmp_path / "tls" / _MARKER).exists()


def test_after_tls_worked_a_failure_never_falls_back_to_plain_http(
    tmp_path: Path,
) -> None:
    cfg = _cfg(tmp_path)
    _beat(cfg, {})  # TLS worked once
    seen, _ = _beat(cfg, {_TLS_LOCAL: httpx.ConnectError("refused")})
    # the pinned https CONTROL_PLANE_URL, as before #4430; http is never tried
    assert seen == [_TLS_LOCAL, "https://10.0.0.5"]
    assert not any(u.startswith("http://") for u in seen)


def test_the_marker_survives_a_supervisor_restart(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _beat(_cfg(tmp_path), {})
    monkeypatch.setitem(heartbeat._api_tls, "seen", False)  # a new process
    monkeypatch.setitem(heartbeat._api_tls, "http_until", float("inf"))
    assert heartbeat._effective_control_plane_url(_cfg(tmp_path)) == _TLS_LOCAL  # type: ignore[arg-type]


def test_seed_falls_back_to_the_cluster_service_over_tls(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path, "")
    _beat(cfg, {})
    seen, _ = _beat(cfg, {_TLS_LOCAL: httpx.ConnectError("refused")})
    assert seen == [_TLS_LOCAL, _TLS_CLUSTER]


def test_a_certificate_failure_is_not_a_missing_listener(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repinned: list[str] = []
    monkeypatch.setattr(cp_tls, "try_repin", lambda d, u: repinned.append(u) or False)
    cfg = _cfg(tmp_path)
    err = httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
    seen, held = _beat(cfg, {_TLS_LOCAL: err})
    # no downgrade to http for an interception or a rotation: re-pin or refuse
    assert seen == [_TLS_LOCAL] and held is None
    assert len(repinned) == 1 and repinned[0].startswith(_TLS_LOCAL)
    assert heartbeat._api_tls_active(cfg)  # type: ignore[arg-type]


def test_a_held_read_timeout_is_not_a_missing_listener(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    seen, held = _beat(cfg, {_TLS_LOCAL: httpx.ReadTimeout("held")})
    assert seen == [_TLS_LOCAL] and held is None
    assert heartbeat._api_tls_active(cfg)  # type: ignore[arg-type]


def test_in_cluster_https_is_never_pinned_on_first_contact() -> None:
    assert cp_tls.in_cluster_tls(_TLS_LOCAL)
    assert cp_tls.in_cluster_tls(_TLS_CLUSTER)
    assert not cp_tls.in_cluster_tls(_HTTP_LOCAL)
    assert not cp_tls.in_cluster_tls("https://10.0.0.5")


def test_unpinned_in_cluster_client_verifies_instead_of_pinning(tmp_path: Path) -> None:
    # first_contact=False and nothing pinned: a verifying client (system trust),
    # never verify=False and never a trust-on-first-use pin
    with cp_tls.client(tmp_path, _TLS_LOCAL, first_contact=False) as c:
        assert c._transport._pool._ssl_context.verify_mode.name == "CERT_REQUIRED"  # type: ignore[attr-defined]
    assert cp_tls.load_pins(tmp_path) is None
