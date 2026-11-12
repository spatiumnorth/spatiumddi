"""Tests for #272 — supervisor heartbeat-target resolution.

A supervisor that is itself part of the control-plane k3s cluster
should heartbeat the in-cluster api Service (resilient to any single
node loss + kube-proxy load-balanced) rather than the seed node's IP
that got baked into ``CONTROL_PLANE_URL`` at install/join time. Remote
(off-cluster) DNS/DHCP agents have no in-cluster DNS to resolve the
``.svc`` name, so they keep using their configured URL — ideally the
MetalLB VIP.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from spatium_supervisor import appliance_state, heartbeat
from spatium_supervisor.config import SupervisorConfig


def _cfg(url: str, tmp_path: Path) -> SupervisorConfig:
    return SupervisorConfig(
        control_plane_url=url,
        hostname="test-node",
        state_dir=tmp_path,
        bootstrap_pairing_code="",
        heartbeat_interval_seconds=30,
        k8s_proxy_enabled=False,
        in_pod_firewall_enabled=False,
    )


def test_control_plane_seed_targets_in_cluster_service(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A control-plane seed redirects to the in-cluster Service even
    # though CONTROL_PLANE_URL points at its own external IP.
    monkeypatch.setattr(
        appliance_state, "detect_appliance_variant", lambda: "control-plane"
    )
    monkeypatch.setattr(
        appliance_state, "read_cluster_join_state", lambda: (None, None)
    )
    cfg = _cfg("https://192.168.0.199", tmp_path)
    assert (
        heartbeat._effective_control_plane_url(cfg)
        == heartbeat._IN_CLUSTER_NODE_LOCAL_URL
    )


def test_promoted_appliance_targets_in_cluster_service(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # An appliance promoted into the control plane (cluster_join_state
    # ready) heartbeats the cluster, not the old seed IP it joined via.
    monkeypatch.setattr(
        appliance_state, "detect_appliance_variant", lambda: "appliance"
    )
    monkeypatch.setattr(
        appliance_state, "read_cluster_join_state", lambda: ("ready", None)
    )
    cfg = _cfg("https://192.168.0.199", tmp_path)
    assert (
        heartbeat._effective_control_plane_url(cfg)
        == heartbeat._IN_CLUSTER_NODE_LOCAL_URL
    )


def test_remote_agent_keeps_configured_url(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A plain data-plane appliance that hasn't joined the control plane
    # uses its configured URL (which an operator should point at the VIP).
    monkeypatch.setattr(
        appliance_state, "detect_appliance_variant", lambda: "appliance"
    )
    monkeypatch.setattr(
        appliance_state, "read_cluster_join_state", lambda: (None, None)
    )
    cfg = _cfg("https://192.168.0.252", tmp_path)
    assert heartbeat._effective_control_plane_url(cfg) == "https://192.168.0.252"


def test_join_state_not_ready_keeps_configured_url(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Mid-promotion (join state pending/failed) is NOT a cluster member
    # yet — keep heartbeating the configured URL until the join settles.
    monkeypatch.setattr(
        appliance_state, "detect_appliance_variant", lambda: "appliance"
    )
    monkeypatch.setattr(
        appliance_state, "read_cluster_join_state", lambda: ("joining", None)
    )
    cfg = _cfg("https://192.168.0.199", tmp_path)
    assert heartbeat._effective_control_plane_url(cfg) == "https://192.168.0.199"


# ── #3645: node-local api Service, https fallback ───────────────────────────


@pytest.fixture(autouse=True)
def _reset_local_api_state() -> None:
    heartbeat._local_api.update(failures=0, last_failure=0.0, fallback_logged=False)


def _member(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        appliance_state, "detect_appliance_variant", lambda: "control-plane"
    )
    monkeypatch.setattr(
        appliance_state, "read_cluster_join_state", lambda: (None, None)
    )


def test_member_uses_the_node_local_service(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _member(monkeypatch)
    url = heartbeat._effective_control_plane_url(_cfg("https://10.0.0.5", tmp_path))
    assert url == heartbeat._IN_CLUSTER_NODE_LOCAL_URL
    assert "-api-local." in url
    # the cluster-wide Service is no longer a member's target at all
    assert url != heartbeat._IN_CLUSTER_CONTROL_PLANE_URL


def test_one_failure_keeps_the_node_local_service(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _member(monkeypatch)
    heartbeat.note_local_api_result(heartbeat._IN_CLUSTER_NODE_LOCAL_URL, False)
    cfg = _cfg("https://10.0.0.5", tmp_path)
    assert heartbeat._effective_control_plane_url(cfg) == heartbeat._IN_CLUSTER_NODE_LOCAL_URL


def test_repeated_failures_fall_back_to_pinned_https_never_cluster_http(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _member(monkeypatch)
    for _ in range(heartbeat._LOCAL_API_FAIL_THRESHOLD):
        heartbeat.note_local_api_result(heartbeat._IN_CLUSTER_NODE_LOCAL_URL, False)
    url = heartbeat._effective_control_plane_url(_cfg("https://10.0.0.5", tmp_path))
    assert url == "https://10.0.0.5"
    assert not url.startswith("http://")


def test_local_service_is_retried_after_the_cooldown_and_restored(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _member(monkeypatch)
    cfg = _cfg("https://10.0.0.5", tmp_path)
    for _ in range(heartbeat._LOCAL_API_FAIL_THRESHOLD):
        heartbeat.note_local_api_result(heartbeat._IN_CLUSTER_NODE_LOCAL_URL, False)
    heartbeat._local_api["last_failure"] -= heartbeat._LOCAL_API_RETRY_S + 1
    assert heartbeat._effective_control_plane_url(cfg) == heartbeat._IN_CLUSTER_NODE_LOCAL_URL
    heartbeat.note_local_api_result(heartbeat._IN_CLUSTER_NODE_LOCAL_URL, True)
    assert heartbeat._local_api["failures"] == 0


def test_a_failed_retry_goes_back_to_https(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _member(monkeypatch)
    cfg = _cfg("https://10.0.0.5", tmp_path)
    for _ in range(heartbeat._LOCAL_API_FAIL_THRESHOLD):
        heartbeat.note_local_api_result(heartbeat._IN_CLUSTER_NODE_LOCAL_URL, False)
    heartbeat._local_api["last_failure"] -= heartbeat._LOCAL_API_RETRY_S + 1
    heartbeat.note_local_api_result(heartbeat._IN_CLUSTER_NODE_LOCAL_URL, False)
    assert heartbeat._effective_control_plane_url(cfg) == "https://10.0.0.5"


def test_results_for_other_urls_do_not_count(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _member(monkeypatch)
    for _ in range(5):
        heartbeat.note_local_api_result("https://10.0.0.5/api/v1/x", False)
    assert heartbeat._local_api["failures"] == 0


def test_no_configured_url_keeps_the_node_local_service(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _member(monkeypatch)
    for _ in range(heartbeat._LOCAL_API_FAIL_THRESHOLD):
        heartbeat.note_local_api_result(heartbeat._IN_CLUSTER_NODE_LOCAL_URL, False)
    assert heartbeat._effective_control_plane_url(_cfg("", tmp_path)) == heartbeat._IN_CLUSTER_NODE_LOCAL_URL
