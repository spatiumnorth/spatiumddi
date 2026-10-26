"""A control-plane node that re-registers after losing its Fleet row asks for the
roles it was serving (#2801).

#2786 made a lone control-plane node re-register by itself when its row goes
away, but the roles lived on the row: the node came back approved with no roles
and its DNS and DHCP stayed down until an operator assigned them again. The
re-register now reads the node's last assignment back from its role env and
sends it as ``restore_roles``; the control plane restores it (only on a
self-bootstrap registration) and audits that.

The teardown on revocation also drops the apply stamp, or the first heartbeat
after the roles come back renders the same env, matches the stamp, and skips
re-creating the role chart the teardown deleted.
"""

from __future__ import annotations

import types
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest
import structlog

from spatium_supervisor import appliance_state, approval_state, heartbeat, service_lifecycle
from spatium_supervisor.identity import load_appliance_id
from spatium_supervisor.register import RegisterResult
from spatium_supervisor.role_orchestrator import (
    compute_target_env,
    last_assigned_roles,
    render_env_file,
)

from .test_revoked_reregister_2696 import (
    FRESH,
    _ControlPlane,
    _registered_before,
    _row_goes_away,
    _run_main,
)

_ASSIGNMENT: dict[str, Any] = {
    "roles": ["dns-bind9", "dhcp"],
    "dns_group_name": "dns-main",
    "dns_engine": "bind9",
    "dns_agent_key": "dnskey-secret",
    "dhcp_group_name": "dhcp-main",
    "dhcp_network_mode": "host",
    "dhcp_agent_key": "dhcpkey-secret",
}


def _write_role_env(state_dir: Path, assignment: dict[str, Any]) -> str:
    """The role env exactly as an accepted heartbeat renders it."""
    rendered = render_env_file(compute_target_env(assignment))
    (state_dir / heartbeat.ROLE_ENV_FILENAME).write_text(rendered, encoding="utf-8")
    return rendered


class _RecordingControlPlane(_ControlPlane):
    def __init__(self, new_ids: list[uuid.UUID]) -> None:
        super().__init__(new_ids)
        self.restore_sent: list[Any] = []

    def register(self, **kwargs: Any) -> RegisterResult:
        self.restore_sent.append(kwargs.get("restore_roles"))
        return super().register(**kwargs)


def _reregister(
    monkeypatch: pytest.MonkeyPatch, state_dir: Path, assignment: dict[str, Any] | None
) -> _RecordingControlPlane:
    cp = _RecordingControlPlane(new_ids=[FRESH])
    _registered_before(state_dir, cp)
    if assignment is not None:
        _write_role_env(state_dir, assignment)
        heartbeat._persist_lifecycle_state(state_dir, "ready", None)
    _run_main(
        monkeypatch,
        state_dir,
        cp,
        variant="control-plane",
        ticks=8,
        events={1: _row_goes_away},
    )
    assert load_appliance_id(state_dir) == FRESH
    assert len(cp.restore_sent) == 1
    return cp


def test_reregister_sends_the_roles_the_node_was_serving(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cp = _reregister(monkeypatch, tmp_path / "state", _ASSIGNMENT)
    assert cp.restore_sent[0] == {
        "roles": ["dns-bind9", "dhcp"],
        "dns_group_name": "dns-main",
        "dhcp_group_name": "dhcp-main",
        "last_apply_state": "ready",
    }, (
        "the re-registering control-plane node did not send the roles it was "
        "serving, so it comes back approved with none and its DNS and DHCP stay down"
    )


def test_a_never_assigned_node_asks_for_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cp = _reregister(monkeypatch, tmp_path / "state", None)
    assert cp.restore_sent == [None]


def test_an_operator_removed_role_stays_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The operator dropped DHCP; the heartbeat that carried it rewrote the
    role env, so the restore asks only for DNS."""
    dns_only = {**_ASSIGNMENT, "roles": ["dns-bind9"]}
    cp = _reregister(monkeypatch, tmp_path / "state", dns_only)
    sent = cp.restore_sent[0]
    assert sent["roles"] == ["dns-bind9"]
    assert "dhcp_group_name" not in sent


def test_last_assigned_roles_round_trips_without_the_agent_keys(tmp_path: Path) -> None:
    """The restore carries roles and group names only; and the assignment the
    control plane rebuilds from them renders the same role env (with the keys
    it ships), so the service containers come back with the env they had."""
    before = _write_role_env(tmp_path, _ASSIGNMENT)
    restored = last_assigned_roles(tmp_path / heartbeat.ROLE_ENV_FILENAME)
    assert restored == {
        "roles": ["dns-bind9", "dhcp"],
        "dns_group_name": "dns-main",
        "dhcp_group_name": "dhcp-main",
    }
    assert "secret" not in repr(restored)
    rebuilt = {
        "roles": restored["roles"],
        "dns_group_name": restored["dns_group_name"],
        "dns_engine": "bind9",
        "dns_agent_key": "dnskey-secret",
        "dhcp_group_name": restored["dhcp_group_name"],
        "dhcp_network_mode": "host",
        "dhcp_agent_key": "dhcpkey-secret",
    }
    assert render_env_file(compute_target_env(rebuilt)) == before


def test_an_idle_role_env_restores_nothing(tmp_path: Path) -> None:
    _write_role_env(tmp_path, {"roles": []})
    assert last_assigned_roles(tmp_path / heartbeat.ROLE_ENV_FILENAME) is None
    assert last_assigned_roles(tmp_path / "missing.env") is None


def test_revoked_teardown_keeps_the_role_env_and_drops_the_apply_stamp(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The role env survives the revocation (it is what the restore reads);
    the apply stamp does not, so the first accepted heartbeat re-creates the
    role chart the teardown deleted instead of skipping it as unchanged."""
    rendered = _write_role_env(tmp_path, _ASSIGNMENT)
    env_path = tmp_path / heartbeat.ROLE_ENV_FILENAME
    monkeypatch.setattr(heartbeat, "role_release_fingerprint", lambda _p: "fp")
    _due, key = heartbeat._role_apply_due(tmp_path, rendered, env_path)
    heartbeat._write_last_apply_hash(tmp_path, key)
    assert heartbeat._role_apply_due(tmp_path, rendered, env_path)[0] is False

    monkeypatch.setattr(appliance_state, "collect", dict)
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
    monkeypatch.setattr(appliance_state, "read_firewall_state", dict)
    monkeypatch.setattr(heartbeat, "_watchdog_check_due", lambda: False)
    monkeypatch.setattr(heartbeat, "probe_port_conflicts", dict)
    monkeypatch.setattr(heartbeat, "_capabilities_payload", dict)
    monkeypatch.setattr(heartbeat, "_effective_control_plane_url", lambda cfg: "http://cp.invalid")
    monkeypatch.setattr(heartbeat, "load_cert", lambda d: None)
    monkeypatch.setattr(
        heartbeat,
        "tear_down_supervised_services",
        lambda: service_lifecycle.LifecycleResult(state="ready", stopped=("dns-bind9",)),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        # #2798: only a marked 403 is a revocation; a bare 404 is not.
        return httpx.Response(
            403,
            json={"detail": "Appliance has been revoked."},
            headers={heartbeat.REVOCATION_HEADER: "revoked"},
        )

    cfg = types.SimpleNamespace(heartbeat_interval_seconds=0, state_dir=tmp_path)
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        for _ in range(approval_state.REVOCATION_STRIKE_LIMIT):
            heartbeat.heartbeat_once(
                cfg, uuid.uuid4(), "tok", None, client, structlog.get_logger()  # type: ignore[arg-type]
            )
    assert approval_state.read_state(tmp_path) == "revoked"
    assert env_path.read_text(encoding="utf-8") == rendered
    assert heartbeat._role_apply_due(tmp_path, rendered, env_path)[0] is True, (
        "the apply stamp outlived the teardown, so the restored roles' first "
        "heartbeat skips re-creating the role chart"
    )
