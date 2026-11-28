"""#4646 — roles held back for a missing agent key ride the heartbeat.

``roles_awaiting_key`` was an info log only, so a node assigned DNS / DHCP on a
control plane with no agent key started nothing and the Fleet row looked
healthy. The apply now records the held-back roles and every heartbeat reports
them (``[]`` once the key arrives; omitted until an apply has recorded one).
"""

from __future__ import annotations

import json
import types
import uuid
from pathlib import Path

import httpx
import pytest
import structlog

from spatium_supervisor import appliance_state as st
from spatium_supervisor import heartbeat as hb
from spatium_supervisor import service_lifecycle

ROLE_ENV = "COMPOSE_PROFILES=dns-bind9,dhcp\nAGENT_GROUP=default\n"
PROFILES = ["dns-bind9", "dhcp"]


def _send_heartbeat(monkeypatch: pytest.MonkeyPatch, state_dir: Path) -> dict:
    monkeypatch.setattr(st, "collect", dict)
    monkeypatch.setattr(st, "detect_deployment_kind", lambda: "docker")
    monkeypatch.setattr(st, "read_firewall_state", dict)
    monkeypatch.setattr(hb, "probe_port_conflicts", dict)
    monkeypatch.setattr(hb, "_capabilities_payload", dict)
    monkeypatch.setattr(hb, "_effective_control_plane_url", lambda cfg: "http://cp.invalid")
    monkeypatch.setattr(hb, "load_cert", lambda d: None)
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(503, json={"detail": "x"})

    cfg = types.SimpleNamespace(heartbeat_interval_seconds=30, state_dir=state_dir)
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        hb.heartbeat_once(
            cfg, uuid.uuid4(), "tok", None, client, structlog.get_logger()  # type: ignore[arg-type]
        )
    assert seen
    return seen[0]


def _apply(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, result, env: str = ROLE_ENV) -> None:
    env_path = tmp_path / "role-compose.env"
    env_path.write_text(env, encoding="utf-8")
    monkeypatch.setattr(hb, "apply_role_assignment", lambda profiles, env: result)
    monkeypatch.setattr(hb, "reconcile_node_labels", lambda *a, **k: (True, None))
    hb._run_role_lifecycle(tmp_path, PROFILES, env, env_path)


def test_heartbeat_reports_the_roles_the_apply_held_back(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _apply(
        monkeypatch,
        tmp_path,
        service_lifecycle.LifecycleResult(
            state="ready", started=tuple(PROFILES), awaiting_key=("dhcp", "dns-bind9")
        ),
    )
    assert _send_heartbeat(monkeypatch, tmp_path)["roles_awaiting_key"] == ["dhcp", "dns-bind9"]


def test_heartbeat_reports_an_empty_list_once_the_key_arrived(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _apply(
        monkeypatch,
        tmp_path,
        service_lifecycle.LifecycleResult(state="ready", awaiting_key=("dhcp",)),
    )
    _apply(
        monkeypatch,
        tmp_path,
        service_lifecycle.LifecycleResult(state="ready", started=tuple(PROFILES)),
        env=ROLE_ENV + "DNS_AGENT_KEY=k\n",  # the env changed, so the apply runs again
    )
    assert _send_heartbeat(monkeypatch, tmp_path)["roles_awaiting_key"] == []


def test_heartbeat_omits_the_field_before_any_apply_recorded_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    assert "roles_awaiting_key" not in _send_heartbeat(monkeypatch, tmp_path)

