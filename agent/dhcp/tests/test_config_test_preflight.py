"""#477 — Kea config-test preflight surfaces the real rejection reason.

_apply_bundle used to write the config then immediately config-reload, logging a
generic ``kea_config_reload_failed`` + marking the daemon "degraded" without the
actual reason. It now runs ``config-test`` first (validates WITHOUT applying,
returns Kea's real error text), so a bad render surfaces "pool … not in subnet"
in daemon_status instead of an opaque "degraded", and a config Kea will reject is
never reloaded onto a running daemon.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from spatium_dhcp_agent import kea_ctrl
from spatium_dhcp_agent import sync as sync_mod
from spatium_dhcp_agent.config import AgentConfig
from spatium_dhcp_agent.kea_ctrl import KeaCtrlError
from spatium_dhcp_agent.sync import SyncLoop


class _FakeHeartbeat:
    def __init__(self) -> None:
        self.daemon_status: dict[str, Any] = {}
        self.pending_acks: list[dict[str, Any]] = []


def _loop(cfg: AgentConfig) -> SyncLoop:
    return SyncLoop(cfg, token_ref=[""], heartbeat=_FakeHeartbeat())


# ── kea_ctrl.config_test ─────────────────────────────────────────────────


def test_config_test_sends_config_test_command(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[str, Any]] = []

    def fake_send(sock, cmd, arguments=None, **kw):  # type: ignore[no-untyped-def]
        seen.append((cmd, arguments))
        return {"result": 0}

    monkeypatch.setattr(kea_ctrl, "send_command", fake_send)
    kea_ctrl.config_test(Path("/x.sock"), {"Dhcp4": {"subnet4": []}})
    assert seen == [("config-test", {"Dhcp4": {"subnet4": []}})]


def test_config_test_raises_the_real_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(sock, cmd, arguments=None, **kw):  # type: ignore[no-untyped-def]
        raise KeaCtrlError(
            "kea command 'config-test' failed: result=1 text='pool 10.0.0.0/24 not in subnet'"
        )

    monkeypatch.setattr(kea_ctrl, "send_command", boom)
    with pytest.raises(KeaCtrlError, match="pool 10.0.0.0/24 not in subnet"):
        kea_ctrl.config_test(Path("/x.sock"), {"Dhcp4": {}})


def test_config_test_soft_passes_when_unsupported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An older daemon answers result=2 ("command not supported") — soft pass so
    # the preflight degrades to a plain reload instead of blocking the apply.
    def boom(sock, cmd, arguments=None, **kw):  # type: ignore[no-untyped-def]
        raise KeaCtrlError(
            "kea command 'config-test' failed: result=2 text='not supported'"
        )

    monkeypatch.setattr(kea_ctrl, "send_command", boom)
    kea_ctrl.config_test(Path("/x.sock"), {"Dhcp4": {}})  # must NOT raise


# ── SyncLoop._reload_socket preflight ────────────────────────────────────


def test_reload_socket_rejection_surfaces_reason_and_skips_reload(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    loop = _loop(agent_cfg)
    reloaded: list[Path] = []

    def bad_test(sock, doc):  # type: ignore[no-untyped-def]
        raise KeaCtrlError(
            "kea command 'config-test' failed: result=1 text='pool not in subnet'"
        )

    monkeypatch.setattr(sync_mod, "config_test", bad_test)
    monkeypatch.setattr(sync_mod, "config_reload", lambda s: reloaded.append(s))

    result = loop._reload_socket(agent_cfg.kea_control_socket, {"Dhcp4": {}}, "dhcp4", 0.0)
    # #882 — the exact value matters now: REJECTED is a verdict on the
    # config and triggers a revert; UNREACHABLE is not.
    assert result == sync_mod.RELOAD_REJECTED
    assert reloaded == []  # never reload a config Kea rejects
    assert loop.heartbeat.daemon_status["status"] == "degraded"
    assert "pool not in subnet" in loop.heartbeat.daemon_status["reason"]
    # The exact prefix is a contract: the control plane reads it as a failed
    # apply (#882's), not as a daemon that is not serving (#1067).
    assert loop.heartbeat.daemon_status["reason"].startswith("dhcp4_config_rejected: ")


def test_reload_socket_happy_path_tests_then_reloads(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    loop = _loop(agent_cfg)
    calls: list[str] = []
    monkeypatch.setattr(sync_mod, "config_test", lambda s, d: calls.append("test"))
    monkeypatch.setattr(sync_mod, "config_reload", lambda s: calls.append("reload"))

    result = loop._reload_socket(agent_cfg.kea_control_socket, {"Dhcp4": {}}, "dhcp4", 0.0)
    assert result == sync_mod.RELOAD_OK
    assert calls == ["test", "reload"]  # preflight BEFORE reload


def test_reload_socket_socket_not_ready_retries_then_reports(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    loop = _loop(agent_cfg)

    def not_ready(sock, doc):  # type: ignore[no-untyped-def]
        raise OSError("no such control socket")

    monkeypatch.setattr(sync_mod, "config_test", not_ready)
    monkeypatch.setattr(sync_mod, "config_reload", lambda s: None)

    # timeout 0 → the OSError branch breaks immediately (no real wait).
    result = loop._reload_socket(agent_cfg.kea_control_socket, {"Dhcp4": {}}, "dhcp4", 0.0)
    assert result == sync_mod.RELOAD_UNREACHABLE
    # Must stay distinct from a config verdict: the control plane reads this
    # one as a daemon that is not serving (#1067).
    assert loop.heartbeat.daemon_status["reason"].startswith("dhcp4_socket_unreachable: ")


def test_reload_socket_transient_kea_error_retries_then_succeeds(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    # During Kea's startup window config-test can answer with a *transient*
    # KeaCtrlError that succeeds a moment later; within the retry deadline that
    # must be retried (not treated as terminal), or the freshly-written config
    # never reloads and the daemon stays on its launch-time config.
    loop = _loop(agent_cfg)
    calls = {"test": 0}

    def flaky_test(sock, doc):  # type: ignore[no-untyped-def]
        calls["test"] += 1
        if calls["test"] == 1:
            raise KeaCtrlError("transient: empty response from kea")
        # second call succeeds

    reloaded: list[Path] = []
    monkeypatch.setattr(sync_mod, "config_test", flaky_test)
    monkeypatch.setattr(sync_mod, "config_reload", lambda s: reloaded.append(s))

    result = loop._reload_socket(agent_cfg.kea_control_socket, {"Dhcp4": {}}, "dhcp4", 5.0)
    assert result == sync_mod.RELOAD_OK
    assert calls["test"] == 2  # retried past the transient KeaCtrlError
    assert reloaded  # reloaded once config-test passed
