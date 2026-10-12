"""Kea preflight: validate before reload, out of process (#477, #1447).

#477 added a preflight so a bad render surfaces Kea's real reason ("pool … not
in subnet") instead of an opaque "degraded", and a config Kea will reject is
never reloaded onto a running daemon. It used the ``config-test`` control
command. On Kea 3.0.3 that command leaves the running server's
multi-threading manager in test mode, and from then on the HA hook's
dedicated HTTP listener never binds — every config change broke HA (#1447).

The preflight is now ``kea-dhcp4 -t <file>`` / ``kea-dhcp6 -t <file>`` in a
separate process, on the exact file ``config-reload`` reads. These tests pin:

* nothing but ``config-reload`` goes to either daemon's control socket;
* ``-t`` checks the same file, with the same bytes, the reload then loads;
* a ``-t`` rejection blocks the reload and reads as a rejection;
* a ``-t`` that could not run blocks the reload too, and never reads as OK.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from spatium_dhcp_agent import kea_ctrl
from spatium_dhcp_agent import sync as sync_mod
from spatium_dhcp_agent.cache import ensure_layout, load_previous_config, save_config
from spatium_dhcp_agent.config import AgentConfig
from spatium_dhcp_agent.config_apply import (
    PHASE_VALIDATE,
    STATUS_OK,
    STATUS_REVERTED,
    ApplyStatus,
)
from spatium_dhcp_agent.kea_ctrl import (
    KeaCheckUnavailable,
    KeaConfigRejected,
    KeaCtrlError,
)
from spatium_dhcp_agent.sync import SyncLoop


class _FakeHeartbeat:
    def __init__(self) -> None:
        self.daemon_status: dict[str, Any] = {}
        self.pending_acks: list[dict[str, Any]] = []
        self.config_apply = ApplyStatus()


def _loop(cfg: AgentConfig) -> SyncLoop:
    return SyncLoop(cfg, token_ref=[""], heartbeat=_FakeHeartbeat())


def _bundle(tag: str, subnet: str = "192.0.2.0/24") -> dict[str, Any]:
    return {
        "etag": tag,
        "scopes": [
            {
                "subnet_cidr": subnet,
                "lease_time": 3600,
                "address_family": "ipv4",
                "pools": [],
                "statics": [],
            }
        ],
    }


def _completed(rc: int, stderr: str = "", stdout: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=stdout, stderr=stderr)


class _KeaWire:
    """Records every control-socket command and every ``-t`` run.

    ``send_command`` is patched at the bottom of ``kea_ctrl`` so any command
    the agent sends — whichever helper sends it — lands here, and
    ``subprocess.run`` is patched where ``config_check`` calls it.
    """

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.commands: list[tuple[str, str]] = []
        self.checks: list[tuple[str, str, str]] = []  # (binary, path, bytes)
        self.reloaded_bytes: dict[str, str] = {}
        self.check_result: Any = lambda argv, text: _completed(0)
        self.paths: dict[str, Path] = {}
        monkeypatch.setattr(kea_ctrl, "send_command", self._send)
        monkeypatch.setattr(subprocess, "run", self._run)

    def _send(self, sock, command, arguments=None, **kw):  # type: ignore[no-untyped-def]
        self.commands.append((str(sock), command))
        if command == "config-reload":
            # What the daemon would read from disk at reload time.
            self.reloaded_bytes[str(sock)] = self.paths[str(sock)].read_text()
        return {"result": 0}

    def _run(self, argv, **kw):  # type: ignore[no-untyped-def]
        assert argv[1] == "-t"
        text = Path(argv[2]).read_text()
        self.checks.append((argv[0], argv[2], text))
        assert kw.get("timeout"), "the -t subprocess must be bounded by a timeout"
        return self.check_result(argv, text)


@pytest.fixture
def wire(agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch) -> _KeaWire:
    ensure_layout(agent_cfg.state_dir)
    w = _KeaWire(monkeypatch)
    w.paths = {
        str(agent_cfg.kea_control_socket): agent_cfg.kea_config_path,
        str(agent_cfg.kea_control_socket_v6): agent_cfg.kea_config_path_v6,
    }
    # The image ships both files; tests that call _reload_socket directly
    # need something on disk for -t to read.
    agent_cfg.kea_config_path.write_text('{"Dhcp4": {}}')
    agent_cfg.kea_config_path_v6.write_text('{"Dhcp6": {}}')
    return w


def _apply(loop: SyncLoop, tag: str, subnet: str = "192.0.2.0/24") -> bool:
    bundle = _bundle(tag, subnet)
    save_config(loop.cfg.state_dir, bundle, tag)
    return loop._apply_with_revert(bundle, tag)


# ── The agent never sends config-test to a running daemon ────────────────


def test_apply_sends_only_config_reload_to_both_daemons(
    agent_cfg: AgentConfig, wire: _KeaWire
) -> None:
    loop = _loop(agent_cfg)
    assert _apply(loop, "one") is True

    v4, v6 = str(agent_cfg.kea_control_socket), str(agent_cfg.kea_control_socket_v6)
    assert wire.commands == [(v4, "config-reload"), (v6, "config-reload")]
    assert all(cmd != "config-test" for _, cmd in wire.commands)
    # Both families were checked out of process instead.
    assert [(b, p) for b, p, _ in wire.checks] == [
        ("kea-dhcp4", str(agent_cfg.kea_config_path)),
        ("kea-dhcp6", str(agent_cfg.kea_config_path_v6)),
    ]
    assert loop.apply_status.status == STATUS_OK


def test_no_config_test_on_bootstrap_or_revert_either(
    agent_cfg: AgentConfig, wire: _KeaWire
) -> None:
    """Every apply path — bootstrap from cache, a refused bundle's revert —
    goes through the same preflight, so none of them may send it."""
    loop = _loop(agent_cfg)
    assert _apply(loop, "good", "10.0.0.0/24") is True

    def refuse_bad(argv, text):  # type: ignore[no-untyped-def]
        if "10.9.9.0/24" in text:
            return _completed(1, "Error encountered: pool not in subnet")
        return _completed(0)

    wire.check_result = refuse_bad
    assert _apply(loop, "bad", "10.9.9.0/24") is False  # rejected → reverted
    _loop(agent_cfg)  # restart: bootstrap from the cached bundle

    assert wire.commands  # reloads did happen
    assert {cmd for _, cmd in wire.commands} == {"config-reload"}


def test_the_check_sees_the_bytes_the_reload_loads(
    agent_cfg: AgentConfig, wire: _KeaWire
) -> None:
    loop = _loop(agent_cfg)
    assert _apply(loop, "one", "198.51.100.0/24") is True
    checked = {path: text for _, path, text in wire.checks}
    assert checked[str(agent_cfg.kea_config_path)] == wire.reloaded_bytes[
        str(agent_cfg.kea_control_socket)
    ]
    assert checked[str(agent_cfg.kea_config_path_v6)] == wire.reloaded_bytes[
        str(agent_cfg.kea_control_socket_v6)
    ]
    assert "198.51.100.0/24" in checked[str(agent_cfg.kea_config_path)]


# ── A -t rejection blocks the reload ─────────────────────────────────────


@pytest.mark.parametrize("family", ["dhcp4", "dhcp6"])
def test_a_rejection_blocks_that_daemons_reload(
    agent_cfg: AgentConfig, wire: _KeaWire, family: str
) -> None:
    loop = _loop(agent_cfg)
    binary = f"kea-{family}"

    def refuse(argv, text):  # type: ignore[no-untyped-def]
        if argv[0] == binary:
            return _completed(
                1,
                stderr="INFO  [kea-dhcp4.dhcp4] noise\n"
                "Error encountered: pool 10.0.0.0/24 is not part of the subnet",
            )
        return _completed(0)

    wire.check_result = refuse
    sock = str(
        agent_cfg.kea_control_socket if family == "dhcp4" else agent_cfg.kea_control_socket_v6
    )
    result = loop._reload_socket(
        Path(sock),
        wire.paths[sock],
        family,
        0.0,
    )
    assert result == sync_mod.RELOAD_REJECTED
    assert (sock, "config-reload") not in wire.commands
    reason = loop.heartbeat.daemon_status["reason"]
    # The exact prefix is a contract: the control plane reads it as a failed
    # apply (#882's), not as a daemon that is not serving (#1067).
    assert reason.startswith(f"{family}_config_rejected: ")
    assert "pool 10.0.0.0/24 is not part of the subnet" in reason


def test_a_rejected_bundle_is_reverted_and_reported(
    agent_cfg: AgentConfig, wire: _KeaWire
) -> None:
    loop = _loop(agent_cfg)
    assert _apply(loop, "good", "10.0.0.0/24") is True
    good_doc = agent_cfg.kea_config_path.read_text()

    wire.check_result = lambda argv, text: (
        _completed(1, "Error encountered: pool not in subnet")
        if "10.9.9.0/24" in text
        else _completed(0)
    )
    wire.commands.clear()
    assert _apply(loop, "bad", "10.9.9.0/24") is False

    assert loop.apply_status.status == STATUS_REVERTED
    assert loop.apply_status.failed_etag == "bad"
    assert "pool not in subnet" in (loop.apply_status.error or "")
    assert agent_cfg.kea_config_path.read_text() == good_doc
    # dhcp4 never reloaded the refused document; what it reloaded is the
    # restored good one.
    assert "10.9.9.0/24" not in wire.reloaded_bytes.get(str(agent_cfg.kea_control_socket), "")


# ── A -t that could not run fails closed ─────────────────────────────────


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(FileNotFoundError(2, "No such file or directory"), id="missing"),
        pytest.param(PermissionError(13, "Permission denied"), id="not-executable"),
        pytest.param(subprocess.TimeoutExpired(["kea-dhcp4"], 30), id="timeout"),
        pytest.param(_completed(-9), id="killed"),
        pytest.param(_completed(134, "terminate called after throwing"), id="crashed"),
    ],
)
def test_a_check_that_cannot_run_is_not_ok_and_blocks_the_reload(
    agent_cfg: AgentConfig, wire: _KeaWire, failure: Any
) -> None:
    loop = _loop(agent_cfg)
    assert _apply(loop, "good", "10.0.0.0/24") is True
    good_doc = agent_cfg.kea_config_path.read_text()

    def broken(argv, text):  # type: ignore[no-untyped-def]
        if isinstance(failure, BaseException):
            raise failure
        return failure

    wire.check_result = broken
    wire.commands.clear()
    assert _apply(loop, "next", "10.1.0.0/24") is False

    # Not reloaded, not reported OK, not promoted to last-known-good.
    assert wire.commands == []
    assert loop.apply_status.status != STATUS_OK
    assert loop.apply_status.phase == PHASE_VALIDATE
    assert loop.apply_status.failed_etag == "next"
    _, prev_etag = load_previous_config(agent_cfg.state_dir)
    assert prev_etag == "good"
    # The file Kea boots from next is the last one that passed.
    assert agent_cfg.kea_config_path.read_text() == good_doc
    # Distinct from a rejection: the daemon was untouched and still serving,
    # so it must read as a failed apply, never as "config rejected" and
    # never as a daemon that is down.
    reason = loop.heartbeat.daemon_status["reason"]
    assert reason.startswith("config_apply_")
    assert "config_rejected" not in reason
    # Quarantined, so it is retried on the backoff (a timeout can be transient).
    assert loop._quarantine.etag == "next"


def test_unvalidated_is_its_own_outcome(agent_cfg: AgentConfig, wire: _KeaWire) -> None:
    loop = _loop(agent_cfg)

    def timeout(argv, text):  # type: ignore[no-untyped-def]
        raise subprocess.TimeoutExpired(argv, 30)

    wire.check_result = timeout
    result = loop._reload_socket(
        agent_cfg.kea_control_socket, agent_cfg.kea_config_path, "dhcp4", 0.0
    )
    assert result == sync_mod.RELOAD_UNVALIDATED
    assert wire.commands == []
    assert loop.heartbeat.daemon_status["reason"].startswith(
        "config_apply_unvalidated: dhcp4: kea-dhcp4 -t timed out"
    )


# ── reload behaviour after the preflight passes ──────────────────────────


def test_reload_socket_socket_not_ready_retries_then_reports(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    loop = _loop(agent_cfg)
    monkeypatch.setattr(sync_mod, "config_check", lambda d, p: None)

    def not_ready(sock):  # type: ignore[no-untyped-def]
        raise OSError("no such control socket")

    monkeypatch.setattr(sync_mod, "config_reload", not_ready)
    result = loop._reload_socket(
        agent_cfg.kea_control_socket, agent_cfg.kea_config_path, "dhcp4", 0.0
    )
    assert result == sync_mod.RELOAD_UNREACHABLE
    # Must stay distinct from a config verdict: the control plane reads this
    # one as a daemon that is not serving (#1067).
    assert loop.heartbeat.daemon_status["reason"].startswith("dhcp4_socket_unreachable: ")


def test_reload_socket_transient_kea_error_retries_then_succeeds(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    # During Kea's startup window the command channel can answer with a
    # *transient* KeaCtrlError that succeeds a moment later; within the retry
    # deadline that is retried, and the -t check is not re-run for it.
    loop = _loop(agent_cfg)
    calls = {"check": 0, "reload": 0}

    def check(daemon, path):  # type: ignore[no-untyped-def]
        calls["check"] += 1

    def flaky_reload(sock):  # type: ignore[no-untyped-def]
        calls["reload"] += 1
        if calls["reload"] == 1:
            raise KeaCtrlError("transient: empty response from kea")

    monkeypatch.setattr(sync_mod, "config_check", check)
    monkeypatch.setattr(sync_mod, "config_reload", flaky_reload)
    monkeypatch.setattr(sync_mod, "_BOOTSTRAP_RELOAD_INTERVAL", 0.01)
    result = loop._reload_socket(
        agent_cfg.kea_control_socket, agent_cfg.kea_config_path, "dhcp4", 5.0
    )
    assert result == sync_mod.RELOAD_OK
    assert calls == {"check": 1, "reload": 2}


# ── kea_ctrl.config_check itself ─────────────────────────────────────────


def test_config_check_runs_the_family_binary_with_a_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[list[str], dict[str, Any]]] = []

    def fake_run(argv, **kw):  # type: ignore[no-untyped-def]
        seen.append((argv, kw))
        return _completed(0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    kea_ctrl.config_check("dhcp4", Path("/etc/kea/kea-dhcp4.conf"))
    kea_ctrl.config_check("dhcp6", Path("/etc/kea/kea-dhcp6.conf"), timeout=5)
    assert [a for a, _ in seen] == [
        ["kea-dhcp4", "-t", "/etc/kea/kea-dhcp4.conf"],
        ["kea-dhcp6", "-t", "/etc/kea/kea-dhcp6.conf"],
    ]
    assert seen[0][1]["timeout"] == kea_ctrl.CONFIG_CHECK_TIMEOUT
    assert seen[1][1]["timeout"] == 5
    assert all(kw["check"] is False for _, kw in seen)


def test_config_check_rejection_carries_keas_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda argv, **kw: _completed(
            1,
            stdout="2026-10-04 INFO  DHCP4_STARTING ...\n",
            stderr="DEBUG noise\nError encountered: subnet 10.0.0.0/24: pool out of range\n",
        ),
    )
    with pytest.raises(KeaConfigRejected, match="pool out of range") as exc:
        kea_ctrl.config_check("dhcp4", Path("/x.conf"))
    # Only the verdict line, not the log noise around it.
    assert "noise" not in str(exc.value)
    assert "DHCP4_STARTING" not in str(exc.value)
    assert isinstance(exc.value, KeaCtrlError)


def test_config_check_unavailable_is_not_a_rejection(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(argv, **kw):  # type: ignore[no-untyped-def]
        raise FileNotFoundError(2, "No such file or directory", "kea-dhcp4")

    monkeypatch.setattr(subprocess, "run", missing)
    with pytest.raises(KeaCheckUnavailable, match="could not run") as exc:
        kea_ctrl.config_check("dhcp4", Path("/x.conf"))
    assert not isinstance(exc.value, KeaCtrlError)


# ── Against the real binary, when the image provides it ──────────────────


@pytest.mark.skipif(shutil.which("kea-dhcp4") is None, reason="kea-dhcp4 not installed")
def test_real_kea_dhcp4_check(tmp_path: Path) -> None:
    good = tmp_path / "good.conf"
    bad = tmp_path / "bad.conf"
    subnet = {"id": 1, "subnet": "192.0.2.0/24"}
    good.write_text(
        json.dumps({"Dhcp4": {"subnet4": [{**subnet, "pools": [{"pool": "192.0.2.10-192.0.2.20"}]}]}})
    )
    bad.write_text(
        json.dumps({"Dhcp4": {"subnet4": [{**subnet, "pools": [{"pool": "10.0.0.10-10.0.0.20"}]}]}})
    )
    kea_ctrl.config_check("dhcp4", good)
    with pytest.raises(KeaConfigRejected, match="10.0.0.10"):
        kea_ctrl.config_check("dhcp4", bad)
