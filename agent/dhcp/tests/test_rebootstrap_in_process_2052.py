"""A 401/404 re-registers in process; it never ends a thread (#2052).

Deleting the Kea server row while its agent was connected made the woken
long-poll answer 404. The sync thread dropped its token and STOPPED, the
supervisor's dead-thread watch returned 2, and the Kea entrypoint stopped the
container, taking Kea with it. Non-negotiable #5: drop the token, keep the
cached config and the daemon.
"""

from __future__ import annotations

import threading
from typing import Any

import pytest

from spatium_dhcp_agent import bootstrap as bootstrap_mod
from spatium_dhcp_agent.cache import ensure_layout, load_token, save_token
from spatium_dhcp_agent.config import AgentConfig
from spatium_dhcp_agent.config_apply import ApplyStatus
from spatium_dhcp_agent.heartbeat import HeartbeatClient
from spatium_dhcp_agent.sync import SyncLoop


class _Resp:
    def __init__(self, status: int):
        self.status_code = status
        self.headers: dict[str, str] = {}
        self.text = ""

    def json(self) -> dict[str, Any]:
        return {}


class _Client:
    def __init__(self, status: int):
        self._status = status

    def __enter__(self) -> _Client:  # noqa: PYI034
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def get(self, *a: Any, **k: Any) -> _Resp:
        return _Resp(self._status)

    def post(self, *a: Any, **k: Any) -> _Resp:
        return _Resp(self._status)


class _Heartbeat:
    def __init__(self) -> None:
        self.daemon_status: dict[str, Any] = {}
        self.pending_acks: list[dict[str, Any]] = []
        self.config_apply = ApplyStatus()


@pytest.fixture
def registered(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    calls: list[int] = []

    def fake_register(cfg: AgentConfig):  # type: ignore[no-untyped-def]
        calls.append(1)
        save_token(cfg.state_dir, "new-token")
        return "agent", "new-token", {}

    monkeypatch.setattr(bootstrap_mod, "register", fake_register)
    return calls


@pytest.mark.parametrize("status", [401, 404])
def test_sync_re_registers_and_keeps_the_thread(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch, registered: list[int], status: int
) -> None:
    ensure_layout(agent_cfg.state_dir)
    save_token(agent_cfg.state_dir, "old-token")
    token_ref = ["old-token"]
    loop = SyncLoop(agent_cfg, token_ref, heartbeat=_Heartbeat())
    loop._current_etag = "e1"
    monkeypatch.setattr(loop, "_client", lambda: _Client(status))

    loop._poll_once()

    assert registered == [1]
    assert token_ref[0] == "new-token"
    assert load_token(agent_cfg.state_dir) == "new-token"
    assert not loop._stop.is_set(), "the sync thread must keep running"
    assert loop._current_etag is None


def test_sync_run_loop_survives_a_404(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch, registered: list[int]
) -> None:
    ensure_layout(agent_cfg.state_dir)
    loop = SyncLoop(agent_cfg, ["old-token"], heartbeat=_Heartbeat())
    seen = threading.Event()
    statuses = iter([404, 304, 304])

    def client() -> _Client:
        try:
            s = next(statuses)
        except StopIteration:
            seen.set()
            s = 304
        return _Client(s)

    monkeypatch.setattr(loop, "_client", client)
    monkeypatch.setattr(loop, "_recheck_v6_unicast", lambda: None)
    t = threading.Thread(target=loop.run, daemon=True)
    t.start()
    assert seen.wait(15), "the loop stopped polling after the 404"
    assert t.is_alive()
    loop.stop()
    t.join(5)


def test_heartbeat_404_re_registers_without_stopping(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch, registered: list[int]
) -> None:
    ensure_layout(agent_cfg.state_dir)
    token_ref = ["old-token"]
    hb = HeartbeatClient(agent_cfg, token_ref)
    monkeypatch.setattr(hb, "_client", lambda: _Client(404))
    monkeypatch.setattr(hb, "_kea_version", lambda: None)
    hb.send_once()
    assert registered == [1]
    assert token_ref[0] == "new-token"
    assert not hb._stop.is_set()


def test_a_second_thread_does_not_register_twice(
    agent_cfg: AgentConfig, registered: list[int]
) -> None:
    ensure_layout(agent_cfg.state_dir)
    token_ref = ["old-token"]
    bootstrap_mod.reauthenticate(agent_cfg, token_ref, "old-token")
    bootstrap_mod.reauthenticate(agent_cfg, token_ref, "old-token")
    assert registered == [1]


def test_failing_register_backs_off_instead_of_spinning(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    ensure_layout(agent_cfg.state_dir)
    sleeps: list[float] = []

    class _Stop(Exception):
        pass

    def fake_sleep(s: float) -> None:
        sleeps.append(s)
        if len(sleeps) == 3:
            raise _Stop

    monkeypatch.setattr(bootstrap_mod.time, "sleep", fake_sleep)
    monkeypatch.setattr(bootstrap_mod, "_client", lambda cfg: _Client(403))
    with pytest.raises(_Stop):
        bootstrap_mod.reauthenticate(agent_cfg, ["old"], "old")
    assert sleeps[0] >= 2.0 and sleeps[2] > sleeps[0]


class _Snap:
    def __init__(self) -> None:
        self.reasons: list[str] = []

    def request(self, reason: str) -> None:
        self.reasons.append(reason)

    def step(self) -> None:
        return None


def test_reregistration_snapshots_the_lease_table_to_the_new_row(
    agent_cfg: AgentConfig, registered: list[int]
) -> None:
    """The new row's lease table is empty — the old row's leases went with
    it. A restart covered that with the ``agent_start`` snapshot; in process
    the lease watcher asks for one when it sees the re-registration."""
    from spatium_dhcp_agent.leases import LeaseWatcher

    ensure_layout(agent_cfg.state_dir)
    token_ref = ["old-token"]
    s4, s6 = _Snap(), _Snap()
    w = LeaseWatcher(agent_cfg, token_ref, _Heartbeat(), snapshot=s4, snapshot_v6=s6)
    s4.reasons.clear()
    s6.reasons.clear()
    w.tick()
    assert s4.reasons == []

    bootstrap_mod.reauthenticate(agent_cfg, token_ref, "old-token")
    w.tick()
    assert s4.reasons == ["agent_reregistered"]
    assert s6.reasons == ["agent_reregistered"]
    w.tick()
    assert s4.reasons == ["agent_reregistered"]


def test_sync_drops_its_etag_when_another_thread_re_registered(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch, registered: list[int]
) -> None:
    ensure_layout(agent_cfg.state_dir)
    token_ref = ["old-token"]
    loop = SyncLoop(agent_cfg, token_ref, heartbeat=_Heartbeat())
    loop._current_etag = "e-old-row"
    sent: list[dict[str, str]] = []

    class _Capture(_Client):
        def get(self, *a: Any, **k: Any) -> _Resp:
            sent.append(dict(k.get("headers") or {}))
            return _Resp(304)

    monkeypatch.setattr(loop, "_client", lambda: _Capture(304))
    bootstrap_mod.reauthenticate(agent_cfg, token_ref, "old-token")  # the heartbeat
    loop._poll_once()
    assert "If-None-Match" not in sent[0]
    assert sent[0]["Authorization"] == "Bearer new-token"
