"""A 401/404 re-registers in process; it never ends a thread (#2052).

Deleting the server row while its agent was connected made the woken
long-poll answer 404. The sync thread dropped its token and STOPPED, the
supervisor's dead-thread watch exited the container, and named went down with
it for the 2-13 s a restart takes. Non-negotiable #5: drop the token, keep the
cached config and the daemon.
"""

from __future__ import annotations

import threading
from typing import Any
from unittest.mock import MagicMock

import pytest

from spatium_dns_agent import bootstrap as bootstrap_mod
from spatium_dns_agent import sync as sync_mod
from spatium_dns_agent.cache import ensure_layout, load_token, save_token
from spatium_dns_agent.config import AgentConfig
from spatium_dns_agent.heartbeat import HeartbeatClient
from spatium_dns_agent.sync import SyncLoop


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
def test_sync_re_registers_and_keeps_the_thread_and_daemon(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch, registered: list[int], status: int
) -> None:
    ensure_layout(agent_cfg.state_dir)
    save_token(agent_cfg.state_dir, "old-token")
    driver = MagicMock()
    hb = MagicMock()
    hb.config_apply = None
    token_ref = ["old-token"]
    loop = SyncLoop(agent_cfg, token_ref, driver, hb)
    loop._current_etag = "e1"
    monkeypatch.setattr(loop, "_client", lambda: _Client(status))
    monkeypatch.setattr(sync_mod, "get_config", lambda c, h, d: c.get())

    loop._poll_once()

    assert registered == [1]
    assert token_ref[0] == "new-token"
    assert load_token(agent_cfg.state_dir) == "new-token"
    assert not loop._stop.is_set(), "the sync thread must keep running"
    assert loop._current_etag is None  # the new row gets a fresh 200
    driver.stop_daemon.assert_not_called()


def test_sync_run_loop_survives_a_404(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch, registered: list[int]
) -> None:
    ensure_layout(agent_cfg.state_dir)
    loop = SyncLoop(agent_cfg, ["old-token"], MagicMock(), MagicMock())
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
    monkeypatch.setattr(sync_mod, "get_config", lambda c, h, d: c.get())
    monkeypatch.setattr(loop, "_refresh_dnssec_state", lambda force=False: None)
    t = threading.Thread(target=loop.run, daemon=True)
    t.start()
    assert seen.wait(10), "the loop stopped polling after the 404"
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
    """A wrong PSK / dead control plane sleeps with backoff inside register."""
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
