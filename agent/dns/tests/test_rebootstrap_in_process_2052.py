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


def test_repeated_reauthentication_is_paced(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A token refused straight after it was minted must not loop register →
    poll → 401 at network speed; the container restart this replaced was
    paced by the orchestrator's back-off."""
    ensure_layout(agent_cfg.state_dir)
    minted = iter(f"token-{i}" for i in range(10))
    monkeypatch.setattr(bootstrap_mod, "register", lambda cfg: ("a", next(minted), {}))
    sleeps: list[float] = []
    monkeypatch.setattr(bootstrap_mod.time, "sleep", sleeps.append)
    token_ref = ["old"]

    bootstrap_mod.reauthenticate(agent_cfg, token_ref, "old")
    assert sleeps == []  # the first one in a while registers at once
    bootstrap_mod.reauthenticate(agent_cfg, token_ref, token_ref[0])
    bootstrap_mod.reauthenticate(agent_cfg, token_ref, token_ref[0])
    assert len(sleeps) == 2 and sleeps[0] >= 5.0 and sleeps[1] >= 10.0

    # Quiet for a window: back to an immediate re-registration.
    monkeypatch.setattr(
        bootstrap_mod,
        "_last_reauth_at",
        bootstrap_mod.time.monotonic() - bootstrap_mod.REAUTH_REPEAT_WINDOW_SECONDS - 1,
    )
    bootstrap_mod.reauthenticate(agent_cfg, token_ref, token_ref[0])
    assert len(sleeps) == 2


class _Driver:
    held_back: list[Any] = []


def test_reregistration_resends_the_startup_reports_to_the_new_row(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch, registered: list[int]
) -> None:
    """The new row has seen no zone-state, DNSSEC state or rendered config,
    and its bundle's structural etag (no server id in it) re-renders nothing.
    A restart sent all three at startup; in process the sync loop resends them
    — even when the HEARTBEAT was the thread that re-registered."""
    ensure_layout(agent_cfg.state_dir)
    token_ref = ["old-token"]
    loop = SyncLoop(agent_cfg, token_ref, _Driver(), MagicMock())
    loop._dnssec_bundle = {
        "zones": [{"name": "a.test.", "serial": 10}, {"name": "b.test.", "serial": 5}]
    }
    loop._reported_serials = {"a.test": 12}  # record ops moved a.test past 10
    loop._dnssec_reported = [{"zone": "a.test."}]
    loop._dnssec_refresh_at = 1e12
    loop._current_etag = "e-old-row"
    posted: list[list[dict[str, Any]]] = []

    def post(entries: list[dict[str, Any]]) -> bool:
        posted.append(entries)
        return True

    monkeypatch.setattr(loop, "_post_zone_state", post)
    pushed: list[str] = []
    monkeypatch.setattr(sync_mod, "push_rendered_config", lambda cfg, tok: pushed.append(tok))
    sent: list[dict[str, str]] = []

    def get_config(c: _Client, headers: dict[str, str], d: Any) -> _Resp:
        sent.append(dict(headers))
        return c.get()

    monkeypatch.setattr(sync_mod, "get_config", get_config)
    monkeypatch.setattr(loop, "_client", lambda: _Client(304))

    # The heartbeat met the 404 first and registered.
    bootstrap_mod.reauthenticate(agent_cfg, token_ref, "old-token")
    loop._poll_once()

    assert posted == [
        [{"zone_name": "a.test.", "serial": 12}, {"zone_name": "b.test.", "serial": 5}]
    ]
    assert pushed == ["new-token"]
    assert "If-None-Match" not in sent[0]
    assert loop._dnssec_reported is None and loop._dnssec_refresh_at == 0.0

    # Once is enough: the next poll sends nothing again.
    loop._poll_once()
    assert len(posted) == 1 and len(pushed) == 1
