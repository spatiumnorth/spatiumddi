"""#4139 — a new process names itself to the control plane before its boot apply."""

from __future__ import annotations

from typing import Any, Self

import httpx

from spatium_dhcp_agent import supervisor as sup_mod
from spatium_dhcp_agent.config import AgentConfig
from spatium_dhcp_agent.heartbeat import HeartbeatClient
from spatium_dhcp_agent.instance import AGENT_INSTANCE, AGENT_INSTANCE_HEADER


class _Client:
    def __init__(self, sent: list[tuple[dict[str, Any], dict[str, str]]], fail: bool) -> None:
        self.sent = sent
        self.fail = fail

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def post(self, url: str, json: dict[str, Any], headers: dict[str, str]) -> httpx.Response:
        self.sent.append((dict(json), dict(headers)))
        if self.fail:
            raise httpx.ConnectError("control plane down")
        return httpx.Response(200, json={}, request=httpx.Request("POST", url))


def test_announce_sends_the_instance_header_with_no_verdict(
    agent_cfg: AgentConfig, monkeypatch
) -> None:
    hb = HeartbeatClient(agent_cfg, ["tok"])
    sent: list[tuple[dict[str, Any], dict[str, str]]] = []
    timeouts: list[float] = []

    def client(timeout: float = 15.0) -> _Client:
        timeouts.append(timeout)
        return _Client(sent, fail=False)

    monkeypatch.setattr(hb, "_client", client)
    hb.announce()
    body, headers = sent[0]
    assert headers[AGENT_INSTANCE_HEADER] == AGENT_INSTANCE
    assert body["config"] == {}
    assert timeouts == [3.0]


def test_announce_never_raises_when_the_control_plane_is_down(
    agent_cfg: AgentConfig, monkeypatch
) -> None:
    hb = HeartbeatClient(agent_cfg, ["tok"])
    monkeypatch.setattr(hb, "_client", lambda timeout=15.0: _Client([], fail=True))
    hb.announce()  # boots from cache regardless (non-negotiable #5)


def test_the_supervisor_announces_before_the_sync_loop_boots(
    agent_cfg: AgentConfig, monkeypatch
) -> None:
    order: list[str] = []

    class _Stop(Exception):
        pass

    class _HB:
        def __init__(self, *a: Any, **k: Any) -> None:
            pass

        def announce(self) -> None:
            order.append("announce")

    class _Sync:
        def __init__(self, *a: Any, **k: Any) -> None:
            order.append("boot_apply")
            raise _Stop

    class _Oom:
        def __init__(self, *a: Any, **k: Any) -> None:
            pass

    monkeypatch.setattr(sup_mod, "ensure_token", lambda cfg: ("id", "tok"))
    monkeypatch.setattr(sup_mod, "build_spool_manager", lambda cfg: object())
    monkeypatch.setattr(sup_mod, "HeartbeatClient", _HB)
    monkeypatch.setattr(sup_mod, "OomWatch", _Oom)
    monkeypatch.setattr(sup_mod, "HAStatusPoller", lambda *a, **k: object())
    monkeypatch.setattr(sup_mod, "PeerResolveWatcher", lambda *a, **k: object())
    monkeypatch.setattr(sup_mod, "SyncLoop", _Sync)
    try:
        sup_mod.run(agent_cfg)
    except _Stop:
        pass
    assert order == ["announce", "boot_apply"]
