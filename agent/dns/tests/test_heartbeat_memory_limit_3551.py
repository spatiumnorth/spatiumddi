"""#3551 — the heartbeat reports the container's memory limit.

named and the agent share the container's limit, and under split-horizon an
RPZ loads once per view that applies it. The control plane compares its
estimate of the group's named memory against the limit the agent reports
here, so it can warn before a supported change OOM-loops the group.
"""

from __future__ import annotations

from typing import Any, Self

import httpx

from spatium_dns_agent import heartbeat as hb_mod
from spatium_dns_agent.config import AgentConfig
from spatium_dns_agent.heartbeat import HeartbeatClient


class _Client:
    def __init__(self, sent: list[dict[str, Any]], refuse: bool) -> None:
        self.sent = sent
        self.refuse = refuse

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def post(
        self, url: str, json: dict[str, Any], headers: dict[str, str]
    ) -> httpx.Response:
        self.sent.append(dict(json))
        req = httpx.Request("POST", url)
        if self.refuse and "memory_limit_bytes" in json:
            # What an older control plane (extra="forbid") answers.
            return httpx.Response(
                422,
                text='{"detail":[{"type":"extra_forbidden","loc":["body","memory_limit_bytes"]}]}',
                request=req,
            )
        return httpx.Response(200, json={}, request=req)


def test_the_limit_rides_on_the_heartbeat(agent_cfg: AgentConfig, monkeypatch) -> None:
    monkeypatch.setattr(hb_mod, "cgroup_memory_limit_bytes", lambda: 1 << 30)
    hb = HeartbeatClient(agent_cfg, ["tok"])
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(hb, "_client", lambda: _Client(sent, refuse=False))
    hb.send_once()
    assert sent[0]["memory_limit_bytes"] == 1 << 30


def test_no_limit_is_reported_as_null(agent_cfg: AgentConfig, monkeypatch) -> None:
    monkeypatch.setattr(hb_mod, "cgroup_memory_limit_bytes", lambda: None)
    hb = HeartbeatClient(agent_cfg, ["tok"])
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(hb, "_client", lambda: _Client(sent, refuse=False))
    hb.send_once()
    assert "memory_limit_bytes" in sent[0]
    assert sent[0]["memory_limit_bytes"] is None


def test_an_older_control_plane_that_refuses_the_field_still_gets_heartbeats(
    agent_cfg: AgentConfig, monkeypatch
) -> None:
    monkeypatch.setattr(hb_mod, "cgroup_memory_limit_bytes", lambda: 1 << 30)
    hb = HeartbeatClient(agent_cfg, ["tok"])
    hb.pending_acks.append({"op_id": "a", "result": "ok"})
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(hb, "_client", lambda: _Client(sent, refuse=True))

    hb.send_once()
    assert "memory_limit_bytes" in sent[0]
    assert "memory_limit_bytes" not in sent[1]
    assert hb.pending_acks == []  # the retry was accepted

    hb.send_once()
    assert "memory_limit_bytes" not in sent[2]
