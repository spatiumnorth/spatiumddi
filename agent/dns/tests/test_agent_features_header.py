"""Every request tells the control plane this agent renders a zone's own SOA
timers (#1171).

The control plane serves a group the zones' own timers only once every BIND9
agent in it says so, and moves the zones' serials when it switches; an agent
that says nothing is taken for an older release, which writes
``3600 600 86400 300`` for every zone. The register call says it before the
agent's first poll, and the heartbeat on every beat.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from spatium_dns_agent import bootstrap, features
from spatium_dns_agent.config import AgentConfig
from spatium_dns_agent.heartbeat import HeartbeatClient
from spatium_dns_agent.sync import SyncLoop


def test_the_header_names_soa_timers() -> None:
    assert features.headers() == {"X-Spatium-Agent-Features": "soa-timers"}


def test_register_sends_it_on_the_wire(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, str] = {}

    def answer(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(
            200, json={"server_id": "s1", "agent_token": "t1", "pending_approval": False}
        )

    real_client = httpx.Client

    def client(**kw: Any) -> httpx.Client:
        return real_client(transport=httpx.MockTransport(answer), **kw)

    monkeypatch.setattr(bootstrap.httpx, "Client", client)

    bootstrap.register(agent_cfg)

    assert seen["x-spatium-agent-features"] == "soa-timers"
    assert seen["x-dns-agent-key"] == "test-key"


@pytest.mark.parametrize("cls", [HeartbeatClient, SyncLoop], ids=["heartbeat", "config-poll"])
def test_the_heartbeat_and_the_config_poll_send_it(agent_cfg: AgentConfig, cls: type) -> None:
    holder = object.__new__(cls)
    holder.cfg = agent_cfg

    with holder._client() as c:
        assert c.headers["X-Spatium-Agent-Features"] == "soa-timers"
