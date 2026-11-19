"""Every config poll names the agent process (#2042).

The control plane stamps the id on each op it ships. When an agent is
replaced, an op the API paged into the departed agent's leftover long-poll is
still ``in_flight`` to the OLD id, so the replacement's first poll — carrying
a new one — gets it back at once instead of after the 5-minute unacknowledged
reset. The id must therefore be the same on every poll of one process (or the
agent's own in-flight ops would be re-sent to it on every poll) and differ
between processes.
"""

from __future__ import annotations

import httpx
import pytest

from spatium_dns_agent import sync
from spatium_dns_agent.apply_guard import ApplyGuard
from spatium_dns_agent.config import AgentConfig
from spatium_dns_agent.sync import SyncLoop


class _NoQuarantine:
    etag = None

    def retry_due(self) -> bool:
        return False


def test_every_poll_of_one_process_carries_the_same_instance_id(
    agent_cfg: AgentConfig,
) -> None:
    seen: list[str | None] = []

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("X-Spatium-Agent-Instance"))
        return httpx.Response(304)

    loop = object.__new__(SyncLoop)
    loop.cfg = agent_cfg
    loop.token_ref = ["t1"]
    loop._quarantine = _NoQuarantine()
    # #2019 / #1968 — read at the top of every poll: nothing armed, no cache
    # held back, no startup report outstanding.
    loop._guard = ApplyGuard(agent_cfg.state_dir)
    loop._boot_hold = None
    loop._boot_report_bundle = None
    loop._current_etag = "sha256:abc"
    # #2052 — the re-registration generation the poll compares against.
    loop._reauth_gen = sync.reauth_generation()
    loop._client = lambda: httpx.Client(  # type: ignore[method-assign]
        base_url="http://cp", transport=httpx.MockTransport(answer)
    )

    loop._poll_once()
    loop._poll_once()

    assert seen == [sync.AGENT_INSTANCE, sync.AGENT_INSTANCE]
    assert sync.AGENT_INSTANCE and len(sync.AGENT_INSTANCE) <= 64


def test_a_duplicate_instance_refusal_backs_off_without_rebootstrapping(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#2044 — another live agent process owns this server identity. The 409
    is not a re-registration case (a new token would not change which process
    owns the row), so the token stays and the agent waits out a slow backoff
    instead of hammering the control plane every 5 s."""
    calls: list[str] = []

    def answer(request: httpx.Request) -> httpx.Response:
        calls.append(request.headers.get("Authorization", ""))
        return httpx.Response(
            409,
            headers={sync.DUPLICATE_INSTANCE_HEADER: "1"},
            json={"detail": "Another agent process is polling as DNS server 'ns1'."},
        )

    reauth: list[object] = []
    monkeypatch.setattr(sync, "reauthenticate", lambda *a, **k: reauth.append(a))
    waits: list[float] = []

    class _Stop:
        def wait(self, timeout: float) -> bool:
            waits.append(timeout)
            return False

    loop = object.__new__(SyncLoop)
    loop.cfg = agent_cfg
    loop.token_ref = ["t1"]
    loop._quarantine = _NoQuarantine()
    loop._guard = ApplyGuard(agent_cfg.state_dir)
    loop._boot_hold = None
    loop._boot_report_bundle = None
    loop._current_etag = "sha256:abc"
    loop._reauth_gen = sync.reauth_generation()
    loop._stop = _Stop()  # type: ignore[assignment]
    loop._client = lambda: httpx.Client(  # type: ignore[method-assign]
        base_url="http://cp", transport=httpx.MockTransport(answer)
    )

    loop._poll_once()

    assert calls == ["Bearer t1"]
    assert reauth == []
    assert loop.token_ref == ["t1"]
    assert loop._current_etag == "sha256:abc"
    assert waits == [sync.DUPLICATE_INSTANCE_BACKOFF]


def test_the_heartbeat_names_the_same_process(agent_cfg: AgentConfig, monkeypatch) -> None:
    """#2044 — the control plane keeps a displaced process's daemon / config
    reports off the server row, which it can only do if the heartbeat says
    which process it is: the same id the config poll sends."""
    from typing import Any, Self

    from spatium_dns_agent.heartbeat import HeartbeatClient

    seen: list[dict[str, str]] = []

    class _Client:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def post(self, url: str, json: dict[str, Any], headers: dict[str, str]) -> httpx.Response:
            seen.append(headers)
            return httpx.Response(200, json={}, request=httpx.Request("POST", url))

    hb = HeartbeatClient(agent_cfg, ["tok"])
    monkeypatch.setattr(hb, "_client", lambda: _Client())
    hb.send_once()
    assert seen and seen[0][sync.AGENT_INSTANCE_HEADER] == sync.AGENT_INSTANCE
    assert seen[0]["Authorization"] == "Bearer tok"
