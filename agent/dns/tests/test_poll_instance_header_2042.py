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
