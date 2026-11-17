"""Unit tests for the generalized agent command channel
(``app.services.appliance.agent_cmd``) — dashboard-and-remote-nettools.

Exercises the in-memory queue directly (no HTTP, no supervisor):

* enqueue → pop → deliver round-trip;
* offline fast-return (``ready=False`` raises ApplianceOffline before
  any wait);
* timeout when no supervisor ever replies;
* readiness heuristic (approved + recent heartbeat).
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.services.appliance import agent_cmd


async def test_enqueue_pop_deliver_roundtrip() -> None:
    appliance_id = uuid.uuid4()

    async def supervisor() -> None:
        # Stand in for the supervisor poll thread: pop the command and
        # post a result back.
        cmd = await agent_cmd.pop_command(appliance_id, timeout=5.0)
        assert cmd is not None
        assert cmd.tool == "ping"
        assert cmd.params == {"host": "1.1.1.1"}
        delivered = await agent_cmd.deliver_result(
            agent_cmd.NetToolResult(
                request_id=cmd.request_id,
                result={"tool": "ping", "argv": ["ping"], "available": True},
            ),
            appliance_id=appliance_id,
        )
        assert delivered is True

    sup = asyncio.create_task(supervisor())
    outcome = await agent_cmd.enqueue_command(
        appliance_id, "ping", {"host": "1.1.1.1"}, ready=True, timeout=5.0
    )
    await asyncio.gather(sup)  # drain the helper task + surface any error
    assert outcome.error is None
    assert outcome.result is not None
    assert outcome.result["available"] is True


async def test_enqueue_offline_fast_returns() -> None:
    appliance_id = uuid.uuid4()
    # ready=False ⇒ raise immediately, never block for the timeout.
    started = asyncio.get_running_loop().time()
    with pytest.raises(agent_cmd.ApplianceOffline):
        await agent_cmd.enqueue_command(
            appliance_id, "ping", {"host": "1.1.1.1"}, ready=False, timeout=30.0
        )
    elapsed = asyncio.get_running_loop().time() - started
    assert elapsed < 1.0, "offline enqueue must fast-return, not wait for timeout"
    # Nothing should have been queued.
    assert agent_cmd.queue_depth(appliance_id) == 0


async def test_enqueue_times_out_when_no_reply() -> None:
    appliance_id = uuid.uuid4()
    with pytest.raises(asyncio.TimeoutError):
        await agent_cmd.enqueue_command(
            appliance_id, "ping", {"host": "1.1.1.1"}, ready=True, timeout=0.2
        )


async def test_pop_skips_cancelled() -> None:
    appliance_id = uuid.uuid4()

    # Enqueue a command that times out → its queue entry is marked
    # cancelled. A later pop must skip it and not hand stale work to the
    # supervisor.
    with pytest.raises(asyncio.TimeoutError):
        await agent_cmd.enqueue_command(
            appliance_id, "ping", {"host": "1.1.1.1"}, ready=True, timeout=0.1
        )

    # Now a real command lands behind the cancelled one.
    async def supervisor() -> None:
        cmd = await agent_cmd.pop_command(appliance_id, timeout=2.0)
        assert cmd is not None
        # The cancelled entry must have been skipped — we get the live one.
        assert cmd.params == {"host": "9.9.9.9"}
        await agent_cmd.deliver_result(
            agent_cmd.NetToolResult(request_id=cmd.request_id, result={"ok": True}),
            appliance_id=appliance_id,
        )

    sup = asyncio.create_task(supervisor())
    outcome = await agent_cmd.enqueue_command(
        appliance_id, "ping", {"host": "9.9.9.9"}, ready=True, timeout=3.0
    )
    await asyncio.gather(sup)  # drain the helper task + surface any error
    assert outcome.result == {"ok": True}


async def test_pop_returns_none_on_timeout() -> None:
    appliance_id = uuid.uuid4()
    cmd = await agent_cmd.pop_command(appliance_id, timeout=0.1)
    assert cmd is None


async def test_deliver_stale_when_future_evicted() -> None:
    # A result for a request_id with no awaiting future returns False.
    delivered = await agent_cmd.deliver_result(
        agent_cmd.NetToolResult(request_id=str(uuid.uuid4()), result={"ok": True}),
        appliance_id=uuid.uuid4(),
    )
    assert delivered is False


def test_appliance_ready_heuristic() -> None:
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    # Approved + fresh heartbeat → ready.
    assert agent_cmd.appliance_ready(
        state="approved", last_seen_at=now - timedelta(seconds=10), now=now
    )
    # Approved but stale heartbeat → not ready.
    assert not agent_cmd.appliance_ready(
        state="approved", last_seen_at=now - timedelta(seconds=600), now=now
    )
    # Approved but never heartbeated → not ready.
    assert not agent_cmd.appliance_ready(state="approved", last_seen_at=None, now=now)
    # Pending (not approved) even with a fresh heartbeat → not ready.
    assert not agent_cmd.appliance_ready(state="pending_approval", last_seen_at=now, now=now)


def test_appliance_ready_naive_datetime_tolerated() -> None:
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    # A naive last_seen_at is treated as UTC rather than raising.
    naive = datetime(2026, 1, 1, 11, 59, 50)  # noqa: DTZ001 — deliberate
    assert agent_cmd.appliance_ready(state="approved", last_seen_at=naive, now=now)


def test_reachability_tool_set() -> None:
    assert agent_cmd.REACHABILITY_TOOLS == frozenset(
        {"ping", "traceroute", "dig", "port-test", "tls-cert"}
    )
    # Server-only tools are intentionally absent.
    for server_only in ("whois", "mac-vendor", "dns-propagation", "mtr"):
        assert server_only not in agent_cmd.REACHABILITY_TOOLS
