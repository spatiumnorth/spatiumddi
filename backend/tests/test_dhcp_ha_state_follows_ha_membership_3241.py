"""A DHCP server's reported HA state describes an HA relationship it is in (#3241).

``ha_state`` and ``ha_last_heartbeat_at`` are written by the agent's HA status
report (``POST /dhcp/agents/ha-status``), and the agent sends one only while its
last config bundle carried a failover block. Nothing cleared them, so a server
that left its HA relationship kept the last state it reported for good:
``GET /dhcp/servers`` said ``hot-standby`` (and the DHCP page drew its HA pill)
for a standalone server whose Kea had unloaded the hook.

The contract, at the API an agent and an operator see:

* once a server's bundle carries no failover block (its group's mode is
  standalone, it moved to another group, its partner left or was deleted, or
  its own peer URL was cleared), its agent's next config poll clears both
  fields, whether that poll answers 200 or 304;
* a report from a server that takes part in no HA relationship stores nothing:
  the agent's poller can send one more before it applies the bundle that
  switches it off;
* a participant's report is stored, and its polls leave it alone.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp import agents as dhcp_agents
from app.core.agent_wake import WakeResult
from app.core.security import create_access_token, hash_password
from app.db import get_db
from app.main import app
from app.models.auth import User
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.services.dhcp import agent_token as dhcp_tokens
from tests.conftest import _TestSessionLocal

REPORTED_AT = datetime(2026, 11, 1, 3, 14, 5, tzinfo=UTC)

# ── fixtures ──────────────────────────────────────────────────────────────────


async def _estate(db: AsyncSession) -> dict[str, Any]:
    """A Kea hot-standby pair whose first member last reported ``hot-standby``,
    and a standalone group beside it."""
    pair = DHCPServerGroup(name=f"pair-{uuid.uuid4().hex[:8]}", mode="hot-standby")
    solo = DHCPServerGroup(name=f"solo-{uuid.uuid4().hex[:8]}", mode="standalone")
    db.add_all([pair, solo])
    await db.flush()
    servers = []
    for label, ip in (("a", "10.9.0.1"), ("b", "10.9.0.2")):
        srv = DHCPServer(
            name=f"{label}-{uuid.uuid4().hex[:6]}",
            driver="kea",
            host=ip,
            port=67,
            server_group_id=pair.id,
            ha_peer_url=f"http://{ip}:8000/",
            agent_id=uuid.uuid4(),
            agent_registered=True,
            agent_approved=True,
            agent_fingerprint="fp",
            ha_state="hot-standby",
            ha_last_heartbeat_at=REPORTED_AT,
        )
        db.add(srv)
        servers.append(srv)
    await db.flush()
    token, _exp = dhcp_tokens.mint_agent_token(
        server_id=str(servers[0].id), agent_id=str(servers[0].agent_id), fingerprint="fp"
    )
    servers[0].agent_token_hash = dhcp_tokens.hash_token(token)
    admin = User(
        username=f"ha3241-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="HA Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(admin)
    await db.commit()
    return {
        "pair": pair.id,
        "solo": solo.id,
        "a": servers[0].id,
        "b": servers[1].id,
        "agent": {"Authorization": f"Bearer {token}"},
        "admin": {"Authorization": f"Bearer {create_access_token(str(admin.id))}"},
    }


@pytest.fixture
def fresh_session_per_request() -> Any:
    """Each request gets its own session, as in production (the shared
    ``client`` fixture would hand the poll and the read one identity map)."""

    async def _get_db() -> AsyncGenerator[AsyncSession, None]:
        async with _TestSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _get_db
    yield
    app.dependency_overrides.clear()


class _NoWake:
    """Stands in for the Redis subscription: nothing wakes a parked poll."""

    async def wait(self, timeout: float) -> WakeResult:
        await asyncio.sleep(timeout)
        return WakeResult.TIMEOUT


@pytest.fixture
def quiet_long_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    @asynccontextmanager
    async def _subscription(_channels: Any) -> AsyncIterator[_NoWake]:
        yield _NoWake()

    monkeypatch.setattr(dhcp_agents, "wake_subscription", _subscription)
    monkeypatch.setattr(dhcp_agents, "LONGPOLL_TIMEOUT_SECONDS", 1)


async def _row(ac: AsyncClient, ids: dict[str, Any]) -> dict[str, Any]:
    resp = await ac.get(f"/api/v1/dhcp/servers/{ids['a']}", headers=ids["admin"])
    assert resp.status_code == 200, resp.text
    return resp.json()


# ── doors out of HA ───────────────────────────────────────────────────────────


async def _group_mode_standalone(db: AsyncSession, ids: dict[str, Any]) -> None:
    (await db.get(DHCPServerGroup, ids["pair"])).mode = "standalone"  # type: ignore[union-attr]


async def _moved_to_a_standalone_group(db: AsyncSession, ids: dict[str, Any]) -> None:
    (await db.get(DHCPServer, ids["a"])).server_group_id = ids["solo"]  # type: ignore[union-attr]


async def _partner_moved_out(db: AsyncSession, ids: dict[str, Any]) -> None:
    (await db.get(DHCPServer, ids["b"])).server_group_id = ids["solo"]  # type: ignore[union-attr]


async def _partner_deleted(db: AsyncSession, ids: dict[str, Any]) -> None:
    await db.delete(await db.get(DHCPServer, ids["b"]))


async def _own_peer_url_cleared(db: AsyncSession, ids: dict[str, Any]) -> None:
    (await db.get(DHCPServer, ids["a"])).ha_peer_url = ""  # type: ignore[union-attr]


DOORS: list[tuple[str, Callable[..., Awaitable[None]]]] = [
    ("group-mode-standalone", _group_mode_standalone),
    ("moved-to-a-standalone-group", _moved_to_a_standalone_group),
    ("partner-moved-out", _partner_moved_out),
    ("partner-deleted", _partner_deleted),
    ("own-peer-url-cleared", _own_peer_url_cleared),
]


@pytest.mark.parametrize("door", [pytest.param(d, id=name) for name, d in DOORS])
async def test_a_server_out_of_ha_reads_no_ha_state_once_its_agent_polls(
    db_session: AsyncSession,
    fresh_session_per_request: None,
    quiet_long_poll: None,
    door: Callable[..., Awaitable[None]],
) -> None:
    ids = await _estate(db_session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        before = await _row(ac, ids)
        assert before["ha_state"] == "hot-standby"

        async with _TestSessionLocal() as other:
            await door(other, ids)
            await other.commit()

        poll = await ac.get("/api/v1/dhcp/agents/config", headers=ids["agent"])
        assert poll.status_code == 200, poll.text
        # The door really took the server out of HA: its agent is told to run
        # no HA hook, so it stops reporting a state.
        assert poll.json()["bundle"]["failover"] is None

        after = await _row(ac, ids)

    assert after["ha_state"] is None, (
        f"the server left HA and its agent fetched a bundle with no HA hook, "
        f"yet its row still reads ha_state={after['ha_state']!r}"
    )
    assert after["ha_last_heartbeat_at"] is None, after["ha_last_heartbeat_at"]


async def test_a_poll_that_answers_304_clears_it_too(
    db_session: AsyncSession, fresh_session_per_request: None, quiet_long_poll: None
) -> None:
    """A row left stale while its agent's config did not change (an older
    build left it so, or a report slipped in after a clear) is cleared on the
    agent's next pass even though the poll ends in 304."""
    ids = await _estate(db_session)
    async with _TestSessionLocal() as other:
        await _group_mode_standalone(other, ids)
        await other.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        first = await ac.get("/api/v1/dhcp/agents/config", headers=ids["agent"])
        assert first.status_code == 200, first.text
        etag = first.json()["etag"]

        async with _TestSessionLocal() as other:
            server = await other.get(DHCPServer, ids["a"])
            server.ha_state = "hot-standby"  # type: ignore[union-attr]
            server.ha_last_heartbeat_at = REPORTED_AT  # type: ignore[union-attr]
            await other.commit()

        again = await ac.get(
            "/api/v1/dhcp/agents/config",
            headers={**ids["agent"], "If-None-Match": f'"{etag}"'},
        )
        assert again.status_code == 304, again.text
        after = await _row(ac, ids)

    assert after["ha_state"] is None, after["ha_state"]
    assert after["ha_last_heartbeat_at"] is None, after["ha_last_heartbeat_at"]


async def test_a_late_report_from_a_server_out_of_ha_stores_nothing(
    db_session: AsyncSession, fresh_session_per_request: None
) -> None:
    """The agent's poller reads Kea until it applies the bundle that switches
    its HA hook off, so one more report can arrive after the server left."""
    ids = await _estate(db_session)
    async with _TestSessionLocal() as other:
        await _moved_to_a_standalone_group(other, ids)
        await other.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        report = await ac.post(
            "/api/v1/dhcp/agents/ha-status",
            json={"state": "hot-standby", "raw": {}},
            headers=ids["agent"],
        )
        # An agent of any version treats only a non-2xx answer as a failure.
        assert report.status_code == 200, report.text
        after = await _row(ac, ids)

    assert after["ha_state"] is None, after["ha_state"]
    assert after["ha_last_heartbeat_at"] is None, after["ha_last_heartbeat_at"]


# ── a participant is unchanged ────────────────────────────────────────────────


async def test_a_participants_report_is_stored(
    db_session: AsyncSession, fresh_session_per_request: None
) -> None:
    ids = await _estate(db_session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        report = await ac.post(
            "/api/v1/dhcp/agents/ha-status",
            json={"state": "partner-down", "raw": {}},
            headers=ids["agent"],
        )
        assert report.status_code == 200, report.text
        after = await _row(ac, ids)

    assert after["ha_state"] == "partner-down"
    reported = datetime.fromisoformat(after["ha_last_heartbeat_at"].replace("Z", "+00:00"))
    assert reported > REPORTED_AT


async def test_a_participants_poll_keeps_its_state(
    db_session: AsyncSession, fresh_session_per_request: None, quiet_long_poll: None
) -> None:
    ids = await _estate(db_session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        poll = await ac.get("/api/v1/dhcp/agents/config", headers=ids["agent"])
        assert poll.status_code == 200, poll.text
        assert poll.json()["bundle"]["failover"] is not None
        after = await _row(ac, ids)

    assert after["ha_state"] == "hot-standby"
    assert after["ha_last_heartbeat_at"] is not None
