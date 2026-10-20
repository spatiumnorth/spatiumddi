"""The Looking Glass config long-poll reads committed state on every wake (#2040).

Same defect as the DHCP long-poll (``test_dhcp_longpoll_wake_2040.py``): one
session for the whole wait, so a re-query handed back the peer rows already in
the identity map and the collector row was never re-read. A peer edit or a
collector disable woke the poll and rebuilt a byte-identical bundle, reaching
the agent only at the long-poll timeout.

Also pins that several no-change wakes in a row neither break the poll (no lazy
load on an expired instance, which in async is a ``MissingGreenlet`` 500) nor
stop it seeing the change that finally lands.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.looking_glass import agents as lg_agents
from app.core import agent_wake
from app.core.agent_wake import WakeResult, looking_glass_collector_channel
from app.core.security import create_access_token, hash_password
from app.db import get_db
from app.main import app
from app.models.auth import User
from app.models.bgp_looking_glass import BGPLGPeer, LookingGlassCollector
from app.services.looking_glass import agent_token as lg_tokens
from tests.conftest import _TestSessionLocal


async def _estate(db: AsyncSession) -> dict[str, Any]:
    col = LookingGlassCollector(
        name=f"col-{uuid.uuid4().hex[:8]}",
        agent_id=uuid.uuid4().hex,
        agent_registered=True,
        status="active",
    )
    db.add(col)
    await db.flush()
    peer = BGPLGPeer(
        name="p1",
        collector_id=col.id,
        local_asn=65000,
        peer_asn=65001,
        peer_address="192.0.2.1",
    )
    db.add(peer)
    await db.flush()
    token, _exp = lg_tokens.mint_agent_token(
        collector_id=str(col.id), agent_id=str(col.agent_id), fingerprint="fp"
    )
    col.agent_token_hash = lg_tokens.hash_token(token)
    await db.commit()
    return {"collector": col.id, "peer": peer.id, "token": token}


@pytest.fixture
def fresh_session_per_request() -> Any:
    """Each request gets its own session, as in production (see the DHCP test)."""

    async def _get_db() -> AsyncGenerator[AsyncSession, None]:
        async with _TestSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _get_db
    yield
    app.dependency_overrides.clear()


class _ScriptedWake:
    """Delivers ``idle`` no-change wakes, then one the test fires after its edit."""

    def __init__(self, idle: int) -> None:
        self.idle = idle
        self.parked = asyncio.Event()
        self.fire = asyncio.Event()
        self.waits = 0

    async def wait(self, timeout: float) -> WakeResult:
        self.waits += 1
        if self.waits <= self.idle:
            return WakeResult.WAKE
        if self.waits == self.idle + 1:
            self.parked.set()
            await asyncio.wait_for(self.fire.wait(), timeout=timeout)
            return WakeResult.WAKE
        await asyncio.sleep(timeout)
        return WakeResult.TIMEOUT


async def _peer_asn(db: AsyncSession, ids: dict[str, Any]) -> None:
    (await db.get(BGPLGPeer, ids["peer"])).peer_asn = 65099  # type: ignore[union-attr]


async def _collector_off(db: AsyncSession, ids: dict[str, Any]) -> None:
    (await db.get(LookingGlassCollector, ids["collector"])).enabled = False  # type: ignore[union-attr]


@pytest.mark.parametrize("idle", [0, 3], ids=["first-wake", "after-3-idle-wakes"])
@pytest.mark.parametrize(
    ("edit", "read", "expected"),
    [
        pytest.param(_peer_asn, lambda b: b["peers"][0]["peer_asn"], 65099, id="peer-asn"),
        pytest.param(_collector_off, lambda b: b["peers"], [], id="collector-disabled"),
    ],
)
async def test_a_parked_lg_poll_sees_the_edit_on_the_wake(
    db_session: AsyncSession,
    fresh_session_per_request: None,
    monkeypatch: pytest.MonkeyPatch,
    idle: int,
    edit: Any,
    read: Any,
    expected: Any,
) -> None:
    ids = await _estate(db_session)
    headers = {"Authorization": f"Bearer {ids['token']}"}
    fake = _ScriptedWake(idle)

    @asynccontextmanager
    async def _subscription(_channels: Any) -> AsyncIterator[_ScriptedWake]:
        yield fake

    monkeypatch.setattr(lg_agents, "wake_subscription", _subscription)
    monkeypatch.setattr(lg_agents, "LONGPOLL_TIMEOUT_SECONDS", 6)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        first = await ac.get("/api/v1/looking-glass/agents/config", headers=headers)
        assert first.status_code == 200, first.text
        etag = first.json()["etag"]
        assert read(first.json()["bundle"]) != expected

        fake.waits = 0
        poll = asyncio.create_task(
            ac.get(
                "/api/v1/looking-glass/agents/config",
                headers={**headers, "If-None-Match": f'"{etag}"'},
            )
        )
        await asyncio.wait_for(fake.parked.wait(), timeout=5)
        async with _TestSessionLocal() as other:
            await edit(other, ids)
            await other.commit()
        fake.fire.set()
        resp = await asyncio.wait_for(poll, timeout=15)

    assert resp.status_code == 200, (
        f"the parked poll answered {resp.status_code} after {fake.waits} wait(s): "
        "it rebuilt the bundle from stale identity-map rows and missed the wake"
    )
    assert fake.waits == idle + 1
    assert read(resp.json()["bundle"]) == expected


async def test_a_collector_edit_publishes_on_its_channel(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []

    async def _publish(*channels: str) -> None:
        seen.extend(channels)

    monkeypatch.setattr(agent_wake, "publish_wake", _publish)
    ids = await _estate(db_session)
    user = User(
        username=f"lg2040-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="LG",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(user)
    await db_session.commit()
    resp = await client.patch(
        f"/api/v1/looking-glass/collectors/{ids['collector']}",
        json={"enabled": False},
        headers={"Authorization": f"Bearer {create_access_token(str(user.id))}"},
    )
    assert resp.status_code == 200, resp.text
    assert looking_glass_collector_channel(ids["collector"]) in seen
