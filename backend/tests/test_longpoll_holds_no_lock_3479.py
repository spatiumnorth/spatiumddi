"""A parked config long-poll holds no lock (#3479).

Each pass of an agent's config long-poll reads (the server row, its bundle,
the op queue) and then parks on the agent's wake channel, up to
``LONGPOLL_TIMEOUT_SECONDS`` a request. The pass's transaction used to stay
open through the park, holding its reads' ACCESS SHARE locks. Seen live: a
DNS-only factory reset's ``TRUNCATE`` waited out the DNS poll's hold on
``dns_record_op``, every reader after it queued behind the ``TRUNCATE``, and
the minute's alert evaluation closed a deadlock in that queue; the reset
answered 500. The DHCP poll held its tables the same way.

Each poll now ends its read transaction before it parks. The probe here is
the lock a ``TRUNCATE`` takes, asked for while the poll is parked.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import asyncpg
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp import agents as dhcp_agents
from app.api.v1.dns import agents as dns_agents
from app.api.v1.looking_glass import agents as lg_agents
from app.config import settings
from app.core.agent_wake import WakeResult
from app.db import get_db
from app.main import app
from tests.conftest import _TestSessionLocal
from tests.test_dhcp_longpoll_wake_2040 import _estate as _dhcp_estate
from tests.test_dns_agents_config_serve_newest import CONFIG_URL as DNS_CONFIG_URL
from tests.test_dns_agents_config_serve_newest import _agent, _render
from tests.test_lg_longpoll_wake_2040 import _estate as _lg_estate

DHCP_CONFIG_URL = "/api/v1/dhcp/agents/config"
LG_CONFIG_URL = "/api/v1/looking-glass/agents/config"


def _dsn() -> str:
    from tests.conftest import _TEST_DATABASE_URL  # noqa: PLC0415

    return str(_TEST_DATABASE_URL).replace("postgresql+asyncpg://", "postgresql://", 1)


@pytest.fixture
def fresh_session_per_request() -> Any:
    """Each request gets its own session, as in production."""

    async def _get_db() -> AsyncGenerator[AsyncSession, None]:
        async with _TestSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _get_db
    yield
    app.dependency_overrides.clear()


class _Park:
    """Stands in for the Redis wake subscription: the first wait parks until
    the test lets it go, then the poll is told the api is stopping, so it
    answers at once."""

    def __init__(self) -> None:
        self.parked = asyncio.Event()
        self.release = asyncio.Event()

    async def wait(self, timeout: float) -> WakeResult:
        self.parked.set()
        await asyncio.wait_for(self.release.wait(), timeout=timeout)
        return WakeResult.SHUTDOWN

    @asynccontextmanager
    async def subscription(self, _channels: Any) -> AsyncIterator[_Park]:
        yield self


async def _truncate_lock(*tables: str) -> None:
    """Take the lock a TRUNCATE of ``tables`` takes, waiting at most 2 s."""
    conn = await asyncpg.connect(_dsn())
    try:
        async with conn.transaction():
            await conn.execute("SET LOCAL lock_timeout = '2s'")
            await conn.execute(f"LOCK TABLE {', '.join(tables)} IN ACCESS EXCLUSIVE MODE")
    finally:
        await conn.close()


async def _parked_poll_then_lock(
    url: str, headers: dict[str, str], park: _Park, *tables: str
) -> int:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        poll = asyncio.create_task(ac.get(url, headers=headers))
        try:
            await asyncio.wait_for(park.parked.wait(), timeout=10)
            await _truncate_lock(*tables)
        finally:
            park.release.set()
        resp = await asyncio.wait_for(poll, timeout=15)
    return resp.status_code


@pytest.mark.asyncio
async def test_a_parked_dns_poll_holds_no_lock(
    db_session: AsyncSession,
    fresh_session_per_request: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback", False)

    async def _no_enqueue(_ids: Any) -> None:
        return None

    monkeypatch.setattr(dns_agents, "enqueue_renders", _no_enqueue)
    park = _Park()
    monkeypatch.setattr(dns_agents, "wake_subscription", park.subscription)
    server, _zone, headers = await _agent(db_session)
    await db_session.commit()
    etag = (await _render(db_session, server)).etag
    await db_session.commit()

    status = await _parked_poll_then_lock(
        DNS_CONFIG_URL,
        {**headers, "If-None-Match": f'"{etag}"'},
        park,
        "dns_record_op",
        "dns_agent_bundle",
        "dns_server",
    )
    assert status == 304


@pytest.mark.asyncio
async def test_a_parked_dhcp_poll_holds_no_lock(
    db_session: AsyncSession,
    fresh_session_per_request: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = await _dhcp_estate(db_session)
    headers = {"Authorization": f"Bearer {ids['token']}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        first = await ac.get(DHCP_CONFIG_URL, headers=headers)
    assert first.status_code == 200, first.text
    park = _Park()
    monkeypatch.setattr(dhcp_agents, "wake_subscription", park.subscription)

    status = await _parked_poll_then_lock(
        DHCP_CONFIG_URL,
        {**headers, "If-None-Match": f'"{first.json()["etag"]}"'},
        park,
        "dhcp_config_op",
        "dhcp_scope",
        "dhcp_server",
    )
    assert status == 304


@pytest.mark.asyncio
async def test_a_parked_looking_glass_poll_holds_no_lock(
    db_session: AsyncSession,
    fresh_session_per_request: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = await _lg_estate(db_session)
    headers = {"Authorization": f"Bearer {ids['token']}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        first = await ac.get(LG_CONFIG_URL, headers=headers)
    assert first.status_code == 200, first.text
    park = _Park()
    monkeypatch.setattr(lg_agents, "wake_subscription", park.subscription)

    status = await _parked_poll_then_lock(
        LG_CONFIG_URL,
        {**headers, "If-None-Match": f'"{first.json()["etag"]}"'},
        park,
        "bgp_lg_peer",
        "looking_glass_collector",
    )
    assert status == 304
