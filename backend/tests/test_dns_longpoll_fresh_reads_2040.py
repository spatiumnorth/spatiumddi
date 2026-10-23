"""The DNS config long-poll reads committed state on every wake (#2040).

The DNS long-poll serves a stored bundle row (#1111) rather than building one,
so the DHCP defect mostly does not apply: the server row is refreshed each pass
and a new render is a new row. One shape remained. A render by a newer renderer
revision REPLACES the row at the same watermark in place (same id,
``agent_bundle_store.store``), and the poll holds the previous pass's instance
while it re-selects, so the identity map handed the old ETag back: the poll
compared the agent's If-None-Match against an ETag that no longer existed,
parked again, and the new render reached the agent only at the long-poll
timeout. ``agent_bundle_store.newest`` now selects with ``populate_existing``.
(The narrow fix rather than the DHCP loop's ``expire_all``: across passes this
loop holds only the server row, refreshed every pass, the bundle row, and op
rows that ``lock_ops`` already re-reads with ``populate_existing``.)
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns import agents as agents_api
from app.config import settings
from app.core.agent_wake import WakeResult
from app.core.http_etag import etag_matches
from app.db import get_db
from app.main import app
from app.services.dns import agent_bundle_store as store
from tests.conftest import _TestSessionLocal
from tests.test_dns_agents_config_serve_newest import CONFIG_URL, _agent, _render


@pytest.fixture
def fresh_session_per_request() -> Any:
    async def _get_db() -> AsyncGenerator[AsyncSession, None]:
        async with _TestSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _get_db
    yield
    app.dependency_overrides.clear()


class _OneWake:
    def __init__(self) -> None:
        self.parked = asyncio.Event()
        self.fire = asyncio.Event()
        self.waits = 0

    async def wait(self, timeout: float) -> WakeResult:
        self.waits += 1
        if self.waits <= 3:
            # Two idle wakes first: several expired passes in a row must not
            # trip a lazy load on an expired instance.
            if self.waits == 3:
                self.parked.set()
                await asyncio.wait_for(self.fire.wait(), timeout=timeout)
            return WakeResult.WAKE
        await asyncio.sleep(timeout)
        return WakeResult.TIMEOUT


@pytest.mark.asyncio
async def test_an_in_place_rerender_reaches_a_parked_poll_on_the_wake(
    db_session: AsyncSession,
    fresh_session_per_request: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback", False)

    async def _no_enqueue(_ids: Any) -> None:
        return None

    monkeypatch.setattr(agents_api, "enqueue_renders", _no_enqueue)
    monkeypatch.setattr(agents_api, "LONGPOLL_TIMEOUT_SECONDS", 6)
    fake = _OneWake()

    @asynccontextmanager
    async def _subscription(_channels: Any) -> AsyncIterator[_OneWake]:
        yield fake

    monkeypatch.setattr(agents_api, "wake_subscription", _subscription)

    server, _zone, headers = await _agent(db_session)
    await db_session.commit()
    first = await _render(db_session, server)
    bundle_id, old_etag = first.id, first.etag

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        poll = asyncio.create_task(
            ac.get(CONFIG_URL, headers={**headers, "If-None-Match": f'"{old_etag}"'})
        )
        await asyncio.wait_for(fake.parked.wait(), timeout=5)
        # A newer renderer revision re-rendering the same watermark: same row,
        # new ETag (what ``store`` does in place).
        async with _TestSessionLocal() as other:
            await other.execute(
                update(store.DNSAgentBundle)
                .where(store.DNSAgentBundle.id == bundle_id)
                .values(etag="sha256:" + "e" * 64)
            )
            await other.commit()
        fake.fire.set()
        resp = await asyncio.wait_for(poll, timeout=15)

    assert resp.status_code == 200, (
        f"the parked poll answered {resp.status_code} after {fake.waits} wait(s): it "
        "compared against the ETag of a stale identity-map row and missed the wake"
    )
    assert fake.waits == 3
    assert etag_matches(resp.headers["etag"], "sha256:" + "e" * 64)
