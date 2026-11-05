"""The supervisor-heartbeat and packet-capture long-polls hold no lock (#3606).

#3604 made the DNS / DHCP / Looking Glass agent polls end their read
transaction before they park (#3479). These two polls hold the same way:
a parked poll must not keep a lock that a restore or an ``ALTER TABLE``
(ACCESS EXCLUSIVE) would have to wait out. The probe is that lock, asked for
while the poll is parked.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import uuid
from collections.abc import AsyncGenerator
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import supervisor as supervisor_api
from app.core import shutdown as shutdown_mod
from app.db import get_db
from app.main import app
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.services.appliance.ca import generate_session_token
from tests.conftest import _TestSessionLocal
from tests.test_longpoll_holds_no_lock_3479 import _Park, _truncate_lock


@pytest.fixture
def fresh_session_per_request() -> Any:
    async def _get_db() -> AsyncGenerator[AsyncSession, None]:
        async with _TestSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _get_db
    yield
    app.dependency_overrides.clear()


async def _approved(db: AsyncSession) -> tuple[Appliance, str]:
    token, token_hash = generate_session_token()
    der = os.urandom(32)
    row = Appliance(
        id=uuid.uuid4(),
        hostname="lp-3606",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        session_token_hash=token_hash,
    )
    db.add(row)
    await db.commit()
    return row, token


async def _run(request_coro: Any, park: _Park, *tables: str) -> Any:
    poll = asyncio.create_task(request_coro)
    try:
        await asyncio.wait_for(park.parked.wait(), timeout=10)
        await _truncate_lock(*tables)
    finally:
        park.release.set()
    return await asyncio.wait_for(poll, timeout=15)


@pytest.mark.asyncio
async def test_a_parked_heartbeat_holds_no_lock(
    db_session: AsyncSession,
    fresh_session_per_request: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row, token = await _approved(db_session)
    park = _Park()
    monkeypatch.setattr(supervisor_api, "wake_subscription", park.subscription)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await _run(
            ac.post(
                "/api/v1/appliance/supervisor/heartbeat",
                json={"appliance_id": str(row.id), "session_token": token, "wait_seconds": 20},
            ),
            park,
            "appliance",
        )
    assert resp.status_code == 200, resp.text
    assert resp.json()["long_poll"] is True


@pytest.mark.asyncio
async def test_a_parked_pcap_poll_holds_no_lock(
    db_session: AsyncSession,
    fresh_session_per_request: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row, _token = await _approved(db_session)
    park = _Park()

    async def _auth(_request: Any, db: AsyncSession) -> Appliance:
        # Cert auth reads the appliance (and the CA) on the request's session.
        found = await db.get(Appliance, row.id)
        assert found is not None
        return found

    async def _sleep(timeout: float) -> bool:
        return (await park.wait(timeout)) is not None

    monkeypatch.setattr(supervisor_api, "_require_cert_auth", _auth)
    monkeypatch.setattr(shutdown_mod, "sleep_or_shutdown", _sleep)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await _run(
            ac.post("/api/v1/appliance/supervisor/pcap/poll"),
            park,
            "packet_capture",
            "appliance",
        )
    assert resp.status_code == 200, resp.text
    assert resp.json()["capture_id"] == ""
