"""A heartbeat held by the long-poll answers the row's NEW state (#2807).

The revoked check ran before the hold only. A row revoked while a heartbeat
was held then failed ``SupervisorHeartbeatResponse.state`` (a Literal without
``revoked``), and a row deleted during the hold failed the post-hold refresh
and the log line after it: both answered 500, so a Fleet revoke landed one
heartbeat late on every long-polling node. After the hold the row is re-read
and put through the same refusal as a fresh heartbeat: 403 ``revoked`` or 403
``unknown`` with ``X-Spatium-Revocation`` (#2798).

The hold is driven by a stand-in ``wake_subscription`` whose first wait makes
the change on its own connection (as a Fleet request would) and wakes, so
each case takes milliseconds.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import supervisor as supervisor_mod
from app.core.agent_wake import WakeResult
from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    APPLIANCE_STATE_REVOKED,
    Appliance,
)
from app.services.appliance.ca import generate_session_token
from tests.conftest import _TestSessionLocal

_HEARTBEAT = "/api/v1/appliance/supervisor/heartbeat"
_HEADER = "X-Spatium-Revocation"


@pytest.fixture(autouse=True)
def _no_failure_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(supervisor_mod, "_CONSUME_FAILURE_DELAY_S", 0.0)


def _hold_that(
    monkeypatch: pytest.MonkeyPatch, during: Callable[[], Awaitable[None]] | None
) -> list[int]:
    """Replace the wake subscription: its first wait runs ``during`` and
    wakes. Returns a list that gets one entry per hold entered."""
    holds: list[int] = []

    class _Sub:
        async def wait(self, _timeout: float) -> WakeResult:
            if during is not None:
                await during()
            return WakeResult.WAKE

    @asynccontextmanager
    async def _fake(_channels: Any) -> AsyncIterator[_Sub]:
        holds.append(1)
        yield _Sub()

    monkeypatch.setattr(supervisor_mod, "wake_subscription", _fake)
    return holds


async def _approved(db: AsyncSession) -> tuple[uuid.UUID, str]:
    token, token_hash = generate_session_token()
    der = os.urandom(32)
    row = Appliance(
        id=uuid.uuid4(),
        hostname="held-node",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        session_token_hash=token_hash,
    )
    db.add(row)
    await db.commit()
    return row.id, token


async def _held_heartbeat(client: AsyncClient, appliance_id: uuid.UUID, token: str) -> Any:
    return await client.post(
        _HEARTBEAT,
        json={"appliance_id": str(appliance_id), "session_token": token, "wait_seconds": 5},
    )


async def test_revoked_during_the_hold_answers_403_revoked(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """REGRESSION (#2807): answered 500 (ValidationError on ``state``)."""
    appliance_id, token = await _approved(db_session)

    async def revoke() -> None:
        async with _TestSessionLocal() as other:
            await other.execute(
                update(Appliance)
                .where(Appliance.id == appliance_id)
                .values(state=APPLIANCE_STATE_REVOKED)
            )
            await other.commit()

    holds = _hold_that(monkeypatch, revoke)
    r = await _held_heartbeat(client, appliance_id, token)

    assert holds == [1]
    assert r.status_code == 403, r.text
    assert r.headers[_HEADER] == "revoked"
    assert r.json()["detail"].startswith("Appliance has been revoked.")


async def test_deleted_during_the_hold_answers_403_unknown(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """REGRESSION (#2807): answered 500 (refresh failed, then MissingGreenlet)."""
    appliance_id, token = await _approved(db_session)

    async def revoke_then_delete() -> None:
        async with _TestSessionLocal() as other:
            await other.execute(
                update(Appliance)
                .where(Appliance.id == appliance_id)
                .values(state=APPLIANCE_STATE_REVOKED)
            )
            await other.execute(delete(Appliance).where(Appliance.id == appliance_id))
            await other.commit()

    holds = _hold_that(monkeypatch, revoke_then_delete)
    r = await _held_heartbeat(client, appliance_id, token)

    assert holds == [1]
    assert r.status_code == 403, r.text
    assert r.headers[_HEADER] == "unknown"
    assert r.json()["detail"] == "Invalid appliance or session."


async def test_a_held_heartbeat_with_nothing_changed_still_answers_200(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    appliance_id, token = await _approved(db_session)
    holds = _hold_that(monkeypatch, None)

    r = await _held_heartbeat(client, appliance_id, token)

    assert holds == [1]
    assert r.status_code == 200, r.text
    assert _HEADER not in r.headers
    body = r.json()
    assert body["long_poll"] is True
    assert body["state"] == APPLIANCE_STATE_APPROVED
