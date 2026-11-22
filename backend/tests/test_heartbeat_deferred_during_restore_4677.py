"""A heartbeat during a restore is deferred, never refused (#4677).

The replay swaps the appliance registry before the running appliance is put
back. A heartbeat in between finds no row for its credential, and the marked
403 that answers it is a revocation strike; two in a row tear the node down.
While the install-wide restore lock is held the answer is 503 + Retry-After.
"""

from __future__ import annotations

import asyncpg
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import supervisor as supervisor_mod
from app.config import settings
from app.services.backup.restore import _RESTORE_LOCK_KEY
from tests.test_heartbeat_held_revoke_2807 import _HEADER, _HEARTBEAT, _approved


@pytest.fixture(autouse=True)
def _no_failure_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(supervisor_mod, "_CONSUME_FAILURE_DELAY_S", 0.0)


async def _heartbeat(client: AsyncClient, appliance_id, token):
    return await client.post(
        _HEARTBEAT, json={"appliance_id": str(appliance_id), "session_token": token}
    )


async def test_unknown_row_heartbeat_is_deferred_while_a_restore_runs(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    import uuid

    ghost = uuid.uuid4()  # the replay removed the row the supervisor holds
    lock = await asyncpg.connect(str(settings.database_url).replace("+asyncpg", "", 1))
    try:
        await lock.fetchval("SELECT pg_advisory_lock($1)", _RESTORE_LOCK_KEY)
        r = await _heartbeat(client, ghost, "tok")
    finally:
        await lock.close()
    assert r.status_code == 503, r.text
    assert r.headers["Retry-After"] == "1"
    assert _HEADER not in r.headers


async def test_unknown_row_heartbeat_is_still_refused_without_a_restore(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    import uuid

    r = await _heartbeat(client, uuid.uuid4(), "tok")
    assert r.status_code == 403, r.text
    assert r.headers[_HEADER] == "unknown"


async def test_known_row_is_unaffected_by_the_restore_lock(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    appliance_id, token = await _approved(db_session)
    lock = await asyncpg.connect(str(settings.database_url).replace("+asyncpg", "", 1))
    try:
        await lock.fetchval("SELECT pg_advisory_lock($1)", _RESTORE_LOCK_KEY)
        r = await _heartbeat(client, appliance_id, token)
    finally:
        await lock.close()
    assert r.status_code == 200, r.text
