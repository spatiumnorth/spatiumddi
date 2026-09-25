"""An API token records that it was used, even when the request only reads (#1158).

``_resolve_api_token`` used to set ``token.last_used_at`` on the request's
session and leave the handler to commit it. Read handlers never commit
(``get_db`` only closes the session), so a token used only for reads, the
usual monitoring, inventory or export integration, showed "Last Used: —"
forever, while its first write set it. The use is now written on a
short-lived session of its own, at most once a minute per token (the
cadence the session path keeps for ``last_seen_at``). A handler that rolls
back cannot undo it, and a failed write never fails the request.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from app.api import deps
from app.core.security import generate_api_token, hash_password
from app.db import AsyncSessionLocal
from app.models.auth import APIToken, User

READ_PATH = "/api/v1/ipam/spaces"


async def _token(db: AsyncSession, scopes: list[str]) -> tuple[APIToken, str]:
    owner = User(
        username=f"lu-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Last-used owner",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(owner)
    await db.flush()
    raw, _prefix, token_hash = generate_api_token()
    token = APIToken(
        name=f"lu-{uuid.uuid4().hex[:6]}",
        token_hash=token_hash,
        prefix=raw[:10],
        scope="user",
        scopes=scopes,
        user_id=owner.id,
        created_by_user_id=owner.id,
        is_active=True,
    )
    db.add(token)
    await db.commit()
    return token, raw


async def _stored_last_used(token_id: uuid.UUID) -> datetime | None:
    """What was actually written, read on a fresh session. The test's
    ``db_session`` is also the request's session (conftest), so its copy of
    the row shows what the request saw, not what reached the database."""
    async with AsyncSessionLocal() as fresh:
        return (
            await fresh.execute(select(APIToken.last_used_at).where(APIToken.id == token_id))
        ).scalar_one()


@pytest.mark.asyncio
async def test_a_read_only_use_is_recorded(client: AsyncClient, db_session: AsyncSession) -> None:
    token, raw = await _token(db_session, ["read"])
    before = datetime.now(UTC)

    r = await client.get(READ_PATH, headers={"Authorization": f"Bearer {raw}"})

    assert r.status_code == 200, r.text
    stored = await _stored_last_used(token.id)
    assert stored is not None, (
        "a read with the token answered 200 but last_used_at was never written — "
        "read handlers never commit the request's session (#1158)"
    )
    assert stored >= before - timedelta(seconds=1)


@pytest.mark.asyncio
async def test_a_handler_rollback_cannot_undo_the_record(db_session: AsyncSession) -> None:
    """The auth dependency runs before the handler. Whatever the handler then
    does to the request's session, a rollback included, the use stays written."""
    token, raw = await _token(db_session, ["read"])
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "http",
            "server": ("test", 80),
            "path": READ_PATH,
            "query_string": b"",
            "headers": [],
        }
    )

    user = await deps._resolve_api_token(db_session, raw, request)
    # Read these first: the rollback expires every instance on the session,
    # and AsyncSession refuses the lazy load that reading them after would
    # need. (That expiry is why the product writes the use on a separate
    # session rather than committing and rolling back this one.)
    resolved_id, owner_id, token_id = user.id, token.user_id, token.id
    await db_session.rollback()  # what a failing handler does

    assert resolved_id == owner_id
    assert await _stored_last_used(token_id) is not None


@pytest.mark.asyncio
async def test_uses_within_a_minute_write_once(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The same throttle as a session's ``last_seen_at``: a token in a tight
    polling loop costs one write a minute, not one per request."""
    token, raw = await _token(db_session, ["read"])
    headers = {"Authorization": f"Bearer {raw}"}

    recent = datetime.now(UTC) - timedelta(seconds=30)
    token.last_used_at = recent
    await db_session.commit()
    assert (await client.get(READ_PATH, headers=headers)).status_code == 200
    assert await _stored_last_used(token.id) == recent

    stale = datetime.now(UTC) - timedelta(seconds=120)
    token.last_used_at = stale
    await db_session.commit()
    assert (await client.get(READ_PATH, headers=headers)).status_code == 200
    stored = await _stored_last_used(token.id)
    assert stored is not None and stored > stale + timedelta(seconds=60)


@pytest.mark.asyncio
async def test_a_failed_write_never_fails_the_request(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Recording the use is best-effort, like ``last_seen_at``: the request
    it describes must answer as if nothing happened."""
    token, raw = await _token(db_session, ["read"])

    def _unavailable() -> AsyncSession:
        raise RuntimeError("database unavailable for the side write")

    monkeypatch.setattr(deps, "AsyncSessionLocal", _unavailable)
    r = await client.get(READ_PATH, headers={"Authorization": f"Bearer {raw}"})

    assert r.status_code == 200, r.text
    assert await _stored_last_used(token.id) is None
