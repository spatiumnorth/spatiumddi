"""A restore ends every session, as its notice says.

A restore replaces ``user_session`` with the archive's copy, so a session
revoked after the archive was made came back live, and so did every session
that was live when it was made. These run the real restore against a scratch
database and then ask the same gates the api uses for an access token
(``live_access_session``) and a refresh cookie (``live_refresh_session``).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import asyncpg
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.v1.auth.router import live_refresh_session
from app.core.jwt_compat import JWTError
from app.core.security import hash_refresh_token, live_access_session
from app.models.auth import User, UserSession
from app.models.base import Base
from app.services.backup import restore
from tests.test_selective_restore_app_role_1693 import (
    _HEAD,
    _admin,
    _archive,
    _dsn,
    _pg_dump,
    _RequestSession,
    _url_for,
    pytestmark,  # noqa: F401 — needs the PostgreSQL client tools
)


def _session(user_id: uuid.UUID, raw: str, *, revoked: bool = False) -> UserSession:
    now = datetime.now(UTC)
    return UserSession(
        id=uuid.uuid4(),
        user_id=user_id,
        refresh_token_hash=hash_refresh_token(raw),
        created_at=now - timedelta(hours=1),
        expires_at=now + timedelta(days=7),
        revoked=revoked,
    )


@pytest.fixture
async def scratch():
    """(url, archive bytes, ids): one user, a session live at archive time that
    stays live, and one live at archive time that is revoked afterwards."""
    suffix = uuid.uuid4().hex[:10]
    dbname = f"spatiumddi_test_rs_{suffix}"
    admin = await _admin()
    try:
        await admin.execute(f'CREATE DATABASE "{dbname}"')
    finally:
        await admin.close()
    url = _url_for(dbname)
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        c = await asyncpg.connect(_dsn(url))
        try:
            await c.execute(
                "CREATE TABLE alembic_version (version_num varchar(32) NOT NULL, "
                "CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))"
            )
            await c.execute("INSERT INTO alembic_version VALUES ($1)", _HEAD)
        finally:
            await c.close()
        user = User(username=f"u{suffix}", email=f"{suffix}@example.com", display_name="u")
        user.id = uuid.uuid4()
        keep = _session(user.id, f"keep-{suffix}")
        gone = _session(user.id, f"gone-{suffix}")
        async with AsyncSession(engine, expire_on_commit=False) as db:
            db.add(user)
            await db.flush()
            db.add_all([keep, gone])
            await db.commit()
        archive = _archive(await _pg_dump(url))
        async with AsyncSession(engine, expire_on_commit=False) as db:
            row = await db.get(UserSession, gone.id)
            row.revoked = True
            await db.commit()
        yield url, archive, {
            "user": user.id,
            "keep": keep,
            "gone": gone,
            "keep_raw": f"keep-{suffix}",
            "gone_raw": f"gone-{suffix}",
        }
    finally:
        await engine.dispose()
        admin = await _admin()
        try:
            await admin.execute(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)')
        finally:
            await admin.close()


async def _restore(url, archive, monkeypatch, sections=None):
    async def _no_safety_dump(_db):
        return None

    monkeypatch.setattr(restore, "_write_pre_restore_safety_dump", _no_safety_dump)
    return await restore.apply_backup_restore(
        _RequestSession(),
        archive_bytes=archive,
        passphrase="restore-1693-passphrase",
        confirmation_phrase=restore.CONFIRM_PHRASE,
        db_url=url,
        sections=sections,
    )


async def _accepted(url, session: UserSession, raw: str, user_id) -> tuple[bool, bool]:
    """(access token accepted, refresh cookie accepted) on the restored database."""
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with AsyncSession(engine, expire_on_commit=False) as db:
            try:
                access = (
                    await live_access_session(db, {"jti": str(session.id), "sub": str(user_id)})
                    is not None
                )
            except JWTError:
                access = False
            refresh = await live_refresh_session(db, raw) is not None
            return access, refresh
    finally:
        await engine.dispose()


async def test_full_restore_ends_a_session_revoked_after_the_archive(scratch, monkeypatch):
    url, archive, ids = scratch
    outcome = await _restore(url, archive, monkeypatch)
    assert await _accepted(url, ids["gone"], ids["gone_raw"], ids["user"]) == (False, False)
    assert outcome.sessions_ended == 2


async def test_full_restore_ends_a_session_live_at_both_ends(scratch, monkeypatch):
    url, archive, ids = scratch
    await _restore(url, archive, monkeypatch)
    assert await _accepted(url, ids["keep"], ids["keep_raw"], ids["user"]) == (False, False)


async def test_restored_rows_refuse_the_refresh_path(scratch, monkeypatch):
    url, archive, ids = scratch
    await _restore(url, archive, monkeypatch)
    c = await asyncpg.connect(_dsn(url))
    try:
        rows = await c.fetch("SELECT revoked, rotated_at, rotated_to_id FROM user_session")
    finally:
        await c.close()
    assert len(rows) == 2
    assert all(r["revoked"] and r["rotated_at"] is None for r in rows)
    for raw in (ids["keep_raw"], ids["gone_raw"]):
        engine = create_async_engine(url, poolclass=NullPool)
        try:
            async with AsyncSession(engine) as db:
                assert await live_refresh_session(db, raw) is None
        finally:
            await engine.dispose()


async def test_selective_restore_of_the_auth_section_ends_sessions(scratch, monkeypatch):
    url, archive, ids = scratch
    outcome = await _restore(url, archive, monkeypatch, sections=["auth"])
    assert await _accepted(url, ids["gone"], ids["gone_raw"], ids["user"]) == (False, False)
    assert await _accepted(url, ids["keep"], ids["keep_raw"], ids["user"]) == (False, False)
    assert outcome.sessions_ended and outcome.sessions_ended > 0


async def test_selective_restore_that_misses_sessions_leaves_them_alone(scratch, monkeypatch):
    url, archive, ids = scratch
    outcome = await _restore(url, archive, monkeypatch, sections=["ipam"])
    assert outcome.sessions_ended is None
    assert await _accepted(url, ids["keep"], ids["keep_raw"], ids["user"]) == (True, True)
