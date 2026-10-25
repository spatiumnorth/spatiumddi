"""``c3a8f5e12d94`` (#2619, #2621) — clamp password minimum, drop dead grants.

Runs on its own connection inside one transaction that is rolled back.
"""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import uuid
from collections.abc import AsyncIterator
from types import ModuleType

import pytest_asyncio
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.settings import PlatformSettings

_PATH = next(
    (pathlib.Path(__file__).resolve().parents[1] / "alembic" / "versions").glob("c3a8f5e12d94_*.py")
)


def _migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("c3a8f5e12d94", _PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest_asyncio.fixture
async def conn() -> AsyncIterator[AsyncConnection]:
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    try:
        async with engine.connect() as c:
            trans = await c.begin()
            try:
                yield c
            finally:
                await trans.rollback()
    finally:
        await engine.dispose()


def _run(sync_conn: object, fn: str) -> None:
    with Operations.context(MigrationContext.configure(connection=sync_conn)):
        getattr(_migration(), fn)()


def _g(action: str, rtype: str) -> dict[str, str]:
    return {"action": action, "resource_type": rtype}


async def _role(conn: AsyncConnection, perms: list[dict]) -> uuid.UUID:
    rid = uuid.uuid4()
    await conn.execute(
        sa.text(
            "INSERT INTO role (id, name, description, is_builtin, permissions) "
            "VALUES (:id, :n, '', false, CAST(:p AS jsonb))"
        ),
        {"id": rid, "n": f"r-{rid.hex[:8]}", "p": json.dumps(perms)},
    )
    return rid


async def _perms(conn: AsyncConnection, rid: uuid.UUID) -> list[dict]:
    r = await conn.execute(sa.text("SELECT permissions FROM role WHERE id = :i"), {"i": rid})
    return list(r.scalar_one())


async def _set_min(conn: AsyncConnection, value: int) -> None:
    exists = (await conn.execute(sa.text("SELECT 1 FROM platform_settings WHERE id=1"))).first()
    if exists is None:
        # Python-side defaults fill the NOT NULL columns; the ORM insert is the
        # only way to build a valid row without listing every one.
        async with AsyncSession(bind=conn, expire_on_commit=False) as s:
            s.add(PlatformSettings(id=1))
            await s.flush()
    await conn.execute(
        sa.text("UPDATE platform_settings SET password_min_length = :v WHERE id=1"), {"v": value}
    )


async def _get_min(conn: AsyncConnection) -> int:
    r = await conn.execute(sa.text("SELECT password_min_length FROM platform_settings WHERE id=1"))
    return int(r.scalar_one())


async def test_upgrade_clamps_minimum_and_drops_only_dead_grants(conn: AsyncConnection) -> None:
    await _set_min(conn, 100)
    keep = [_g("admin", "manage_asns"), _g("read", "subnet")]
    mixed = await _role(conn, [_g("read", "asn"), _g("write", "domain"), *keep])
    only_dead = await _role(conn, [_g("admin", "asn")])
    clean = await _role(conn, keep)

    await conn.run_sync(lambda c: _run(c, "upgrade"))

    assert await _get_min(conn) == 72
    assert await _perms(conn, mixed) == keep
    assert await _perms(conn, only_dead) == []
    assert await _perms(conn, clean) == keep

    await conn.run_sync(lambda c: _run(c, "downgrade"))  # documented no-op
    assert await _get_min(conn) == 72
    assert await _perms(conn, mixed) == keep


async def test_values_at_or_below_72_are_left_alone(conn: AsyncConnection) -> None:
    await _set_min(conn, 72)
    await conn.run_sync(lambda c: _run(c, "upgrade"))
    assert await _get_min(conn) == 72
    await _set_min(conn, 12)
    await conn.run_sync(lambda c: _run(c, "upgrade"))
    assert await _get_min(conn) == 12
