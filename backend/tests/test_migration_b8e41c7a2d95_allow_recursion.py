"""``b8e41c7a2d95`` (#1817) — allow_recursion defaults to local + private networks.

The old default ``["any"]`` rendered as an open resolver once the BIND9 agent
inherited ``allow-query { any; }``. The migration rewrites exactly that value
(and empty) to the local + private networks default, leaves an operator's list alone, bumps the
bundle marker of the affected agent servers, and downgrades the new default
back to ``["any"]``.

Runs on its own connection inside one transaction that is rolled back.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import uuid
from collections.abc import AsyncIterator
from types import ModuleType

import pytest
import pytest_asyncio
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.dns import DEFAULT_ALLOW_RECURSION as DEFAULT
from app.models.dns import DNSServer, DNSServerGroup, DNSServerOptions

_PATH = next(
    (pathlib.Path(__file__).resolve().parents[1] / "alembic" / "versions").glob("b8e41c7a2d95_*.py")
)


def _migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("b8e41c7a2d95", _PATH)
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


async def _seed(session: AsyncSession) -> tuple[dict[str, DNSServerGroup], dict[str, DNSServer]]:
    values = {
        "any": ["any"],
        "ANY": [" ANY "],
        "empty": [],
        "custom": ["10.0.0.0/8", "localhost"],
        "any_plus": ["any", "!10.9.0.0/16"],
        "none": ["none"],
        "default": list(DEFAULT),
        # An operator's own list that happens to be BIND's built-in default:
        # not the new default, so neither direction touches it.
        "bind_builtin": ["localhost", "localnets"],
    }
    groups: dict[str, DNSServerGroup] = {}
    servers: dict[str, DNSServer] = {}
    for key, value in values.items():
        g = DNSServerGroup(name=f"{key}-{uuid.uuid4().hex[:6]}")
        session.add(g)
        await session.flush()
        groups[key] = g
        session.add(DNSServerOptions(group_id=g.id, allow_recursion=value))
        s = DNSServer(
            group_id=g.id,
            name=f"ns-{uuid.uuid4().hex[:6]}",
            host="192.0.2.53",
            driver="bind9",
            agent_id=uuid.uuid4(),
            is_primary=True,
        )
        session.add(s)
        servers[key] = s
    await session.flush()
    return groups, servers


async def _read(conn: AsyncConnection, groups: dict[str, DNSServerGroup]) -> dict[str, list]:
    out = {}
    for key, g in groups.items():
        out[key] = (
            await conn.execute(
                sa.text("SELECT allow_recursion FROM dns_server_options WHERE group_id = :g"),
                {"g": g.id},
            )
        ).scalar_one()
    return out


@pytest.mark.asyncio
async def test_upgrade_rewrites_only_the_old_default_then_downgrade(
    conn: AsyncConnection,
) -> None:
    session = AsyncSession(
        bind=conn, join_transaction_mode="create_savepoint", expire_on_commit=False
    )
    groups, servers = await _seed(session)
    seq_before = {
        k: (
            await conn.execute(
                sa.text("SELECT bundle_dirty_seq FROM dns_server WHERE id = :i"),
                {"i": s.id},
            )
        ).scalar_one()
        for k, s in servers.items()
    }

    await conn.run_sync(_run, "upgrade")

    new = list(DEFAULT)
    assert await _read(conn, groups) == {
        "any": new,
        "ANY": new,
        "empty": new,
        "custom": ["10.0.0.0/8", "localhost"],
        "any_plus": ["any", "!10.9.0.0/16"],
        "none": ["none"],
        "default": new,
        "bind_builtin": ["localhost", "localnets"],
    }
    seq_after = {
        k: (
            await conn.execute(
                sa.text("SELECT bundle_dirty_seq FROM dns_server WHERE id = :i"),
                {"i": s.id},
            )
        ).scalar_one()
        for k, s in servers.items()
    }
    for k in ("any", "ANY", "empty"):
        assert seq_after[k] == seq_before[k] + 1, k  # agents must re-render
    for k in ("custom", "any_plus", "none", "default", "bind_builtin"):
        assert seq_after[k] == seq_before[k], k  # untouched

    # The column default is the new one too.
    default = (
        await conn.execute(
            sa.text(
                "SELECT column_default FROM information_schema.columns "
                "WHERE table_name='dns_server_options' AND column_name='allow_recursion'"
            )
        )
    ).scalar_one()
    for element in DEFAULT:
        assert element in default, (element, default)

    await conn.run_sync(_run, "downgrade")
    back = await _read(conn, groups)
    assert back["any"] == back["ANY"] == back["empty"] == ["any"]
    assert back["default"] == ["any"]  # indistinguishable from the new default
    assert back["custom"] == ["10.0.0.0/8", "localhost"]
    assert back["any_plus"] == ["any", "!10.9.0.0/16"]
    assert back["none"] == ["none"]
    assert back["bind_builtin"] == ["localhost", "localnets"]  # exact match only
    default_after = (
        await conn.execute(
            sa.text(
                "SELECT column_default FROM information_schema.columns "
                "WHERE table_name='dns_server_options' AND column_name='allow_recursion'"
            )
        )
    ).scalar_one()
    assert '["any"]' in default_after


def test_what_counts_as_the_old_default() -> None:
    m = _migration()
    assert m._was_default(["any"])
    assert m._was_default([" Any "])
    assert m._was_default([])
    assert m._was_default(None)
    assert not m._was_default(["any", "10.0.0.0/8"])
    assert not m._was_default(["none"])
    assert not m._was_default(["localhost", "localnets"])
    assert not m._was_default(list(DEFAULT))
    assert m._NEW == list(DEFAULT)


def test_model_default_is_not_open() -> None:
    from app.models.dns import DNSServerOptions as Opts

    assert Opts().allow_recursion in (None, list(DEFAULT))
    assert Opts.__table__.c.allow_recursion.default.arg(None) == list(DEFAULT)
    assert "100.64.0.0/10" not in DEFAULT  # CGNAT / Tailscale is added explicitly
    from app.drivers.dns.base import ServerOptions

    assert ServerOptions().allow_recursion == DEFAULT
