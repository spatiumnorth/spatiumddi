"""``ff32b91acad8`` (#1171) — the upgrade remaps the timers and moves no serial.

The first version of this migration moved the serial of every zone with edited
SOA timers. The agent of the release before, still running when the new
release's first bundle reached it, then served each moved serial with its
literal ``3600 600 86400 300`` until its pod was replaced (44 s and 52 s on a
single node upgraded from 2026.10.02-1). Now the migration only remaps each
timer still at its old stored default, and records that no BIND9 agent of an
existing group is known to render a zone's own timers yet. The serial moves
when a group starts serving them (``services.dns.soa_timers``).

Each test runs the migration on its own connection, inside one transaction that
is rolled back: the two columns are dropped first (the schema before the
revision), and the drop, the migration's DDL and every row go with it.
"""

from __future__ import annotations

import importlib.util
import logging
import os
import pathlib
import uuid
from collections.abc import AsyncIterator, Callable
from types import ModuleType
from typing import Any

import pytest
import pytest_asyncio
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.dns import DNSServer, DNSServerGroup, DNSZone

_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "alembic"
    / "versions"
    / "ff32b91acad8_zone_soa_timers_served_defaults.py"
)

OLD = {"refresh": 86400, "retry": 7200, "expire": 3600000, "minimum": 3600}
EDITED = {"refresh": 7200, "retry": 900, "expire": 1209600, "minimum": 60}


def _migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("ff32b91acad8", _PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(sync_conn: Any, step: Callable[[], None]) -> None:
    with Operations.context(MigrationContext.configure(connection=sync_conn)):
        step()


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


async def _seed(conn: AsyncConnection) -> dict[str, uuid.UUID]:
    """Groups, servers and zones as 2026.10.02-1 leaves them."""
    session = AsyncSession(
        bind=conn, join_transaction_mode="create_savepoint", expire_on_commit=False
    )
    groups = {
        name: DNSServerGroup(name=f"{name}-{uuid.uuid4().hex[:6]}")
        for name in ("bind9", "powerdns", "empty", "disabled", "pending")
    }
    session.add_all(groups.values())
    await session.flush()

    def server(group: str, **kw: Any) -> DNSServer:
        return DNSServer(
            group_id=groups[group].id,
            name=f"ns-{uuid.uuid4().hex[:6]}",
            host="192.0.2.53",
            **{"agent_id": uuid.uuid4(), **kw},
        )

    session.add_all(
        [
            server("bind9", driver="bind9"),
            server("bind9", driver="bind9", agent_id=None),  # never registered
            server("powerdns", driver="powerdns"),
            server("disabled", driver="bind9", is_enabled=False),
            server("pending", driver="bind9", pending_approval=True),
        ]
    )

    def zone(group: str, serial: int, **timers: int) -> DNSZone:
        return DNSZone(
            group_id=groups[group].id,
            name=f"z{uuid.uuid4().hex[:6]}.example.test.",
            zone_type="primary",
            kind="forward",
            last_serial=serial,
            **timers,
        )

    zones = {
        "untouched": zone("bind9", 0, **OLD),
        "edited": zone("bind9", 0, **EDITED),
        "minimum": zone("bind9", 2026100300, **{**OLD, "minimum": 120}),
        "powerdns": zone("powerdns", 5, **EDITED),
    }
    session.add_all(zones.values())
    await session.commit()
    ids = {k: z.id for k, z in zones.items()} | {f"g:{k}": g.id for k, g in groups.items()}
    await session.close()
    return ids


async def _before_the_revision(conn: AsyncConnection) -> None:
    await conn.execute(sa.text("ALTER TABLE dns_server DROP COLUMN agent_renders_soa_timers"))
    await conn.execute(sa.text("ALTER TABLE dns_server_group DROP COLUMN serves_soa_timers"))


async def _zone_rows(conn: AsyncConnection, ids: dict[str, uuid.UUID]) -> dict[str, tuple]:
    rows = (
        await conn.execute(
            sa.text(
                "SELECT id, refresh, retry, expire, minimum, last_serial FROM dns_zone "
                "WHERE id = ANY(:ids)"
            ),
            {"ids": [ids[k] for k in ("untouched", "edited", "minimum", "powerdns")]},
        )
    ).all()
    by_id = {r[0]: tuple(r[1:]) for r in rows}
    return {k: by_id[ids[k]] for k in ("untouched", "edited", "minimum", "powerdns")}


async def _next(conn: AsyncConnection, serial: int) -> int:
    """``compute_next_serial`` against the transaction's own clock."""
    base = await conn.scalar(
        sa.text("SELECT CAST(to_char(now() AT TIME ZONE 'UTC', 'YYYYMMDD') AS integer) * 100")
    )
    return max(int(base), serial + 1)


@pytest.mark.asyncio
async def test_upgrade_remaps_each_old_default_and_moves_no_serial(
    conn: AsyncConnection, caplog: pytest.LogCaptureFixture
) -> None:
    ids = await _seed(conn)
    await _before_the_revision(conn)

    with caplog.at_level(logging.INFO, logger="alembic.runtime.migration"):
        await conn.run_sync(_run, _migration().upgrade)

    assert await _zone_rows(conn, ids) == {
        "untouched": (3600, 600, 86400, 300, 0),
        "edited": (7200, 900, 1209600, 60, 0),
        "minimum": (3600, 600, 86400, 120, 2026100300),
        "powerdns": (7200, 900, 1209600, 60, 5),
    }
    assert not any("serial moved" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_upgrade_starts_every_group_with_a_bind9_agent_on_the_literal(
    conn: AsyncConnection, caplog: pytest.LogCaptureFixture
) -> None:
    """At this point a group's BIND9 agents are the previous release's, which
    write the literal; a group with none can serve the zones' own timers."""
    ids = await _seed(conn)
    await _before_the_revision(conn)

    with caplog.at_level(logging.INFO, logger="alembic.runtime.migration"):
        await conn.run_sync(_run, _migration().upgrade)

    serves = dict(
        (
            await conn.execute(
                sa.text("SELECT id, serves_soa_timers FROM dns_server_group WHERE id = ANY(:g)"),
                {"g": [v for k, v in ids.items() if k.startswith("g:")]},
            )
        ).all()
    )
    assert {k[2:]: serves[v] for k, v in ids.items() if k.startswith("g:")} == {
        "bind9": False,
        "powerdns": True,
        "empty": True,
        "disabled": True,
        "pending": True,
    }
    assert (
        await conn.scalar(sa.text("SELECT count(*) FROM dns_server WHERE agent_renders_soa_timers"))
        == 0
    )
    assert any("1 group(s) serve 3600 600 86400 300" in r.getMessage() for r in caplog.records), [
        r.getMessage() for r in caplog.records
    ]


@pytest.mark.asyncio
async def test_downgrade_moves_the_serial_where_a_group_served_the_zones_own_timers(
    conn: AsyncConnection,
) -> None:
    """The release before writes the literal for every zone, so where a group
    was serving a zone's own timers its SOA changes back: a new serial sends a
    secondary to transfer it, as the switch on did."""
    ids = await _seed(conn)
    await _before_the_revision(conn)
    await conn.run_sync(_run, _migration().upgrade)
    await conn.execute(
        sa.text("UPDATE dns_server_group SET serves_soa_timers = true WHERE id = :g"),
        {"g": ids["g:bind9"]},
    )

    await conn.run_sync(_run, _migration().downgrade)

    assert await _zone_rows(conn, ids) == {
        "untouched": (3600, 600, 86400, 300, 0),
        "edited": (7200, 900, 1209600, 60, await _next(conn, 0)),
        "minimum": (3600, 600, 86400, 120, await _next(conn, 2026100300)),
        "powerdns": (7200, 900, 1209600, 60, await _next(conn, 5)),
    }
    columns = (
        await conn.execute(
            sa.text(
                "SELECT table_name, column_name FROM information_schema.columns "
                "WHERE column_name IN ('agent_renders_soa_timers', 'serves_soa_timers')"
            )
        )
    ).all()
    assert columns == []
