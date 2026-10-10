"""``a3d9e5c17b42`` (#1513) — Technitium SVCB/HTTPS targets keep what they served.

Before #1513 both Technitium paths sent a dot-less target as absolute, so
``1 cdn.example.net alpn=h2`` was served as ``cdn.example.net.``. #1513 reads
a dot-less target as zone-relative, so the migration writes the dot those
rows were served with — on Technitium groups only, multi-label targets only.

Runs on its own connection inside one transaction that is rolled back.
"""

from __future__ import annotations

import importlib.util
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

from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone

_PATH = next(
    (pathlib.Path(__file__).resolve().parents[1] / "alembic" / "versions").glob("a3d9e5c17b42_*.py")
)


def _migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("a3d9e5c17b42", _PATH)
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


async def test_only_technitium_multi_label_targets_gain_the_dot(conn: AsyncConnection) -> None:
    session = AsyncSession(
        bind=conn, join_transaction_mode="create_savepoint", expire_on_commit=False
    )
    groups = {d: DNSServerGroup(name=f"{d}-{uuid.uuid4().hex[:6]}") for d in ("t", "api", "b")}
    session.add_all(groups.values())
    await session.flush()
    for key, driver in (("t", "technitium"), ("api", "technitium_api"), ("b", "bind9")):
        session.add(
            DNSServer(
                group_id=groups[key].id,
                name=f"ns-{uuid.uuid4().hex[:6]}",
                host="192.0.2.53",
                driver=driver,
            )
        )
    zones = {
        k: DNSZone(
            group_id=g.id,
            name=f"z{uuid.uuid4().hex[:6]}.example.test.",
            zone_type="primary",
            kind="forward",
        )
        for k, g in groups.items()
    }
    session.add_all(zones.values())
    await session.flush()

    def rec(zone: str, rtype: str, value: str) -> DNSRecord:
        r = DNSRecord(zone_id=zones[zone].id, name="svc", record_type=rtype, value=value)
        session.add(r)
        return r

    rows = {
        "t_multi": rec("t", "SVCB", '1 cdn.example.net alpn="h2"'),
        "api_multi": rec("api", "HTTPS", "1 cdn.example.net"),
        "t_dotted": rec("t", "SVCB", "1 cdn.example.net. alpn=h2"),
        "t_single": rec("t", "SVCB", "1 svc alpn=h2"),
        "t_root": rec("t", "HTTPS", "1 . alpn=h2"),
        "t_cname": rec("t", "CNAME", "cdn.example.net"),
        "bind_multi": rec("b", "SVCB", "1 svc.sub alpn=h2"),
    }
    await session.flush()
    ids = {k: r.id for k, r in rows.items()}

    def _up(sync_conn: object) -> None:
        with Operations.context(MigrationContext.configure(connection=sync_conn)):
            _migration().upgrade()

    await conn.run_sync(_up)
    got = {
        k: (
            await conn.execute(sa.text("SELECT value FROM dns_record WHERE id=:i"), {"i": i})
        ).scalar_one()
        for k, i in ids.items()
    }
    assert got == {
        "t_multi": '1 cdn.example.net. alpn="h2"',
        "api_multi": "1 cdn.example.net.",
        "t_dotted": "1 cdn.example.net. alpn=h2",
        "t_single": "1 svc alpn=h2",
        "t_root": "1 . alpn=h2",
        "t_cname": "cdn.example.net",
        "bind_multi": "1 svc.sub alpn=h2",
    }
