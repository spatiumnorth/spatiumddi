"""``a3d9e5c17b42`` (#1513) — Technitium SVCB/HTTPS targets keep what they served.

Before #1513 both Technitium paths sent a dot-less target as absolute, so
``1 cdn.example.net alpn=h2`` was served as ``cdn.example.net.``. #1513 reads
a dot-less target as zone-relative, so the migration writes the dot those
rows were served with — on Technitium groups only, multi-label targets only.

Runs on its own connection inside one transaction that is rolled back.
"""

from __future__ import annotations

import gzip
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


async def test_the_rewrite_reaches_the_agents(conn: AsyncConnection) -> None:
    """Case 7 of the #1731 walk: a raw UPDATE is invisible to the bundle
    dirty listener, so without a mark of its own the stored bundle stays
    current, the long-poll answers 304, and the agent never sees the dot. The
    migration marks the group's agent-based servers, so the next bundle
    carries the migrated value; queued ops are rewritten too."""
    from app.services.dns import agent_bundle_store as store
    from app.services.dns.agent_bundle_render import render_and_store

    session = AsyncSession(
        bind=conn, join_transaction_mode="create_savepoint", expire_on_commit=False
    )
    tgroup = DNSServerGroup(name=f"t-{uuid.uuid4().hex[:6]}")
    bgroup = DNSServerGroup(name=f"b-{uuid.uuid4().hex[:6]}")
    session.add_all([tgroup, bgroup])
    await session.flush()
    tsrv = DNSServer(
        group_id=tgroup.id,
        name=f"ns-{uuid.uuid4().hex[:6]}",
        host="192.0.2.53",
        driver="technitium",
        agent_id=uuid.uuid4(),
        is_primary=True,
    )
    bsrv = DNSServer(
        group_id=bgroup.id,
        name=f"ns-{uuid.uuid4().hex[:6]}",
        host="192.0.2.54",
        driver="bind9",
        agent_id=uuid.uuid4(),
        is_primary=True,
    )
    session.add_all([tsrv, bsrv])
    await session.flush()
    zone = DNSZone(group_id=tgroup.id, name="up.test.", zone_type="primary", kind="forward")
    session.add(zone)
    await session.flush()
    session.add(
        DNSRecord(
            zone_id=zone.id, name="c7s", record_type="SVCB", value='1 cdn.example.net alpn="h2"'
        )
    )
    await session.flush()

    before = await render_and_store(session, tsrv, rendered_by=store.RENDERED_BY_WORKER)
    await render_and_store(session, bsrv, rendered_by=store.RENDERED_BY_WORKER)
    await session.flush()
    await session.refresh(tsrv)
    await session.refresh(bsrv)
    assert store.is_current(tsrv) and store.is_current(bsrv)
    bseq = bsrv.bundle_dirty_seq

    op_id = uuid.uuid4()
    member = {"value": "1 cdn.example.net alpn=h2", "priority": None}
    await conn.execute(
        sa.text(
            "INSERT INTO dns_record_op (id, server_id, zone_name, op, record, state, attempts) "
            "VALUES (:id, :s, 'up.test', 'update', CAST(:r AS jsonb), 'pending', 0)"
        ),
        {
            "id": op_id,
            "s": tsrv.id,
            "r": json.dumps(
                {
                    "name": "c7s",
                    "type": "SVCB",
                    "value": "1 cdn.example.net alpn=h2",
                    "rrset": {"ttl": None, "members": [member]},
                }
            ),
        },
    )

    def _up(sync_conn: object) -> None:
        with Operations.context(MigrationContext.configure(connection=sync_conn)):
            _migration().upgrade()

    await conn.run_sync(_up)
    await session.refresh(tsrv)
    await session.refresh(bsrv)
    assert not store.is_current(tsrv), "the Technitium server's stored bundle is still current"
    assert store.is_current(bsrv) and bsrv.bundle_dirty_seq == bseq

    op_record = (
        await conn.execute(sa.text("SELECT record FROM dns_record_op WHERE id=:i"), {"i": op_id})
    ).scalar_one()
    assert op_record["value"] == "1 cdn.example.net. alpn=h2"
    assert op_record["rrset"]["members"][0]["value"] == "1 cdn.example.net. alpn=h2"

    after = await render_and_store(session, tsrv, rendered_by=store.RENDERED_BY_WORKER)
    assert after.etag != before.etag
    assert after.bundle is not None
    raw = await store.load_body(session, after.bundle)
    assert raw is not None
    body = json.loads(gzip.decompress(raw))
    values = [r["value"] for z in body["zones"] for r in z["records"] if r["type"] == "SVCB"]
    assert values == ['1 cdn.example.net. alpn="h2"']
    assert body["svcb_target_rule"] == "zone-file"

    # The marker is the agent's cue to read dot-less targets as relative, and
    # it is in the structural fingerprint, so its arrival re-reconciles a
    # Technitium agent even though a record value never moves that etag. A
    # BIND9 server's bundle does not carry it, so its etag does not move.
    from app.services.dns import agent_config

    t_asm = await agent_config._assemble(session, tsrv, stream=False)
    b_asm = await agent_config._assemble(session, bsrv, stream=False)
    assert t_asm.structural["svcb_target_rule"] == "zone-file"
    assert "svcb_target_rule" not in b_asm.structural
    assert "svcb_target_rule" not in b_asm.body
