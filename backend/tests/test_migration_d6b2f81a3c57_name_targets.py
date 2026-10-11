"""``d6b2f81a3c57`` (#1759) — name-valued targets keep what they served.

Before #1759 both Technitium paths sent a dot-less CNAME / DNAME / NS / PTR /
MX / SRV / NAPTR target as absolute. #1759 reads it as zone-relative, so the
migration writes the dot those rows were served with in Technitium groups
(multi-label only), and on rows the Technitium importer stamped in any group
(every label, since Technitium's value was always absolute).

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

from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone

_PATH = next(
    (pathlib.Path(__file__).resolve().parents[1] / "alembic" / "versions").glob("d6b2f81a3c57_*.py")
)


def _migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("d6b2f81a3c57", _PATH)
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


def _up(sync_conn: object) -> None:
    with Operations.context(MigrationContext.configure(connection=sync_conn)):
        _migration().upgrade()


def test_the_target_rewrite_rules() -> None:
    m = _migration()
    f = m._dot_terminate
    assert f("CNAME", "web.example.net", single_label=False) == "web.example.net."
    assert f("CNAME", "web", single_label=False) == "web"
    assert f("CNAME", "web", single_label=True) == "web."
    assert f("MX", "@", single_label=True) == "@"
    assert f("MX", ".", single_label=True) == "."
    assert f("NS", "ns1.example.net.", single_label=False) == "ns1.example.net."
    naptr = '100 10 "S" "SIP+D2U" "" _sip._udp.example.net'
    assert f("NAPTR", naptr, single_label=False) == naptr + "."
    assert f("NAPTR", '100 10 "" "" "!^.*$!x!" .', single_label=True) == (
        '100 10 "" "" "!^.*$!x!" .'
    )
    # a NAPTR missing its replacement: the regexp is not a name
    no_repl = '100 10 "U" "E2U+sip" "!^.*$!sip:info@example.net!"'
    assert f("NAPTR", no_repl, single_label=True) == no_repl


async def test_technitium_groups_and_imported_rows(conn: AsyncConnection) -> None:
    session = AsyncSession(
        bind=conn, join_transaction_mode="create_savepoint", expire_on_commit=False
    )
    groups = {d: DNSServerGroup(name=f"{d}-{uuid.uuid4().hex[:6]}") for d in ("t", "api", "b")}
    session.add_all(groups.values())
    await session.flush()
    servers = {}
    for key, driver in (("t", "technitium"), ("api", "technitium_api"), ("b", "bind9")):
        servers[key] = DNSServer(
            group_id=groups[key].id,
            name=f"ns-{uuid.uuid4().hex[:6]}",
            host="192.0.2.53",
            driver=driver,
            agent_id=uuid.uuid4() if driver != "technitium_api" else None,
            is_primary=True,
        )
    session.add_all(servers.values())
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

    def rec(zone: str, rtype: str, value: str, name: str = "x", **kw: object) -> DNSRecord:
        r = DNSRecord(zone_id=zones[zone].id, name=name, record_type=rtype, value=value, **kw)
        session.add(r)
        return r

    rows = {
        "t_cname": rec("t", "CNAME", "web.example.net"),
        "api_ns": rec("api", "NS", "ns1.example.net", name="sub"),
        "t_mx": rec("t", "MX", "mail.example.net", priority=10),
        "t_srv": rec("t", "SRV", "sip.example.net", priority=1, weight=1, port=5060),
        "t_ptr": rec("t", "PTR", "host.example.net"),
        "t_dname": rec("t", "DNAME", "other.example.net"),
        "t_naptr": rec("t", "NAPTR", '100 10 "S" "SIP+D2U" "" _sip._udp.example.net'),
        "t_dotted": rec("t", "CNAME", "web.example.net."),
        # the fix, not something to preserve
        "t_single": rec("t", "CNAME", "web"),
        "t_at": rec("t", "MX", "@", priority=10),
        "t_null_mx": rec("t", "MX", ".", priority=0),
        # not a name-valued type
        "t_txt": rec("t", "TXT", "v=spf1 include:x.example.net -all"),
        # BIND9 group: hand-made rows are relative and keep meaning so
        "b_hand": rec("b", "CNAME", "web.sub"),
        # ...but a row the Technitium importer stamped was absolute
        "b_imp_multi": rec("b", "CNAME", "web.example.net", import_source="technitium"),
        "b_imp_single": rec("b", "CNAME", "localhost", import_source="technitium"),
        "b_imp_mx": rec("b", "MX", "mail.example.net", import_source="technitium", priority=5),
        "b_other_import": rec("b", "CNAME", "web.sub", import_source="bind9"),
        # an imported single label in a Technitium group was absolute as well
        "t_imp_single": rec("t", "CNAME", "localhost", import_source="technitium"),
        # imported, then the VALUE edited by an operator: theirs now. In a
        # BIND9 group it keeps the meaning they typed; in a Technitium group
        # it takes the multi-label rule like any other row.
        "b_imp_edited": rec("b", "CNAME", "web.sub", name="edited", import_source="technitium"),
        "t_imp_edited": rec("t", "CNAME", "web", name="edited", import_source="technitium"),
        # imported, then only the TTL edited: still the importer's value
        "b_imp_ttl": rec("b", "PTR", "host.example.net", name="ttl", import_source="technitium"),
        # imported into a BIND9 group, but in the trash: rewritten, not pushed
        "b_imp_trashed": rec("b", "NS", "ns9.example.net", name="gone", import_source="technitium"),
    }
    await session.flush()
    ids = {k: r.id for k, r in rows.items()}
    await conn.execute(
        sa.text("UPDATE dns_record SET deleted_at = now() WHERE id = :i"),
        {"i": ids["b_imp_trashed"]},
    )
    for key, fields in (
        ("b_imp_edited", ["value"]),
        ("t_imp_edited", ["ttl", "value"]),
        ("b_imp_ttl", ["ttl"]),
    ):
        await conn.execute(
            sa.text(
                "INSERT INTO audit_log (id, user_display_name, auth_source, action, "
                "resource_type, resource_id, resource_display, changed_fields, result, row_hash) "
                "VALUES (:id, 'op', 'local', 'update', 'dns_record', :rid, 'x', "
                "CAST(:f AS jsonb), 'success', repeat('0', 64))"
            ),
            {"id": uuid.uuid4(), "rid": str(ids[key]), "f": json.dumps(fields)},
        )
    zserial = zones["b"].last_serial
    bseq = servers["b"].bundle_dirty_seq
    tseq = servers["t"].bundle_dirty_seq

    # queued ops: a Technitium-group one, and a BIND9 one for an imported row
    async def queue(
        server: str,
        zone: str,
        name: str,
        rtype: str,
        value: str,
        record_id: uuid.UUID | None = None,
        members: list[str] | None = None,
    ) -> uuid.UUID:
        oid = uuid.uuid4()
        payload: dict = {"name": name, "type": rtype, "value": value}
        if record_id is not None:
            payload["record_id"] = str(record_id)
        payload["rrset"] = {
            "ttl": None,
            "members": [{"value": v, "priority": None} for v in (members or [value])],
        }
        await conn.execute(
            sa.text(
                "INSERT INTO dns_record_op (id, server_id, zone_name, op, record, state, attempts) "
                "VALUES (:id, :s, :z, 'update', CAST(:r AS jsonb), 'in_flight', 0)"
            ),
            {
                "id": oid,
                "s": servers[server].id,
                "z": zones[zone].name.rstrip("."),
                "r": json.dumps(payload),
            },
        )
        return oid

    t_op = await queue("t", "t", "x", "CNAME", "web.example.net")
    b_imp_op = await queue("b", "b", "x", "CNAME", "web.example.net")
    b_hand_op = await queue("b", "b", "x", "CNAME", "web.sub")
    # an OLDER op for an imported row, holding a value the row no longer
    # has: matched by record_id, so its own value is fixed, not replaced
    b_old_op = await queue("b", "b", "x", "CNAME", "old.example.net", record_id=ids["b_imp_multi"])
    # an op for the edited row, which shares no content with the imported one
    b_edited_op = await queue("b", "b", "edited", "CNAME", "web.sub", record_id=ids["b_imp_edited"])
    before = {
        r[0] for r in (await conn.execute(sa.text("SELECT id FROM dns_record_op"))).fetchall()
    }

    await conn.run_sync(_up)

    got = {
        k: (
            await conn.execute(sa.text("SELECT value FROM dns_record WHERE id=:i"), {"i": i})
        ).scalar_one()
        for k, i in ids.items()
    }
    assert got == {
        "t_cname": "web.example.net.",
        "api_ns": "ns1.example.net.",
        "t_mx": "mail.example.net.",
        "t_srv": "sip.example.net.",
        "t_ptr": "host.example.net.",
        "t_dname": "other.example.net.",
        "t_naptr": '100 10 "S" "SIP+D2U" "" _sip._udp.example.net.',
        "t_dotted": "web.example.net.",
        "t_single": "web",
        "t_at": "@",
        "t_null_mx": ".",
        "t_txt": "v=spf1 include:x.example.net -all",
        "b_hand": "web.sub",
        "b_imp_multi": "web.example.net.",
        "b_imp_single": "localhost.",
        "b_imp_mx": "mail.example.net.",
        "b_other_import": "web.sub",
        "t_imp_single": "localhost.",
        "b_imp_edited": "web.sub",
        "t_imp_edited": "web",
        "b_imp_ttl": "host.example.net.",
        "b_imp_trashed": "ns9.example.net.",
    }

    async def op_record(oid: uuid.UUID) -> dict:
        return (
            await conn.execute(sa.text("SELECT record FROM dns_record_op WHERE id=:i"), {"i": oid})
        ).scalar_one()

    for oid, want in ((t_op, "web.example.net."), (b_imp_op, "web.example.net.")):
        r = await op_record(oid)
        assert r["value"] == want
        assert r["rrset"]["members"][0]["value"] == want
    assert (await op_record(b_hand_op))["value"] == "web.sub"
    assert (await op_record(b_old_op))["value"] == "old.example.net."
    assert (await op_record(b_edited_op))["value"] == "web.sub"

    # The BIND9 group's re-pointed RRsets are pushed: records are not
    # structural there, so without an op the daemon keeps the old answer.
    new_ops = (
        await conn.execute(
            sa.text(
                "SELECT server_id, zone_name, op, record, target_serial, state "
                "FROM dns_record_op WHERE NOT (id = ANY(:b))"
            ),
            {"b": list(before)},
        )
    ).fetchall()
    assert {o.server_id for o in new_ops} == {servers["b"].id}
    assert all(o.op == "update" and o.state == "pending" for o in new_ops)
    by_rrset = {(o.record["name"], o.record["type"]): o for o in new_ops}
    # one op per re-pointed live RRset; the trashed row is not pushed, the
    # edited and hand-made rows' RRsets are not re-pointed on their own
    assert set(by_rrset) == {("x", "CNAME"), ("x", "MX"), ("ttl", "PTR")}
    cname = by_rrset[("x", "CNAME")].record
    # every live member of the RRset, the twin "web.sub" rows once
    assert sorted(m["value"] for m in cname["rrset"]["members"]) == [
        "localhost.",
        "web.example.net.",
        "web.sub",
    ]
    mx = by_rrset[("x", "MX")].record
    assert mx["rrset"]["members"] == [{"value": "mail.example.net.", "priority": 5}]
    assert mx["record_id"] == str(ids["b_imp_mx"]) and mx["value"] == "mail.example.net."
    await session.refresh(zones["b"])
    assert zones["b"].last_serial > zserial
    assert {o.target_serial for o in new_ops} == {zones["b"].last_serial}
    assert all(o.zone_name == zones["b"].name for o in new_ops)

    # the stored bundles of both groups' agents are stale; the agentless
    # group's server has none to mark
    await session.refresh(servers["t"])
    await session.refresh(servers["b"])
    assert servers["t"].bundle_dirty_seq == tseq + 1
    assert servers["b"].bundle_dirty_seq == bseq + 1


async def test_nothing_to_rewrite_leaves_the_bundles_alone(conn: AsyncConnection) -> None:
    session = AsyncSession(
        bind=conn, join_transaction_mode="create_savepoint", expire_on_commit=False
    )
    g = DNSServerGroup(name=f"t-{uuid.uuid4().hex[:6]}")
    session.add(g)
    await session.flush()
    srv = DNSServer(
        group_id=g.id,
        name=f"ns-{uuid.uuid4().hex[:6]}",
        host="192.0.2.53",
        driver="technitium",
        agent_id=uuid.uuid4(),
        is_primary=True,
    )
    z = DNSZone(group_id=g.id, name="n.test.", zone_type="primary", kind="forward")
    session.add_all([srv, z])
    await session.flush()
    session.add(DNSRecord(zone_id=z.id, name="x", record_type="CNAME", value="web.example.net."))
    await session.flush()
    seq = srv.bundle_dirty_seq
    await conn.run_sync(_up)
    await session.refresh(srv)
    assert srv.bundle_dirty_seq == seq
