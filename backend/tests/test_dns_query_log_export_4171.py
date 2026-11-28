"""Logs → DNS Queries export (#4171) and the view filter it carries (#4170).

The export selects exactly the rows the paged read selects, streams them as
CSV or JSON Lines, caps them, escapes spreadsheet formulas, is gated like the
query log read, and leaves an audit row naming the filter used.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.logs import router as logs_router
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.dns import DNSServer, DNSServerGroup
from app.models.logs import DNSQueryLogEntry

pytestmark = pytest.mark.asyncio

_NOW = datetime.now(UTC)


def _tag() -> str:
    return uuid.uuid4().hex[:6]


async def _user(db: AsyncSession, permissions: list[dict] | None) -> str:
    u = User(
        username=f"u-{_tag()}",
        email=f"{_tag()}@example.test",
        display_name="u",
        hashed_password=hash_password("x"),
        is_superadmin=permissions is None,
    )
    db.add(u)
    await db.flush()
    if permissions is not None:
        role = Role(name=f"r-{_tag()}", description="", permissions=permissions)
        db.add(role)
        await db.flush()
        grp = Group(name=f"g-{_tag()}", description="")
        grp.roles = [role]
        grp.users = [u]
        db.add(grp)
        await db.flush()
    return create_access_token(str(u.id))


def _h(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _estate(db: AsyncSession) -> dict:
    g = DNSServerGroup(name=f"grp-{_tag()}")
    db.add(g)
    await db.flush()
    srv = DNSServer(group_id=g.id, name=f"ns-{_tag()}", driver="bind9", host="192.0.2.1")
    other = DNSServer(group_id=g.id, name=f"ns2-{_tag()}", driver="bind9", host="192.0.2.2")
    db.add_all([srv, other])
    await db.flush()
    rows = [
        ("a.example.test", "A", "internal", "NOERROR", "198.51.100.5"),
        ("b.example.test", "AAAA", "external", "NXDOMAIN", "198.51.100.6"),
        ("c.example.test", "A", "external", "REFUSED", "203.0.113.9"),
        ("=HYPERLINK(1).test", "A", "internal", None, "198.51.100.5"),
    ]
    for i, (qname, qtype, view, rcode, ip) in enumerate(rows):
        db.add(
            DNSQueryLogEntry(
                server_id=srv.id,
                ts=_NOW - timedelta(minutes=10 - i),
                client_ip=ip,
                client_port=5000 + i,
                qname=qname,
                qclass="IN",
                qtype=qtype,
                flags="+E(0)",
                view=view,
                rcode=rcode,
                answer_count=1 if rcode == "NOERROR" else None,
                raw=f"query: {qname}",
            )
        )
    db.add(
        DNSQueryLogEntry(
            server_id=other.id, ts=_NOW, qname="elsewhere.test", qtype="A", raw="query: x"
        )
    )
    await db.commit()
    return {"g": g, "srv": srv, "other": other}


def _csv_rows(text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(text)))


async def test_csv_export_matches_filter_and_columns(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    e = await _estate(db_session)
    token = await _user(db_session, None)
    await db_session.commit()

    r = await client.get(
        "/api/v1/logs/dns-queries/export.csv",
        params={"server_id": str(e["srv"].id), "view": "external", "qtype": "A"},
        headers=_h(token),
    )
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/csv")
    assert r.headers["x-export-truncated"] == "false"
    assert r.headers["x-export-rows"] == "1"
    disp = r.headers["content-disposition"]
    assert f"dns-queries-{e['srv'].name}-" in disp and disp.count(".csv") >= 1
    rows = _csv_rows(r.text)
    assert [x["qname"] for x in rows] == ["c.example.test"]
    row = rows[0]
    assert row["server"] == e["srv"].name
    assert row["view"] == "external" and row["rcode"] == "REFUSED"
    assert row["client_ip"] == "203.0.113.9" and row["client_port"] == "5002"
    assert row["ts"].endswith("Z") and row["raw"] == "query: c.example.test"
    assert list(row) == list(logs_router.EXPORT_COLUMNS)


async def test_export_equals_paged_read_for_same_filter(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    e = await _estate(db_session)
    token = await _user(db_session, None)
    await db_session.commit()

    paged = await client.post(
        "/api/v1/logs/dns-queries",
        json={"server_id": str(e["srv"].id), "client_ip": "198.51.100.5", "view": "internal"},
        headers=_h(token),
    )
    exp = await client.get(
        "/api/v1/logs/dns-queries/export.csv",
        params={"server_id": str(e["srv"].id), "client_ip": "198.51.100.5", "view": "internal"},
        headers=_h(token),
    )
    assert [ev["qname"] for ev in paged.json()["events"]] == [
        x["qname"].removeprefix("'") for x in _csv_rows(exp.text)
    ]
    assert len(paged.json()["events"]) == 2


async def test_csv_neutralises_formula_cells(client: AsyncClient, db_session: AsyncSession) -> None:
    e = await _estate(db_session)
    token = await _user(db_session, None)
    await db_session.commit()

    r = await client.get(
        "/api/v1/logs/dns-queries/export.csv",
        params={"server_id": str(e["srv"].id), "q": "HYPERLINK"},
        headers=_h(token),
    )
    rows = _csv_rows(r.text)
    assert len(rows) == 1
    assert rows[0]["qname"] == "'=HYPERLINK(1).test"
    assert not any(c.startswith("=") for c in rows[0].values())


async def test_jsonl_export_is_one_object_per_line(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    e = await _estate(db_session)
    token = await _user(db_session, None)
    await db_session.commit()

    r = await client.get(
        "/api/v1/logs/dns-queries/export.jsonl",
        params={"group_id": str(e["g"].id), "rcode": "NXDOMAIN"},
        headers=_h(token),
    )
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/x-ndjson")
    assert f"dns-queries-{e['g'].name}-" in r.headers["content-disposition"]
    lines = [json.loads(x) for x in r.text.splitlines()]
    assert len(lines) == 1
    assert lines[0]["qname"] == "b.example.test" and lines[0]["view"] == "external"
    assert lines[0]["answer_count"] is None and set(lines[0]) == set(logs_router.EXPORT_COLUMNS)


async def test_cap_truncates_and_says_so(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    e = await _estate(db_session)
    token = await _user(db_session, None)
    await db_session.commit()
    monkeypatch.setattr(logs_router, "EXPORT_ROW_CAP", 2)

    r = await client.get(
        "/api/v1/logs/dns-queries/export.csv",
        params={"server_id": str(e["srv"].id)},
        headers=_h(token),
    )
    assert r.status_code == 200
    assert r.headers["x-export-truncated"] == "true"
    assert r.headers["x-export-row-cap"] == "2"
    assert len(_csv_rows(r.text)) == 2
    # Newest rows win, so the cap drops the oldest.
    assert [x["qname"] for x in _csv_rows(r.text)][0] == "'=HYPERLINK(1).test"
    audit = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == "export")))
        .scalars()
        .all()
    )
    assert audit[-1].new_value["truncated"] is True


async def test_export_writes_audit_row_with_filter(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    e = await _estate(db_session)
    token = await _user(db_session, None)
    await db_session.commit()

    r = await client.get(
        "/api/v1/logs/dns-queries/export.jsonl",
        params={"server_id": str(e["srv"].id), "view": "external", "q": "example"},
        headers=_h(token),
    )
    assert r.status_code == 200
    row = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "export", AuditLog.resource_type == "dns_query_log"
            )
        )
    ).scalar_one()
    assert row.resource_id == str(e["srv"].id)
    assert row.new_value["filter"] == {"view": "external", "q": "example"}
    assert row.new_value["format"] == "jsonl" and row.new_value["rows"] == 2


async def test_export_refused_without_read_on_server(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    e = await _estate(db_session)
    token = await _user(db_session, [{"action": "read", "resource_type": "subnet"}])
    await db_session.commit()

    r = await client.get(
        "/api/v1/logs/dns-queries/export.csv",
        params={"server_id": str(e["srv"].id)},
        headers=_h(token),
    )
    assert r.status_code == 403
    n = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.resource_type == "dns_query_log")
            )
        )
        .scalars()
        .all()
    )
    assert n == []


async def test_scoped_grant_only_exports_its_server(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    e = await _estate(db_session)
    token = await _user(
        db_session,
        [{"action": "read", "resource_type": "server", "resource_id": str(e["srv"].id)}],
    )
    await db_session.commit()

    r = await client.get("/api/v1/logs/dns-queries/export.jsonl", headers=_h(token))
    assert r.status_code == 200, r.text
    names = {json.loads(x)["qname"] for x in r.text.splitlines()}
    assert "elsewhere.test" not in names and "a.example.test" in names


async def test_bad_client_ip_filter_is_422(client: AsyncClient, db_session: AsyncSession) -> None:
    await _estate(db_session)
    token = await _user(db_session, None)
    await db_session.commit()
    r = await client.get(
        "/api/v1/logs/dns-queries/export.csv", params={"client_ip": "not an ip!"}, headers=_h(token)
    )
    assert r.status_code == 422


async def test_view_filter_on_copilot_find_dns_queries(db_session: AsyncSession) -> None:
    from app.services.ai.tools.dns import FindDNSQueriesArgs, find_dns_queries

    e = await _estate(db_session)
    su = User(
        username=f"su-{_tag()}",
        email=f"{_tag()}@example.test",
        display_name="su",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(su)
    await db_session.commit()
    out = await find_dns_queries(
        db_session, su, FindDNSQueriesArgs(server_id=str(e["srv"].id), view="external")
    )
    assert {r["qname"] for r in out} == {"b.example.test", "c.example.test"}


@pytest.mark.parametrize("fmt", ["csv", "jsonl"])
async def test_export_error_statuses_never_500(
    client: AsyncClient, db_session: AsyncSession, fmt: str
) -> None:
    """Missing ids are 404, bad filters 422, a caller without read on ``server``
    403 -- on both formats, and none of them leaves an audit row."""
    e = await _estate(db_session)
    admin = await _user(db_session, None)
    nobody = await _user(db_session, [{"action": "read", "resource_type": "subnet"}])
    await db_session.commit()
    url = f"/api/v1/logs/dns-queries/export.{fmt}"
    missing = str(uuid.uuid4())

    r = await client.get(url, params={"server_id": missing}, headers=_h(admin))
    assert r.status_code == 404, r.text
    r = await client.get(url, params={"group_id": missing}, headers=_h(admin))
    assert r.status_code == 404, r.text
    r = await client.get(url, params={"server_id": "not-a-uuid"}, headers=_h(admin))
    assert r.status_code == 422
    r = await client.get(url, params={"since": "yesterday-ish"}, headers=_h(admin))
    assert r.status_code == 422
    r = await client.get(url, params={"until": "2026-13-45"}, headers=_h(admin))
    assert r.status_code == 422
    r = await client.get(url, params={"client_ip": "not an ip!"}, headers=_h(admin))
    assert r.status_code == 422
    r = await client.get(url, params={"q": "x" * 300}, headers=_h(admin))
    assert r.status_code == 422
    r = await client.get(url, params={"server_id": str(e["srv"].id)}, headers=_h(nobody))
    assert r.status_code == 403
    r = await client.get(url)
    assert r.status_code in (401, 403)
    audit = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.resource_type == "dns_query_log")
            )
        )
        .scalars()
        .all()
    )
    assert audit == []


async def test_scoped_grant_cannot_export_another_servers_rows_by_id(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    e = await _estate(db_session)
    token = await _user(
        db_session,
        [{"action": "read", "resource_type": "server", "resource_id": str(e["srv"].id)}],
    )
    await db_session.commit()
    r = await client.get(
        "/api/v1/logs/dns-queries/export.csv",
        params={"server_id": str(e["other"].id)},
        headers=_h(token),
    )
    assert r.status_code == 403
