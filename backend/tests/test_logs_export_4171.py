"""Logs → DNS Queries / DHCP Activity export as CSV / JSON Lines (#4171)."""

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
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.models.dns import DNSServer, DNSServerGroup
from app.models.logs import DHCPLogEntry, DNSQueryLogEntry
from app.services.logs import export as export_svc

pytestmark = pytest.mark.asyncio

_NOW = datetime(2026, 11, 14, 15, 0, tzinfo=UTC)


def _tag() -> str:
    return uuid.uuid4().hex[:6]


async def _user(db: AsyncSession, permissions: list[dict] | None) -> dict[str, str]:
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
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _dns(db: AsyncSession) -> tuple[DNSServer, DNSServer]:
    g = DNSServerGroup(name=f"g-{_tag()}")
    db.add(g)
    await db.flush()
    a = DNSServer(group_id=g.id, name=f"ns-a-{_tag()}", driver="bind9", host="192.0.2.1")
    b = DNSServer(group_id=g.id, name=f"ns-b-{_tag()}", driver="bind9", host="192.0.2.2")
    db.add_all([a, b])
    await db.flush()
    rows = [
        (a, "ok.example.test", "A", "NOERROR", "v1", "198.51.100.5"),
        (a, "=HYPERLINK(1)", "TXT", "NXDOMAIN", "v2", "198.51.100.6"),
        (b, "other.example.test", "AAAA", "NOERROR", "v1", "203.0.113.9"),
    ]
    for i, (srv, qn, qt, rc, view, ip) in enumerate(rows):
        db.add(
            DNSQueryLogEntry(
                server_id=srv.id,
                ts=_NOW - timedelta(minutes=10 - i),
                client_ip=ip,
                client_port=5300 + i,
                qname=qn,
                qclass="IN",
                qtype=qt,
                flags="+",
                view=view,
                rcode=rc,
                answer_count=1,
                raw=f"query: {qn}",
            )
        )
    await db.commit()
    return a, b


async def test_csv_shape_filters_and_formula_neutralised(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    a, _b = await _dns(db_session)
    h = await _user(db_session, None)
    r = await client.get(
        "/api/v1/logs/dns-queries/export",
        params={"format": "csv", "server_id": str(a.id)},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/csv")
    cd = r.headers["content-disposition"]
    assert f'filename="dns-queries-{a.name}-' in cd and 'Z.csv"' in cd
    assert r.headers["x-export-capped"] == "false"
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert [x["qname"] for x in rows] == ["'=HYPERLINK(1)", "ok.example.test"]
    assert list(rows[0]) == list(export_svc.DNS_COLUMNS)
    assert rows[1]["ts"].endswith("Z") and rows[1]["server"] == a.name
    assert rows[1]["client_ip"] == "198.51.100.5" and rows[1]["rcode"] == "NOERROR"

    # Same filters as the list endpoint: rcode + view + qtype narrow it.
    r = await client.get(
        "/api/v1/logs/dns-queries/export",
        params={"format": "csv", "rcode": "NXDOMAIN", "view": "v2", "qtype": "txt"},
        headers=h,
    )
    assert [x["qname"] for x in csv.DictReader(io.StringIO(r.text))] == ["'=HYPERLINK(1)"]
    r = await client.get(
        "/api/v1/logs/dns-queries/export",
        params={"format": "csv", "client_ip": "203.0.113.9"},
        headers=h,
    )
    assert [x["qname"] for x in csv.DictReader(io.StringIO(r.text))] == ["other.example.test"]


async def test_jsonl_shape_and_all_servers(client: AsyncClient, db_session: AsyncSession) -> None:
    await _dns(db_session)
    h = await _user(db_session, None)
    r = await client.get("/api/v1/logs/dns-queries/export", params={"format": "jsonl"}, headers=h)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/x-ndjson")
    assert (
        "-all-" in r.headers["content-disposition"] and ".jsonl" in r.headers["content-disposition"]
    )
    recs = [json.loads(line) for line in r.text.splitlines()]
    assert [x["qname"] for x in recs] == ["other.example.test", "=HYPERLINK(1)", "ok.example.test"]
    # JSON keeps values verbatim (no CSV quoting) and carries the typed fields.
    assert recs[1]["client_port"] == 5301 and recs[1]["answer_count"] == 1
    assert set(recs[0]) == set(export_svc.DNS_COLUMNS)


async def test_cap_is_applied_and_reported(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _dns(db_session)
    h = await _user(db_session, None)
    monkeypatch.setattr(export_svc, "EXPORT_ROW_CAP", 2)
    monkeypatch.setattr(logs_router, "EXPORT_ROW_CAP", 2)
    r = await client.get("/api/v1/logs/dns-queries/export", params={"format": "jsonl"}, headers=h)
    assert len(r.text.splitlines()) == 2
    assert r.headers["x-export-capped"] == "true"
    assert r.headers["x-export-row-count"] == "2"
    audit = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == "export")))
        .scalars()
        .all()
    )
    assert audit[-1].new_value["capped"] is True


async def test_audit_row_written(client: AsyncClient, db_session: AsyncSession) -> None:
    a, _ = await _dns(db_session)
    h = await _user(db_session, None)
    await client.get(
        "/api/v1/logs/dns-queries/export",
        params={"format": "csv", "server_id": str(a.id), "q": "ok.example"},
        headers=h,
    )
    row = (
        (
            await db_session.execute(
                select(AuditLog)
                .where(AuditLog.action == "export", AuditLog.resource_type == "dns_query_log")
                .order_by(AuditLog.timestamp.desc())
            )
        )
        .scalars()
        .first()
    )
    assert row is not None
    assert row.new_value["format"] == "csv" and row.new_value["rows"] == 1
    assert row.new_value["filters"] == {"q": "ok.example"}
    assert row.new_value["scope"]["server_id"] == str(a.id)


async def test_permission_refused_and_scoped_grant_narrows(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    a, b = await _dns(db_session)
    nobody = await _user(db_session, [])
    r = await client.get("/api/v1/logs/dns-queries/export", headers=nobody)
    assert r.status_code == 403
    scoped = await _user(
        db_session, [{"action": "read", "resource_type": "server", "resource_id": str(a.id)}]
    )
    r = await client.get(
        "/api/v1/logs/dns-queries/export", params={"format": "jsonl"}, headers=scoped
    )
    assert r.status_code == 200
    assert {json.loads(x)["server"] for x in r.text.splitlines()} == {a.name}
    r = await client.get(
        "/api/v1/logs/dns-queries/export", params={"server_id": str(b.id)}, headers=scoped
    )
    assert r.status_code == 403
    # Same as the list: a group filter narrows to what the grant covers, so
    # the sibling server B's rows are never in the file.
    r = await client.get(
        "/api/v1/logs/dns-queries/export",
        params={"group_id": str(a.group_id), "format": "jsonl"},
        headers=scoped,
    )
    assert r.status_code == 200
    assert {json.loads(x)["server"] for x in r.text.splitlines()} == {a.name}


async def test_dhcp_export(client: AsyncClient, db_session: AsyncSession) -> None:
    g = DHCPServerGroup(name=f"g-{_tag()}")
    db_session.add(g)
    await db_session.flush()
    s = DHCPServer(server_group_id=g.id, name=f"kea-{_tag()}", driver="kea", host="192.0.2.9")
    db_session.add(s)
    await db_session.flush()
    for i, sev in enumerate(["INFO", "ERROR"]):
        db_session.add(
            DHCPLogEntry(
                server_id=s.id,
                ts=_NOW - timedelta(minutes=i),
                severity=sev,
                code="DHCP4_LEASE_ALLOC",
                ip_address="192.0.2.50",
                raw=f"{sev} line",
            )
        )
    await db_session.commit()
    h = await _user(db_session, None)
    r = await client.get(
        "/api/v1/logs/dhcp-activity/export",
        params={"format": "csv", "severity": "error"},
        headers=h,
    )
    assert r.status_code == 200, r.text
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert [x["severity"] for x in rows] == ["ERROR"] and rows[0]["ip_address"] == "192.0.2.50"
    assert "dhcp-activity-all-" in r.headers["content-disposition"]


async def test_session_open_until_last_chunk(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The get_db dependency must not tear the session down before the body
    generator has finished (the ASGI test transport buffers the response, so
    the check runs inside the generator)."""
    from app.db import get_db
    from app.main import app

    await _dns(db_session)
    h = await _user(db_session, None)
    state: dict[str, object] = {"closed": False, "seen": []}

    async def tracked():  # type: ignore[no-untyped-def]
        try:
            yield db_session
        finally:
            state["closed"] = True

    real = logs_router.stream_export

    async def watching(*a, **kw):  # type: ignore[no-untyped-def]
        async for chunk in real(*a, **kw):
            state["seen"].append(state["closed"])  # type: ignore[attr-defined]
            yield chunk
        state["seen"].append(state["closed"])  # type: ignore[attr-defined]

    monkeypatch.setattr(logs_router, "stream_export", watching)
    app.dependency_overrides[get_db] = tracked
    try:
        r = await client.get(
            "/api/v1/logs/dns-queries/export", params={"format": "jsonl"}, headers=h
        )
    finally:
        app.dependency_overrides.pop(get_db, None)
    assert r.status_code == 200 and len(r.text.splitlines()) == 3
    assert state["seen"] and not any(state["seen"])  # type: ignore[arg-type]
    assert state["closed"] is True


async def test_cors_exposes_export_headers() -> None:
    from app.main import app

    cors = [m for m in app.user_middleware if m.cls.__name__ == "CORSMiddleware"]
    exposed = {h.lower() for h in cors[0].kwargs["expose_headers"]}
    assert {"x-export-capped", "x-export-row-count", "x-export-row-cap"} <= exposed
