"""The DNS query analytics rollups take the grid's filters (#4072)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.logs import DNSQueryLogEntry

from .test_dns_query_rcode import _make_bind9_server, _make_user

pytestmark = pytest.mark.asyncio

_ROWS = [
    # (client, qname, qtype, rcode)
    ("192.0.2.5", "a.test", "A", "NOERROR"),
    ("192.0.2.5", "a.test", "AAAA", "NOERROR"),
    ("192.0.2.9", "b.test", "AAAA", "NXDOMAIN"),
    ("198.51.100.7", "c.test", "A", "NOERROR"),
]


async def _setup(db: AsyncSession) -> str:
    server = await _make_bind9_server(db)
    for i, (ip, qname, qtype, rcode) in enumerate(_ROWS):
        db.add(
            DNSQueryLogEntry(
                server_id=server.id,
                ts=datetime.now(UTC) - timedelta(minutes=i),
                client_ip=ip,
                qname=qname,
                qtype=qtype,
                rcode=rcode,
                raw="x",
            )
        )
    _, token = await _make_user(db, username=f"u{uuid.uuid4().hex[:6]}")
    await db.commit()
    return token


async def _analytics(client: AsyncClient, token: str, **body: str) -> dict:
    r = await client.post(
        "/api/v1/logs/dns-queries/analytics",
        json=body,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text
    return r.json()


async def test_unfiltered_is_whole_window(client: AsyncClient, db_session: AsyncSession) -> None:
    token = await _setup(db_session)
    assert (await _analytics(client, token))["total_queries"] == 4


async def test_cidr_narrows_every_card(client: AsyncClient, db_session: AsyncSession) -> None:
    token = await _setup(db_session)
    a = await _analytics(client, token, client_ip="192.0.2.0/24")
    assert a["total_queries"] == 3
    assert {r["key"].split("/")[0] for r in a["top_clients"]} == {"192.0.2.5", "192.0.2.9"}
    assert {r["key"] for r in a["top_qnames"]} == {"a.test", "b.test"}


async def test_prefix_qtype_name_rcode(client: AsyncClient, db_session: AsyncSession) -> None:
    token = await _setup(db_session)
    assert (await _analytics(client, token, client_ip="192.0."))["total_queries"] == 3
    a = await _analytics(client, token, qtype="aaaa")
    assert a["total_queries"] == 2
    assert {r["key"] for r in a["qtype_distribution"]} == {"AAAA"}
    assert (await _analytics(client, token, q="c.te"))["total_queries"] == 1
    a = await _analytics(client, token, rcode="NXDOMAIN")
    assert [r["key"] for r in a["rcode_distribution"]] == ["NXDOMAIN"]


async def test_bad_client_filter_is_422(client: AsyncClient, db_session: AsyncSession) -> None:
    token = await _setup(db_session)
    r = await client.post(
        "/api/v1/logs/dns-queries/analytics",
        json={"client_ip": "not-an-ip"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 422
