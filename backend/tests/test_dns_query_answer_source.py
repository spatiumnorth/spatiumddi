"""How a DNS query was answered (#4251): ingest, filter and API.

PowerDNS Authoritative reports a per-query verdict; BIND9 does not, so its
rows must stay NULL (unknown) rather than be inferred.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.logs import DNSQueryLogEntry
from tests.test_dns_query_rcode import (
    _ingest,
    _make_bind9_server,
    _make_user,
    _query_line,
    _response_line,
)

_NOW = datetime.now(UTC)
_PDNS_STAMP = f"{_NOW:%b} {_NOW.day:02d} {_NOW:%H:%M:%S}"


def _pdns_line(qname: str, verdict: str) -> str:
    return (
        f"{_PDNS_STAMP} Remote 192.0.2.5:54321 wants '{qname}|A', "
        f"do = 0, bufsize = 4096: {verdict}"
    )


async def _pdns_server(db: AsyncSession) -> Any:
    server = await _make_bind9_server(db)
    server.driver = "powerdns"
    await db.flush()
    return server


@pytest.mark.asyncio
async def test_pdns_verdicts_are_stored(db_session: AsyncSession) -> None:
    server = await _pdns_server(db_session)
    await _ingest(
        db_session,
        server,
        [
            _pdns_line("hit.example.test", "packetcache HIT"),
            _pdns_line("auth.example.test", "1 RR(s)"),
            _pdns_line("none.example.test", "0 RR(s)"),
        ],
    )
    rows = {
        r.qname: r.answer_source
        for r in (await db_session.execute(select(DNSQueryLogEntry))).scalars()
    }
    assert rows == {
        "hit.example.test": "cache",
        "auth.example.test": "authoritative",
        "none.example.test": None,
    }


@pytest.mark.asyncio
async def test_bind9_rows_stay_unknown(db_session: AsyncSession) -> None:
    server = await _make_bind9_server(db_session)
    await _ingest(
        db_session,
        server,
        [
            _query_line(50001, "a.example.test"),
            _response_line(50001, "a.example.test", "NOERROR", 1),
        ],
    )
    row = (await db_session.execute(select(DNSQueryLogEntry))).scalars().one()
    assert row.answer_source is None
    assert row.answer_upstream is None


@pytest.mark.asyncio
async def test_api_reports_and_filters_answer_source(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server = await _pdns_server(db_session)
    _, token = await _make_user(db_session, username="srcreader")
    await _ingest(
        db_session,
        server,
        [
            _pdns_line("hit.example.test", "packetcache HIT"),
            _pdns_line("auth.example.test", "1 RR(s)"),
            _pdns_line("none.example.test", "0 RR(s)"),
        ],
    )
    await db_session.flush()
    headers = {"Authorization": f"Bearer {token}"}

    async def names(**filt: str) -> list[tuple[str, str | None]]:
        res = await client.post(
            "/api/v1/logs/dns-queries",
            json={"server_id": str(server.id), **filt},
            headers=headers,
        )
        assert res.status_code == 200, res.text
        return sorted((e["qname"], e["answer_source"]) for e in res.json()["events"])

    assert await names(answer_source="cache") == [("hit.example.test", "cache")]
    assert await names(answer_source="Authoritative") == [("auth.example.test", "authoritative")]
    assert await names(answer_source="unknown") == [("none.example.test", None)]
    assert len(await names()) == 3
