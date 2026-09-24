"""The answer half of the DNS query log (issue #914).

``dns_query_log_entry`` recorded the question and nothing about the
response, so the five outcomes an operator is actually triaging — a
query that never arrived, NOERROR, a NODATA NOERROR, NXDOMAIN, REFUSED,
SERVFAIL — collapsed into "there is a row" or "there is not". These
tests pin the two properties that make the fix trustworthy rather than
merely present:

* **Correlation.** named logs the response as an INDEPENDENT line, so
  the outcome only reaches the right query row if the key holds. A
  cross-stamp is worse than no rcode: it reports a confident wrong
  answer.
* **NULL means UNKNOWN.** Never "fine". Every surface has to keep an
  unrecorded outcome distinguishable from a successful one, because the
  whole point of the column is telling those two apart.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.agents import QueryLogBatch, agent_query_log_entries
from app.models.dns import DNSServer, DNSServerGroup
from app.models.logs import DNSQueryLogEntry


async def _make_user(db: AsyncSession, *, username: str) -> tuple[Any, str]:
    from app.core.security import create_access_token, hash_password
    from app.models.auth import User

    user = User(
        username=username,
        email=f"{username}@example.test",
        display_name=username,
        hashed_password=hash_password("x"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return user, create_access_token(str(user.id))


async def _make_bind9_server(db: AsyncSession) -> DNSServer:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:8]}", description="")
    db.add(group)
    await db.flush()
    server = DNSServer(
        name=f"s-{uuid.uuid4().hex[:8]}",
        host="127.0.0.1",
        port=53,
        driver="bind9",
        group_id=group.id,
    )
    db.add(server)
    await db.flush()
    return server


# Stamped relative to now, not a fixed date: the ingest drops lines already
# past the 24 h log retention (#1077), so a hard-coded date makes every line
# here vanish the day after it was written. English month abbreviations are
# spelled out rather than taken from strftime("%b"), which is locale-dependent.
_MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
_NOW = datetime.now(UTC) - timedelta(minutes=5)
_STAMP = f"{_NOW.day:02d}-{_MONTHS[_NOW.month - 1]}-{_NOW.year} {_NOW:%H:%M:%S}"


def _query_line(port: int, qname: str, qtype: str = "A") -> str:
    return (
        f"{_STAMP}.480 queries: info: client @0x7f83 10.1.2.3#{port} "
        f"({qname}): view internal: query: {qname} IN {qtype} +E(0)K (127.0.0.1)"
    )


def _response_line(port: int, qname: str, rcode: str, answers: int, qtype: str = "A") -> str:
    return (
        f"{_STAMP}.490 responses: info: client @0x7f83 10.1.2.3#{port} "
        f"({qname}): view internal: response: {qname} IN {qtype} {rcode} "
        f"{answers} 1 1 +E(0)K (127.0.0.1)"
    )


async def _ingest(db: AsyncSession, server: DNSServer, lines: list[str]) -> dict[str, Any]:
    result = await agent_query_log_entries(QueryLogBatch(lines=lines), db, auth=(server, {}))
    return dict(result)


@pytest.mark.asyncio
async def test_response_line_stamps_its_own_query_row(db_session: AsyncSession) -> None:
    """The common case: both lines in one batch, matched without a query."""
    server = await _make_bind9_server(db_session)
    result = await _ingest(
        db_session,
        server,
        [
            _query_line(50001, "www.example.test"),
            _response_line(50001, "www.example.test", "NXDOMAIN", 0),
        ],
    )
    assert result["inserted"] == 1, "a response must not create a second row"
    assert result["responses_matched"] == 1
    assert result["responses_unmatched"] == 0

    row = (await db_session.execute(select(DNSQueryLogEntry))).scalars().one()
    assert row.qname == "www.example.test"
    assert row.rcode == "NXDOMAIN"
    assert row.answer_count == 0


@pytest.mark.asyncio
async def test_responses_do_not_cross_stamp_between_clients(
    db_session: AsyncSession,
) -> None:
    """Interleaved traffic is the normal case on a busy resolver.

    A confident wrong outcome is worse than a blank one, so the key has
    to hold when two queries are in flight at once.
    """
    server = await _make_bind9_server(db_session)
    await _ingest(
        db_session,
        server,
        [
            _query_line(50001, "a.example.test"),
            _query_line(50002, "b.example.test"),
            _response_line(50002, "b.example.test", "REFUSED", 0),
            _response_line(50001, "a.example.test", "NOERROR", 2),
        ],
    )
    rows = {
        r.qname: r for r in (await db_session.execute(select(DNSQueryLogEntry))).scalars().all()
    }
    assert rows["a.example.test"].rcode == "NOERROR"
    assert rows["a.example.test"].answer_count == 2
    assert rows["b.example.test"].rcode == "REFUSED"


@pytest.mark.asyncio
async def test_response_in_a_later_batch_still_matches(db_session: AsyncSession) -> None:
    """The batch boundary must not systematically blank the last query.

    The shipper caps its batches, so the split lands on the same row
    every time under load — a bias, not noise, and it would hit the
    busiest servers hardest.
    """
    server = await _make_bind9_server(db_session)
    await _ingest(db_session, server, [_query_line(50003, "late.example.test")])
    result = await _ingest(
        db_session,
        server,
        [_response_line(50003, "late.example.test", "SERVFAIL", 0)],
    )
    assert result["inserted"] == 0
    assert result["responses_matched"] == 1

    row = (await db_session.execute(select(DNSQueryLogEntry))).scalars().one()
    assert row.rcode == "SERVFAIL"


@pytest.mark.asyncio
async def test_orphan_response_is_dropped_not_stored(db_session: AsyncSession) -> None:
    """A response with no question answers nothing.

    Storing it as its own row would double-count every query in the
    analytics rollups the same table feeds.
    """
    server = await _make_bind9_server(db_session)
    result = await _ingest(
        db_session,
        server,
        [_response_line(50004, "orphan.example.test", "NOERROR", 1)],
    )
    assert result["inserted"] == 0
    assert result["responses_matched"] == 0
    assert result["responses_unmatched"] == 1
    assert (await db_session.execute(select(DNSQueryLogEntry))).scalars().all() == []


@pytest.mark.asyncio
async def test_query_without_a_response_keeps_a_null_rcode(
    db_session: AsyncSession,
) -> None:
    """Response logging off is the default, and it must not read as NOERROR."""
    server = await _make_bind9_server(db_session)
    await _ingest(db_session, server, [_query_line(50005, "quiet.example.test")])
    row = (await db_session.execute(select(DNSQueryLogEntry))).scalars().one()
    assert row.rcode is None
    assert row.answer_count is None


@pytest.mark.asyncio
async def test_query_log_api_filters_and_reports_rcode(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server = await _make_bind9_server(db_session)
    _, token = await _make_user(db_session, username="rcodereader")
    await _ingest(
        db_session,
        server,
        [
            _query_line(50006, "ok.example.test"),
            _response_line(50006, "ok.example.test", "NOERROR", 1),
            _query_line(50007, "gone.example.test"),
            _response_line(50007, "gone.example.test", "NXDOMAIN", 0),
            _query_line(50008, "unlogged.example.test"),
        ],
    )
    await db_session.flush()
    headers = {"Authorization": f"Bearer {token}"}

    res = await client.post(
        "/api/v1/logs/dns-queries",
        json={"server_id": str(server.id), "rcode": "nxdomain"},
        headers=headers,
    )
    assert res.status_code == 200, res.text
    events = res.json()["events"]
    assert [e["qname"] for e in events] == ["gone.example.test"]
    assert events[0]["rcode"] == "NXDOMAIN"
    assert events[0]["answer_count"] == 0

    # "UNKNOWN" is a selectable value, not an absence — it is how an
    # operator finds out whether response logging is on at all.
    res = await client.post(
        "/api/v1/logs/dns-queries",
        json={"server_id": str(server.id), "rcode": "UNKNOWN"},
        headers=headers,
    )
    assert [e["qname"] for e in res.json()["events"]] == ["unlogged.example.test"]
    assert res.json()["events"][0]["rcode"] is None


@pytest.mark.asyncio
async def test_analytics_counts_unrecorded_outcomes_explicitly(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A server with response logging off must show one honest bar, not
    an empty panel that reads as "no failures"."""
    server = await _make_bind9_server(db_session)
    _, token = await _make_user(db_session, username="rcodeanalytics")
    await _ingest(
        db_session,
        server,
        [
            _query_line(50010, "a.example.test"),
            _response_line(50010, "a.example.test", "NOERROR", 1),
            _query_line(50011, "b.example.test"),
        ],
    )
    await db_session.flush()
    res = await client.post(
        "/api/v1/logs/dns-queries/analytics",
        json={"server_id": str(server.id)},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200, res.text
    dist = {r["key"]: r["count"] for r in res.json()["rcode_distribution"]}
    assert dist == {"NOERROR": 1, "UNKNOWN": 1}


@pytest.mark.asyncio
async def test_response_log_requires_query_log(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Refused rather than silently ignored — the response lines are
    written to the query-log channel, so on its own the toggle would
    change named.conf and produce nothing."""
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:8]}", description="")
    db_session.add(group)
    await db_session.flush()
    _, token = await _make_user(db_session, username="optswriter")
    await db_session.flush()
    headers = {"Authorization": f"Bearer {token}"}
    res = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        json={"query_log_enabled": False, "response_log_enabled": True},
        headers=headers,
    )
    assert res.status_code == 422
    assert "query_log_enabled" in res.text


@pytest.mark.asyncio
async def test_turning_query_logging_off_clears_response_logging(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Turning query logging off is not a request for the impossible pair.

    Rejecting it would name a field the caller never sent and would leave
    no single call that disables query logging at all — so response
    logging is cleared alongside it, which is the only coherent resulting
    state.
    """
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:8]}", description="")
    db_session.add(group)
    await db_session.flush()
    _, token = await _make_user(db_session, username="optsclearer")
    await db_session.flush()
    headers = {"Authorization": f"Bearer {token}"}

    on = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        json={"query_log_enabled": True, "response_log_enabled": True},
        headers=headers,
    )
    assert on.status_code == 200, on.text
    assert on.json()["response_log_enabled"] is True

    off = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        json={"query_log_enabled": False},
        headers=headers,
    )
    assert off.status_code == 200, off.text
    assert off.json()["query_log_enabled"] is False
    assert off.json()["response_log_enabled"] is False


# ── RPZ per-hit surface (issue #914) ─────────────────────────────────


async def _rpz_hit(
    db: AsyncSession,
    server: DNSServer,
    *,
    client_ip: str,
    qname: str,
    policy: str = "NXDOMAIN",
    minutes_ago: int = 0,
) -> None:
    from app.models.dns_rpz_hit import DNSRPZHit

    db.add(
        DNSRPZHit(
            server_id=server.id,
            ts=datetime.now(UTC) - timedelta(minutes=minutes_ago),
            client_ip=client_ip,
            qname=qname,
            trigger="QNAME",
            policy=policy,
            rpz_zone="spatium-blocklist.rpz",
            raw="x",
        )
    )
    await db.flush()


@pytest.mark.asyncio
async def test_recent_hits_excludes_passthru_by_default(db_session: AsyncSession) -> None:
    """A PASSTHRU is an explicit ALLOW. Listing it among blocks makes a
    working allowlist read as an infection."""
    from app.services.dns_threat import rpz as rpz_service

    server = await _make_bind9_server(db_session)
    await _rpz_hit(db_session, server, client_ip="10.0.0.5", qname="bad.example")
    await _rpz_hit(
        db_session, server, client_ip="10.0.0.5", qname="allowed.example", policy="PASSTHRU"
    )

    blocked = await rpz_service.recent_hits(db_session)
    assert [h["qname"] for h in blocked] == ["bad.example"]

    both = await rpz_service.recent_hits(db_session, include_passthru=True)
    assert {h["qname"] for h in both} == {"bad.example", "allowed.example"}


@pytest.mark.asyncio
async def test_recent_hits_filters_and_orders_newest_first(
    db_session: AsyncSession,
) -> None:
    from app.services.dns_threat import rpz as rpz_service

    server = await _make_bind9_server(db_session)
    await _rpz_hit(db_session, server, client_ip="10.0.0.5", qname="old.example", minutes_ago=30)
    await _rpz_hit(db_session, server, client_ip="10.0.0.5", qname="new.example", minutes_ago=1)
    await _rpz_hit(db_session, server, client_ip="10.0.0.6", qname="other.example")

    mine = await rpz_service.recent_hits(db_session, client_ip="10.0.0.5")
    assert [h["qname"] for h in mine] == ["new.example", "old.example"]


@pytest.mark.asyncio
async def test_recent_hits_substring_filter_escapes_like_metacharacters(
    db_session: AsyncSession,
) -> None:
    """Searching for ``%`` must not match every row — the #879 finding,
    which made search look broken rather than permissive."""
    from app.services.dns_threat import rpz as rpz_service

    server = await _make_bind9_server(db_session)
    await _rpz_hit(db_session, server, client_ip="10.0.0.5", qname="tracker.example")
    assert await rpz_service.recent_hits(db_session, qname_contains="%") == []
    assert len(await rpz_service.recent_hits(db_session, qname_contains="tracker")) == 1


@pytest.mark.asyncio
async def test_rpz_hits_endpoint(client: AsyncClient, db_session: AsyncSession) -> None:
    from app.models.feature_module import FeatureModule

    db_session.add(FeatureModule(id="security.dns_threat", enabled=True))
    server = await _make_bind9_server(db_session)
    _, token = await _make_user(db_session, username="rpzhits")
    await _rpz_hit(db_session, server, client_ip="10.0.0.5", qname="bad.example")

    res = await client.get(
        "/api/v1/dns-threat/rpz/hits",
        params={"client_ip": "10.0.0.5"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert len(body) == 1
    assert body[0]["qname"] == "bad.example"
    assert body[0]["policy"] == "NXDOMAIN"

    bad = await client.get(
        "/api/v1/dns-threat/rpz/hits",
        params={"client_ip": "not-an-ip"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert bad.status_code == 422
