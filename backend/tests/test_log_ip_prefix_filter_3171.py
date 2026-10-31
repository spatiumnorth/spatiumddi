"""Log IP / MAC filters take a partial value as you type (#3171).

``client_ip`` is ``inet``; ``client_ip == '127'`` is a Postgres data error,
so the filter box 422'd with the generic "cannot be stored as sent" text on
every keystroke until a whole address was typed. A partial value now matches
by prefix, a CIDR by containment, a whole address exactly, and a value that
cannot be an address answers a 422 naming the field.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPServer
from app.models.dns import DNSServer
from app.models.feature_module import FeatureModule
from app.models.logs import DHCPLogEntry, DNSQueryLogEntry

from .test_dns_query_rcode import _make_bind9_server, _make_user, _rpz_hit

pytestmark = pytest.mark.asyncio

_IPS = ["127.0.0.1", "192.168.0.4", "192.168.1.9", "fd00::1", "2001:db8::5"]


def _h(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _dns_rows(db: AsyncSession) -> str:
    server = await _make_bind9_server(db)
    for i, ip in enumerate(_IPS):
        db.add(
            DNSQueryLogEntry(
                server_id=server.id,
                ts=datetime.now(UTC) - timedelta(minutes=i),
                client_ip=ip,
                qname=f"q{i}.test",
                qtype="A",
                raw="x",
            )
        )
    _, token = await _make_user(db, username=f"u{uuid.uuid4().hex[:6]}")
    await db.commit()
    return token


async def _dns_ips(client: AsyncClient, token: str, value: str) -> set[str]:
    r = await client.post("/api/v1/logs/dns-queries", json={"client_ip": value}, headers=_h(token))
    assert r.status_code == 200, (value, r.text)
    return {e["client_ip"] for e in r.json()["events"]}


async def test_dns_partial_full_cidr_and_v6(client: AsyncClient, db_session: AsyncSession) -> None:
    token = await _dns_rows(db_session)
    assert await _dns_ips(client, token, "127") == {"127.0.0.1"}
    assert await _dns_ips(client, token, "192.168.0.") == {"192.168.0.4"}
    assert await _dns_ips(client, token, "192.168") == {"192.168.0.4", "192.168.1.9"}
    assert await _dns_ips(client, token, "192.168.0.4") == {"192.168.0.4"}
    assert await _dns_ips(client, token, "192.168.0.0/24") == {"192.168.0.4"}
    assert await _dns_ips(client, token, "fd00:") == {"fd00::1"}
    assert await _dns_ips(client, token, "FD00:") == {"fd00::1"}
    assert await _dns_ips(client, token, "2001:db8::/32") == {"2001:db8::5"}
    assert await _dns_ips(client, token, "fd00::1") == {"fd00::1"}


async def test_dns_percent_is_literal(client: AsyncClient, db_session: AsyncSession) -> None:
    token = await _dns_rows(db_session)
    r = await client.post("/api/v1/logs/dns-queries", json={"client_ip": "1%"}, headers=_h(token))
    assert r.status_code == 422
    assert r.json()["detail"].startswith("client_ip:")


async def test_dns_junk_names_the_field(client: AsyncClient, db_session: AsyncSession) -> None:
    token = await _dns_rows(db_session)
    r = await client.post(
        "/api/v1/logs/dns-queries", json={"client_ip": "abc xyz"}, headers=_h(token)
    )
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail.startswith("client_ip: not an IP address")
    assert "cannot be stored" not in detail


async def _dhcp_rows(db: AsyncSession) -> str:
    srv = DHCPServer(name=f"k-{uuid.uuid4().hex[:6]}", driver="kea", host="127.0.0.1")
    db.add(srv)
    await db.flush()
    for i, (ip, mac) in enumerate(
        [("10.1.0.5", "08:00:2b:01:02:03"), ("10.2.0.5", "aa:bb:cc:00:00:01")]
    ):
        db.add(
            DHCPLogEntry(
                server_id=srv.id,
                ts=datetime.now(UTC) - timedelta(minutes=i),
                severity="INFO",
                code="DHCP4_LEASE_ALLOC",
                ip_address=ip,
                mac_address=mac,
                raw="x",
            )
        )
    _, token = await _make_user(db, username=f"d{uuid.uuid4().hex[:6]}")
    await db.commit()
    return token


async def _dhcp(client: AsyncClient, token: str, **body: str) -> tuple[int, dict]:
    r = await client.post("/api/v1/logs/dhcp-activity", json=body, headers=_h(token))
    return r.status_code, r.json()


async def test_dhcp_ip_and_mac_partial(client: AsyncClient, db_session: AsyncSession) -> None:
    token = await _dhcp_rows(db_session)
    code, body = await _dhcp(client, token, ip_address="10.1.")
    assert code == 200 and [e["ip_address"] for e in body["events"]] == ["10.1.0.5"]
    code, body = await _dhcp(client, token, ip_address="10.2.0.0/16")
    assert code == 200 and [e["ip_address"] for e in body["events"]] == ["10.2.0.5"]
    code, body = await _dhcp(client, token, mac_address="AA-BB")
    assert code == 200 and [e["mac_address"] for e in body["events"]] == ["aa:bb:cc:00:00:01"]
    code, body = await _dhcp(client, token, mac_address="0800.2b")
    assert code == 200 and [e["mac_address"] for e in body["events"]] == ["08:00:2b:01:02:03"]
    code, body = await _dhcp(client, token, mac_address="08:00:2b:01:02:03")
    assert code == 200 and len(body["events"]) == 1


async def test_dhcp_junk_names_the_field(client: AsyncClient, db_session: AsyncSession) -> None:
    token = await _dhcp_rows(db_session)
    code, body = await _dhcp(client, token, ip_address="abc xyz")
    assert code == 422 and body["detail"].startswith("ip_address: not")
    code, body = await _dhcp(client, token, mac_address="zz:zz")
    assert code == 422 and body["detail"].startswith("mac_address: not")


async def test_rpz_hits_partial_and_junk(client: AsyncClient, db_session: AsyncSession) -> None:
    db_session.add(FeatureModule(id="security.dns_threat", enabled=True))
    server = await _make_bind9_server(db_session)
    _, token = await _make_user(db_session, username=f"r{uuid.uuid4().hex[:6]}")
    await _rpz_hit(db_session, server, client_ip="10.0.0.5", qname="a.example")
    await _rpz_hit(db_session, server, client_ip="172.16.0.9", qname="b.example")

    async def hits(value: str):
        return await client.get(
            "/api/v1/dns-threat/rpz/hits", params={"client_ip": value}, headers=_h(token)
        )

    r = await hits("10.")
    assert r.status_code == 200 and [h["qname"] for h in r.json()] == ["a.example"]
    r = await hits("172.16.0.0/16")
    assert r.status_code == 200 and [h["qname"] for h in r.json()] == ["b.example"]
    r = await hits("abc xyz")
    assert r.status_code == 422 and r.json()["detail"].startswith("client_ip: not")


async def test_copilot_tool_answers_junk_as_text(db_session: AsyncSession) -> None:
    from app.services.ai.tools.observability import (
        QueryDNSQueryLogArgs,
        query_dns_query_log,
    )

    user, _ = await _make_user(db_session, username=f"t{uuid.uuid4().hex[:6]}")
    await _make_bind9_server(db_session)
    out = await query_dns_query_log(db_session, user, QueryDNSQueryLogArgs(client_ip="abc xyz"))
    assert out and out[0]["result"].startswith("client_ip: not")
    out = await query_dns_query_log(db_session, user, QueryDNSQueryLogArgs(client_ip="127"))
    assert not any("result" in r and "not an" in str(r["result"]) for r in out)


_ = DNSServer
