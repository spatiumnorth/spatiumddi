"""Logs → DNS Queries / DHCP Activity read one server, a group, or all (#2120).

The three agent-log reads used to take a required ``server_id``, so a group
behind one load-balanced address had to be searched server by server. Now
``server_id`` and ``group_id`` are both optional, and the selected set is
always intersected with the servers the caller may read — a filter is a
request, never an authorisation.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import Group, Role, User
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.models.dns import DNSServer, DNSServerGroup
from app.models.logs import DHCPLogEntry, DNSQueryLogEntry

pytestmark = pytest.mark.asyncio

_NOW = datetime.now(UTC)


def _tag() -> str:
    return uuid.uuid4().hex[:6]


async def _user(db: AsyncSession, permissions: list[dict] | None) -> str:
    """``None`` → superadmin; otherwise a user holding exactly ``permissions``."""
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


async def _dns_estate(db: AsyncSession) -> dict:
    """Group A with two BIND9 servers, group B with one; one query each."""
    ga = DNSServerGroup(name=f"ga-{_tag()}")
    gb = DNSServerGroup(name=f"gb-{_tag()}")
    db.add_all([ga, gb])
    await db.flush()
    a1 = DNSServer(group_id=ga.id, name=f"a1-{_tag()}", driver="bind9", host="192.0.2.1")
    a2 = DNSServer(group_id=ga.id, name=f"a2-{_tag()}", driver="bind9", host="192.0.2.2")
    b1 = DNSServer(group_id=gb.id, name=f"b1-{_tag()}", driver="bind9", host="192.0.2.3")
    db.add_all([a1, a2, b1])
    await db.flush()
    for i, (srv, qname) in enumerate(
        [(a1, "one.a.test"), (a2, "two.a.test"), (b1, "three.b.test")]
    ):
        db.add(
            DNSQueryLogEntry(
                server_id=srv.id,
                ts=_NOW - timedelta(minutes=10 - i),
                client_ip="198.51.100.5",
                qname=qname,
                qtype="A",
                raw=f"query: {qname} IN A",
            )
        )
    await db.commit()
    return {"ga": ga, "gb": gb, "a1": a1, "a2": a2, "b1": b1}


async def test_group_filter_merges_its_servers_newest_first(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    e = await _dns_estate(db_session)
    token = await _user(db_session, None)
    await db_session.commit()

    r = await client.post(
        "/api/v1/logs/dns-queries", json={"group_id": str(e["ga"].id)}, headers=_h(token)
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert [ev["qname"] for ev in body["events"]] == ["two.a.test", "one.a.test"]
    assert [ev["server_name"] for ev in body["events"]] == [e["a2"].name, e["a1"].name]
    assert {ev["server_id"] for ev in body["events"]} == {str(e["a1"].id), str(e["a2"].id)}
    assert set(body["server_ids"]) == {str(e["a1"].id), str(e["a2"].id)}
    assert body["server_id"] is None


async def test_no_filter_reads_every_server(client: AsyncClient, db_session: AsyncSession) -> None:
    e = await _dns_estate(db_session)
    token = await _user(db_session, None)
    await db_session.commit()

    r = await client.post("/api/v1/logs/dns-queries", json={}, headers=_h(token))
    assert r.status_code == 200, r.text
    assert [ev["qname"] for ev in r.json()["events"]] == [
        "three.b.test",
        "two.a.test",
        "one.a.test",
    ]
    # Single-server reads behave as before, and now name the server too.
    r = await client.post(
        "/api/v1/logs/dns-queries", json={"server_id": str(e["b1"].id)}, headers=_h(token)
    )
    assert [ev["server_name"] for ev in r.json()["events"]] == [e["b1"].name]


async def test_server_outside_requested_group_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    e = await _dns_estate(db_session)
    token = await _user(db_session, None)
    await db_session.commit()
    r = await client.post(
        "/api/v1/logs/dns-queries",
        json={"server_id": str(e["b1"].id), "group_id": str(e["ga"].id)},
        headers=_h(token),
    )
    assert r.status_code == 422, r.text


async def test_group_scoped_user_cannot_see_another_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    e = await _dns_estate(db_session)
    token = await _user(
        db_session,
        [{"action": "read", "resource_type": "server", "resource_id": str(e["ga"].id)}],
    )
    await db_session.commit()

    # "All" narrows to group A — group B's query never appears.
    r = await client.post("/api/v1/logs/dns-queries", json={}, headers=_h(token))
    assert r.status_code == 200, r.text
    assert {ev["qname"] for ev in r.json()["events"]} == {"one.a.test", "two.a.test"}

    # Its own group works.
    r = await client.post(
        "/api/v1/logs/dns-queries", json={"group_id": str(e["ga"].id)}, headers=_h(token)
    )
    assert r.status_code == 200, r.text
    assert len(r.json()["events"]) == 2

    # Another group, or one of its servers, is refused outright.
    r = await client.post(
        "/api/v1/logs/dns-queries", json={"group_id": str(e["gb"].id)}, headers=_h(token)
    )
    assert r.status_code == 403, r.text
    r = await client.post(
        "/api/v1/logs/dns-queries", json={"server_id": str(e["b1"].id)}, headers=_h(token)
    )
    assert r.status_code == 403, r.text

    # Analytics over "all" count only what the user may read.
    r = await client.post("/api/v1/logs/dns-queries/analytics", json={}, headers=_h(token))
    assert r.status_code == 200, r.text
    assert r.json()["total_queries"] == 2

    # And the picker lists only group A's servers.
    r = await client.get("/api/v1/logs/agent-sources", headers=_h(token))
    assert r.status_code == 200, r.text
    dns = {s["server_id"] for s in r.json() if s["server_kind"] == "dns"}
    assert dns == {str(e["a1"].id), str(e["a2"].id)}
    assert {s["group_name"] for s in r.json() if s["server_kind"] == "dns"} == {e["ga"].name}


async def test_server_scoped_grant_reads_only_that_server(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    e = await _dns_estate(db_session)
    token = await _user(
        db_session,
        [{"action": "read", "resource_type": "server", "resource_id": str(e["a1"].id)}],
    )
    await db_session.commit()
    r = await client.post(
        "/api/v1/logs/dns-queries", json={"group_id": str(e["ga"].id)}, headers=_h(token)
    )
    assert r.status_code == 200, r.text
    assert [ev["qname"] for ev in r.json()["events"]] == ["one.a.test"]


async def test_analytics_aggregate_across_a_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    e = await _dns_estate(db_session)
    token = await _user(db_session, None)
    await db_session.commit()
    r = await client.post(
        "/api/v1/logs/dns-queries/analytics",
        json={"group_id": str(e["ga"].id)},
        headers=_h(token),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_queries"] == 2
    assert {row["key"] for row in body["top_qnames"]} == {"one.a.test", "two.a.test"}
    assert body["top_clients"] == [{"key": "198.51.100.5", "count": 2}]


async def _dhcp_estate(db: AsyncSession) -> dict:
    ga = DHCPServerGroup(name=f"hga-{_tag()}")
    gb = DHCPServerGroup(name=f"hgb-{_tag()}")
    db.add_all([ga, gb])
    await db.flush()
    a1 = DHCPServer(server_group_id=ga.id, name=f"ka1-{_tag()}", driver="kea", host="192.0.2.11")
    a2 = DHCPServer(server_group_id=ga.id, name=f"ka2-{_tag()}", driver="kea", host="192.0.2.12")
    b1 = DHCPServer(server_group_id=gb.id, name=f"kb1-{_tag()}", driver="kea", host="192.0.2.13")
    db.add_all([a1, a2, b1])
    await db.flush()
    for i, srv in enumerate([a1, a2, b1]):
        db.add(
            DHCPLogEntry(
                server_id=srv.id,
                ts=_NOW - timedelta(minutes=10 - i),
                severity="INFO",
                code="DHCP4_LEASE_ALLOC",
                raw=f"line from {srv.name}",
            )
        )
    await db.commit()
    return {"ga": ga, "gb": gb, "a1": a1, "a2": a2, "b1": b1}


async def test_dhcp_activity_group_all_and_scope(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    e = await _dhcp_estate(db_session)
    admin = await _user(db_session, None)
    scoped = await _user(
        db_session,
        [{"action": "read", "resource_type": "server", "resource_id": str(e["ga"].id)}],
    )
    await db_session.commit()

    r = await client.post(
        "/api/v1/logs/dhcp-activity", json={"group_id": str(e["ga"].id)}, headers=_h(admin)
    )
    assert r.status_code == 200, r.text
    assert [ev["server_name"] for ev in r.json()["events"]] == [e["a2"].name, e["a1"].name]

    r = await client.post("/api/v1/logs/dhcp-activity", json={}, headers=_h(admin))
    assert len(r.json()["events"]) == 3

    r = await client.post("/api/v1/logs/dhcp-activity", json={}, headers=_h(scoped))
    assert r.status_code == 200, r.text
    assert {ev["server_id"] for ev in r.json()["events"]} == {
        str(e["a1"].id),
        str(e["a2"].id),
    }
    r = await client.post(
        "/api/v1/logs/dhcp-activity", json={"group_id": str(e["gb"].id)}, headers=_h(scoped)
    )
    assert r.status_code == 403, r.text


async def test_unscoped_grant_on_another_type_is_still_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Admitting scoped ``server`` grants must not admit unrelated grants."""
    await _dns_estate(db_session)
    token = await _user(db_session, [{"action": "read", "resource_type": "subnet"}])
    await db_session.commit()
    r = await client.post("/api/v1/logs/dns-queries", json={}, headers=_h(token))
    assert r.status_code == 403, r.text


async def test_find_dns_queries_tool_takes_a_group(db_session: AsyncSession) -> None:
    from app.models.auth import User as UserModel
    from app.services.ai.tools.dns import FindDNSQueriesArgs, find_dns_queries

    e = await _dns_estate(db_session)
    admin = UserModel(
        username=f"t-{_tag()}",
        email=f"{_tag()}@example.test",
        display_name="t",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    admin.groups = []
    db_session.add(admin)
    await db_session.flush()
    rows = await find_dns_queries(
        db_session, admin, FindDNSQueriesArgs(group_id=str(e["ga"].id), minutes=60)
    )
    assert {r["qname"] for r in rows} == {"one.a.test", "two.a.test"}
    assert {r["server_name"] for r in rows} == {e["a1"].name, e["a2"].name}
