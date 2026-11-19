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


async def test_dns_group_grant_does_not_reach_dhcp_or_windows_routes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A grant scoped to a DNS group reads that group's DNS logs only: no
    DHCP server, and the WinRM routes still need the grant unscoped."""
    e = await _dns_estate(db_session)
    h = await _dhcp_estate(db_session)
    token = await _user(
        db_session,
        [{"action": "read", "resource_type": "server", "resource_id": str(e["ga"].id)}],
    )
    await db_session.commit()

    r = await client.post("/api/v1/logs/dhcp-activity", json={}, headers=_h(token))
    assert r.status_code == 200, r.text
    assert r.json()["events"] == [] and r.json()["server_ids"] == []
    r = await client.post(
        "/api/v1/logs/dhcp-activity", json={"server_id": str(h["a1"].id)}, headers=_h(token)
    )
    assert r.status_code == 403, r.text
    r = await client.get("/api/v1/logs/agent-sources", headers=_h(token))
    assert all(s["server_kind"] == "dns" for s in r.json())

    # WinRM surfaces keep the unscoped gate.
    r = await client.get("/api/v1/logs/sources", headers=_h(token))
    assert r.status_code == 403, r.text
    r = await client.post(
        "/api/v1/logs/query",
        json={"server_kind": "dns", "server_id": str(e["a1"].id), "log_name": "DNS Server"},
        headers=_h(token),
    )
    assert r.status_code == 403, r.text


async def test_server_bound_api_token_is_narrowed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An API token bound to one server reads that server even when its
    owner may read everything, and cannot name another server's id."""
    from app.core.security import generate_api_token
    from app.models.auth import APIToken

    e = await _dns_estate(db_session)
    owner = User(
        username=f"o-{_tag()}",
        email=f"{_tag()}@example.test",
        display_name="o",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(owner)
    await db_session.flush()
    raw, _prefix, token_hash = generate_api_token()
    db_session.add(
        APIToken(
            name=f"t-{_tag()}",
            token_hash=token_hash,
            prefix=raw[:10],
            scope="user",
            scopes=[],
            resource_grants=[
                {"action": "read", "resource_type": "server", "resource_id": str(e["a1"].id)}
            ],
            user_id=owner.id,
            created_by_user_id=owner.id,
            is_active=True,
        )
    )
    await db_session.commit()

    r = await client.post("/api/v1/logs/dns-queries", json={}, headers=_h(raw))
    assert r.status_code == 200, r.text
    assert [ev["qname"] for ev in r.json()["events"]] == ["one.a.test"]
    r = await client.post(
        "/api/v1/logs/dns-queries", json={"server_id": str(e["b1"].id)}, headers=_h(raw)
    )
    assert r.status_code == 403, r.text


async def test_scoped_time_bound_grant_admits_its_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A time-bound grant (#65) scoped to a group works like a role grant."""
    from app.models.time_bound_grant import TimeBoundGrant

    e = await _dns_estate(db_session)
    u = User(
        username=f"tb-{_tag()}",
        email=f"{_tag()}@example.test",
        display_name="tb",
        hashed_password=hash_password("x"),
    )
    db_session.add(u)
    await db_session.flush()
    grp = Group(name=f"tbg-{_tag()}", description="")
    grp.users = [u]
    db_session.add(grp)
    await db_session.flush()
    db_session.add(
        TimeBoundGrant(
            group_id=grp.id,
            action="read",
            resource_type="server",
            resource_id=str(e["ga"].id),
            expires_at=_NOW + timedelta(hours=2),
            reason="2120",
            granted_by_user_id=u.id,
        )
    )
    await db_session.commit()
    token = create_access_token(str(u.id))

    r = await client.post("/api/v1/logs/dns-queries", json={}, headers=_h(token))
    assert r.status_code == 200, r.text
    assert {ev["qname"] for ev in r.json()["events"]} == {"one.a.test", "two.a.test"}


async def test_search_box_matches_like_metacharacters_literally(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _dns_estate(db_session)
    token = await _user(db_session, None)
    await db_session.commit()
    r = await client.post("/api/v1/logs/dns-queries", json={"q": "%"}, headers=_h(token))
    assert r.status_code == 200, r.text
    assert r.json()["events"] == []
    r = await client.post("/api/v1/logs/dns-queries", json={"q": "one_a"}, headers=_h(token))
    assert r.json()["events"] == []
    r = await client.post("/api/v1/logs/dns-queries", json={"q": "one.a"}, headers=_h(token))
    assert [ev["qname"] for ev in r.json()["events"]] == ["one.a.test"]
