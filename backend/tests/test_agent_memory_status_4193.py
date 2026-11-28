"""Agents report their actual memory use on the heartbeat (#4193).

The DNS and DHCP agents send an optional ``memory`` block (container used /
peak / limit from the cgroup, daemon and agent RSS). The control plane keeps
the latest on the server row, folds a sample into the metric-sample bucket for
a short history, and shows both beside the blocklist memory estimate.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.models.dns import DNSServer, DNSServerGroup
from app.models.metrics import DHCPMetricSample, DNSMetricSample
from app.services.agents.memory_status import MEMORY_STALE_AFTER, fresh_memory_status
from app.services.ai.tools.dhcp import ListDHCPServersArgs, list_dhcp_servers
from app.services.dns.memory_estimate import group_memory_estimate

MIB = 1 << 20
BLOCK = {
    "used_bytes": 700 * MIB,
    "peak_bytes": 900 * MIB,
    "limit_bytes": 1024 * MIB,
    "daemon_rss_bytes": 600 * MIB,
    "agent_rss_bytes": 80 * MIB,
}


async def _dns(db: AsyncSession) -> DNSServer:
    group = DNSServerGroup(name=f"m-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    srv = DNSServer(
        group_id=group.id, name=f"ns-{uuid.uuid4().hex[:6]}", driver="bind9", host="10.0.0.53"
    )
    db.add(srv)
    await db.commit()
    return srv


async def _dhcp(db: AsyncSession) -> DHCPServer:
    group = DHCPServerGroup(name=f"m-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    srv = DHCPServer(
        name=f"kea-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="127.0.0.1",
        port=67,
        status="active",
        server_group_id=group.id,
    )
    db.add(srv)
    await db.commit()
    return srv


async def _post(client: AsyncClient, kind: str, server: object, path: str, body: dict):
    from app.main import app

    if kind == "dhcp":
        from app.api.v1.dhcp.agents import _auth_agent
    else:
        from app.api.v1.dns.agents import _auth_agent  # type: ignore[no-redef]
    far = int((datetime.now(UTC) + timedelta(days=30)).timestamp())
    app.dependency_overrides[_auth_agent] = lambda: (server, {"exp": far})
    try:
        return await client.post(f"/api/v1/{kind}/agents/{path}", json=body)
    finally:
        app.dependency_overrides.pop(_auth_agent, None)


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"mem-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="memory",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _samples(db: AsyncSession, model: type, sid: uuid.UUID) -> list:
    stmt = select(model).where(model.server_id == sid).execution_options(populate_existing=True)
    return list((await db.execute(stmt)).scalars())


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["dns", "dhcp"])
async def test_heartbeat_stores_the_report_and_a_sample(
    kind: str, client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await (_dns if kind == "dns" else _dhcp)(db_session)
    model = DNSMetricSample if kind == "dns" else DHCPMetricSample
    sid = srv.id

    # The two heartbeats below must land in the same one-minute bucket. Near
    # the top of a minute they can straddle it and write two samples, so start
    # clear of the edge.
    second = datetime.now(UTC).second
    if second >= 50:
        await asyncio.sleep(61 - second)

    r = await _post(client, kind, srv, "heartbeat", {"memory": BLOCK})
    assert r.status_code == 200, r.text
    row = await db_session.get(type(srv), sid, populate_existing=True)
    assert row is not None and row.memory_status is not None
    assert row.memory_status["used_bytes"] == 700 * MIB
    assert row.memory_status["daemon_rss_bytes"] == 600 * MIB
    assert row.memory_status["reported_at"]

    (sample,) = await _samples(db_session, model, sid)
    assert sample.mem_used_bytes == 700 * MIB
    assert sample.mem_peak_bytes == 900 * MIB
    assert sample.mem_daemon_rss_bytes == 600 * MIB
    assert sample.mem_agent_rss_bytes == 80 * MIB

    # A second heartbeat in the same minute updates the bucket, keeping the peak.
    lower = {**BLOCK, "used_bytes": 650 * MIB, "peak_bytes": 700 * MIB}
    assert (await _post(client, kind, srv, "heartbeat", {"memory": lower})).status_code == 200
    (sample,) = await _samples(db_session, model, sid)
    assert sample.mem_used_bytes == 650 * MIB
    assert sample.mem_peak_bytes == 900 * MIB


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["dns", "dhcp"])
async def test_bad_block_leaves_the_report_alone_and_an_older_agent_clears_it(
    kind: str, client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await (_dns if kind == "dns" else _dhcp)(db_session)
    sid = srv.id
    assert (await _post(client, kind, srv, "heartbeat", {})).status_code == 200
    row = await db_session.get(type(srv), sid, populate_existing=True)
    assert row is not None and row.memory_status is None  # unknown, not zero

    assert (await _post(client, kind, srv, "heartbeat", {"memory": BLOCK})).status_code == 200
    # Malformed (negative) must not 422 the heartbeat or overwrite.
    r = await _post(client, kind, srv, "heartbeat", {"memory": {"used_bytes": -5}})
    assert r.status_code == 200, r.text
    row = await db_session.get(type(srv), sid, populate_existing=True)
    assert row is not None and row.memory_status["used_bytes"] == 700 * MIB

    # An older agent (no block) replaces this build's agent: the stored figures
    # are cleared, the history sample stays.
    assert (await _post(client, kind, srv, "heartbeat", {})).status_code == 200
    row = await db_session.get(type(srv), sid, populate_existing=True)
    assert row is not None and row.memory_status is None
    model = DNSMetricSample if kind == "dns" else DHCPMetricSample
    assert len(await _samples(db_session, model, sid)) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["dns", "dhcp"])
async def test_a_cleared_or_stale_report_reads_as_not_reported_everywhere(
    kind: str, client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await (_dns if kind == "dns" else _dhcp)(db_session)
    sid = srv.id
    gid = srv.group_id if kind == "dns" else None
    headers = await _admin(db_session)

    async def api_value() -> dict | None:
        if kind == "dns":
            r = await client.get(f"/api/v1/dns/groups/{gid}/servers", headers=headers)
            return next(s for s in r.json() if s["id"] == str(sid))["memory_status"]
        r = await client.get(f"/api/v1/dhcp/servers/{sid}", headers=headers)
        return r.json()["memory_status"]

    async def copilot_value() -> dict | None:
        user = User(username="cp", email="cp@example.com", hashed_password="x", is_superadmin=True)
        if kind == "dhcp":
            rows = await list_dhcp_servers(db_session, user, ListDHCPServersArgs())
            return next(r for r in rows if r["id"] == str(sid))["memory"]
        from app.services.ai.tools.dns import FindDnsServersArgs, find_dns_servers

        rows = await find_dns_servers(db_session, user, FindDnsServersArgs())
        return next(r for r in rows if r["id"] == str(sid))["memory"]

    # Reported, then an older agent heartbeats without the block.
    assert (await _post(client, kind, srv, "heartbeat", {"memory": BLOCK})).status_code == 200
    await db_session.refresh(srv)
    assert await api_value() is not None
    assert (await _post(client, kind, srv, "heartbeat", {})).status_code == 200
    await db_session.refresh(srv)
    assert await api_value() is None
    assert await copilot_value() is None

    # A report nothing has refreshed for longer than the stale threshold.
    assert (await _post(client, kind, srv, "heartbeat", {"memory": BLOCK})).status_code == 200
    row = await db_session.get(type(srv), sid, populate_existing=True)
    assert row is not None
    old = datetime.now(UTC) - MEMORY_STALE_AFTER - timedelta(seconds=5)
    row.memory_status = {**row.memory_status, "reported_at": old.isoformat()}
    await db_session.commit()
    await db_session.refresh(srv)
    assert await api_value() is None
    assert await copilot_value() is None
    if kind == "dns":
        est = await group_memory_estimate(db_session, gid)
        assert est is not None and est.servers[0].daemon_rss_bytes is None


def test_fresh_memory_status_bounds() -> None:
    now = datetime.now(UTC)
    ok = {"used_bytes": 1, "reported_at": (now - timedelta(seconds=30)).isoformat()}
    assert fresh_memory_status(ok, now) == ok
    near = {"used_bytes": 1, "reported_at": (now - timedelta(seconds=100)).isoformat()}
    assert fresh_memory_status(near, now) == near  # still inside 120 s
    old = {"used_bytes": 1, "reported_at": (now - MEMORY_STALE_AFTER * 2).isoformat()}
    assert fresh_memory_status(old, now) is None
    assert fresh_memory_status({"used_bytes": 1}, now) is None  # undated
    assert fresh_memory_status({"reported_at": "garbage"}, now) is None
    assert fresh_memory_status(None, now) is None


@pytest.mark.asyncio
async def test_a_metric_push_in_the_same_bucket_keeps_the_memory_columns(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await _dns(db_session)
    sid = srv.id
    assert (await _post(client, "dns", srv, "heartbeat", {"memory": BLOCK})).status_code == 200
    (sample,) = await _samples(db_session, DNSMetricSample, sid)
    bucket = sample.bucket_at
    r = await _post(
        client,
        "dns",
        srv,
        "metrics",
        {"bucket_at": bucket.isoformat(), "queries_total": 5, "noerror": 5},
    )
    assert r.status_code == 200, r.text
    (sample,) = await _samples(db_session, DNSMetricSample, sid)
    assert sample.queries_total == 5
    assert sample.mem_used_bytes == 700 * MIB


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["dns", "dhcp"])
async def test_read_endpoints_expose_the_report_and_history(
    kind: str, client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await (_dns if kind == "dns" else _dhcp)(db_session)
    sid = srv.id
    gid = srv.group_id if kind == "dns" else None
    headers = await _admin(db_session)
    assert (await _post(client, kind, srv, "heartbeat", {"memory": BLOCK})).status_code == 200
    await db_session.refresh(srv)  # the heartbeat's onupdate expired modified_at

    if kind == "dns":
        r = await client.get(f"/api/v1/dns/groups/{gid}/servers", headers=headers)
        listed = next(s for s in r.json() if s["id"] == str(sid))
    else:
        r = await client.get(f"/api/v1/dhcp/servers/{sid}", headers=headers)
        listed = r.json()
    assert r.status_code == 200, r.text
    assert listed["memory_status"]["limit_bytes"] == 1024 * MIB
    assert listed["memory_status"]["agent_rss_bytes"] == 80 * MIB

    r = await client.get(f"/api/v1/{kind}/servers/{sid}/memory-history", headers=headers)
    assert r.status_code == 200, r.text
    pts = r.json()["points"]
    assert len(pts) == 1 and pts[0]["used_bytes"] == 700 * MIB and pts[0]["peak_bytes"]
    r = await client.get(f"/api/v1/{kind}/servers/{uuid.uuid4()}/memory-history", headers=headers)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_unreported_server_reads_as_null(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await _dns(db_session)
    gid, sid = srv.group_id, srv.id
    headers = await _admin(db_session)
    r = await client.get(f"/api/v1/dns/groups/{gid}/servers", headers=headers)
    assert r.json()[0]["memory_status"] is None
    r = await client.get(f"/api/v1/dns/servers/{sid}/memory-history", headers=headers)
    assert r.json()["points"] == []


@pytest.mark.asyncio
async def test_the_group_estimate_carries_each_servers_actual_memory(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await _dns(db_session)
    srv_name = srv.name
    other = DNSServer(group_id=srv.group_id, name="zz-old", driver="bind9", host="10.0.0.54")
    db_session.add(other)
    await db_session.commit()
    gid = srv.group_id
    assert (await _post(client, "dns", srv, "heartbeat", {"memory": BLOCK})).status_code == 200

    est = await group_memory_estimate(db_session, gid)
    assert est is not None
    by_name = {s.name: s for s in est.servers}
    assert by_name[srv_name].daemon_rss_bytes == 600 * MIB
    assert by_name[srv_name].used_bytes == 700 * MIB
    assert by_name["zz-old"].daemon_rss_bytes is None  # older agent: unknown

    headers = await _admin(db_session)
    r = await client.get(f"/api/v1/dns/groups/{gid}/memory-estimate", headers=headers)
    body = {s["name"]: s for s in r.json()["servers"]}
    assert body[srv_name]["daemon_rss_bytes"] == 600 * MIB
    assert body["zz-old"]["daemon_rss_bytes"] is None


@pytest.mark.asyncio
async def test_the_copilot_server_tool_returns_the_report(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await _dhcp(db_session)
    sid = srv.id
    assert (await _post(client, "dhcp", srv, "heartbeat", {"memory": BLOCK})).status_code == 200
    user = User(
        username=f"cp-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="cp",
        hashed_password="x",
        is_superadmin=True,
    )
    rows = await list_dhcp_servers(db_session, user, ListDHCPServersArgs())
    mine = next(r for r in rows if r["id"] == str(sid))
    assert mine["memory"]["daemon_rss_bytes"] == 600 * MIB
