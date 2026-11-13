"""RRL is seeded on for a group made public-facing, and the extra rate-limit
knobs round-trip (#3577)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSServerOptions
from app.services.dns.agent_config import build_config_bundle


async def _headers(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"a-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@x.test",
        display_name="a",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _rrl(db: AsyncSession, gid: uuid.UUID) -> bool:
    db.expire_all()
    row = (
        await db.execute(select(DNSServerOptions).where(DNSServerOptions.group_id == gid))
    ).scalar_one()
    return row.rrl_enabled


@pytest.mark.asyncio
async def test_new_public_facing_group_has_rrl_on(client: AsyncClient, db_session: AsyncSession):
    h = await _headers(db_session)
    r = await client.post(
        "/api/v1/dns/groups", json={"name": "pub-3577", "is_public_facing": True}, headers=h
    )
    assert r.status_code == 201, r.text
    gid = uuid.UUID(r.json()["id"])
    assert await _rrl(db_session, gid) is True
    o = await client.get(f"/api/v1/dns/groups/{gid}/options", headers=h)
    assert o.json()["rrl_enabled"] is True


@pytest.mark.asyncio
async def test_new_internal_group_keeps_rrl_off(client: AsyncClient, db_session: AsyncSession):
    h = await _headers(db_session)
    r = await client.post("/api/v1/dns/groups", json={"name": "int-3577"}, headers=h)
    assert await _rrl(db_session, uuid.UUID(r.json()["id"])) is False


@pytest.mark.asyncio
async def test_flipping_existing_group_public_turns_rrl_on(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    g = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(g)
    await db_session.flush()
    db_session.add(DNSServerOptions(group_id=g.id))
    await db_session.commit()
    gid = g.id
    assert await _rrl(db_session, gid) is False

    # An unrelated edit does not touch RRL.
    r = await client.put(f"/api/v1/dns/groups/{gid}", json={"description": "x"}, headers=h)
    assert r.status_code == 200, r.text
    assert await _rrl(db_session, gid) is False

    r = await client.put(f"/api/v1/dns/groups/{gid}", json={"is_public_facing": True}, headers=h)
    assert r.status_code == 200, r.text
    assert await _rrl(db_session, gid) is True

    # Operator can turn it back off; re-saving public-facing does not re-enable.
    r = await client.put(
        f"/api/v1/dns/groups/{gid}/options", json={"rrl_enabled": False}, headers=h
    )
    assert r.status_code == 200, r.text
    r = await client.put(f"/api/v1/dns/groups/{gid}", json={"is_public_facing": True}, headers=h)
    assert await _rrl(db_session, gid) is False


@pytest.mark.asyncio
async def test_extra_knobs_round_trip_into_agent_bundle_opts(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    g = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(g)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{g.id}/options"
    body = {
        "rrl_enabled": True,
        "rrl_nxdomains_per_second": 5,
        "rrl_errors_per_second": 6,
        "rrl_ipv4_prefix_length": 24,
        "rrl_ipv6_prefix_length": 56,
        "rrl_max_table_size": 20000,
    }
    r = await client.put(url, json=body, headers=h)
    assert r.status_code == 200, r.text
    for k, v in body.items():
        assert r.json()[k] == v
    # null clears.
    r = await client.put(url, json={"rrl_nxdomains_per_second": None}, headers=h)
    assert r.json()["rrl_nxdomains_per_second"] is None
    assert r.json()["rrl_errors_per_second"] == 6
    # Range check.
    r = await client.put(url, json={"rrl_ipv4_prefix_length": 40}, headers=h)
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_extra_knobs_refused_on_powerdns_and_technitium(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    for driver in ("powerdns", "technitium"):
        g = DNSServerGroup(name=f"g-{driver}-{uuid.uuid4().hex[:6]}")
        db_session.add(g)
        await db_session.flush()
        db_session.add(
            DNSServer(group_id=g.id, name=f"s-{driver}", driver=driver, host="h", port=53)
        )
        await db_session.commit()
        url = f"/api/v1/dns/groups/{g.id}/options"
        r = await client.put(url, json={"rrl_nxdomains_per_second": 5}, headers=h)
        assert r.status_code == 422, (driver, r.text)
        assert "rrl_nxdomains_per_second" in r.text
        # Unset / default re-save passes.
        r = await client.put(url, json={"rrl_window": 20}, headers=h)
        assert r.status_code == 200, (driver, r.text)


@pytest.mark.asyncio
async def test_extra_knobs_flow_into_the_bundle_and_shift_the_etag(db_session: AsyncSession):
    g = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(g)
    await db_session.flush()
    opts = DNSServerOptions(group_id=g.id, rrl_enabled=True)
    srv = DNSServer(group_id=g.id, name="ns1", driver="bind9", host="10.0.0.1", port=53)
    db_session.add_all([opts, srv])
    await db_session.commit()

    before = await build_config_bundle(db_session, srv)
    assert before["options"]["rrl_nxdomains_per_second"] is None
    opts.rrl_nxdomains_per_second = 7
    opts.rrl_ipv4_prefix_length = 24
    await db_session.commit()
    after = await build_config_bundle(db_session, srv)
    assert after["options"]["rrl_nxdomains_per_second"] == 7
    assert after["options"]["rrl_ipv4_prefix_length"] == 24
    assert after["etag"] != before["etag"]
