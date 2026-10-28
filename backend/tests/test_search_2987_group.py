"""Search fixes #2987 / #2989 / #2990 / #2991."""

from __future__ import annotations

import ipaddress
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.search.schemas import shape_of

pytestmark = pytest.mark.asyncio


async def _admin(db: AsyncSession) -> dict[str, str]:
    tag = uuid.uuid4().hex[:8]
    u = User(
        username=f"a-{tag}",
        email=f"{tag}@t.io",
        display_name="a",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _net(db: AsyncSession, block: str, subnet: str) -> Subnet:
    sp = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(sp)
    await db.flush()
    b = IPBlock(space_id=sp.id, network=block, name="blk", description="")
    db.add(b)
    await db.flush()
    sn = Subnet(
        space_id=sp.id, block_id=b.id, network=subnet, name="sn", description="", status="active"
    )
    db.add(sn)
    await db.flush()
    return sn


async def _ip(db: AsyncSession, sn: Subnet, addr: str, host: str = "", mac: str | None = None):
    row = IPAddress(
        subnet_id=sn.id,
        address=ipaddress.ip_address(addr),
        status="allocated",
        hostname=host,
        description="",
        mac_address=mac,
    )
    db.add(row)
    await db.flush()
    return row


async def _search(client: AsyncClient, h: dict, q: str, **params):
    r = await client.get("/api/v1/search", params={"q": q, **params}, headers=h)
    assert r.status_code == 200
    return r.json()


# ── #2989 ────────────────────────────────────────────────────────────────


async def test_shape_cidr_normalised():
    assert shape_of("10.0.96.5/24").cidr == "10.0.96.0/24"
    assert shape_of("fd33:233:0:400::5/64").cidr == "fd33:233:0:400::/64"
    assert shape_of("10.0.96.0/24").cidr == "10.0.96.0/24"
    assert shape_of("web").cidr == ""


@pytest.mark.parametrize(
    "block,subnet,q",
    [
        ("10.0.0.0/16", "10.0.96.0/24", "10.0.96.0/24"),  # control
        ("10.0.0.0/16", "10.0.96.0/24", "10.0.96.5/24"),
        ("fd33:233::/32", "fd33:233:0:400::/64", "fd33:233:0:400::5/64"),
    ],
)
async def test_cidr_with_host_bits_finds_subnet(client, db_session, block, subnet, q):
    h = await _admin(db_session)
    sn = await _net(db_session, block, subnet)
    body = await _search(client, h, q)
    assert str(sn.id) in {r["id"] for r in body["results"] if r["type"] == "subnet"}


# ── #2990 ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "block,subnet,q",
    [
        ("10.233.96.0/19", "10.233.98.10/32", "10.233.98.10"),
        ("fd33:233::/32", "fd33:233:0:401::a/128", "fd33:233:0:401::a"),
        ("10.0.0.0/16", "10.0.5.0/24", "10.0.5.7"),  # control: containment still works
    ],
)
async def test_single_address_subnet_found_by_its_address(client, db_session, block, subnet, q):
    h = await _admin(db_session)
    sn = await _net(db_session, block, subnet)
    body = await _search(client, h, q)
    assert str(sn.id) in {r["id"] for r in body["results"] if r["type"] == "subnet"}


# ── #2987 ────────────────────────────────────────────────────────────────


async def test_total_does_not_follow_limit(client, db_session):
    h = await _admin(db_session)
    sn = await _net(db_session, "10.0.0.0/16", "10.0.5.0/24")
    for i in range(1, 26):
        await _ip(db_session, sn, f"10.0.5.{i}", host=f"cnt2987-{i:02d}")
    small = await _search(client, h, "cnt2987", limit=20)
    big = await _search(client, h, "cnt2987", limit=100)
    assert small["total"] == big["total"] == 25
    assert len(small["results"]) == 20
    assert small["total_capped"] is False


async def test_total_capped_flag(client, db_session):
    h = await _admin(db_session)
    sn = await _net(db_session, "10.0.0.0/8", "10.0.0.0/22")
    for i in range(1, 106):
        await _ip(db_session, sn, f"10.0.{i // 250}.{i % 250 + 1}", host=f"cap2987-{i:03d}")
    body = await _search(client, h, "cap2987", limit=20)
    assert body["total_capped"] is True
    assert body["total"] >= 100


# ── #2991 ────────────────────────────────────────────────────────────────


async def test_ipam_address_search_escapes_wildcards(client, db_session):
    h = await _admin(db_session)
    sn = await _net(db_session, "10.0.0.0/16", "10.0.5.0/24")
    await _ip(db_session, sn, "10.0.5.1", host="stem-db-01")
    await _ip(db_session, sn, "10.0.5.2", host="stem-dbx01")
    await _ip(db_session, sn, "10.0.5.3", host="stem-db_01")
    for q, want in (
        ("stem-db_01", {"stem-db_01"}),
        ("stem-db%01", set()),
        ("stem-db-01", {"stem-db-01"}),
    ):
        for url in ("/api/v1/ipam/addresses/search", f"/api/v1/ipam/subnets/{sn.id}/addresses"):
            r = await client.get(url, params={"q": q}, headers=h)
            assert r.status_code == 200
            rows = r.json()["items"] if isinstance(r.json(), dict) else r.json()
            assert {x["hostname"] for x in rows} == want, (url, q)
    r = await client.get("/api/v1/ipam/addresses/search/ids", params={"q": "stem-db_01"}, headers=h)
    assert r.status_code == 200


async def test_ipam_address_search_hostname_filter_escaped(client, db_session):
    h = await _admin(db_session)
    sn = await _net(db_session, "10.0.0.0/16", "10.0.5.0/24")
    await _ip(db_session, sn, "10.0.5.1", host="dbx01")
    r = await client.get(
        f"/api/v1/ipam/subnets/{sn.id}/addresses", params={"hostname": "db_01"}, headers=h
    )
    assert r.json() == []


@pytest.mark.parametrize(
    "q", ["02:16:80:00:00:20", "02-16-80-00-00-20", "021680000020", "0216.8000.0020", "02-16-80"]
)
async def test_ipam_address_search_mac_any_style(client, db_session, q):
    h = await _admin(db_session)
    sn = await _net(db_session, "10.0.0.0/16", "10.0.5.0/24")
    await _ip(db_session, sn, "10.0.5.9", host="macrow", mac="02:16:80:00:00:20")
    await _ip(db_session, sn, "10.0.5.10", host="other", mac="aa:bb:cc:dd:ee:ff")
    r = await client.get("/api/v1/ipam/addresses/search", params={"q": q}, headers=h)
    assert r.status_code == 200
    body = r.json()
    rows = body["items"]
    assert {x["hostname"] for x in rows} == {"macrow"}


async def test_ipam_address_search_ip_not_taken_for_mac(client, db_session):
    h = await _admin(db_session)
    sn = await _net(db_session, "10.0.0.0/16", "10.0.5.0/24")
    await _ip(db_session, sn, "10.0.5.9", host="a", mac="00:00:10:00:10:00")
    r = await client.get("/api/v1/ipam/addresses/search", params={"q": "10.0.5.9"}, headers=h)
    body = r.json()
    rows = body["items"]
    assert {x["hostname"] for x in rows} == {"a"}
