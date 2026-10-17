"""An IP's alias obeys the CNAME-and-other-data rule (#2080).

RFC 1034 section 3.6.2 / RFC 2181 section 10.1: a name holding a CNAME holds
nothing else. The DNS record API has refused such a pair since #1381, but the
IPAM alias path (allocate, next-IP, ``POST /addresses/{id}/aliases``) wrote
the alias without asking, and BIND then refused the whole zone. The aliases
now go through the same ``find_cname_conflict`` check, in both directions,
before anything is written: 409 for a clash, 422 for a CNAME at the apex.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSView, DNSZone
from app.models.ipam import IPBlock, IPSpace


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u2080-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _setup(
    client: AsyncClient,
    db: AsyncSession,
    block_cidr: str = "10.98.0.0/16",
    subnet_cidr: str = "10.98.5.0/24",
) -> tuple[dict[str, str], str, DNSZone]:
    headers = await _headers(db)
    grp = DNSServerGroup(name=f"g2080-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host="10.9.9.9",
            name=f"ns-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    zone = DNSZone(
        group_id=grp.id,
        name=f"c{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(zone)
    space = IPSpace(name=f"sp2080-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=block_cidr, name="b")
    db.add(block)
    await db.flush()
    await db.commit()
    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": subnet_cidr,
            "dns_group_id": str(grp.id),
            "dns_zone_id": str(zone.id),
            "skip_reverse_zone": True,
        },
    )
    assert resp.status_code == 201, resp.text
    return headers, str(resp.json()["id"]), zone


async def _records(db: AsyncSession, zone_id: uuid.UUID) -> list[tuple[str, str]]:
    rows = (
        await db.execute(
            select(DNSRecord.name, DNSRecord.record_type)
            .where(DNSRecord.zone_id == zone_id)
            .execution_options(populate_existing=True)
        )
    ).all()
    return sorted((str(n), str(t)) for n, t in rows)


async def _alloc(
    client: AsyncClient, headers: dict[str, str], sid: str, addr: str, host: str, **extra: object
):
    return await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=headers,
        json={"address": addr, "hostname": host, **extra},
    )


@pytest.mark.asyncio
async def test_cname_alias_onto_a_name_with_data_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    first = await _alloc(client, headers, sid, "10.98.5.10", "web")
    assert first.status_code == 201, first.text

    # allocate: the alias names an existing host (an A)
    resp = await _alloc(
        client,
        headers,
        sid,
        "10.98.5.11",
        "other",
        aliases=[{"name": "web", "record_type": "CNAME"}],
    )
    assert resp.status_code == 409, resp.text
    assert "CNAME" in resp.text and "web" in resp.text
    # nothing of the refused request was written, the IP included
    assert await _records(db_session, zone.id) == [("web", "A")]

    # next-IP
    nxt = await client.post(
        f"/api/v1/ipam/subnets/{sid}/next",
        headers=headers,
        json={"hostname": "other", "aliases": [{"name": "WEB", "record_type": "CNAME"}]},
    )
    assert nxt.status_code == 409, nxt.text

    # add-alias on an existing address
    ok = await _alloc(client, headers, sid, "10.98.5.12", "other")
    assert ok.status_code == 201, ok.text
    add = await client.post(
        f"/api/v1/ipam/addresses/{ok.json()['id']}/aliases",
        headers=headers,
        json={"name": "web", "record_type": "CNAME"},
    )
    assert add.status_code == 409, add.text
    assert await _records(db_session, zone.id) == [("other", "A"), ("web", "A")]


@pytest.mark.asyncio
async def test_data_alias_onto_a_cname_is_refused_and_apex_cname_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    host = await _alloc(
        client,
        headers,
        sid,
        "10.98.5.20",
        "host",
        aliases=[{"name": "www", "record_type": "CNAME"}],
    )
    assert host.status_code == 201, host.text

    # A alias onto the CNAME, in both directions of the same rule
    other = await _alloc(client, headers, sid, "10.98.5.21", "h2")
    assert other.status_code == 201, other.text
    add = await client.post(
        f"/api/v1/ipam/addresses/{other.json()['id']}/aliases",
        headers=headers,
        json={"name": "www", "record_type": "A"},
    )
    assert add.status_code == 409, add.text
    assert "can hold no A record" in add.text

    # a second CNAME at the same name
    again = await client.post(
        f"/api/v1/ipam/addresses/{other.json()['id']}/aliases",
        headers=headers,
        json={"name": "www", "record_type": "CNAME"},
    )
    assert again.status_code == 409, again.text

    # the apex never takes a CNAME
    apex = await client.post(
        f"/api/v1/ipam/addresses/{other.json()['id']}/aliases",
        headers=headers,
        json={"name": "@", "record_type": "CNAME"},
    )
    assert apex.status_code == 422, apex.text
    assert "apex" in apex.text

    assert await _records(db_session, zone.id) == [("h2", "A"), ("host", "A"), ("www", "CNAME")]


@pytest.mark.asyncio
async def test_a_request_cannot_clash_with_itself(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The host name and sibling aliases are not in the database yet."""
    headers, sid, zone = await _setup(client, db_session)
    # alias CNAME named like the IP's own host record
    r1 = await _alloc(
        client,
        headers,
        sid,
        "10.98.5.30",
        "same",
        aliases=[{"name": "same", "record_type": "CNAME"}],
    )
    assert r1.status_code == 409, r1.text
    # a CNAME and an A alias at one name in one request
    r2 = await _alloc(
        client,
        headers,
        sid,
        "10.98.5.31",
        "h",
        aliases=[
            {"name": "x", "record_type": "CNAME"},
            {"name": "x", "record_type": "A"},
        ],
    )
    assert r2.status_code == 409, r2.text
    assert await _records(db_session, zone.id) == []

    # no clash: distinct names, and an A alias beside the host's own A
    r3 = await _alloc(
        client,
        headers,
        sid,
        "10.98.5.32",
        "h3",
        aliases=[
            {"name": "c1", "record_type": "CNAME"},
            {"name": "a1", "record_type": "A"},
        ],
    )
    assert r3.status_code == 201, r3.text
    assert await _records(db_session, zone.id) == [
        ("a1", "A"),
        ("c1", "CNAME"),
        ("h3", "A"),
    ]


@pytest.mark.asyncio
async def test_a_view_scoped_row_blocks_a_cname_alias(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An alias has no view, so it renders into every view: a row scoped to any
    one view at the same name is beside it there (split horizon)."""
    headers, sid, zone = await _setup(client, db_session)
    view = DNSView(group_id=zone.group_id, name=f"v{uuid.uuid4().hex[:6]}")
    db_session.add(view)
    await db_session.flush()
    db_session.add(
        DNSRecord(
            zone_id=zone.id,
            view_id=view.id,
            name="intra",
            fqdn=f"intra.{zone.name.rstrip('.')}",
            record_type="TXT",
            value='"x"',
        )
    )
    await db_session.commit()
    resp = await _alloc(
        client,
        headers,
        sid,
        "10.98.5.40",
        "h40",
        aliases=[{"name": "intra", "record_type": "CNAME"}],
    )
    assert resp.status_code == 409, resp.text
    assert "TXT" in resp.text
    assert await _records(db_session, zone.id) == [("intra", "TXT")]


@pytest.mark.asyncio
async def test_ipv6_address_alias_is_checked_as_aaaa(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An A alias on an IPv6 address is written as an AAAA, and the refusal
    says so; the request's own AAAA host record is named in a self-clash."""
    headers, sid, zone = await _setup(
        client, db_session, block_cidr="fd98::/48", subnet_cidr="fd98:0:0:5::/64"
    )
    base = await _alloc(
        client,
        headers,
        sid,
        "fd98:0:0:5::10",
        "v6host",
        aliases=[{"name": "svc", "record_type": "CNAME"}],
    )
    assert base.status_code == 201, base.text
    add = await client.post(
        f"/api/v1/ipam/addresses/{base.json()['id']}/aliases",
        headers=headers,
        json={"name": "svc", "record_type": "A"},
    )
    assert add.status_code == 409, add.text
    assert "can hold no AAAA record" in add.text

    self_clash = await _alloc(
        client,
        headers,
        sid,
        "fd98:0:0:5::11",
        "loop",
        aliases=[{"name": "loop", "record_type": "CNAME"}],
    )
    assert self_clash.status_code == 409, self_clash.text
    assert "own AAAA record" in self_clash.text
    assert await _records(db_session, zone.id) == [("svc", "CNAME"), ("v6host", "AAAA")]
