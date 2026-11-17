"""Server-side pagination for DNS records + DHCP leases (#455).

Covers the paginated envelope ``{items, total, page, page_size}``, the
``search`` filter, and the exact-match ``record_type`` / ``state`` filters on
the three converted endpoints:

* ``GET /dns/groups/{gid}/zones/{zid}/records``  (zone records)
* ``GET /dns/groups/{gid}/records``               (group-wide records)
* ``GET /dhcp/servers/{id}/leases``               (leases)
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPLease, DHCPServer
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone


async def _admin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _zone(db: AsyncSession, grp: DNSServerGroup, name: str) -> DNSZone:
    zone = DNSZone(
        group_id=grp.id,
        name=name,
        zone_type="primary",
        kind="forward",
        primary_ns=f"ns1.{name}",
        admin_email=f"admin.{name}",
    )
    db.add(zone)
    await db.flush()
    return zone


def _rec(zone: DNSZone, name: str, rtype: str, value: str) -> DNSRecord:
    return DNSRecord(
        zone_id=zone.id,
        name=name,
        fqdn=f"{name}.{zone.name}",
        record_type=rtype,
        value=value,
    )


# ── DNS zone records ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_zone_records_paginate_and_filter(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin_headers(db_session)
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    zone = await _zone(db_session, grp, "campus.example.edu.")
    # 25 A records + 5 MX records.
    for i in range(25):
        db_session.add(_rec(zone, f"host{i:03d}", "A", f"10.0.0.{i + 1}"))
    for i in range(5):
        db_session.add(_rec(zone, f"mail{i}", "MX", f"mx{i}.example.edu."))
    await db_session.commit()

    base = f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/records"

    # Default envelope shape + total across the whole set.
    r = await client.get(base, headers=h, params={"page_size": 10})
    assert r.status_code == 200, r.text
    body = r.json()
    # The page envelope, plus the zone's served apex beside it (#3518), which
    # is neither an item nor counted in ``total``.
    assert set(body) == {"items", "total", "page", "page_size", "served_apex"}
    assert body["total"] == 30
    assert body["page"] == 1
    assert body["page_size"] == 10
    assert len(body["items"]) == 10

    # Page 3 holds the remaining 10.
    r3 = await client.get(base, headers=h, params={"page_size": 10, "page": 3})
    assert r3.json()["total"] == 30
    assert len(r3.json()["items"]) == 10

    # No page bleed: pages 1+2 are disjoint.
    p1 = {i["id"] for i in r.json()["items"]}
    p2 = {
        i["id"]
        for i in (await client.get(base, headers=h, params={"page_size": 10, "page": 2})).json()[
            "items"
        ]
    }
    assert p1.isdisjoint(p2)

    # record_type exact filter.
    rmx = await client.get(base, headers=h, params={"record_type": "MX"})
    assert rmx.json()["total"] == 5
    assert all(i["record_type"] == "MX" for i in rmx.json()["items"])

    # search over name.
    rs = await client.get(base, headers=h, params={"search": "host01"})
    # host010..host019 + host01 -> host010-019 is 10, plus none named exactly host01
    assert rs.json()["total"] >= 1
    assert all("host01" in i["name"] for i in rs.json()["items"])

    # search over value.
    rv = await client.get(base, headers=h, params={"search": "10.0.0.1"})
    assert rv.json()["total"] >= 1


@pytest.mark.asyncio
async def test_zone_records_page_size_bounds(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _admin_headers(db_session)
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    zone = await _zone(db_session, grp, "z.example.edu.")
    await db_session.commit()
    base = f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/records"
    # page_size over the cap (1000) is rejected by the Query bound.
    assert (await client.get(base, headers=h, params={"page_size": 5000})).status_code == 422
    assert (await client.get(base, headers=h, params={"page": 0})).status_code == 422


# ── DNS group-wide records ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_group_records_paginate_and_zone_search(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin_headers(db_session)
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    z1 = await _zone(db_session, grp, "alpha.example.edu.")
    z2 = await _zone(db_session, grp, "beta.example.edu.")
    for i in range(6):
        db_session.add(_rec(z1, f"a{i}", "A", f"10.1.0.{i + 1}"))
    for i in range(4):
        db_session.add(_rec(z2, f"b{i}", "A", f"10.2.0.{i + 1}"))
    await db_session.commit()

    base = f"/api/v1/dns/groups/{grp.id}/records"
    r = await client.get(base, headers=h, params={"page_size": 4})
    body = r.json()
    assert body["total"] == 10
    assert len(body["items"]) == 4
    # items carry zone context.
    assert all("zone_name" in i for i in body["items"])

    # search by zone name narrows to that zone's records.
    rz = await client.get(base, headers=h, params={"search": "beta"})
    assert rz.json()["total"] == 4
    assert all(i["zone_name"] == "beta.example.edu" for i in rz.json()["items"])


# ── DHCP leases ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_leases_paginate_search_and_state(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin_headers(db_session)
    srv = DHCPServer(
        name=f"s-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="127.0.0.1",
        port=67,
    )
    db_session.add(srv)
    await db_session.flush()
    now = datetime.now(UTC)
    for i in range(12):
        db_session.add(
            DHCPLease(
                server_id=srv.id,
                ip_address=f"10.0.5.{i + 1}",
                mac_address=f"aa:bb:cc:00:00:{i:02x}",
                hostname=f"dev-{i:02d}",
                state="active" if i % 2 == 0 else "expired",
                last_seen_at=now - timedelta(minutes=i),
            )
        )
    await db_session.commit()

    base = f"/api/v1/dhcp/servers/{srv.id}/leases"

    r = await client.get(base, headers=h, params={"page_size": 5})
    body = r.json()
    assert set(body) == {"items", "total", "page", "page_size"}
    assert body["total"] == 12
    assert len(body["items"]) == 5
    # Ordered newest-first (i=0 has the most recent last_seen_at).
    assert body["items"][0]["hostname"] == "dev-00"

    # state filter.
    ra = await client.get(base, headers=h, params={"state": "active"})
    assert ra.json()["total"] == 6
    assert all(i["state"] == "active" for i in ra.json()["items"])

    # search by hostname.
    rh = await client.get(base, headers=h, params={"search": "dev-07"})
    assert rh.json()["total"] == 1
    assert rh.json()["items"][0]["hostname"] == "dev-07"

    # search by ip (INET cast to text).
    rip = await client.get(base, headers=h, params={"search": "10.0.5.3"})
    assert rip.json()["total"] >= 1
    assert any(i["ip_address"] == "10.0.5.3" for i in rip.json()["items"])

    # search by mac (MACADDR cast to text).
    rmac = await client.get(base, headers=h, params={"search": "aa:bb:cc:00:00:05"})
    assert rmac.json()["total"] == 1


@pytest.mark.asyncio
async def test_leases_missing_server_404(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _admin_headers(db_session)
    await db_session.commit()
    r = await client.get(f"/api/v1/dhcp/servers/{uuid.uuid4()}/leases", headers=h)
    assert r.status_code == 404
