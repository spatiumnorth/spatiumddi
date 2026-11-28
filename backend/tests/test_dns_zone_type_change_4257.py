"""Edit Zone's type change and the delegation wizard keep #3838's rule (#4257, #4258, #4261).

A zone SpatiumDDI does not serve as primary must hold no records of ours, and
a delegation's NS + glue records are written into a primary parent only.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone


async def _setup(db: AsyncSession) -> tuple[DNSServerGroup, dict[str, str]]:
    user = User(
        username=f"tc-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    return grp, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _zone(
    db: AsyncSession, grp: DNSServerGroup, zone_type: str, name: str | None = None
) -> DNSZone:
    zone = DNSZone(
        group_id=grp.id,
        name=name or f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type=zone_type,
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
        ttl=3600,
        forwarders=["192.0.2.53"] if zone_type == "forward" else [],
        masters=["192.0.2.1"] if zone_type in {"secondary", "stub"} else [],
    )
    db.add(zone)
    await db.flush()
    return zone


async def _record(db: AsyncSession, zone: DNSZone, name: str, rtype: str, value: str) -> None:
    fqdn = zone.name if name == "@" else f"{name}.{zone.name}"
    db.add(
        DNSRecord(zone_id=zone.id, fqdn=fqdn, name=name, record_type=rtype, value=value, ttl=3600)
    )
    await db.flush()


def _url(zone: DNSZone, tail: str = "") -> str:
    return f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}{tail}"


@pytest.mark.parametrize("new_type", ["secondary", "stub", "forward"])
async def test_primary_holding_records_cannot_change_type(
    client: AsyncClient, db_session: AsyncSession, new_type: str
) -> None:
    grp, h = await _setup(db_session)
    zone = await _zone(db_session, grp, "primary")
    await _record(db_session, zone, "www", "A", "192.0.2.5")
    body: dict[str, object] = {"zone_type": new_type}
    if new_type == "forward":
        body["forwarders"] = ["192.0.2.53"]
    else:
        body["masters"] = ["192.0.2.1"]
    r = await client.put(_url(zone), headers=h, json=body)
    assert r.status_code == 409, r.text
    assert "holds 1 record(s)" in r.json()["detail"]
    await db_session.refresh(zone)
    assert zone.zone_type == "primary"


async def test_secondary_holding_records_cannot_become_forward(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp, h = await _setup(db_session)
    zone = await _zone(db_session, grp, "secondary")
    await _record(db_session, zone, "www", "A", "192.0.2.5")
    r = await client.put(
        _url(zone), headers=h, json={"zone_type": "forward", "forwarders": ["192.0.2.53"]}
    )
    assert r.status_code == 409, r.text


async def test_empty_primary_can_change_type(client: AsyncClient, db_session: AsyncSession) -> None:
    grp, h = await _setup(db_session)
    zone = await _zone(db_session, grp, "primary")
    r = await client.put(
        _url(zone), headers=h, json={"zone_type": "secondary", "masters": ["192.0.2.1"]}
    )
    assert r.status_code == 200, r.text
    assert r.json()["zone_type"] == "secondary"


async def test_empty_secondary_cannot_become_primary_4261(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp, h = await _setup(db_session)
    zone = await _zone(db_session, grp, "secondary")
    r = await client.put(_url(zone), headers=h, json={"zone_type": "primary"})
    assert r.status_code == 409, r.text
    assert "Sync with server" in r.json()["detail"]
    assert "served empty" in r.json()["detail"]
    await db_session.refresh(zone)
    assert zone.zone_type == "secondary"


async def test_empty_stub_cannot_become_primary_4261(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp, h = await _setup(db_session)
    zone = await _zone(db_session, grp, "stub")
    r = await client.put(_url(zone), headers=h, json={"zone_type": "primary"})
    assert r.status_code == 409, r.text
    assert "served empty" in r.json()["detail"]


async def test_secondary_with_records_can_become_primary_4261(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp, h = await _setup(db_session)
    zone = await _zone(db_session, grp, "secondary")
    await _record(db_session, zone, "www", "A", "192.0.2.5")
    r = await client.put(_url(zone), headers=h, json={"zone_type": "primary"})
    assert r.status_code == 200, r.text
    assert r.json()["zone_type"] == "primary"


@pytest.mark.parametrize("parent_type", ["secondary", "stub"])
async def test_delegation_into_non_primary_parent_refused_4258(
    client: AsyncClient, db_session: AsyncSession, parent_type: str
) -> None:
    grp, h = await _setup(db_session)
    parent = await _zone(db_session, grp, parent_type, "corp.example.")
    child = await _zone(db_session, grp, "primary", "dev.corp.example.")
    await _record(db_session, child, "@", "NS", "ns1.dev.corp.example.")
    r = await client.get(_url(child, "/delegation-preview"), headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["has_parent"] is False
    assert body["parent_zone_name"] == parent.name
    assert f"is a {parent_type} zone" in body["reason"]
    assert "add the delegation on the primary server" in body["reason"]
    r = await client.post(_url(child, "/delegate-from-parent"), headers=h)
    assert r.status_code == 409, r.text
    assert "add the delegation on the primary server" in r.json()["detail"]
    from sqlalchemy import func, select

    n = (
        await db_session.execute(
            select(func.count()).select_from(DNSRecord).where(DNSRecord.zone_id == parent.id)
        )
    ).scalar_one()
    assert n == 0


async def test_delegation_into_primary_parent_allowed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp, h = await _setup(db_session)
    await _zone(db_session, grp, "primary", "corp.example.")
    child = await _zone(db_session, grp, "primary", "dev.corp.example.")
    await _record(db_session, child, "@", "NS", "ns1.dev.corp.example.")
    r = await client.get(_url(child, "/delegation-preview"), headers=h)
    assert r.json()["has_parent"] is True
    assert r.json().get("reason") is None
    r = await client.post(_url(child, "/delegate-from-parent"), headers=h)
    assert r.status_code == 201, r.text
    assert any(rec["record_type"] == "NS" for rec in r.json())
