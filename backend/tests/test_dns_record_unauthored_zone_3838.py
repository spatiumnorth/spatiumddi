"""A record write into a secondary / stub / forward zone is refused (#3838).

Those zones serve their masters' data or forward queries; a record written
there was stored and listed but served by nobody. Delete stays open so a row
that predates the rule can be cleaned up.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.services.dns.zone_synthesis import unauthored_zone_error


async def _setup(db: AsyncSession, zone_type: str) -> tuple[DNSZone, dict[str, str]]:
    user = User(
        username=f"ua-{uuid.uuid4().hex[:8]}",
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
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
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
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    return zone, headers


def _url(zone: DNSZone) -> str:
    return f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/records"


async def _count(db: AsyncSession, zone: DNSZone) -> int:
    return (
        await db.execute(
            select(func.count()).select_from(DNSRecord).where(DNSRecord.zone_id == zone.id)
        )
    ).scalar_one()


def test_the_rule() -> None:
    class Z:
        name = "x."
        zone_type = "primary"

    z = Z()
    assert unauthored_zone_error(z, "add") is None
    z.zone_type = "stub"
    assert "stub zone" in (unauthored_zone_error(z, "add") or "")


@pytest.mark.parametrize("zone_type", ["secondary", "stub", "forward"])
async def test_create_and_bulk_create_are_refused(
    client: AsyncClient, db_session: AsyncSession, zone_type: str
) -> None:
    zone, headers = await _setup(db_session, zone_type)
    rec = {"name": "www", "record_type": "A", "value": "192.0.2.61"}
    r = await client.post(_url(zone), headers=headers, json=rec)
    assert r.status_code == 422, r.text
    assert zone_type in r.json()["detail"]
    r = await client.post(_url(zone) + "/bulk-create", headers=headers, json={"records": [rec]})
    assert r.status_code == 422, r.text
    assert await _count(db_session, zone) == 0


async def test_primary_still_accepts(client: AsyncClient, db_session: AsyncSession) -> None:
    zone, headers = await _setup(db_session, "primary")
    rec = {"name": "www", "record_type": "A", "value": "192.0.2.61"}
    r = await client.post(_url(zone), headers=headers, json=rec)
    assert r.status_code == 201, r.text


async def test_update_refused_delete_allowed_on_legacy_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    zone, headers = await _setup(db_session, "secondary")
    rec = DNSRecord(
        zone_id=zone.id, name="www", fqdn=f"www.{zone.name}", record_type="A", value="192.0.2.61"
    )
    db_session.add(rec)
    await db_session.flush()
    r = await client.put(f"{_url(zone)}/{rec.id}", headers=headers, json={"value": "192.0.2.62"})
    assert r.status_code == 422, r.text
    r = await client.delete(f"{_url(zone)}/{rec.id}", headers=headers)
    assert r.status_code == 204, r.text


@pytest.mark.parametrize("zone_type", ["secondary", "stub"])
async def test_import_preview_and_commit_agree(
    client: AsyncClient, db_session: AsyncSession, zone_type: str
) -> None:
    """A clean preview must not be followed by a refused commit."""
    zone, headers = await _setup(db_session, zone_type)
    base = f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/import"
    body = {"zone_file": "www IN A 192.0.2.61\n"}
    for path in ("/preview", "/commit"):
        r = await client.post(base + path, headers=headers, json=body)
        assert r.status_code == 422, (path, r.text)
        assert zone_type in r.json()["detail"]
    sheet = {"file": ("r.csv", b"name,type,value\nwww,A,192.0.2.61\n", "text/csv")}
    for path in ("/spreadsheet/preview", "/spreadsheet/commit"):
        r = await client.post(base + path, headers=headers, files=sheet)
        assert r.status_code == 422, (path, r.text)
    assert await _count(db_session, zone) == 0


async def test_pool_create_refused_on_secondary(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    zone, headers = await _setup(db_session, "secondary")
    r = await client.post(
        f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/pools",
        headers=headers,
        json={"name": "p", "record_name": "web", "record_type": "A"},
    )
    assert r.status_code == 422, r.text
    assert "secondary" in r.json()["detail"]


async def test_legacy_rows_still_listed(client: AsyncClient, db_session: AsyncSession) -> None:
    zone, headers = await _setup(db_session, "secondary")
    db_session.add(
        DNSRecord(
            zone_id=zone.id,
            name="www",
            fqdn=f"www.{zone.name}",
            record_type="A",
            value="192.0.2.61",
        )
    )
    await db_session.flush()
    r = await client.get(_url(zone), headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["total"] == 1
