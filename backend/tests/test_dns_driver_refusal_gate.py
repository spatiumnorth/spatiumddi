"""One driver-refusal gate for record values (#2959) and TTLs (#2942).

``_check_driver_refusals`` is the single place the record API asks the
zone's drivers whether they can hold a record, at every write path: create,
update, bulk create, the zone-file import and the spreadsheet import. These
tests pin what the merge of the two gates promises: values are checked
before TTLs, only what a write changes is checked, and the spreadsheet
import (which carried only the TTL half before) refuses an unholdable value
too.
"""

from __future__ import annotations

import csv
import io
import uuid

import pytest
from fastapi import HTTPException
from httpx import AsyncClient, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.router import _check_driver_refusals
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.services.dns_io import spreadsheet as sheet_io

# Linode has no CAA flags field (#2959) and reads TTL 0 as "automatic" (#2942).
UNHOLDABLE_CAA = '128 issue "ca.org"'


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"gate-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Gate Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _zone(db: AsyncSession, driver: str = "linode") -> DNSZone:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver=driver,
            host="10.0.0.1",
            name=f"srv-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
        ttl=3600,
    )
    db.add(zone)
    await db.flush()
    return zone


async def _legacy_caa(db: AsyncSession, zone: DNSZone) -> DNSRecord:
    """A CAA row stored before #2959, with a value Linode cannot hold."""
    row = DNSRecord(
        zone_id=zone.id,
        name="@",
        fqdn=zone.name,
        record_type="CAA",
        value=UNHOLDABLE_CAA,
        ttl=300,
    )
    db.add(row)
    await db.flush()
    return row


def _base(zone: DNSZone) -> str:
    return f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}"


@pytest.mark.asyncio
async def test_value_refusal_is_reported_before_ttl(db_session: AsyncSession) -> None:
    zone = await _zone(db_session)
    with pytest.raises(HTTPException) as exc:
        await _check_driver_refusals([("CAA", UNHOLDABLE_CAA, 0)], zone.group_id, db_session)
    assert exc.value.status_code == 422
    assert "flags 128" in str(exc.value.detail)


@pytest.mark.asyncio
async def test_unchecked_fields_pass(db_session: AsyncSession) -> None:
    zone = await _zone(db_session)
    await _check_driver_refusals([("CAA", None, None)], zone.group_id, db_session)
    await _check_driver_refusals([("CAA", None, 300)], zone.group_id, db_session)
    with pytest.raises(HTTPException):
        await _check_driver_refusals([("CAA", None, 0)], zone.group_id, db_session)


@pytest.mark.asyncio
async def test_update_checks_only_what_it_changes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    zone = await _zone(db_session)
    row = await _legacy_caa(db_session, zone)
    # A TTL-only edit of a pre-#2959 row is not refused for the value it keeps.
    resp = await client.put(f"{_base(zone)}/records/{row.id}", headers=headers, json={"ttl": 600})
    assert resp.status_code == 200, resp.text
    resp = await client.put(f"{_base(zone)}/records/{row.id}", headers=headers, json={"ttl": 0})
    assert resp.status_code == 422, resp.text
    assert "linode" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_zone_file_import_refuses_an_unholdable_value(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    zone = await _zone(db_session)
    resp = await client.post(
        f"{_base(zone)}/import/commit",
        headers=headers,
        json={
            "zone_file": f"$ORIGIN {zone.name}\n$TTL 300\n@ IN CAA {UNHOLDABLE_CAA}\n",
            "conflict_strategy": "merge",
        },
    )
    assert resp.status_code == 422, resp.text
    assert "flags 128" in resp.json()["detail"]


def _csv(rows: list[dict[str, object]]) -> bytes:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=sheet_io.RECORD_COLUMNS, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return buf.getvalue().encode()


async def _sheet_commit(
    client: AsyncClient, headers: dict[str, str], zone: DNSZone, data: bytes
) -> Response:
    return await client.post(
        f"{_base(zone)}/import/spreadsheet/commit",
        headers=headers,
        files={"file": ("records.csv", data, "text/csv")},
        data={"mode": "merge"},
    )


@pytest.mark.asyncio
async def test_spreadsheet_import_refuses_an_unholdable_value(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    zone = await _zone(db_session)
    data = _csv([{"name": "@", "type": "CAA", "ttl": 300, "value": UNHOLDABLE_CAA}])
    resp = await _sheet_commit(client, headers, zone, data)
    assert resp.status_code == 422, resp.text
    assert "flags 128" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_spreadsheet_import_accepts_a_holdable_value(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    zone = await _zone(db_session)
    data = _csv([{"name": "@", "type": "CAA", "ttl": 300, "value": '0 issue "ca.org"'}])
    resp = await _sheet_commit(client, headers, zone, data)
    assert resp.status_code == 200, resp.text
