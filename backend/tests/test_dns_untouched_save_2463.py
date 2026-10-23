"""An update dialog's untouched Save is a no-op (#2463).

Edit Record sends every field it shows; the API used to treat each as a
change: the zone serial bumped, an "update" op was queued and the audit row
named ``name`` / ``value`` / ``ttl`` / ``view_id`` for a row that did not move.
Now only a field whose value differs counts.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone


async def _setup(db: AsyncSession) -> tuple[dict[str, str], DNSZone]:
    user = User(
        username=f"u2463-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
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
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}, zone


async def _state(db: AsyncSession, zone_id: uuid.UUID) -> tuple[int | None, int, list[list[str]]]:
    serial = await db.scalar(
        select(DNSZone.last_serial)
        .where(DNSZone.id == zone_id)
        .execution_options(populate_existing=True)
    )
    ops = len((await db.execute(select(DNSRecordOp))).scalars().all())
    rows = (
        (
            await db.execute(
                select(AuditLog.changed_fields)
                .where(AuditLog.action == "update", AuditLog.resource_type == "dns_record")
                .order_by(AuditLog.timestamp)
            )
        )
        .scalars()
        .all()
    )
    return serial, ops, [list(r or []) for r in rows]


async def test_untouched_record_save_changes_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, zone = await _setup(db_session)
    base = f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/records"
    r = await client.post(
        base, headers=headers, json={"name": "www", "record_type": "A", "value": "10.98.1.10"}
    )
    assert r.status_code == 201, r.text
    rid = r.json()["id"]
    before = await _state(db_session, zone.id)

    r = await client.put(
        f"{base}/{rid}",
        headers=headers,
        json={
            "name": "www",
            "record_type": "A",
            "value": "10.98.1.10",
            "ttl": None,
            "priority": None,
            "weight": None,
            "port": None,
            "view_id": None,
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["value"] == "10.98.1.10"
    assert await _state(db_session, zone.id) == before


async def test_a_real_record_edit_audits_only_what_changed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, zone = await _setup(db_session)
    base = f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/records"
    r = await client.post(
        base, headers=headers, json={"name": "www", "record_type": "A", "value": "10.98.1.10"}
    )
    rid = r.json()["id"]
    serial, ops, _ = await _state(db_session, zone.id)

    r = await client.put(
        f"{base}/{rid}",
        headers=headers,
        json={"name": "www", "record_type": "A", "value": "10.98.1.11", "ttl": None},
    )
    assert r.status_code == 200, r.text
    new_serial, new_ops, audits = await _state(db_session, zone.id)
    assert new_serial != serial
    assert new_ops == ops + 1
    assert audits[-1] == ["value"]
    row = await db_session.scalar(
        select(DNSRecord.value)
        .where(DNSRecord.id == uuid.UUID(rid))
        .execution_options(populate_existing=True)
    )
    assert row == "10.98.1.11"


async def test_untouched_zone_save_audits_no_changed_field(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, zone = await _setup(db_session)
    url = f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}"
    r = await client.put(url, headers=headers, json={"ttl": 3600, "primary_ns": "ns1.example."})
    assert r.status_code == 200, r.text
    r = await client.put(url, headers=headers, json={"ttl": 7200, "primary_ns": "ns1.example."})
    assert r.status_code == 200, r.text
    rows = (
        (
            await db_session.execute(
                select(AuditLog.changed_fields)
                .where(AuditLog.action == "update", AuditLog.resource_type == "dns_zone")
                .order_by(AuditLog.timestamp)
            )
        )
        .scalars()
        .all()
    )
    assert [list(x or []) for x in rows] == [[], ["ttl"]]
