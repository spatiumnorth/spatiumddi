"""Set-based zone soft-delete and SQL-paginated trash listing (#1231).

A zone's soft-delete used to load every record, stamp each through the ORM
and write one audit row per record, holding the global audit lock for every
hash; the trash page loaded every soft-deleted row of every type into Python
on each view. On a 250k-record zone both were minutes of work in a request.
The records are now stamped by one UPDATE and counted on the zone's own audit
row, and the trash listing filters, counts and pages in SQL.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.soft_delete import _row_display


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"sb-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Set-based Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _zone_with_records(db: AsyncSession, n: int) -> tuple[DNSServerGroup, DNSZone]:
    group = DNSServerGroup(name=f"sb-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    zone = DNSZone(
        group_id=group.id,
        name=f"z{uuid.uuid4().hex[:6]}.test.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.test.",
        admin_email="admin.example.test.",
    )
    db.add(zone)
    await db.flush()
    for i in range(n):
        db.add(
            DNSRecord(
                zone_id=zone.id,
                name=f"h{i}",
                fqdn=f"h{i}.{zone.name}",
                record_type="A",
                value=f"192.0.2.{i + 1}",
            )
        )
    await db.flush()
    return group, zone


async def _records(db: AsyncSession, zone_id: uuid.UUID) -> list[DNSRecord]:
    return list(
        (
            await db.execute(
                select(DNSRecord)
                .where(DNSRecord.zone_id == zone_id)
                .execution_options(include_deleted=True, populate_existing=True)
            )
        )
        .scalars()
        .all()
    )


@pytest.mark.asyncio
async def test_zone_soft_delete_stamps_records_set_based_and_audits_once(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    group, zone = await _zone_with_records(db_session, 3)
    group_id, zone_id = group.id, zone.id
    await db_session.commit()

    resp = await client.delete(f"/api/v1/dns/groups/{group_id}/zones/{zone_id}", headers=headers)
    assert resp.status_code == 204, resp.text

    db_session.expire_all()
    zone_row = (
        await db_session.execute(
            select(DNSZone).where(DNSZone.id == zone_id).execution_options(include_deleted=True)
        )
    ).scalar_one()
    records = await _records(db_session, zone_id)
    assert len(records) == 3
    assert all(r.deleted_at is not None for r in records)
    assert {r.deletion_batch_id for r in records} == {zone_row.deletion_batch_id}

    audits = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == "soft_delete")))
        .scalars()
        .all()
    )
    zone_audits = [a for a in audits if a.resource_id == str(zone_id)]
    assert len(zone_audits) == 1
    assert zone_audits[0].old_value["cascaded"] == {"dns_record": 3}
    # No audit row per record: that is what held the audit lock for minutes.
    record_ids = {str(r.id) for r in records}
    assert not [a for a in audits if a.resource_id in record_ids]


@pytest.mark.asyncio
async def test_a_record_trashed_earlier_keeps_its_own_batch(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    group, zone = await _zone_with_records(db_session, 2)
    group_id, zone_id = group.id, zone.id
    await db_session.commit()
    first_id, second_id = (r.id for r in await _records(db_session, zone_id))
    base = f"/api/v1/dns/groups/{group_id}/zones/{zone_id}"

    resp = await client.delete(f"{base}/records/{first_id}", headers=headers)
    assert resp.status_code == 204, resp.text
    db_session.expire_all()
    rows = {r.id: r for r in await _records(db_session, zone_id)}
    first_batch = rows[first_id].deletion_batch_id
    assert first_batch is not None

    resp = await client.delete(base, headers=headers)
    assert resp.status_code == 204, resp.text
    db_session.expire_all()
    rows = {r.id: r for r in await _records(db_session, zone_id)}
    zone_batch = rows[second_id].deletion_batch_id
    assert rows[first_id].deletion_batch_id == first_batch != zone_batch

    # Restoring the zone brings back its own records only.
    resp = await client.post(f"/api/v1/admin/trash/dns_zone/{zone_id}/restore", headers=headers)
    assert resp.status_code == 200, resp.text
    db_session.expire_all()
    rows = {r.id: r for r in await _records(db_session, zone_id)}
    assert rows[second_id].deleted_at is None
    assert rows[first_id].deleted_at is not None


@pytest.mark.asyncio
async def test_trash_listing_pages_in_sql(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _admin(db_session)
    tag = uuid.uuid4().hex[:6]
    now = datetime.now(UTC)
    for i in range(5):
        db_session.add(
            IPSpace(
                name=f"pg-{tag}-{i}",
                description="",
                deleted_at=now - timedelta(minutes=i),
                deletion_batch_id=uuid.uuid4(),
            )
        )
    await db_session.commit()

    url = f"/api/v1/admin/trash?type=ip_space&q=pg-{tag}"
    first = (await client.get(f"{url}&limit=2&offset=0", headers=headers)).json()
    second = (await client.get(f"{url}&limit=2&offset=2", headers=headers)).json()
    assert first["total"] == second["total"] == 5
    assert [i["name_or_cidr"] for i in first["items"]] == [f"pg-{tag}-0", f"pg-{tag}-1"]
    assert [i["name_or_cidr"] for i in second["items"]] == [f"pg-{tag}-2", f"pg-{tag}-3"]
    assert all(i["batch_size"] == 1 for i in first["items"])


@pytest.mark.asyncio
async def test_trash_search_is_literal(client: AsyncClient, db_session: AsyncSession) -> None:
    """``%`` and ``_`` are characters to find, not wildcards (the #879 lesson)."""
    headers = await _admin(db_session)
    tag = uuid.uuid4().hex[:6]
    now = datetime.now(UTC)
    for name in (f"lit-{tag}-50%", f"lit-{tag}-500"):
        db_session.add(IPSpace(name=name, description="", deleted_at=now))
    await db_session.commit()

    body = (await client.get(f"/api/v1/admin/trash?q=lit-{tag}-50%25", headers=headers)).json()
    assert [i["name_or_cidr"] for i in body["items"]] == [f"lit-{tag}-50%"]


@pytest.mark.asyncio
async def test_trash_listing_label_matches_row_display(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The SQL label must be the string ``_row_display`` shows, or ``q`` would
    match a different string from the one on screen."""
    headers = await _admin(db_session)
    now = datetime.now(UTC)
    space = IPSpace(name=f"lbl-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    # A trailing NBSP: Python's strip() removes it, so the SQL label must too.
    named = IPBlock(space_id=space.id, network="10.77.0.0/16", name="campus\u00a0")
    db_session.add(named)
    await db_session.flush()
    unnamed = Subnet(space_id=space.id, block_id=named.id, network="10.77.1.0/24", name="")
    db_session.add(unnamed)
    _, zone = await _zone_with_records(db_session, 1)
    record = (await _records(db_session, zone.id))[0]
    objs = [space, named, unnamed, zone, record]
    expected = {str(obj.id): _row_display(obj) for obj in objs}
    for obj in objs:
        obj.deleted_at = now
    await db_session.commit()

    items = (await client.get("/api/v1/admin/trash?limit=1000", headers=headers)).json()["items"]
    shown = {i["id"]: i["name_or_cidr"] for i in items}
    for obj_id, label in expected.items():
        assert shown[obj_id] == label
