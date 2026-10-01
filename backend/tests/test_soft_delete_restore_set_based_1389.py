"""Restoring a trashed zone is set-based (#1389).

#1231 made a zone's soft-delete stamp its records with one UPDATE and count
them on the zone's audit row. Restore still loaded every record, ran one
conflict ``SELECT`` per record, and wrote one audit row per record under the
global audit lock: 250k of each for a 250k-record zone. Now the conflicts are
found by one query, the records come back by one UPDATE per zone, and the
zone's own restore row carries the count.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import event, select
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServerGroup, DNSView, DNSZone
from app.services.soft_delete import restore_batch


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"rs-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Restore Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _zone_with_records(
    db: AsyncSession, n: int, view_id: uuid.UUID | None = None
) -> tuple[uuid.UUID, uuid.UUID]:
    group = DNSServerGroup(name=f"rs-{uuid.uuid4().hex[:6]}")
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
                view_id=view_id,
                name=f"h{i}",
                fqdn=f"h{i}.{zone.name}",
                record_type="A",
                value=f"192.0.2.{i + 1}",
            )
        )
    await db.flush()
    return group.id, zone.id


async def _trash_zone(
    client: AsyncClient, headers: dict[str, str], group_id: uuid.UUID, zone_id: uuid.UUID
) -> None:
    resp = await client.delete(f"/api/v1/dns/groups/{group_id}/zones/{zone_id}", headers=headers)
    assert resp.status_code == 204, resp.text


async def _records(db: AsyncSession, zone_id: uuid.UUID) -> list[DNSRecord]:
    stmt = (
        select(DNSRecord)
        .where(DNSRecord.zone_id == zone_id)
        .execution_options(include_deleted=True, populate_existing=True)
    )
    return list((await db.execute(stmt)).scalars().all())


class _RecordStatements:
    def __init__(self) -> None:
        self.statements: list[str] = []

    def __call__(self, conn, cursor, statement, parameters, context, executemany):  # noqa: ANN001
        flat = " ".join(statement.split())
        if "dns_record" in flat and "dns_record_op" not in flat:
            self.statements.append(flat)


@pytest.mark.asyncio
async def test_a_zone_restore_is_one_audit_row_carrying_the_count(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    group_id, zone_id = await _zone_with_records(db_session, 3)
    await db_session.commit()
    await _trash_zone(client, headers, group_id, zone_id)

    resp = await client.post(f"/api/v1/admin/trash/dns_zone/{zone_id}/restore", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["restored"] == 4  # the zone and its three records

    db_session.expire_all()
    records = await _records(db_session, zone_id)
    assert len(records) == 3
    assert all(r.deleted_at is None and r.deletion_batch_id is None for r in records)

    restores = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == "restore")))
        .scalars()
        .all()
    )
    assert [a.resource_id for a in restores] == [str(zone_id)]
    assert restores[0].new_value["restored"] == {"dns_record": 3}


@pytest.mark.asyncio
async def test_record_statements_do_not_grow_with_the_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The per-record SELECT is what made a 250k-record restore 250k queries."""
    headers = await _admin(db_session)
    group_id, zone_id = await _zone_with_records(db_session, 40)
    await db_session.commit()
    await _trash_zone(client, headers, group_id, zone_id)

    counter = _RecordStatements()
    event.listen(Engine, "before_cursor_execute", counter)
    try:
        resp = await client.post(f"/api/v1/admin/trash/dns_zone/{zone_id}/restore", headers=headers)
    finally:
        event.remove(Engine, "before_cursor_execute", counter)
    assert resp.status_code == 200, resp.text
    # The conflict query, the load of records outside a restored zone, the
    # UPDATE, and the batch-type probe: a handful, not one per record.
    assert len(counter.statements) <= 6, counter.statements


@pytest.mark.asyncio
async def test_a_live_duplicate_refuses_the_whole_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    group_id, zone_id = await _zone_with_records(db_session, 2)
    await db_session.commit()
    await _trash_zone(client, headers, group_id, zone_id)

    zone_name = (
        await db_session.execute(
            select(DNSZone.name)
            .where(DNSZone.id == zone_id)
            .execution_options(include_deleted=True)
        )
    ).scalar_one()
    db_session.add(
        DNSRecord(
            zone_id=zone_id,
            name="h0",
            fqdn=f"h0.{zone_name}",
            record_type="A",
            value="192.0.2.1",
        )
    )
    await db_session.commit()

    resp = await client.post(f"/api/v1/admin/trash/dns_zone/{zone_id}/restore", headers=headers)
    assert resp.status_code == 409, resp.text
    [conflict] = resp.json()["detail"]["conflicts"]
    assert conflict["type"] == "dns_record"
    assert conflict["display"] == f"h0.{zone_name} A"

    db_session.expire_all()
    trashed = [r for r in await _records(db_session, zone_id) if r.deleted_at is not None]
    assert len(trashed) == 2  # nothing restored


@pytest.mark.asyncio
async def test_the_same_record_in_another_view_is_not_a_conflict(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Under split-horizon one name, type and value in two views is two records."""
    headers = await _admin(db_session)
    group_id, zone_id = await _zone_with_records(db_session, 1)
    view = DNSView(group_id=group_id, name=f"v-{uuid.uuid4().hex[:6]}")
    db_session.add(view)
    await db_session.commit()
    await _trash_zone(client, headers, group_id, zone_id)

    [trashed] = await _records(db_session, zone_id)
    db_session.add(
        DNSRecord(
            zone_id=zone_id,
            view_id=view.id,
            name=trashed.name,
            fqdn=trashed.fqdn,
            record_type=trashed.record_type,
            value=trashed.value,
        )
    )
    await db_session.commit()

    resp = await client.post(f"/api/v1/admin/trash/dns_zone/{zone_id}/restore", headers=headers)
    assert resp.status_code == 200, resp.text
    db_session.expire_all()
    assert all(r.deleted_at is None for r in await _records(db_session, zone_id))


@pytest.mark.asyncio
async def test_an_mx_at_another_priority_is_not_a_conflict(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Priority, weight and port are part of a record's identity, as bulk
    create treats them (#1230): MX 10 and MX 20 to one host are two records."""
    headers = await _admin(db_session)
    group_id, zone_id = await _zone_with_records(db_session, 0)
    zone_name = (
        await db_session.execute(select(DNSZone.name).where(DNSZone.id == zone_id))
    ).scalar_one()
    db_session.add(
        DNSRecord(
            zone_id=zone_id,
            name="@",
            fqdn=zone_name,
            record_type="MX",
            value=f"mail.{zone_name}",
            priority=10,
        )
    )
    await db_session.commit()
    await _trash_zone(client, headers, group_id, zone_id)

    db_session.add(
        DNSRecord(
            zone_id=zone_id,
            name="@",
            fqdn=zone_name,
            record_type="MX",
            value=f"mail.{zone_name}",
            priority=20,
        )
    )
    await db_session.commit()

    resp = await client.post(f"/api/v1/admin/trash/dns_zone/{zone_id}/restore", headers=headers)
    assert resp.status_code == 200, resp.text
    db_session.expire_all()
    assert all(r.deleted_at is None for r in await _records(db_session, zone_id))


@pytest.mark.asyncio
async def test_a_record_trashed_before_the_zone_stays_in_the_trash(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The UPDATE is keyed on the batch, not the zone: a record deleted on
    its own earlier comes back with its own batch."""
    headers = await _admin(db_session)
    group_id, zone_id = await _zone_with_records(db_session, 2)
    await db_session.commit()
    first, second = await _records(db_session, zone_id)
    first_id, second_id = first.id, second.id
    base = f"/api/v1/dns/groups/{group_id}/zones/{zone_id}"
    resp = await client.delete(f"{base}/records/{first_id}", headers=headers)
    assert resp.status_code == 204, resp.text
    await _trash_zone(client, headers, group_id, zone_id)

    resp = await client.post(f"/api/v1/admin/trash/dns_zone/{zone_id}/restore", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["restored"] == 2  # the zone and one record

    db_session.expire_all()
    rows = {r.id: r for r in await _records(db_session, zone_id)}
    assert rows[second_id].deleted_at is None
    assert rows[first_id].deleted_at is not None


@pytest.mark.asyncio
async def test_skip_conflicts_leaves_only_the_duplicate_in_a_zone_batch(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The route refuses ``skip_conflicts`` on a zone batch, but the service
    supports it: the duplicate stays in the trash and the rest come back."""
    headers = await _admin(db_session)
    group_id, zone_id = await _zone_with_records(db_session, 3)
    await db_session.commit()
    await _trash_zone(client, headers, group_id, zone_id)

    records = await _records(db_session, zone_id)
    dup = next(r for r in records if r.name == "h1")
    dup_id, batch_id = dup.id, dup.deletion_batch_id
    db_session.add(
        DNSRecord(
            zone_id=zone_id,
            name=dup.name,
            fqdn=dup.fqdn,
            record_type=dup.record_type,
            value=dup.value,
        )
    )
    await db_session.commit()

    async def _no_clash(_obj: object) -> None:
        return None

    result = await restore_batch(
        db_session, batch_id, conflict_check=_no_clash, skip_conflicts=True
    )
    await db_session.commit()
    assert [c["id"] for c in result.conflicts] == [str(dup_id)]
    assert result.bulk == {zone_id: {"dns_record": 2}}

    db_session.expire_all()
    rows = {r.id: r for r in await _records(db_session, zone_id)}
    trashed = [rid for rid, r in rows.items() if r.deleted_at is not None]
    assert trashed == [dup_id]
