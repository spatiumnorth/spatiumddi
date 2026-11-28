"""#963 — bulk-delete records shares the singular route's contract.

Before: ``POST .../records/bulk-delete`` hard-deleted under a plain
``CurrentUser`` while ``DELETE .../records/{id}`` soft-deleted by default and
required superadmin for ``?permanent=true``. #951 made the bulk route work on
agent-based zones (the default deployment shape), which is when the asymmetry
started to matter: a DNS editor selecting rows in the grid permanently
destroyed records the singular route would have put in the trash.

Now: default is a soft delete under ONE ``deletion_batch_id`` (so the whole
selection restores together), ``permanent=true`` is superadmin-only, and the
403 fires before any wire op is enqueued.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone


async def _user(db: AsyncSession, *, superadmin: bool) -> dict[str, str]:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"bd-{tag}",
        email=f"{tag}@example.test",
        display_name="Bulk Delete",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    if not superadmin:
        # A DNS Editor: every action on the three DNS resource types, and
        # nothing else. NOT the ``{"*", "*"}`` wildcard — ``require_superadmin``
        # admits that as an *effective* superadmin (LDAP/OIDC users mapped to a
        # Superadmin-role group), which is exactly the bar this route must hold.
        role = Role(
            name=f"r-{tag}",
            description="",
            permissions=[
                {"action": "*", "resource_type": rt}
                for rt in ("dns_group", "dns_zone", "dns_record")
            ],
        )
        group = Group(name=f"g-{tag}", description="")
        group.roles = [role]
        group.users = [user]
        db.add_all([role, group])
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _agent_zone(db: AsyncSession) -> tuple[DNSServer, DNSZone]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver="bind9",
        host="10.0.0.1",
        name=f"srv-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
    )
    db.add(server)
    await db.flush()
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(zone)
    await db.flush()
    return server, zone


async def _records(db: AsyncSession, zone: DNSZone, n: int) -> list[uuid.UUID]:
    rows = [
        DNSRecord(
            zone_id=zone.id,
            name=f"h{i}",
            fqdn=f"h{i}.{zone.name}",
            record_type="A",
            value=f"10.1.0.{i + 1}",
        )
        for i in range(n)
    ]
    db.add_all(rows)
    await db.flush()
    return [r.id for r in rows]


def _url(zone: DNSZone, *, permanent: bool = False) -> str:
    base = f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/records/bulk-delete"
    return f"{base}?permanent=true" if permanent else base


async def _rows_including_deleted(db: AsyncSession, ids: list[uuid.UUID]) -> list[DNSRecord]:
    db.expire_all()
    return list(
        (
            await db.execute(
                select(DNSRecord)
                .where(DNSRecord.id.in_(ids))
                .execution_options(include_deleted=True)
            )
        )
        .scalars()
        .all()
    )


async def _ops(db: AsyncSession, server_id: uuid.UUID) -> list[DNSRecordOp]:
    return list(
        (await db.execute(select(DNSRecordOp).where(DNSRecordOp.server_id == server_id)))
        .scalars()
        .all()
    )


@pytest.mark.asyncio
async def test_default_is_one_soft_delete_batch_with_wire_retraction(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _user(db_session, superadmin=False)
    server, zone = await _agent_zone(db_session)
    server_id = server.id
    ids = await _records(db_session, zone, 3)
    await db_session.commit()

    resp = await client.post(
        _url(zone), headers=headers, json={"record_ids": [str(i) for i in ids]}
    )
    assert resp.status_code == 200, resp.text
    body: dict[str, Any] = resp.json()
    assert body["deleted"] == 3 and body["skipped"] == [], body
    batch_id = body["deletion_batch_id"]
    assert batch_id is not None

    rows = await _rows_including_deleted(db_session, ids)
    assert len(rows) == 3, "soft delete must keep the rows"
    assert all(r.deleted_at is not None for r in rows)
    # ONE batch id across the selection — that is what makes "undo that bulk
    # delete" a single restore from /admin/trash.
    assert {str(r.deletion_batch_id) for r in rows} == {batch_id}
    # Hidden from the default read, like every other soft-deleted row.
    db_session.expire_all()
    visible = (await db_session.execute(select(DNSRecord).where(DNSRecord.id.in_(ids)))).scalars()
    assert list(visible) == []

    # The retraction still reaches the agent (#632): one queued delete per record.
    ops = await _ops(db_session, server_id)
    assert sorted(o.op for o in ops) == ["delete"] * 3
    assert {o.state for o in ops} == {"pending"}

    audits = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "dns_record",
                    AuditLog.resource_id.in_([str(i) for i in ids]),
                )
            )
        )
        .scalars()
        .all()
    )
    assert {a.action for a in audits} == {"soft_delete"}
    assert {a.old_value["deletion_batch_id"] for a in audits} == {batch_id}


@pytest.mark.asyncio
async def test_permanent_requires_superadmin_and_queues_nothing_on_refusal(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _user(db_session, superadmin=False)
    server, zone = await _agent_zone(db_session)
    server_id = server.id
    ids = await _records(db_session, zone, 2)
    await db_session.commit()

    resp = await client.post(
        _url(zone, permanent=True), headers=headers, json={"record_ids": [str(i) for i in ids]}
    )
    assert resp.status_code == 403, resp.text
    rows = await _rows_including_deleted(db_session, ids)
    assert len(rows) == 2 and all(r.deleted_at is None for r in rows)
    # The gate ran before dispatch: nothing sits in the agent's queue.
    assert await _ops(db_session, server_id) == []


@pytest.mark.asyncio
async def test_permanent_as_superadmin_hard_deletes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _user(db_session, superadmin=True)
    server, zone = await _agent_zone(db_session)
    server_id = server.id
    ids = await _records(db_session, zone, 2)
    await db_session.commit()

    resp = await client.post(
        _url(zone, permanent=True), headers=headers, json={"record_ids": [str(i) for i in ids]}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["deleted"] == 2 and body["deletion_batch_id"] is None, body
    assert await _rows_including_deleted(db_session, ids) == []
    ops = await _ops(db_session, server_id)
    assert sorted(o.op for o in ops) == ["delete"] * 2


@pytest.mark.asyncio
async def test_failed_wire_delete_keeps_the_row_on_the_soft_path(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A server that REJECTED the delete still serves the record; trashing the
    row would tell the operator it is gone. Same rule as #951's permanent path."""
    from app.api.v1.dns import router as dns_router

    headers = await _user(db_session, superadmin=False)
    _server, zone = await _agent_zone(db_session)
    ids = await _records(db_session, zone, 2)
    await db_session.commit()

    real = dns_router.enqueue_record_ops_batch

    async def _first_fails(db: AsyncSession, z: DNSZone, ops: list[dict[str, Any]]) -> list[Any]:
        rows = await real(db, z, ops)
        rows[0].state = "failed"
        rows[0].last_error = "REFUSED"
        return rows

    monkeypatch.setattr(dns_router, "enqueue_record_ops_batch", _first_fails)
    resp = await client.post(
        _url(zone), headers=headers, json={"record_ids": [str(i) for i in ids]}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["deleted"] == 1, body
    assert [s["reason"] for s in body["skipped"]] == ["wire delete failed: REFUSED"]
    rows = {r.id: r for r in await _rows_including_deleted(db_session, ids)}
    assert rows[ids[0]].deleted_at is None
    assert rows[ids[1]].deleted_at is not None


# ── review findings on #963 ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_duplicate_ids_count_once_and_the_batch_is_capped(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _user(db_session, superadmin=False)
    server, zone = await _agent_zone(db_session)
    server_id = server.id
    ids = await _records(db_session, zone, 1)
    await db_session.commit()

    resp = await client.post(
        _url(zone), headers=headers, json={"record_ids": [str(ids[0]), str(ids[0])]}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["deleted"] == 1, resp.json()
    # One op, one audit row — not two of each for one row.
    assert len(await _ops(db_session, server_id)) == 1
    audits = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.action == "soft_delete", AuditLog.resource_id == str(ids[0])
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(audits) == 1

    from app.api.v1.dns import router as dns_router

    too_many = [str(uuid.uuid4()) for _ in range(dns_router.BULK_DELETE_RECORDS_MAX + 1)]
    resp = await client.post(_url(zone), headers=headers, json={"record_ids": too_many})
    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_pool_managed_record_is_skipped_like_the_singular_route(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The singular route 422s a pool member's record; the bulk route skips it
    with that reason. Trashing it would let the next health pass re-create the
    record and make the trashed copy unrestorable."""
    from app.models.dns import DNSPool, DNSPoolMember

    headers = await _user(db_session, superadmin=False)
    _server, zone = await _agent_zone(db_session)
    ids = await _records(db_session, zone, 2)
    pool = DNSPool(group_id=zone.group_id, zone_id=zone.id, name="p", record_name="svc")
    db_session.add(pool)
    await db_session.flush()
    member = DNSPoolMember(pool_id=pool.id, address="10.9.9.9")
    db_session.add(member)
    await db_session.flush()
    rec = await db_session.get(DNSRecord, ids[0])
    assert rec is not None
    rec.pool_member_id = member.id
    await db_session.commit()

    resp = await client.post(
        _url(zone), headers=headers, json={"record_ids": [str(i) for i in ids]}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["deleted"] == 1, body
    assert [s["record_id"] for s in body["skipped"]] == [str(ids[0])]
    assert "pool" in body["skipped"][0]["reason"].lower()
    rows = {r.id: r for r in await _rows_including_deleted(db_session, ids)}
    assert rows[ids[0]].deleted_at is None
    assert rows[ids[1]].deleted_at is not None


@pytest.mark.asyncio
async def test_bulk_batch_restores_together_and_skip_conflicts_leaves_only_the_duplicate(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """One batch id makes the bulk delete one restore — and a record the
    operator re-created by hand must not pin the other N in the trash."""
    headers = await _user(db_session, superadmin=True)
    server, zone = await _agent_zone(db_session)
    server_id, zone_id = server.id, zone.id
    ids = await _records(db_session, zone, 3)
    await db_session.commit()

    resp = await client.post(
        _url(zone), headers=headers, json={"record_ids": [str(i) for i in ids]}
    )
    assert resp.status_code == 200, resp.text
    # Hand-recreate the first record while the batch sits in the trash.
    trashed = await _rows_including_deleted(db_session, ids)
    first = next(r for r in trashed if r.id == ids[0])
    db_session.add(
        DNSRecord(
            zone_id=zone_id,
            name=first.name,
            fqdn=first.fqdn,
            record_type=first.record_type,
            value=first.value,
        )
    )
    await db_session.commit()

    restore = f"/api/v1/admin/trash/dns_record/{ids[1]}/restore"
    resp = await client.post(restore, headers=headers)
    assert resp.status_code == 409, resp.text  # default: all-or-nothing, as before

    resp = await client.post(f"{restore}?skip_conflicts=true", headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["restored"] == 2, body
    assert [s["id"] for s in body["skipped"]] == [str(ids[0])]
    rows = {r.id: r for r in await _rows_including_deleted(db_session, ids)}
    assert rows[ids[0]].deleted_at is not None
    assert rows[ids[1]].deleted_at is None and rows[ids[2]].deleted_at is None
    # The re-push went out as ONE batch: one create op per restored record,
    # all carrying the same target serial (one bump, not one per record).
    creates = [o for o in await _ops(db_session, server_id) if o.op == "create"]
    assert len(creates) == 2
    assert len({o.target_serial for o in creates}) == 1


@pytest.mark.asyncio
async def test_skip_conflicts_is_refused_on_a_cascade_batch(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A zone's batch holds the zone AND its records. Skipping a row there can
    restore a child whose parent stayed deleted — records pointing at a
    soft-deleted zone, hidden by the zone's own filter and re-pushed to the
    provider as if live. Only a flat batch of independent siblings (a bulk
    record delete) may be partially restored."""
    headers = await _user(db_session, superadmin=True)
    _server, zone = await _agent_zone(db_session)
    ids = await _records(db_session, zone, 2)
    group_id, zone_id = zone.group_id, zone.id
    await db_session.commit()

    resp = await client.delete(f"/api/v1/dns/groups/{group_id}/zones/{zone_id}", headers=headers)
    assert resp.status_code == 204, resp.text
    rows = await _rows_including_deleted(db_session, ids)
    batch_ids = {r.deletion_batch_id for r in rows}
    assert len(batch_ids) == 1 and None not in batch_ids, "records ride the zone's batch"

    restore = f"/api/v1/admin/trash/dns_record/{ids[0]}/restore"
    resp = await client.post(f"{restore}?skip_conflicts=true", headers=headers)
    assert resp.status_code == 422, resp.text
    assert "dns_zone" in resp.json()["detail"], resp.text
    # Nothing was restored on the way to the refusal.
    rows = await _rows_including_deleted(db_session, ids)
    assert all(r.deleted_at is not None for r in rows)

    # The whole-batch restore still works — that is the supported path here.
    resp = await client.post(restore, headers=headers)
    assert resp.status_code == 200, resp.text
    rows = await _rows_including_deleted(db_session, ids)
    assert all(r.deleted_at is None for r in rows)


@pytest.mark.asyncio
@pytest.mark.parametrize("permanent", [False, True])
async def test_serverless_group_deletes_like_the_singular_route_4368(
    client: AsyncClient, db_session: AsyncSession, permanent: bool
) -> None:
    """#4368: a group with no server has nothing to retract, so the records
    still go to the Trash (or are removed) instead of every one being skipped."""
    headers = await _user(db_session, superadmin=permanent)
    server, zone = await _agent_zone(db_session)
    await db_session.delete(server)
    await db_session.flush()
    ids = await _records(db_session, zone, 3)
    await db_session.commit()

    resp = await client.post(
        _url(zone, permanent=permanent),
        headers=headers,
        json={"record_ids": [str(i) for i in ids]},
    )
    assert resp.status_code == 200, resp.text
    body: dict[str, Any] = resp.json()
    assert body["deleted"] == 3 and body["skipped"] == [], body
    rows = await _rows_including_deleted(db_session, ids)
    if permanent:
        assert rows == []
        assert body["deletion_batch_id"] is None
    else:
        assert len(rows) == 3 and all(r.deleted_at is not None for r in rows)
        assert {str(r.deletion_batch_id) for r in rows} == {body["deletion_batch_id"]}
