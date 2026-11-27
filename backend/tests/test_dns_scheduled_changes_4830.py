"""Scheduled DNS record changes (#4830).

A record create / update / delete held until a set time. The API stores and
lists it, the due sweep replays it through the normal record handlers (so the
op queue and the record's audit row are the live ones), and a zone or record
moving to the Trash cancels it for good.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.celery_app import celery_app
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.dns import (
    DNSRecord,
    DNSRecordOp,
    DNSScheduledChange,
    DNSServer,
    DNSServerGroup,
    DNSZone,
)
from app.services.ai.tools.dns import FindScheduledDnsChangesArgs, find_scheduled_dns_changes
from app.services.dns import scheduled_changes

# ── helpers ─────────────────────────────────────────────────────────────────


def _hdr(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _user(db: AsyncSession, permissions: list[dict] | None = None) -> User:
    """A superadmin, or (``permissions`` given) a holder of exactly those."""
    # The tests read ids and names off rows after several commits, with the API
    # and the sweep running on this same session.
    db.sync_session.expire_on_commit = False
    user = User(
        username=f"sc-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Scheduler",
        hashed_password=hash_password("x"),
        is_superadmin=permissions is None,
    )
    user.groups = []
    if permissions is not None:
        role = Role(name=f"r-{uuid.uuid4().hex[:8]}", permissions=permissions)
        group = Group(name=f"g-{uuid.uuid4().hex[:8]}")
        group.roles = [role]
        user.groups = [group]
        db.add_all([role, group])
    db.add(user)
    await db.flush()
    return user


async def _zone(db: AsyncSession) -> DNSZone:
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
    return zone


async def _rec(db: AsyncSession, zone: DNSZone, name: str = "www", value: str = "192.0.2.1"):
    rec = DNSRecord(
        zone_id=zone.id,
        name=name,
        fqdn=f"{name}.{zone.name}",
        record_type="A",
        value=value,
        ttl=300,
    )
    db.add(rec)
    await db.flush()
    return rec


def _base(zone: DNSZone) -> str:
    return f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/scheduled-changes"


def _when(minutes: int = 60) -> str:
    return (datetime.now(UTC) + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")


async def _schedule(client: AsyncClient, zone: DNSZone, user: User, **body: Any):
    body.setdefault("scheduled_at", _when())
    return await client.post(_base(zone), headers=_hdr(user), json=body)


async def _make_due(db: AsyncSession, change_id: str) -> None:
    """Move a pending change's time into the past, as time passing would."""
    await db.execute(
        update(DNSScheduledChange)
        .where(DNSScheduledChange.id == uuid.UUID(change_id))
        .values(scheduled_at=datetime.now(UTC) - timedelta(seconds=5))
    )
    await db.commit()


async def _state(db: AsyncSession, change_id: str) -> DNSScheduledChange:
    row = (
        await db.execute(
            select(DNSScheduledChange)
            .where(DNSScheduledChange.id == uuid.UUID(change_id))
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    return row


async def _records(db: AsyncSession, zone: DNSZone | uuid.UUID) -> list[DNSRecord]:
    # A rollback in the sweep expires the zone, so a test may pass its id instead.
    zone_id = zone if isinstance(zone, uuid.UUID) else zone.id
    return list(
        (await db.execute(select(DNSRecord).where(DNSRecord.zone_id == zone_id))).scalars().all()
    )


async def _audit_actions(db: AsyncSession, resource_type: str) -> list[str]:
    rows = await db.execute(select(AuditLog.action).where(AuditLog.resource_type == resource_type))
    return sorted(rows.scalars().all())


CREATE = {"name": "new", "record_type": "A", "value": "192.0.2.50", "ttl": 120}

# ── scheduling: API contract ────────────────────────────────────────────────


async def test_schedule_create_holds_the_record_back_and_audits(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user = await _user(db_session)
    zone = await _zone(db_session)
    await db_session.commit()

    resp = await _schedule(client, zone, user, action="create", record=CREATE)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["state"] == "pending" and body["action"] == "create"
    assert body["scheduled_at"].endswith("Z") or body["scheduled_at"].endswith("+00:00")
    assert body["record_label"] == f"new.{zone.name} A"
    # Nothing is written, and nothing is queued for any server, until it runs.
    assert await _records(db_session, zone) == []
    ops = (await db_session.execute(select(DNSRecordOp))).scalars().all()
    assert ops == []
    assert await _audit_actions(db_session, "dns_scheduled_change") == ["schedule"]

    got = await client.get(f"{_base(zone)}/{body['id']}", headers=_hdr(user))
    assert got.status_code == 200 and got.json()["id"] == body["id"]
    listed = await client.get(_base(zone), headers=_hdr(user), params={"state": "pending"})
    assert listed.json()["total"] == 1


async def test_bad_input_is_a_422_and_unknown_ids_a_404(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user = await _user(db_session)
    zone = await _zone(db_session)
    rec = await _rec(db_session, zone)
    await db_session.commit()

    naive = (datetime.now(UTC) + timedelta(hours=1)).replace(tzinfo=None).isoformat()
    past = _when(-5)
    far = _when(60 * 24 * 400)
    for when, why in ((naive, "offset"), (past, "future"), (far, "days ahead")):
        resp = await _schedule(
            client, zone, user, action="create", record=CREATE, scheduled_at=when
        )
        assert resp.status_code == 422, (why, resp.text)
        assert why in resp.text
    # shape: a create takes a record, an update/delete a record_id
    for bad in (
        {"action": "create"},
        {"action": "create", "record": CREATE, "record_id": str(rec.id)},
        {"action": "update", "record_id": str(rec.id)},
        {"action": "update", "record_id": str(rec.id), "changes": {}},
        {"action": "delete"},
        {"action": "delete", "record_id": str(rec.id), "record": CREATE},
        {"action": "explode", "record_id": str(rec.id)},
    ):
        resp = await _schedule(client, zone, user, **bad)
        assert resp.status_code == 422, (bad, resp.text)
    # a bad value is refused now, not at run time
    resp = await _schedule(
        client, zone, user, action="create", record={**CREATE, "value": "not-an-ip"}
    )
    assert resp.status_code == 422, resp.text
    # unknown / foreign ids
    resp = await _schedule(client, zone, user, action="delete", record_id=str(uuid.uuid4()))
    assert resp.status_code == 404
    other = await _zone(db_session)
    other_rec = await _rec(db_session, other)
    await db_session.commit()
    resp = await _schedule(client, zone, user, action="delete", record_id=str(other_rec.id))
    assert resp.status_code == 404  # a record of another zone is not this zone's
    resp = await client.get(f"{_base(zone)}/{uuid.uuid4()}", headers=_hdr(user))
    assert resp.status_code == 404
    resp = await client.post(f"{_base(zone)}/{uuid.uuid4()}/cancel", headers=_hdr(user))
    assert resp.status_code == 404
    resp = await client.get(_base(zone), headers=_hdr(user), params={"state": "bogus"})
    assert resp.status_code == 422
    resp = await client.get(_base(zone), headers=_hdr(user), params={"action": "bogus"})
    assert resp.status_code == 422
    unknown_zone = _base(zone).replace(str(zone.id), str(uuid.uuid4()))
    assert (await client.get(unknown_zone, headers=_hdr(user))).status_code == 404
    assert (await _audit_actions(db_session, "dns_scheduled_change")) == []


async def test_permissions_are_refused_not_500(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    zone = await _zone(db_session)
    rec = await _rec(db_session, zone)
    reader = await _user(db_session, [{"action": "read", "resource_type": "dns_record"}])
    writer = await _user(
        db_session,
        [
            {"action": "read", "resource_type": "dns_record"},
            {"action": "write", "resource_type": "dns_record"},
        ],
    )
    nobody = await _user(db_session, [{"action": "read", "resource_type": "subnet"}])
    await db_session.commit()

    # no DNS grant at all: refused at the gate, lists included
    assert (await client.get(_base(zone), headers=_hdr(nobody))).status_code == 403
    assert (
        await _schedule(client, zone, nobody, action="create", record=CREATE)
    ).status_code == 403
    # read-only: may look, may not schedule
    assert (await client.get(_base(zone), headers=_hdr(reader))).status_code == 200
    assert (
        await _schedule(client, zone, reader, action="create", record=CREATE)
    ).status_code == 403
    # write without delete: a scheduled delete needs the delete grant
    assert (
        await _schedule(client, zone, writer, action="delete", record_id=str(rec.id))
    ).status_code == 403
    ok = await _schedule(client, zone, writer, action="create", record=CREATE)
    assert ok.status_code == 201, ok.text
    # a reader cannot cancel or edit it
    cid = ok.json()["id"]
    assert (
        await client.post(f"{_base(zone)}/{cid}/cancel", headers=_hdr(reader))
    ).status_code == 403
    assert (
        await client.put(
            f"{_base(zone)}/{cid}", headers=_hdr(reader), json={"scheduled_at": _when(5)}
        )
    ).status_code == 403


async def test_edit_and_cancel_only_while_pending(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user = await _user(db_session)
    zone = await _zone(db_session)
    await db_session.commit()
    cid = (await _schedule(client, zone, user, action="create", record=CREATE)).json()["id"]
    url = f"{_base(zone)}/{cid}"

    assert (await client.put(url, headers=_hdr(user), json={})).status_code == 422
    new_when = _when(180)
    resp = await client.put(url, headers=_hdr(user), json={"scheduled_at": new_when})
    assert resp.status_code == 200, resp.text
    assert (await _state(db_session, cid)).scheduled_at > datetime.now(UTC) + timedelta(minutes=170)
    resp = await client.put(
        url, headers=_hdr(user), json={"record": {**CREATE, "value": "192.0.2.99"}}
    )
    assert resp.status_code == 200 and resp.json()["payload"]["value"] == "192.0.2.99"
    # wrong content kind for the action
    resp = await client.put(url, headers=_hdr(user), json={"changes": {"ttl": 5}})
    assert resp.status_code == 422
    assert (
        await client.put(url, headers=_hdr(user), json={"scheduled_at": _when(-1)})
    ).status_code == 422

    resp = await client.post(f"{url}/cancel", headers=_hdr(user))
    assert resp.status_code == 200 and resp.json()["state"] == "cancelled"
    assert (await client.post(f"{url}/cancel", headers=_hdr(user))).status_code == 409
    assert (
        await client.put(url, headers=_hdr(user), json={"scheduled_at": _when(5)})
    ).status_code == 409
    # a cancelled change never runs, however late
    await db_session.execute(
        update(DNSScheduledChange).values(scheduled_at=datetime.now(UTC) - timedelta(hours=1))
    )
    await db_session.commit()
    counts = await scheduled_changes.run_due(db_session)
    assert counts["executed"] == 0 and await _records(db_session, zone) == []
    assert await _audit_actions(db_session, "dns_scheduled_change") == [
        "schedule",
        "scheduled_cancel",
        "update",
        "update",
    ]


async def test_list_paginates_and_filters(client: AsyncClient, db_session: AsyncSession) -> None:
    user = await _user(db_session)
    zone = await _zone(db_session)
    rec = await _rec(db_session, zone)
    await db_session.commit()
    for i in range(3):
        r = await _schedule(
            client,
            zone,
            user,
            action="create",
            record={**CREATE, "name": f"n{i}"},
            scheduled_at=_when(10 + i),
        )
        assert r.status_code == 201
    await _schedule(client, zone, user, action="delete", record_id=str(rec.id))
    page = await client.get(_base(zone), headers=_hdr(user), params={"page_size": 2, "page": 2})
    body = page.json()
    assert body["total"] == 4 and len(body["items"]) == 2 and body["page"] == 2
    only = await client.get(_base(zone), headers=_hdr(user), params={"record_id": str(rec.id)})
    assert only.json()["total"] == 1 and only.json()["items"][0]["action"] == "delete"
    only = await client.get(_base(zone), headers=_hdr(user), params={"action": "create"})
    assert only.json()["total"] == 3
    assert (
        await client.get(_base(zone), headers=_hdr(user), params={"page_size": 0})
    ).status_code == 422


# ── execution ───────────────────────────────────────────────────────────────


async def test_due_create_runs_through_the_record_path_once(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user = await _user(db_session)
    zone = await _zone(db_session)
    await db_session.commit()
    zone_id = zone.id
    cid = (await _schedule(client, zone, user, action="create", record=CREATE)).json()["id"]

    # Not due yet: the sweep leaves it.
    assert (await scheduled_changes.run_due(db_session))["executed"] == 0
    assert await _records(db_session, zone) == []

    await _make_due(db_session, cid)
    assert (await scheduled_changes.run_due(db_session))["executed"] == 1
    recs = await _records(db_session, zone)
    assert [(r.name, r.value, r.ttl, r.created_by_user_id) for r in recs] == [
        ("new", "192.0.2.50", 120, user.id)
    ]
    # The RFC 2136 path: the op is queued for the zone's agent server.
    ops = (await db_session.execute(select(DNSRecordOp))).scalars().all()
    assert [(o.op, o.record["value"], o.state) for o in ops] == [
        ("create", "192.0.2.50", "pending")
    ]
    row = await _state(db_session, cid)
    assert row.state == "executed" and row.record_id == recs[0].id and row.finished_at
    assert await _audit_actions(db_session, "dns_record") == ["create"]
    assert await _audit_actions(db_session, "dns_scheduled_change") == [
        "schedule",
        "scheduled_execute",
    ]

    # A second sweep, or a second worker with the same id, runs nothing again.
    assert await scheduled_changes.run_change(db_session, uuid.UUID(cid)) == "skipped"
    assert (await scheduled_changes.run_due(db_session))["executed"] == 0
    assert len(await _records(db_session, zone_id)) == 1


async def test_due_update_and_delete(client: AsyncClient, db_session: AsyncSession) -> None:
    user = await _user(db_session)
    zone = await _zone(db_session)
    rec = await _rec(db_session, zone)
    gone = await _rec(db_session, zone, name="old", value="192.0.2.9")
    await db_session.commit()
    upd = await _schedule(
        client,
        zone,
        user,
        action="update",
        record_id=str(rec.id),
        changes={"value": "192.0.2.77", "ttl": None},
    )
    assert upd.status_code == 201, upd.text
    # an explicit null survives the round trip (it clears the TTL)
    assert upd.json()["payload"] == {"value": "192.0.2.77", "ttl": None}
    dele = await _schedule(client, zone, user, action="delete", record_id=str(gone.id))
    assert dele.status_code == 201, dele.text
    # both still there until due
    assert len(await _records(db_session, zone)) == 2
    await _make_due(db_session, upd.json()["id"])
    await _make_due(db_session, dele.json()["id"])
    counts = await scheduled_changes.run_due(db_session)
    assert counts["executed"] == 2, counts

    await db_session.refresh(rec)
    assert rec.value == "192.0.2.77" and rec.ttl is None
    live = await _records(db_session, zone)
    assert [r.name for r in live] == ["www"]  # the other is in the Trash
    trashed = (
        await db_session.execute(
            select(DNSRecord).where(DNSRecord.id == gone.id).execution_options(include_deleted=True)
        )
    ).scalar_one()
    assert trashed.deleted_at is not None
    ops = sorted(
        (o.op, o.record["value"])
        for o in (await db_session.execute(select(DNSRecordOp))).scalars().all()
    )
    assert ops == [("delete", "192.0.2.9"), ("update", "192.0.2.77")]


async def test_a_record_edited_since_scheduling_is_not_overwritten(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user = await _user(db_session)
    zone = await _zone(db_session)
    rec = await _rec(db_session, zone)
    await db_session.commit()
    cid = (
        await _schedule(
            client, zone, user, action="update", record_id=str(rec.id), changes={"ttl": 60}
        )
    ).json()["id"]
    rec.value = "192.0.2.200"  # someone else edits it first
    await db_session.commit()
    await _make_due(db_session, cid)
    assert (await scheduled_changes.run_due(db_session))["failed"] == 1
    row = await _state(db_session, cid)
    assert row.state == "failed" and "changed after" in (row.result_message or "")
    await db_session.refresh(rec)
    assert rec.ttl == 300 and rec.value == "192.0.2.200"
    assert (await db_session.execute(select(DNSRecordOp))).scalars().all() == []
    assert "scheduled_execute" in await _audit_actions(db_session, "dns_scheduled_change")


async def test_a_refused_change_fails_cleanly(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The twin check is judged when it runs: the change fails, the row records why."""
    user = await _user(db_session)
    zone = await _zone(db_session)
    await db_session.commit()
    zone_id = zone.id
    cid = (await _schedule(client, zone, user, action="create", record=CREATE)).json()["id"]
    await _rec(db_session, zone, name="new", value="192.0.2.50")  # the same RR appears first
    await db_session.commit()
    await _make_due(db_session, cid)
    assert (await scheduled_changes.run_due(db_session))["failed"] == 1
    row = await _state(db_session, cid)
    assert row.state == "failed" and row.result_message and "Refused" in row.result_message
    assert len(await _records(db_session, zone_id)) == 1


async def test_the_scheduler_is_held_to_its_permissions_at_run_time(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    zone = await _zone(db_session)
    writer = await _user(db_session, [{"action": "write", "resource_type": "dns_record"}])
    await db_session.commit()
    cid = (await _schedule(client, zone, writer, action="create", record=CREATE)).json()["id"]
    writer.is_active = False  # off-boarded before the change ran
    await db_session.commit()
    await _make_due(db_session, cid)
    assert (await scheduled_changes.run_due(db_session))["failed"] == 1
    row = await _state(db_session, cid)
    assert "inactive" in (row.result_message or "")
    assert await _records(db_session, zone) == []


async def test_a_dead_worker_claim_is_settled_not_replayed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user = await _user(db_session)
    zone = await _zone(db_session)
    await db_session.commit()
    cid = (await _schedule(client, zone, user, action="create", record=CREATE)).json()["id"]
    await db_session.execute(
        update(DNSScheduledChange).values(
            state="running", started_at=datetime.now(UTC) - timedelta(hours=1)
        )
    )
    await db_session.commit()
    counts = await scheduled_changes.run_due(db_session)
    assert counts["stuck"] == 1 and counts["executed"] == 0
    row = await _state(db_session, cid)
    assert row.state == "failed" and "stopped" in (row.result_message or "")
    assert await _records(db_session, zone) == []
    # a live claim is left alone
    cid2 = (await _schedule(client, zone, user, action="create", record=CREATE)).json()["id"]
    await db_session.execute(
        update(DNSScheduledChange)
        .where(DNSScheduledChange.id == uuid.UUID(cid2))
        .values(state="running", started_at=datetime.now(UTC))
    )
    await db_session.commit()
    assert (await scheduled_changes.run_due(db_session))["stuck"] == 0
    assert (await _state(db_session, cid2)).state == "running"


# ── Trash ───────────────────────────────────────────────────────────────────


async def test_trashing_the_zone_cancels_and_a_restore_does_not_rearm(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user = await _user(db_session)
    zone = await _zone(db_session)
    rec = await _rec(db_session, zone)
    await db_session.commit()
    a = (await _schedule(client, zone, user, action="create", record=CREATE)).json()["id"]
    b = (await _schedule(client, zone, user, action="delete", record_id=str(rec.id))).json()["id"]
    zone_id, group_id = zone.id, zone.group_id

    resp = await client.delete(f"/api/v1/dns/groups/{group_id}/zones/{zone_id}", headers=_hdr(user))
    assert resp.status_code in (200, 204), resp.text

    # hidden from every read while the zone is in the Trash
    assert (await client.get(_base(zone), headers=_hdr(user))).status_code == 404
    tool = await find_scheduled_dns_changes(db_session, user, FindScheduledDnsChangesArgs())
    assert tool == []
    for cid in (a, b):
        row = await _state(db_session, cid)
        assert row.state == "cancelled" and "Trash" in (row.result_message or "")
    # and nothing runs
    await _make_due(db_session, a)
    assert (await scheduled_changes.run_due(db_session))["executed"] == 0

    # a trashed zone refuses a new change
    resp = await _schedule(client, zone, user, action="create", record=CREATE)
    assert resp.status_code == 404

    restored = await client.post(
        f"/api/v1/admin/trash/dns_zone/{zone_id}/restore", headers=_hdr(user)
    )
    assert restored.status_code == 200, restored.text
    # back in view, still cancelled, and still not run
    listed = await client.get(_base(zone), headers=_hdr(user))
    assert {i["id"]: i["state"] for i in listed.json()["items"]} == {
        a: "cancelled",
        b: "cancelled",
    }
    assert (await scheduled_changes.run_due(db_session))["executed"] == 0
    assert [r.name for r in await _records(db_session, zone_id)] == ["www"]
    tool = await find_scheduled_dns_changes(db_session, user, FindScheduledDnsChangesArgs())
    assert {t["state"] for t in tool} == {"cancelled"}


async def test_trashing_one_record_cancels_only_its_changes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user = await _user(db_session)
    zone = await _zone(db_session)
    r1 = await _rec(db_session, zone, name="one")
    r2 = await _rec(db_session, zone, name="two", value="192.0.2.2")
    await db_session.commit()
    c1 = (
        await _schedule(
            client, zone, user, action="update", record_id=str(r1.id), changes={"ttl": 1}
        )
    ).json()["id"]
    c2 = (
        await _schedule(
            client, zone, user, action="update", record_id=str(r2.id), changes={"ttl": 2}
        )
    ).json()["id"]
    resp = await client.delete(
        f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/records/{r1.id}", headers=_hdr(user)
    )
    assert resp.status_code == 204, resp.text
    assert (await _state(db_session, c1)).state == "cancelled"
    assert (await _state(db_session, c2)).state == "pending"
    # trashed record: a new change against it is a 404
    resp = await _schedule(client, zone, user, action="delete", record_id=str(r1.id))
    assert resp.status_code == 404
    # restoring the record does not re-arm the cancelled change
    restored = await client.post(
        f"/api/v1/admin/trash/dns_record/{r1.id}/restore", headers=_hdr(user)
    )
    assert restored.status_code == 200, restored.text
    await _make_due(db_session, c1)
    await _make_due(db_session, c2)
    counts = await scheduled_changes.run_due(db_session)
    assert counts["executed"] == 1
    await db_session.refresh(r1)
    await db_session.refresh(r2)
    assert r1.ttl == 300 and r2.ttl == 2


async def test_a_change_that_outlives_its_target_is_cancelled_at_run_time(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A record removed by a path that does not go through the Trash batch (a
    purge) cannot be updated: the change is cancelled, not run or crashed."""
    user = await _user(db_session)
    zone = await _zone(db_session)
    rec = await _rec(db_session, zone)
    await db_session.commit()
    cid = (
        await _schedule(
            client, zone, user, action="update", record_id=str(rec.id), changes={"ttl": 1}
        )
    ).json()["id"]
    await db_session.delete(rec)
    await db_session.commit()
    await _make_due(db_session, cid)
    assert (await scheduled_changes.run_due(db_session))["cancelled"] == 1
    row = await _state(db_session, cid)
    assert row.state == "cancelled" and row.record_id is None


# ── MCP + beat ──────────────────────────────────────────────────────────────


async def test_the_copilot_tool_filters_and_scopes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user = await _user(db_session)
    z1 = await _zone(db_session)
    z2 = await _zone(db_session)
    await db_session.commit()
    await _schedule(client, z1, user, action="create", record=CREATE)
    await _schedule(client, z2, user, action="create", record=CREATE)
    every = await find_scheduled_dns_changes(db_session, user, FindScheduledDnsChangesArgs())
    assert len(every) == 2
    one = await find_scheduled_dns_changes(
        db_session, user, FindScheduledDnsChangesArgs(zone_id=str(z1.id), state="pending")
    )
    assert [r["zone_name"] for r in one] == [z1.name]
    assert one[0]["fields"]["value"] == "192.0.2.50" and one[0]["action"] == "create"
    none = await find_scheduled_dns_changes(
        db_session, user, FindScheduledDnsChangesArgs(state="executed")
    )
    assert none == []


def test_the_args_refuse_an_unknown_state() -> None:
    import pytest

    with pytest.raises(ValueError):
        FindScheduledDnsChangesArgs(state="soon")


def test_the_sweep_is_scheduled_and_gated_on_core_dns() -> None:
    celery_app.loader.import_default_modules()
    entry = celery_app.conf.beat_schedule["dns-scheduled-changes"]
    assert entry["task"] == "app.tasks.dns_scheduled_changes.run_due"
    task = celery_app.tasks[entry["task"]]
    assert getattr(task.run, "__module_gate__", None) == "core.dns"
