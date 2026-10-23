"""Webhook subscription CRUD + delivery retry write audit rows (#2293)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from urllib.parse import urlsplit

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.event_subscription import EventOutbox

_SUBS = "/api/v1/webhooks"
# Sentinels: none may ever appear in an audit row.
_SECRET = "SENTINEL-hmac-secret-2293"
_HDR = "SENTINEL-bearer-2293"
_PATH_TOKEN = "SENTINEL-path-token-2293"
_SECRET2 = "SENTINEL-rotated-secret-2293"


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"wha-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Webhook Auditor",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _rows(db: AsyncSession, rtype: str, rid: str) -> list[AuditLog]:
    res = await db.execute(
        select(AuditLog)
        .where(AuditLog.resource_type == rtype, AuditLog.resource_id == rid)
        .order_by(AuditLog.timestamp)
    )
    return list(res.scalars().all())


def _no_secrets(rows: list[AuditLog]) -> None:
    blob = json.dumps([[r.old_value, r.new_value, r.resource_display] for r in rows], default=str)
    for s in (_SECRET, _HDR, _PATH_TOKEN, _SECRET2):
        assert s not in blob


async def test_create_update_delete_each_write_one_audit_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    name = f"wh-{uuid.uuid4().hex[:6]}"
    url = f"https://receiver.example.test/hooks/{_PATH_TOKEN}"
    r = await client.post(
        _SUBS,
        headers=h,
        json={
            "name": name,
            "url": url,
            "secret": _SECRET,
            "headers": {"Authorization": f"Bearer {_HDR}"},
            "event_types": ["subnet.created"],
        },
    )
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    rows = await _rows(db_session, "event_subscription", sid)
    assert [x.action for x in rows] == ["create"]
    assert rows[0].new_value["name"] == name
    assert rows[0].new_value["secret_set"] is True
    assert rows[0].new_value["headers_set"] is True
    assert rows[0].new_value["event_types"] == ["subnet.created"]
    assert urlsplit(rows[0].new_value["url"]).hostname == "receiver.example.test"

    u = await client.put(
        f"{_SUBS}/{sid}",
        headers=h,
        json={
            "name": name,
            "url": "https://other.example.test/x",
            "secret": _SECRET2,
            "event_types": ["ip.allocated"],
        },
    )
    assert u.status_code == 200, u.text
    rows = await _rows(db_session, "event_subscription", sid)
    assert [x.action for x in rows] == ["create", "update"]
    upd = rows[1]
    assert upd.old_value["event_types"] == ["subnet.created"]
    assert upd.new_value["event_types"] == ["ip.allocated"]
    assert upd.new_value["url_changed"] is True
    assert upd.new_value["secret_rotated"] is True

    d = await client.delete(f"{_SUBS}/{sid}", headers=h)
    assert d.status_code == 204
    rows = await _rows(db_session, "event_subscription", sid)
    assert [x.action for x in rows] == ["create", "update", "delete"]
    assert rows[2].new_value is None
    assert rows[2].old_value["name"] == name
    _no_secrets(rows)


async def test_retry_writes_one_audit_row(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _admin(db_session)
    r = await client.post(
        _SUBS,
        headers=h,
        json={"name": f"wh-{uuid.uuid4().hex[:6]}", "url": "https://r.example.test/h"},
    )
    sid = uuid.UUID(r.json()["id"])
    row = EventOutbox(
        subscription_id=sid,
        event_type="subnet.created",
        payload={"secret_in_payload": _SECRET},
        state="dead",
        attempts=8,
        next_attempt_at=datetime.now(UTC),
    )
    db_session.add(row)
    await db_session.flush()

    resp = await client.post(f"{_SUBS}/deliveries/{row.id}/retry", headers=h)
    assert resp.status_code == 200, resp.text
    rows = await _rows(db_session, "event_outbox", str(row.id))
    assert [x.action for x in rows] == ["retry"]
    assert rows[0].old_value["state"] == "dead"
    assert rows[0].new_value["state"] == "pending"
    _no_secrets(rows)
