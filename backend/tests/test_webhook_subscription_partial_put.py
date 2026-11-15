"""PUT /webhooks/{id} applies only the keys it carries (#4236).

The Edit dialog sends the fields the operator changed. A field another client
stored since the dialog read the subscription must survive that Save.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User

_SUBS = "/api/v1/webhooks"


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"wh-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Webhook Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def test_partial_put_leaves_unsent_fields_as_stored(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    created = await client.post(
        _SUBS,
        headers=headers,
        json={
            "name": "partial",
            "description": "other client's text",
            "enabled": False,
            "url": "https://192.0.2.11/b",
            "event_types": ["subnet.created"],
            "timeout_seconds": 7,
            "max_attempts": 3,
        },
    )
    assert created.status_code == 201, created.text
    sid = created.json()["id"]

    resp = await client.put(f"{_SUBS}/{sid}", headers=headers, json={"max_attempts": 4})
    assert resp.status_code == 200, resp.text

    got = (await client.get(f"{_SUBS}/{sid}", headers=headers)).json()
    assert got["max_attempts"] == 4
    assert got["name"] == "partial"
    assert got["description"] == "other client's text"
    assert got["enabled"] is False
    assert got["url"] == "https://192.0.2.11/b"
    assert got["event_types"] == ["subnet.created"]
    assert got["timeout_seconds"] == 7
    assert got["secret_set"] is True

    # An explicit null event filter still means "all events".
    resp = await client.put(f"{_SUBS}/{sid}", headers=headers, json={"event_types": None})
    assert resp.status_code == 200, resp.text
    assert resp.json()["event_types"] is None
    assert resp.json()["max_attempts"] == 4


async def test_partial_put_url_change_with_stored_headers_still_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    created = await client.post(
        _SUBS,
        headers=headers,
        json={
            "name": "guarded",
            "url": "https://192.0.2.11/b",
            "headers": {"X-Token": "fixture-not-real"},
        },
    )
    sid = created.json()["id"]

    moved = await client.put(
        f"{_SUBS}/{sid}", headers=headers, json={"url": "https://192.0.2.12/c"}
    )
    assert moved.status_code == 422, moved.text
    # An unrelated partial Save does not trip the guard.
    ok = await client.put(f"{_SUBS}/{sid}", headers=headers, json={"max_attempts": 2})
    assert ok.status_code == 200, ok.text
    assert ok.json()["headers_set"] is True
