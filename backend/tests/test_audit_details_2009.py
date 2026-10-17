"""#2009: the audit API returns an entry's recorded details, redacted."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User

pytestmark = pytest.mark.asyncio

_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"


async def _admin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"a-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _entry(db: AsyncSession) -> AuditLog:
    row = AuditLog(
        action="appliance.upgrade_scheduled",
        resource_type="appliance",
        resource_id=str(uuid.uuid4()),
        resource_display="node-1",
        user_display_name="alice",
        auth_source="local",
        result="success",
        old_value={"api_key": "hunter2"},
        new_value={
            "direction": "backward",
            "schema_check": {"ok": False, "reason": "newer schema"},
            "desired_slot_image_url": "https://x/img",
            "registry_password": "s3cret",
            "note": f"token {_JWT}",
            "nested": [{"psk": "abcd"}],
        },
        changed_fields=["desired_appliance_version"],
    )
    db.add(row)
    await db.commit()
    return row


async def test_single_entry_returns_details_with_secrets_redacted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    row = await _entry(db_session)
    r = await client.get(f"/api/v1/audit/{row.id}", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    nv = body["new_value"]
    assert nv["direction"] == "backward"
    assert nv["schema_check"] == {"ok": False, "reason": "newer schema"}
    assert body["changed_fields"] == ["desired_appliance_version"]
    assert nv["registry_password"] == "[redacted]"
    assert nv["nested"][0]["psk"] == "[redacted]"
    assert body["old_value"]["api_key"] == "[redacted]"
    assert _JWT not in r.text and "s3cret" not in r.text and "hunter2" not in r.text


async def test_list_omits_details_unless_asked(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    await _entry(db_session)
    plain = (await client.get("/api/v1/audit", headers=h)).json()["items"][0]
    assert plain["new_value"] is None
    full = (await client.get("/api/v1/audit?include_details=true", headers=h)).json()["items"][0]
    assert full["new_value"]["direction"] == "backward"
    assert full["new_value"]["registry_password"] == "[redacted]"


async def test_unknown_entry_is_404(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _admin(db_session)
    await db_session.commit()
    r = await client.get(f"/api/v1/audit/{uuid.uuid4()}", headers=h)
    assert r.status_code == 404
