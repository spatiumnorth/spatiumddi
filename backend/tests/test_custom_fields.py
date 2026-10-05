"""Tests for custom field definitions CRUD and its audit trail (#1584).

Every mutation must write an ``audit_log`` row before the response is
returned (non-negotiable #4); these tests pin the create / update /
delete rows for ``/api/v1/custom-fields``.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User


async def _make_user(db: AsyncSession) -> tuple[User, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password(uuid.uuid4().hex),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user, create_access_token(str(user.id))


async def _audit_rows(db: AsyncSession, resource_id: str) -> list[AuditLog]:
    return list(
        (
            await db.execute(
                select(AuditLog)
                .where(
                    AuditLog.resource_type == "custom_field",
                    AuditLog.resource_id == resource_id,
                )
                .order_by(AuditLog.seq)
            )
        )
        .scalars()
        .all()
    )


@pytest.mark.asyncio
async def test_crud_roundtrip_writes_audit_log(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_user(db_session)
    h = {"Authorization": f"Bearer {token}"}

    body = {
        "resource_type": "subnet",
        "name": "owner_team",
        "label": "Owner team",
        "field_type": "text",
    }
    r = await client.post("/api/v1/custom-fields", headers=h, json=body)
    assert r.status_code == 201, r.text
    field_id = r.json()["id"]

    r = await client.put(
        f"/api/v1/custom-fields/{field_id}",
        headers=h,
        json={"label": "Owning team", "is_required": True},
    )
    assert r.status_code == 200, r.text
    assert r.json()["label"] == "Owning team"

    r = await client.delete(f"/api/v1/custom-fields/{field_id}", headers=h)
    assert r.status_code == 204

    rows = await _audit_rows(db_session, field_id)
    assert [row.action for row in rows] == ["create", "update", "delete"]
    create_row, update_row, delete_row = rows
    assert create_row.old_value is None
    assert create_row.new_value is not None
    assert create_row.new_value["name"] == "owner_team"
    assert create_row.new_value["resource_type"] == "subnet"
    assert update_row.old_value is not None and update_row.new_value is not None
    assert update_row.old_value["label"] == "Owner team"
    assert update_row.new_value["label"] == "Owning team"
    assert update_row.new_value["is_required"] is True
    assert sorted(update_row.changed_fields or []) == ["is_required", "label"]
    assert delete_row.old_value is not None
    assert delete_row.old_value["name"] == "owner_team"
    assert delete_row.new_value is None


@pytest.mark.asyncio
async def test_duplicate_create_writes_no_audit_log(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_user(db_session)
    h = {"Authorization": f"Bearer {token}"}
    body = {
        "resource_type": "subnet",
        "name": "cost_centre",
        "label": "Cost centre",
        "field_type": "text",
    }
    r = await client.post("/api/v1/custom-fields", headers=h, json=body)
    assert r.status_code == 201, r.text
    field_id = r.json()["id"]

    r = await client.post("/api/v1/custom-fields", headers=h, json=body)
    assert r.status_code == 409, r.text

    rows = await _audit_rows(db_session, field_id)
    assert [row.action for row in rows] == ["create"]
