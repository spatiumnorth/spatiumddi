"""Diagnostics error mutations are audited (#2301)."""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.diagnostics import InternalError

FP = "f" * 64


async def _setup(db: AsyncSession) -> tuple[dict[str, str], InternalError, User]:
    user = User(
        username=f"u{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="n",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    err = InternalError(
        service="api",
        exception_class="ValueError",
        message="boom",
        traceback="tb",
        fingerprint=FP,
    )
    db.add(err)
    await db.flush()
    await db.commit()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    return headers, err, user


async def _rows(db: AsyncSession, action: str, err_id: uuid.UUID) -> list[AuditLog]:
    res = await db.execute(
        select(AuditLog).where(
            AuditLog.resource_type == "internal_error",
            AuditLog.resource_id == str(err_id),
            AuditLog.action == action,
        )
    )
    return list(res.scalars().all())


async def test_acknowledge_writes_one_audit_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, err, user = await _setup(db_session)
    err_id = err.id
    r = await client.post(f"/api/v1/diagnostics/errors/{err_id}/acknowledge", headers=headers)
    assert r.status_code == 200, r.text
    rows = await _rows(db_session, "acknowledge", err_id)
    assert len(rows) == 1
    assert rows[0].user_id == user.id
    assert rows[0].new_value["fingerprint"] == FP
    assert rows[0].new_value["exception_class"] == "ValueError"
    # a repeat acknowledge changes nothing, so adds nothing
    await client.post(f"/api/v1/diagnostics/errors/{err_id}/acknowledge", headers=headers)
    assert len(await _rows(db_session, "acknowledge", err_id)) == 1


async def test_suppress_records_the_duration(client: AsyncClient, db_session: AsyncSession) -> None:
    headers, err, _ = await _setup(db_session)
    err_id = err.id
    r = await client.post(
        f"/api/v1/diagnostics/errors/{err_id}/suppress", json={"hours": 48}, headers=headers
    )
    assert r.status_code == 200, r.text
    rows = await _rows(db_session, "suppress", err_id)
    assert len(rows) == 1
    assert rows[0].new_value["hours"] == 48
    assert rows[0].new_value["fingerprint"] == FP


async def test_delete_is_audited_after_the_row_is_gone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, err, _ = await _setup(db_session)
    err_id = err.id
    r = await client.delete(f"/api/v1/diagnostics/errors/{err_id}", headers=headers)
    assert r.status_code == 204, r.text
    assert await db_session.get(InternalError, err_id) is None
    rows = await _rows(db_session, "delete", err_id)
    assert len(rows) == 1
    assert rows[0].new_value["exception_class"] == "ValueError"
