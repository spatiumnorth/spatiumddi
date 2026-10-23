"""PUT /ai/tools/catalog is audited with a diff of the tools it changed (#2300)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.services.ai.tools import REGISTRY

pytestmark = pytest.mark.asyncio

KEY = "ai_tools_catalog"


async def _admin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"u-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="Root",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _rows(db: AsyncSession) -> list[AuditLog]:
    res = await db.execute(select(AuditLog).where(AuditLog.resource_id == KEY))
    return list(res.scalars().all())


def _reads() -> tuple[set[str], set[str]]:
    reads = [t for t in REGISTRY.all() if not t.writes]
    return (
        {t.name for t in reads if t.default_enabled},
        {t.name for t in reads if not t.default_enabled},
    )


async def test_enabling_a_default_off_tool_is_audited_as_a_diff(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    defaults, off = _reads()
    extra = sorted(off)[0]
    r = await client.put(
        "/api/v1/ai/tools/catalog", json={"enabled": sorted(defaults | {extra})}, headers=h
    )
    assert r.status_code == 200
    rows = await _rows(db_session)
    assert len(rows) == 1
    row = rows[0]
    assert row.user_display_name == "Root"
    assert row.new_value["enabled"] == [extra]
    assert row.new_value["disabled"] == []


async def test_disabling_reports_only_the_removed_tools(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    defaults, _ = _reads()
    dropped = sorted(defaults)[0]
    r = await client.put(
        "/api/v1/ai/tools/catalog", json={"enabled": sorted(defaults - {dropped})}, headers=h
    )
    assert r.status_code == 200
    (row,) = await _rows(db_session)
    assert row.new_value["disabled"] == [dropped]
    assert row.new_value["enabled"] == []


async def test_repeating_the_same_write_adds_no_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    defaults, off = _reads()
    body = {"enabled": sorted(defaults | {sorted(off)[0]})}
    assert (await client.put("/api/v1/ai/tools/catalog", json=body, headers=h)).status_code == 200
    assert (await client.put("/api/v1/ai/tools/catalog", json=body, headers=h)).status_code == 200
    assert len(await _rows(db_session)) == 1
