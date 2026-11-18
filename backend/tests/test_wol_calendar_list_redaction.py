"""The calendar list serves the schedule editor's picker without addresses."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import Group, Role, User
from app.models.wol_schedule import WolCalendar


async def _user_with(db: AsyncSession, perms: list[dict]) -> dict[str, str]:
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:6]}@x.com",
        display_name="U",
        hashed_password=hash_password("x"),
    )
    role = Role(name=f"r-{uuid.uuid4().hex[:6]}", permissions=perms)
    grp = Group(name=f"g-{uuid.uuid4().hex[:6]}")
    grp.roles = [role]
    db.add_all([u, role, grp])
    u.groups = [grp]
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


@pytest.mark.asyncio
async def test_calendar_list_hides_address_from_schedule_readers(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    db_session.add(
        WolCalendar(
            name="cal",
            kind="ical",
            url="https://cal.example/feed?token=abc",
            username="svc",
        )
    )
    await db_session.flush()
    sched = await _user_with(db_session, [{"action": "read", "resource_type": "wol_schedule"}])
    cal = await _user_with(db_session, [{"action": "read", "resource_type": "wol_calendar"}])

    r = await client.get("/api/v1/wake-scheduler/calendars", headers=sched)
    assert r.status_code == 200, r.text
    row = r.json()[0]
    assert row["name"] == "cal" and row["url"] == "" and row["username"] is None

    r = await client.get("/api/v1/wake-scheduler/calendars", headers=cal)
    assert r.json()[0]["url"] == "https://cal.example/feed?token=abc"
    assert r.json()[0]["username"] == "svc"
