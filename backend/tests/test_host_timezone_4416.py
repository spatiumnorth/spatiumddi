"""Host time zone aliases (#4416): the API stores a name the host applies."""

from __future__ import annotations

import re
import uuid
import zoneinfo
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services.host_timezone import HOST_TZ_ALIASES, canonical_host_timezone


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="superadmin",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    if await db.get(PlatformSettings, 1) is None:
        db.add(PlatformSettings(id=1))
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("sent", "stored"),
    [
        ("US/Pacific", "America/Los_Angeles"),
        ("Asia/Calcutta", "Asia/Kolkata"),
        ("Europe/Kyiv", "Europe/Kyiv"),
        ("UTC", "UTC"),
    ],
)
async def test_put_settings_stores_the_name_the_host_applies(
    client: AsyncClient, db_session: AsyncSession, sent: str, stored: str
) -> None:
    headers = await _superadmin(db_session)
    r = await client.put("/api/v1/settings", headers=headers, json={"timezone": sent})
    assert r.status_code == 200, r.text
    assert r.json()["timezone"] == stored


@pytest.mark.asyncio
async def test_put_settings_still_refuses_a_bogus_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    r = await client.put("/api/v1/settings", headers=headers, json={"timezone": "Mars/Base"})
    assert r.status_code == 422


def test_alias_table_is_well_formed() -> None:
    for alias, canon in HOST_TZ_ALIASES.items():
        zoneinfo.ZoneInfo(alias)
        zoneinfo.ZoneInfo(canon)
        assert canon not in HOST_TZ_ALIASES, f"{alias} -> {canon} is not canonical"
    assert canonical_host_timezone("America/Chicago") == "America/Chicago"


def test_frontend_alias_table_mirrors_the_backend() -> None:
    ts = Path(__file__).resolve().parents[2] / "frontend/src/lib/hostTimezones.ts"
    if not ts.exists():  # the backend image does not carry the frontend tree
        pytest.skip("frontend sources not mounted")
    # prettier unquotes keys that are plain identifiers (``CET: ...``).
    pairs = dict(re.findall(r'^  "?([\w/+-]+)"?: "(.+)",$', ts.read_text(), re.M))
    assert pairs == HOST_TZ_ALIASES
