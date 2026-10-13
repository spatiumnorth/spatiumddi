"""#1836: the Security dashboard counts the sign-ins the audit log records.

The panel filtered ``result == "denied"`` but ``/auth/login`` writes
``"failure"`` for a bad credential, so a real failed sign-in never showed.
Seeded rows would have hidden that, so this drives the real endpoint.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.settings import PlatformSettings

_PASSWORD = "Sup3r-secret!"


@pytest.mark.asyncio
async def test_real_failed_signin_is_counted_on_security_dashboard(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    if await db_session.get(PlatformSettings, 1) is None:
        db_session.add(PlatformSettings(id=1))
    admin = User(
        username=f"adm-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@x.com",
        display_name="Admin",
        hashed_password=hash_password(_PASSWORD),
        auth_source="local",
        is_active=True,
        is_superadmin=True,
        force_password_change=False,
        password_changed_at=datetime.now(UTC),
    )
    db_session.add(admin)
    await db_session.commit()

    for _ in range(2):
        bad = await client.post(
            "/api/v1/auth/login", json={"username": admin.username, "password": "wrong-pass"}
        )
        assert bad.status_code == 401, bad.text

    token = create_access_token(str(admin.id))
    r = await client.get(
        "/api/v1/dashboards/security/summary", headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["failed_login_total"] == 2
    rows = body["failed_login_top_sources"]
    assert [(x["user_display_name"], x["failure_count"]) for x in rows] == [(admin.username, 2)]
