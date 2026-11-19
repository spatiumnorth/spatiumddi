"""Settings-router tests for maintenance mode (issue #57).

Covers:

* PUT /settings toggling on stamps ``maintenance_started_at`` and writes
  the audit row; toggling off clears the timestamp + writes the audit row.
* GET /settings + /health/platform expose the maintenance fields.
* An over-length ``maintenance_message`` (>500 chars) is rejected 422.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import maintenance_mode
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User


async def _make_superadmin(db: AsyncSession, username: str = "mssuper") -> tuple[User, str]:
    user = User(
        username=username,
        email=f"{username}@example.com",
        display_name=username,
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    token = create_access_token(str(user.id))
    return user, token


async def _make_settings_editor(db: AsyncSession, username: str = "mssettings") -> tuple[User, str]:
    """A non-superadmin user granted exactly ``write`` on ``settings`` via a
    group → role, so they pass the generic write:settings gate but NOT the
    maintenance-mode superadmin gate (FIX 3)."""
    role = Role(
        name=f"settings-editor-{uuid.uuid4().hex[:6]}",
        description="",
        permissions=[{"action": "write", "resource_type": "settings"}],
    )
    group = Group(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    group.roles = [role]
    user = User(
        username=username,
        email=f"{username}@example.com",
        display_name=username,
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=False,
    )
    user.groups = [group]
    db.add_all([role, group, user])
    await db.flush()
    token = create_access_token(str(user.id))
    return user, token


@pytest.fixture(autouse=True)
def _reset_cache() -> None:
    maintenance_mode.invalidate_cache()


@pytest.mark.asyncio
async def test_enable_stamps_started_at_and_audits(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_superadmin(db_session)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"maintenance_mode_enabled": True, "maintenance_message": "migrating"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["maintenance_mode_enabled"] is True
    assert body["maintenance_message"] == "migrating"
    assert body["maintenance_started_at"] is not None

    audit = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "maintenance_mode.enabled")
            )
        )
        .scalars()
        .all()
    )
    assert len(audit) == 1
    assert audit[0].resource_type == "platform_settings"
    assert audit[0].resource_id == "maintenance"
    assert audit[0].new_value == {"enabled": True, "message": "migrating"}


@pytest.mark.asyncio
async def test_disable_clears_started_at_and_audits(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_superadmin(db_session)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    # Enable, then disable.
    await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"maintenance_mode_enabled": True},
    )
    resp = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"maintenance_mode_enabled": False},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["maintenance_mode_enabled"] is False
    assert body["maintenance_started_at"] is None

    disabled_audit = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "maintenance_mode.disabled")
            )
        )
        .scalars()
        .all()
    )
    assert len(disabled_audit) == 1


@pytest.mark.asyncio
async def test_no_flip_no_audit(db_session: AsyncSession, client: AsyncClient) -> None:
    _, token = await _make_superadmin(db_session)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    # Writing the SAME (false) value must not produce an audit row or stamp.
    resp = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"maintenance_mode_enabled": False},
    )
    assert resp.status_code == 200, resp.text
    audit = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.action.in_(["maintenance_mode.enabled", "maintenance_mode.disabled"])
                )
            )
        )
        .scalars()
        .all()
    )
    assert audit == []


@pytest.mark.asyncio
async def test_get_settings_exposes_fields(db_session: AsyncSession, client: AsyncClient) -> None:
    _, token = await _make_superadmin(db_session)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.get("/api/v1/settings", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert "maintenance_mode_enabled" in body
    assert "maintenance_message" in body
    assert "maintenance_started_at" in body


@pytest.mark.asyncio
async def test_health_platform_exposes_fields(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_superadmin(db_session)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"maintenance_mode_enabled": True, "maintenance_message": "hi"},
    )
    # The banner fields are for a signed-in caller (#2935).
    resp = await client.get("/health/platform", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["maintenance_mode"] is True
    assert body["maintenance_message"] == "hi"
    assert body["maintenance_started_at"] is not None


@pytest.mark.asyncio
async def test_overlong_message_422(db_session: AsyncSession, client: AsyncClient) -> None:
    _, token = await _make_superadmin(db_session)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"maintenance_message": "x" * 501},
    )
    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_non_superadmin_cannot_set_maintenance_enabled(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """FIX 3 — a delegated write:settings editor passes the generic gate but
    is 403'd when the PUT body carries ``maintenance_mode_enabled`` (flipping
    it is a platform-wide DoS; superadmin only)."""
    _, token = await _make_settings_editor(db_session)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"maintenance_mode_enabled": True},
    )
    assert resp.status_code == 403, resp.text
    assert "superadmin" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_non_superadmin_cannot_set_maintenance_message(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """FIX 3 — the maintenance_message field is under the same superadmin gate."""
    _, token = await _make_settings_editor(db_session)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"maintenance_message": "you cannot set this"},
    )
    assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_non_superadmin_can_still_write_other_settings(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """FIX 3 — the maintenance gate is field-scoped: a write:settings editor
    can still write non-maintenance fields."""
    _, token = await _make_settings_editor(db_session)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"dns_auto_sync_enabled": True},
    )
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_superadmin_can_set_maintenance_enabled(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """FIX 3 — the superadmin path still succeeds (gate doesn't over-block)."""
    _, token = await _make_superadmin(db_session, username="msgatesuper")
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"maintenance_mode_enabled": True},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["maintenance_mode_enabled"] is True


@pytest.mark.asyncio
async def test_message_only_change_writes_audit_row(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """A maintenance_message reword WITHOUT flipping the enable flag still
    writes an audit row (non-negotiable #4) — previously only the enable /
    disable flip audited."""
    _, token = await _make_superadmin(db_session, username="msmsgaudit")
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    # Set an initial message while ENABLING (this writes the .enabled row).
    await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"maintenance_mode_enabled": True, "maintenance_message": "first"},
    )
    # Reword the banner WITHOUT touching the enable flag.
    resp = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"maintenance_message": "reworded banner"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["maintenance_message"] == "reworded banner"
    # The enable flag never flipped, so no new enabled/disabled rows — but a
    # dedicated message_changed audit row must exist.
    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "maintenance_mode.message_changed")
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].resource_type == "platform_settings"
    assert rows[0].resource_id == "maintenance"
    assert rows[0].new_value == {"enabled": True, "message": "reworded banner"}
