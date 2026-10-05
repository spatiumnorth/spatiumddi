"""Resolving an alert event and forcing an evaluation are superadmin-only.

Both routes used to require only a signed-in user, so the builtin read-only
Viewer could dismiss a transition-once alert for good (registrar change,
hijack latch, ...) or trigger an evaluator pass that delivers to the
configured syslog / webhook / SMTP targets. They now match the alert-rule
writes in the same router, and a resolve is audited.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.alerts import AlertEvent, AlertRule
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User

pytestmark = pytest.mark.asyncio


async def _user(db: AsyncSession, *, superadmin: bool) -> tuple[User, str]:
    u = User(
        username=f"u-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="U",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    db.add(u)
    await db.flush()
    if not superadmin:
        role = Role(
            name=f"viewer-{uuid.uuid4().hex[:6]}",
            description="",
            permissions=[{"action": "read", "resource_type": "*"}],
        )
        db.add(role)
        await db.flush()
        group = Group(name=f"g-{uuid.uuid4().hex[:6]}", description="")
        group.roles = [role]
        group.users = [u]
        db.add(group)
        await db.flush()
    return u, create_access_token(str(u.id))


async def _event(db: AsyncSession) -> AlertEvent:
    rule = AlertRule(name="r", rule_type="subnet_utilization", severity="warning", enabled=True)
    db.add(rule)
    await db.flush()
    ev = AlertEvent(
        rule_id=rule.id,
        subject_type="subnet",
        subject_id=str(uuid.uuid4()),
        subject_display="10.9.0.0/24",
        severity="warning",
        message="hot",
        fired_at=datetime.now(UTC),
    )
    db.add(ev)
    await db.commit()
    return ev


async def test_viewer_cannot_resolve(client: AsyncClient, db_session: AsyncSession) -> None:
    ev = await _event(db_session)
    _, tok = await _user(db_session, superadmin=False)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/alerts/events/{ev.id}/resolve", headers={"Authorization": f"Bearer {tok}"}
    )
    assert resp.status_code == 403, resp.text
    await db_session.refresh(ev)
    assert ev.resolved_at is None
    rows = (
        (await db_session.execute(select(AuditLog).where(AuditLog.resource_type == "alert_event")))
        .scalars()
        .all()
    )
    assert rows == []


async def test_viewer_cannot_evaluate(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services import alerts as alert_service

    called = False

    async def _boom(db: AsyncSession) -> dict[str, int]:
        nonlocal called
        called = True
        return {
            k: 0
            for k in (
                "opened",
                "resolved",
                "delivered_syslog",
                "delivered_webhook",
                "delivered_smtp",
            )
        }

    monkeypatch.setattr(alert_service, "evaluate_all", _boom)
    _, tok = await _user(db_session, superadmin=False)
    await db_session.commit()

    resp = await client.post("/api/v1/alerts/evaluate", headers={"Authorization": f"Bearer {tok}"})
    assert resp.status_code == 403, resp.text
    assert called is False


async def test_superadmin_resolve_is_audited(client: AsyncClient, db_session: AsyncSession) -> None:
    ev = await _event(db_session)
    admin, tok = await _user(db_session, superadmin=True)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/alerts/events/{ev.id}/resolve", headers={"Authorization": f"Bearer {tok}"}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["resolved_at"] is not None
    rows = (
        (await db_session.execute(select(AuditLog).where(AuditLog.resource_type == "alert_event")))
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].action == "resolve"
    assert rows[0].resource_id == str(ev.id)
    assert rows[0].user_id == admin.id


async def test_superadmin_can_evaluate(client: AsyncClient, db_session: AsyncSession) -> None:
    _, tok = await _user(db_session, superadmin=True)
    await db_session.commit()
    resp = await client.post("/api/v1/alerts/evaluate", headers={"Authorization": f"Bearer {tok}"})
    assert resp.status_code == 200, resp.text
