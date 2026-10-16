"""#1987 null on a NOT NULL rule field is a 422; #1988 disabling a rule
closes its open alerts (the evaluator never visits a disabled rule)."""

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
from app.models.auth import User

pytestmark = pytest.mark.asyncio


async def _setup(db: AsyncSession) -> tuple[AlertRule, dict[str, str]]:
    u = User(
        username=f"u-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="U",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    rule = AlertRule(name="r", rule_type="subnet_utilization", severity="warning", enabled=True)
    db.add(rule)
    await db.flush()
    for resolved in (None, datetime.now(UTC)):
        db.add(
            AlertEvent(
                rule_id=rule.id,
                subject_type="subnet",
                subject_id=str(uuid.uuid4()),
                subject_display="10.9.0.0/24",
                severity="warning",
                message="hot",
                fired_at=datetime.now(UTC),
                resolved_at=resolved,
            )
        )
    await db.commit()
    return rule, {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


@pytest.mark.parametrize(
    "field",
    [
        "enabled",
        "severity",
        "name",
        "description",
        "notify_syslog",
        "notify_webhook",
        "notify_smtp",
    ],
)
async def test_null_on_required_field_is_422(
    client: AsyncClient, db_session: AsyncSession, field: str
) -> None:
    rule, h = await _setup(db_session)
    r = await client.patch(f"/api/v1/alerts/rules/{rule.id}", json={field: None}, headers=h)
    assert r.status_code == 422, r.text
    assert field in r.json()["detail"]


async def test_null_clears_nullable_field(client: AsyncClient, db_session: AsyncSession) -> None:
    rule, h = await _setup(db_session)
    rule.threshold_percent = 80
    await db_session.commit()
    r = await client.patch(
        f"/api/v1/alerts/rules/{rule.id}", json={"threshold_percent": None}, headers=h
    )
    assert r.status_code == 200, r.text
    assert r.json()["threshold_percent"] is None


async def test_disable_resolves_open_events_and_audits(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    rule, h = await _setup(db_session)
    r = await client.patch(f"/api/v1/alerts/rules/{rule.id}", json={"enabled": False}, headers=h)
    assert r.status_code == 200, r.text
    r = await client.get("/api/v1/alerts/events?open_only=true", headers=h)
    assert [e for e in r.json() if e["rule_id"] == str(rule.id)] == []
    audit = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_type == "alert_rule", AuditLog.resource_id == str(rule.id)
            )
        )
    ).scalar_one()
    assert audit.new_value["resolved_open_events"]["old"] == 1


async def test_other_edit_leaves_open_events_open(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    rule, h = await _setup(db_session)
    r = await client.patch(
        f"/api/v1/alerts/rules/{rule.id}", json={"severity": "critical"}, headers=h
    )
    assert r.status_code == 200, r.text
    r = await client.get("/api/v1/alerts/events?open_only=true", headers=h)
    assert len([e for e in r.json() if e["rule_id"] == str(rule.id)]) == 1
