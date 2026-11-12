"""#3830 — the events list pages and reports its total."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.alerts import AlertEvent, AlertRule
from app.models.auth import User

pytestmark = pytest.mark.asyncio


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"a-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="A",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def test_offset_pages_past_limit_and_total_counts_every_match(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    rule = AlertRule(
        name="r",
        description="",
        rule_type="subnet_utilization",
        severity="info",
        enabled=True,
        threshold_percent=0,
    )
    db_session.add(rule)
    await db_session.flush()
    now = datetime.now(UTC)
    for i in range(7):
        db_session.add(
            AlertEvent(
                rule_id=rule.id,
                subject_type="subnet",
                subject_id=str(i),
                severity="info",
                message=f"m{i}",
                fired_at=now - timedelta(minutes=i),
                resolved_at=None if i < 5 else now,
            )
        )
    await db_session.commit()

    r1 = await client.get("/api/v1/alerts/events?open_only=true&limit=2", headers=h)
    assert r1.status_code == 200
    assert r1.headers["x-total-count"] == "5"
    assert [e["subject_id"] for e in r1.json()] == ["0", "1"]

    r2 = await client.get("/api/v1/alerts/events?open_only=true&limit=2&offset=2", headers=h)
    assert [e["subject_id"] for e in r2.json()] == ["2", "3"]
    r3 = await client.get("/api/v1/alerts/events?open_only=true&limit=2&offset=4", headers=h)
    assert [e["subject_id"] for e in r3.json()] == ["4"]
    assert r3.headers["x-total-count"] == "5"

    all_states = await client.get("/api/v1/alerts/events?limit=1", headers=h)
    assert all_states.headers["x-total-count"] == "7"
