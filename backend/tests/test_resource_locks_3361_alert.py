"""The "lock removed" alert rule (#3361)."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertEvent, AlertRule
from app.services import alerts as alerts_svc
from tests.test_resource_locks_3361 import _ipam, _lock, _user


@pytest.mark.asyncio
async def test_lock_removed_rule_fires_per_unlock_with_who_what_why(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, _, subnet = await _ipam(db_session)
    admin = await _user(db_session)
    rule = AlertRule(
        name="Lock removed", rule_type="resource_lock_removed", severity="warning", enabled=True
    )
    db_session.add(rule)
    sid = subnet.id
    await db_session.commit()

    for reason in ("freeze over", "second thaw"):
        assert (await _lock(client, admin, "subnet", sid)).status_code == 200
        r = await client.post(
            f"/api/v1/locks/subnet/{sid}/unlock", headers=admin, json={"reason": reason}
        )
        assert r.status_code == 204

    await alerts_svc.evaluate_all(db_session)
    events = (
        (await db_session.execute(select(AlertEvent).where(AlertEvent.rule_id == rule.id)))
        .scalars()
        .all()
    )
    # One event per unlock, not one per object.
    assert len(events) == 2
    assert all(e.resolved_at is None for e in events)
    messages = " | ".join(e.message for e in events)
    assert "freeze over" in messages and "second thaw" in messages
    assert "10.30.0.0/24" in messages
    assert "Locker" in messages  # who


@pytest.mark.asyncio
async def test_lock_removed_rule_ignores_locks_and_old_unlocks(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from datetime import UTC, datetime, timedelta

    _, _, subnet = await _ipam(db_session)
    admin = await _user(db_session)
    rule = AlertRule(
        name="Lock removed", rule_type="resource_lock_removed", severity="warning", enabled=True
    )
    db_session.add(rule)
    sid = subnet.id
    await db_session.commit()
    assert (await _lock(client, admin, "subnet", sid)).status_code == 200
    # A lock alone is not a removal.
    assert await alerts_svc._matching_resource_lock_removed_subjects(db_session, rule) == []
    assert (
        await client.post(
            f"/api/v1/locks/subnet/{sid}/unlock", headers=admin, json={"reason": "done"}
        )
    ).status_code == 204
    assert len(await alerts_svc._matching_resource_lock_removed_subjects(db_session, rule)) == 1
    # Past the recency window it stops matching (the event then auto-resolves).
    rule.threshold_days = 1
    from sqlalchemy import text

    await db_session.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update"))
    await db_session.execute(
        text("UPDATE audit_log SET timestamp = :t WHERE action = 'unlock'"),
        {"t": datetime.now(UTC) - timedelta(days=3)},
    )
    await db_session.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update"))
    assert await alerts_svc._matching_resource_lock_removed_subjects(db_session, rule) == []


def test_lock_removed_rule_is_registered_and_described() -> None:
    from app.services.alert_rule_catalogue import build_catalogue

    assert "resource_lock_removed" in alerts_svc.RULE_TYPES
    assert "resource_lock_removed" in {s.rule_type for s in build_catalogue()}
