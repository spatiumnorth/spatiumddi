"""``appliance_heartbeat_stale`` alert rule (#2259).

Fires for an approved appliance whose supervisor has gone silent, and
resolves on its own when heartbeats resume.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertEvent, AlertRule
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.services import alerts as alerts_svc
from app.services.alerts import evaluate_all


async def _node(
    db: AsyncSession,
    *,
    last_seen: datetime | None,
    state: str = APPLIANCE_STATE_APPROVED,
    revoked: bool = False,
) -> Appliance:
    der = os.urandom(32)
    row = Appliance(
        id=uuid.uuid4(),
        hostname=f"n-{uuid.uuid4().hex[:6]}",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=state,
        deployment_kind="appliance",
        last_seen_at=last_seen,
        revoked_at=datetime.now(UTC) if revoked else None,
    )
    db.add(row)
    await db.flush()
    return row


async def _open_events(db: AsyncSession, rule: AlertRule) -> list[AlertEvent]:
    return list(
        (
            await db.execute(
                select(AlertEvent).where(
                    AlertEvent.rule_id == rule.id, AlertEvent.resolved_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )


async def _no_delivery(rule, event, targets):  # type: ignore[no-untyped-def]
    return (False, False, False)


async def test_fires_for_stale_and_resolves_when_heartbeats_resume(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(alerts_svc, "_deliver", _no_delivery)
    rule = AlertRule(
        name="Appliance heartbeat lost (test)",
        rule_type="appliance_heartbeat_stale",
        severity="warning",
        enabled=True,
    )
    db_session.add(rule)
    now = datetime.now(UTC)
    silent = await _node(db_session, last_seen=now - timedelta(minutes=10))
    await _node(db_session, last_seen=now - timedelta(seconds=20))  # healthy
    await _node(db_session, last_seen=None)  # never heartbeated
    await _node(db_session, last_seen=now - timedelta(days=3), revoked=True)
    await _node(db_session, last_seen=now - timedelta(days=3), state="pending_approval")
    await db_session.commit()

    await evaluate_all(db_session)
    events = await _open_events(db_session, rule)
    assert [e.subject_id for e in events] == [str(silent.id)]
    assert len(events[0].subject_id) <= 64
    assert events[0].severity == "warning"

    # Silence drags on -> escalates to critical.
    silent.last_seen_at = now - timedelta(hours=2)
    await db_session.commit()
    await evaluate_all(db_session)
    events = await _open_events(db_session, rule)
    assert len(events) == 1 and events[0].severity == "critical"

    # Supervisor comes back -> the event resolves.
    silent.last_seen_at = datetime.now(UTC)
    await db_session.commit()
    await evaluate_all(db_session)
    assert await _open_events(db_session, rule) == []
    resolved = (
        (await db_session.execute(select(AlertEvent).where(AlertEvent.rule_id == rule.id)))
        .scalars()
        .all()
    )
    assert len(resolved) == 1 and resolved[0].resolved_at is not None


async def test_seed_creates_enabled_rule(db_session: AsyncSession) -> None:
    from app.services.alerts import seed_appliance_heartbeat_alert_rule

    await seed_appliance_heartbeat_alert_rule()
    await seed_appliance_heartbeat_alert_rule()  # idempotent
    rules = (
        (
            await db_session.execute(
                select(AlertRule).where(AlertRule.rule_type == "appliance_heartbeat_stale")
            )
        )
        .scalars()
        .all()
    )
    assert len(rules) == 1 and rules[0].enabled is True


async def test_fleet_mcp_row_reports_staleness(db_session: AsyncSession) -> None:
    from app.services.ai.tools.appliance import _row_to_dict

    now = datetime.now(UTC)
    old = await _node(db_session, last_seen=now - timedelta(hours=1))
    new = await _node(db_session, last_seen=now)
    never = await _node(db_session, last_seen=None)
    assert _row_to_dict(old)["heartbeat_stale"] is True
    assert _row_to_dict(new)["heartbeat_stale"] is False
    assert _row_to_dict(never)["heartbeat_stale"] is None
