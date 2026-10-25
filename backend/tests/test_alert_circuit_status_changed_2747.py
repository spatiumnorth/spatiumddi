"""#2747 — a circuit moved on again while its first transition's alert is
still open is reported for its CURRENT transition."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertEvent, AlertRule
from app.models.circuit import Circuit
from app.models.ownership import Provider
from app.services.alerts import _evaluate_circuit_status_changed_rule

pytestmark = pytest.mark.asyncio


async def _run(db: AsyncSession, rule: AlertRule) -> tuple[int, int]:
    res = await _evaluate_circuit_status_changed_rule(db, rule, datetime.now(UTC))
    await db.flush()
    return res[0], res[1]


async def _events(db: AsyncSession, rule: AlertRule) -> list[AlertEvent]:
    rows = await db.execute(
        select(AlertEvent).where(AlertEvent.rule_id == rule.id).order_by(AlertEvent.fired_at)
    )
    return list(rows.scalars().all())


async def test_second_transition_supersedes_open_event(db_session: AsyncSession) -> None:
    prov = Provider(name="p-2747", kind="transit")
    db_session.add(prov)
    rule = AlertRule(
        name="ckt",
        rule_type="circuit_status_changed",
        severity="info",
        enabled=False,
        notify_syslog=False,
        notify_webhook=False,
        notify_smtp=False,
    )
    db_session.add(rule)
    await db_session.flush()
    t0 = datetime.now(UTC) - timedelta(minutes=5)
    c = Circuit(
        name="c1",
        provider_id=prov.id,
        status="suspended",
        previous_status="active",
        last_status_change_at=t0,
    )
    db_session.add(c)
    await db_session.flush()

    assert await _run(db_session, rule) == (1, 0)
    # Same transition, next pass: nothing new.
    assert await _run(db_session, rule) == (0, 0)

    c.previous_status, c.status = "suspended", "decom"
    c.last_status_change_at = t0 + timedelta(minutes=2)
    await db_session.flush()

    assert await _run(db_session, rule) == (1, 1)
    evs = await _events(db_session, rule)
    assert len(evs) == 2
    assert evs[0].resolved_at is not None
    assert evs[1].resolved_at is None
    assert "decom" in evs[1].message
    assert evs[1].last_observed_value["to"] == "decom"
    # And it is stable afterwards.
    assert await _run(db_session, rule) == (0, 0)
