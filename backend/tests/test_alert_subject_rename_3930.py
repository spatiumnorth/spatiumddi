"""#3930 — an open alert follows its subject's rename."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertEvent, AlertRule
from app.services import alerts

from .test_alert_resolve_hysteresis_2778 import _no_delivery, _subnet

pytestmark = pytest.mark.asyncio


@pytest.mark.parametrize("new_name", ["lan-r97", "office"])
async def test_rename_updates_subject_and_adds_no_now_part(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, new_name: str
) -> None:
    monkeypatch.setattr(alerts, "_deliver", _no_delivery)
    rule = AlertRule(
        name="u",
        rule_type=alerts.RULE_TYPE_SUBNET_UTILIZATION,
        severity="info",
        enabled=True,
        threshold_percent=7,
    )
    db_session.add(rule)
    subnet = await _subnet(db_session)
    subnet.name = "lan-r41"
    subnet.utilization_percent = 7.1
    await db_session.commit()
    await alerts.evaluate_all(db_session)

    subnet.name = new_name
    await db_session.commit()
    for _ in range(3):
        await alerts.evaluate_all(db_session)
    db_session.expire_all()
    events = list((await db_session.execute(select(AlertEvent))).scalars().all())
    assert len(events) == 1 and events[0].resolved_at is None
    ev = events[0]
    assert new_name in ev.subject_display and "r41" not in ev.subject_display
    assert new_name in ev.message and "r41" not in ev.message
    assert "[now:" not in ev.message
