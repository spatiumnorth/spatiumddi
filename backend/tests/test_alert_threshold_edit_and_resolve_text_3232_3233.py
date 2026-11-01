"""#3232 / #3233 — what an open alert and its rule say about thresholds."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertEvent, AlertRule
from app.services import alerts as alerts_svc

from .test_alert_appliance_disk_usage import GIB, _node, _pct_of
from .test_alert_resolve_hysteresis_2778 import _no_delivery, _subnet

pytestmark = pytest.mark.asyncio


async def _event(db: AsyncSession) -> AlertEvent:
    db.expire_all()
    return (
        await db.execute(select(AlertEvent).where(AlertEvent.resolved_at.is_(None)))
    ).scalar_one()


async def test_subnet_threshold_edit_is_not_shown_as_the_current_reading(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(alerts_svc, "_deliver", _no_delivery)
    rule = AlertRule(
        name="u",
        rule_type=alerts_svc.RULE_TYPE_SUBNET_UTILIZATION,
        severity="warning",
        enabled=True,
        threshold_percent=68,
    )
    db_session.add(rule)
    subnet = await _subnet(db_session)
    subnet.utilization_percent = 71.4
    await db_session.commit()
    await alerts_svc.evaluate_all(db_session)
    assert "(threshold 68%)" in (await _event(db_session)).message

    for new in (73, 63):
        rule.threshold_percent = new
        await db_session.commit()
        await alerts_svc.evaluate_all(db_session)
        msg = (await _event(db_session)).message
        assert f"(threshold {new}%)" in msg and "71.4%" in msg
        assert "[now:" not in msg

    # A real reading change afterwards still shows only the reading.
    subnet.utilization_percent = 64.3
    await db_session.commit()
    await alerts_svc.evaluate_all(db_session)
    msg = (await _event(db_session)).message
    assert "[now: 64.3%" in msg and "(threshold 63%)" in msg
    assert "[now: 63" not in msg


async def test_var_threshold_edit_is_not_shown_as_the_current_reading(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(alerts_svc, "_deliver", _no_delivery)
    rule = AlertRule(
        name="v",
        rule_type=alerts_svc.RULE_TYPE_APPLIANCE_DISK_USAGE,
        severity="warning",
        enabled=True,
        threshold_percent=0,
    )
    db_session.add(rule)
    await _node(db_session, var=_pct_of(40 * GIB, 27))
    await db_session.commit()
    await alerts_svc.evaluate_all(db_session)
    rule.threshold_percent = 26
    await db_session.commit()
    await alerts_svc.evaluate_all(db_session)
    msg = (await _event(db_session)).message
    assert "26% threshold" in msg and "[now:" not in msg


async def test_seeded_var_description_states_the_resolve_margin(
    db_session: AsyncSession,
) -> None:
    await alerts_svc.seed_appliance_disk_usage_alert_rule()
    rule = (
        await db_session.execute(
            select(AlertRule).where(AlertRule.rule_type == "appliance_disk_usage")
        )
    ).scalar_one()
    assert "5 points below the threshold" in rule.description
    assert "drops below" not in rule.description

    # A row still carrying the old seeded text is refreshed; an edited one is not.
    rule.description = alerts_svc._appliance_disk_description(legacy=True)
    await db_session.commit()
    await alerts_svc.seed_appliance_disk_usage_alert_rule()
    await db_session.refresh(rule)
    assert "5 points below" in rule.description
    rule.description = "mine"
    await db_session.commit()
    await alerts_svc.seed_appliance_disk_usage_alert_rule()
    await db_session.refresh(rule)
    assert rule.description == "mine"
