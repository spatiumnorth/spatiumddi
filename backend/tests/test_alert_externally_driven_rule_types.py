"""Externally driven alert rules are skipped by the evaluator, quietly (#1469).

``audit_chain_broken``, ``schema_behind_head`` and ``cluster_upgrade_failed``
are seeded singleton rules whose events are opened and resolved by their own
task (audit-chain verify, schema check, upgrade orchestrator). ``evaluate_all``
has nothing to evaluate for them. Before #1469 only ``audit_chain_broken`` had
a pass-through branch, so the other two fell into the ``else`` and logged
``alert_unknown_rule_type`` on every 60 s tick — the bulk of the worker's
warnings on an appliance.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.testing import capture_logs

from app.models.alerts import AlertEvent, AlertRule
from app.services import alerts
from app.services.upgrades.alerts import RULE_TYPE_CLUSTER_UPGRADE_FAILED

_EXTERNAL = [
    alerts.RULE_TYPE_AUDIT_CHAIN_BROKEN,
    alerts.RULE_TYPE_SCHEMA_BEHIND_HEAD,
    RULE_TYPE_CLUSTER_UPGRADE_FAILED,
]


async def _seed(db: AsyncSession, rule_type: str) -> AlertEvent:
    rule = AlertRule(
        name=f"test-{rule_type}",
        description="",
        rule_type=rule_type,
        severity="critical",
        enabled=True,
    )
    db.add(rule)
    await db.flush()
    event = AlertEvent(
        rule_id=rule.id,
        subject_type="platform",
        subject_id="platform",
        subject_display="platform",
        severity="critical",
        message="raised by the owning task",
        fired_at=datetime.now(UTC),
    )
    db.add(event)
    await db.flush()
    return event


@pytest.mark.asyncio
@pytest.mark.parametrize("rule_type", _EXTERNAL)
async def test_evaluator_skips_externally_driven_rule_without_warning(
    db_session: AsyncSession, rule_type: str
) -> None:
    event = await _seed(db_session, rule_type)

    with capture_logs() as logs:
        summary = await alerts.evaluate_all(db_session)

    unknown = [e for e in logs if e.get("event") == "alert_unknown_rule_type"]
    assert unknown == [], f"{rule_type} is externally driven, not unknown: {unknown}"

    # Skipping must not touch the event the owning task opened.
    await db_session.refresh(event)
    assert event.resolved_at is None
    assert summary["resolved"] == 0


@pytest.mark.asyncio
async def test_a_genuinely_unknown_rule_type_still_warns(db_session: AsyncSession) -> None:
    await _seed(db_session, "no_such_rule_type")

    with capture_logs() as logs:
        await alerts.evaluate_all(db_session)

    assert any(
        e.get("event") == "alert_unknown_rule_type" and e.get("type") == "no_such_rule_type"
        for e in logs
    )
