"""#3542 — an open alert held by the resolve margin says it is held."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertEvent, AlertRule
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services import alerts

pytestmark = pytest.mark.asyncio


async def test_held_subnet_alert_says_so_and_is_stable(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[str] = []

    async def count(rule, event, targets):  # type: ignore[no-untyped-def]
        sent.append(event.subject_id)
        return (False, False, False)

    monkeypatch.setattr(alerts, "_deliver", count)
    db_session.add(
        AlertRule(
            name="u",
            rule_type=alerts.RULE_TYPE_SUBNET_UTILIZATION,
            severity="info",
            enabled=True,
            threshold_percent=46,
        )
    )
    space = IPSpace(name=f"s-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="root")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.9.0.0/28", name="lan")
    subnet.utilization_percent = 50.0
    db_session.add(subnet)
    await db_session.commit()
    await alerts.evaluate_all(db_session)

    subnet.utilization_percent = 42.86
    await db_session.commit()
    messages = []
    for _ in range(3):
        await alerts.evaluate_all(db_session)
        db_session.expire_all()
        ev = (await db_session.execute(select(AlertEvent))).scalars().one()
        assert ev.resolved_at is None
        messages.append(ev.message)
    assert "held open" in messages[0] and "below 41%" in messages[0]
    assert messages[0].count("held open") == 1
    assert len(set(messages)) == 1  # re-evaluation does not churn the text
    assert len(sent) == 1  # and does not re-notify

    # Back at or above the threshold: no longer merely held.
    subnet.utilization_percent = 50.0
    await db_session.commit()
    await alerts.evaluate_all(db_session)
    db_session.expire_all()
    ev = (await db_session.execute(select(AlertEvent))).scalars().one()
    assert "held open" not in ev.message
