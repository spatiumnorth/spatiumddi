"""#2778 — percentage-threshold rules resolve a margin below their threshold."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertEvent, AlertRule
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services import alerts

pytestmark = pytest.mark.asyncio


async def _no_delivery(rule, event, targets):  # type: ignore[no-untyped-def]
    return (False, False, False)


async def _subnet(db: AsyncSession) -> Subnet:
    space = IPSpace(name=f"s-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="root")
    db.add(block)
    await db.flush()
    s = Subnet(space_id=space.id, block_id=block.id, network="10.9.0.0/24", name="lan")
    db.add(s)
    await db.flush()
    return s


async def test_subnet_utilization_hovering_at_threshold_is_one_event(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[str] = []

    async def count(rule, event, targets):  # type: ignore[no-untyped-def]
        sent.append(event.subject_id)
        return (False, False, False)

    monkeypatch.setattr(alerts, "_deliver", count)
    rule = AlertRule(
        name="u",
        rule_type=alerts.RULE_TYPE_SUBNET_UTILIZATION,
        severity="warning",
        enabled=True,
        threshold_percent=80,
    )
    db_session.add(rule)
    subnet = await _subnet(db_session)
    await db_session.commit()

    for pct in (80.1, 79.9, 80.1, 79.9, 76.0):
        subnet.utilization_percent = pct
        await db_session.commit()
        await alerts.evaluate_all(db_session)
    events = list((await db_session.execute(select(AlertEvent))).scalars().all())
    assert len(events) == 1 and events[0].resolved_at is None
    assert len(sent) == 1

    subnet.utilization_percent = 74.0
    await db_session.commit()
    await alerts.evaluate_all(db_session)
    db_session.expire_all()
    events = list((await db_session.execute(select(AlertEvent))).scalars().all())
    assert len(events) == 1 and events[0].resolved_at is not None


async def test_subnet_in_the_margin_with_nothing_open_does_not_fire(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(alerts, "_deliver", _no_delivery)
    rule = AlertRule(
        name="u",
        rule_type=alerts.RULE_TYPE_SUBNET_UTILIZATION,
        severity="warning",
        enabled=True,
        threshold_percent=80,
    )
    db_session.add(rule)
    subnet = await _subnet(db_session)
    subnet.utilization_percent = 78.0
    await db_session.commit()
    await alerts.evaluate_all(db_session)
    assert list((await db_session.execute(select(AlertEvent))).scalars().all()) == []
