"""#3831 — a percentage rule at 5% or less still resolves on an empty subnet."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertEvent, AlertRule
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services import alerts


@pytest.mark.parametrize(
    ("threshold", "floor"), [(0, 0), (1, 0.5), (3, 1.5), (5, 2.5), (6, 1), (46, 41), (90, 85)]
)
def test_floor_is_above_zero_for_any_positive_threshold(threshold: float, floor: float) -> None:
    assert alerts._pct_resolve_floor(float(threshold)) == floor


@pytest.mark.asyncio
@pytest.mark.parametrize("threshold", [1, 3, 5])
async def test_low_threshold_alert_resolves_when_subnet_empties(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, threshold: int
) -> None:
    async def nodeliver(rule, event, targets):  # type: ignore[no-untyped-def]
        return (False, False, False)

    monkeypatch.setattr(alerts, "_deliver", nodeliver)
    db_session.add(
        AlertRule(
            name="u",
            rule_type=alerts.RULE_TYPE_SUBNET_UTILIZATION,
            severity="info",
            enabled=True,
            threshold_percent=threshold,
        )
    )
    space = IPSpace(name=f"s-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="root")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.9.0.0/28", name="lan")
    subnet.utilization_percent = 7.14
    db_session.add(subnet)
    await db_session.commit()
    await alerts.evaluate_all(db_session)
    ev = (await db_session.execute(select(AlertEvent))).scalars().one()
    assert ev.resolved_at is None

    subnet.utilization_percent = 0.0
    await db_session.commit()
    for _ in range(3):
        await alerts.evaluate_all(db_session)
    db_session.expire_all()
    ev = (await db_session.execute(select(AlertEvent))).scalars().one()
    assert ev.resolved_at is not None
