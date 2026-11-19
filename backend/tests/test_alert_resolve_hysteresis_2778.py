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


# ── dhcp_pool_exhaustion ───────────────────────────────────────────────────


async def _pool(db: AsyncSession) -> object:
    from app.models.dhcp import DHCPPool, DHCPScope, DHCPServerGroup

    subnet = await _subnet(db)
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, name="sc")
    db.add(scope)
    await db.flush()
    pool = DHCPPool(
        scope_id=scope.id,
        name="p",
        start_ip="10.9.0.10",
        end_ip="10.9.0.109",
        pool_type="dynamic",
    )
    db.add(pool)
    await db.flush()
    return pool


def _occupancy(monkeypatch: pytest.MonkeyPatch, state: dict) -> None:
    from app.services.dhcp import pool_occupancy as po

    async def fake(db, pools):  # type: ignore[no-untyped-def]
        return {p.id: po.PoolOccupancy(assigned=state["assigned"], total=100) for p in pools}

    monkeypatch.setattr(po, "compute_pool_occupancy_batch", fake)


async def _events(db: AsyncSession) -> list[AlertEvent]:
    db.expire_all()
    return list((await db.execute(select(AlertEvent))).scalars().all())


async def test_pool_percent_hovering_is_one_event_and_resolves_below_margin(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[str] = []

    async def count(rule, event, targets):  # type: ignore[no-untyped-def]
        sent.append(event.subject_id)
        return (False, False, False)

    monkeypatch.setattr(alerts, "_deliver", count)
    state = {"assigned": 0}
    _occupancy(monkeypatch, state)
    rule = AlertRule(
        name="p",
        rule_type=alerts.RULE_TYPE_DHCP_POOL_EXHAUSTION,
        severity="warning",
        enabled=True,
        threshold_percent=80,
    )
    db_session.add(rule)
    await _pool(db_session)
    await db_session.commit()

    state["assigned"] = 78  # inside the margin, nothing open
    await alerts.evaluate_all(db_session)
    assert await _events(db_session) == []

    for assigned in (80, 79, 80, 79, 76):
        state["assigned"] = assigned
        await alerts.evaluate_all(db_session)
    evs = await _events(db_session)
    assert len(evs) == 1 and evs[0].resolved_at is None and len(sent) == 1

    state["assigned"] = 74
    await alerts.evaluate_all(db_session)
    evs = await _events(db_session)
    assert len(evs) == 1 and evs[0].resolved_at is not None


async def test_pool_min_free_leg_is_unchanged(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(alerts, "_deliver", _no_delivery)
    state = {"assigned": 0}
    _occupancy(monkeypatch, state)
    rule = AlertRule(
        name="p",
        rule_type=alerts.RULE_TYPE_DHCP_POOL_EXHAUSTION,
        severity="warning",
        enabled=True,
        min_free_addresses=10,
    )
    db_session.add(rule)
    await _pool(db_session)
    await db_session.commit()

    state["assigned"] = 95  # 5 free < 10
    await alerts.evaluate_all(db_session)
    assert len(await _events(db_session)) == 1
    state["assigned"] = 85  # 15 free: resolves immediately, no margin on this leg
    await alerts.evaluate_all(db_session)
    evs = await _events(db_session)
    assert len(evs) == 1 and evs[0].resolved_at is not None
