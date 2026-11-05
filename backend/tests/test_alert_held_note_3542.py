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


# ── Validation additions ───────────────────────────────────────────────────


async def _subnet(db: AsyncSession, name: str = "lan", pct: float = 50.0) -> Subnet:
    space = IPSpace(name=f"s-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="root")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.9.0.0/24", name=name)
    subnet.utilization_percent = pct
    db.add(subnet)
    await db.flush()
    return subnet


async def _event(db: AsyncSession) -> AlertEvent:
    db.expire_all()
    return (await db.execute(select(AlertEvent))).scalars().one()


async def _no_delivery(rule, event, targets):  # type: ignore[no-untyped-def]
    return (False, False, False)


def _occupancy(monkeypatch: pytest.MonkeyPatch, state: dict) -> None:
    from app.services.dhcp import pool_occupancy as po

    async def fake(db, pools):  # type: ignore[no-untyped-def]
        return {p.id: po.PoolOccupancy(assigned=state["assigned"], total=100) for p in pools}

    monkeypatch.setattr(po, "compute_pool_occupancy_batch", fake)


async def _pool(db: AsyncSession) -> None:
    from app.models.dhcp import DHCPPool, DHCPScope, DHCPServerGroup

    subnet = await _subnet(db, pct=0.0)
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, name="sc")
    db.add(scope)
    await db.flush()
    db.add(
        DHCPPool(
            scope_id=scope.id,
            name="p",
            start_ip="10.9.0.10",
            end_ip="10.9.0.109",
            pool_type="dynamic",
        )
    )
    await db.flush()


async def test_held_dhcp_pool_alert_says_so_then_drops_it(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[str] = []

    async def count(rule, event, targets):  # type: ignore[no-untyped-def]
        sent.append(event.subject_id)
        return (False, False, False)

    monkeypatch.setattr(alerts, "_deliver", count)
    state = {"assigned": 85}
    _occupancy(monkeypatch, state)
    db_session.add(
        AlertRule(
            name="p",
            rule_type=alerts.RULE_TYPE_DHCP_POOL_EXHAUSTION,
            severity="warning",
            enabled=True,
            threshold_percent=80,
        )
    )
    await _pool(db_session)
    await db_session.commit()
    await alerts.evaluate_all(db_session)
    assert "held open" not in (await _event(db_session)).message

    state["assigned"] = 77  # under 80, above the 75 floor
    messages = []
    for _ in range(3):
        await alerts.evaluate_all(db_session)
        ev = await _event(db_session)
        assert ev.resolved_at is None
        messages.append(ev.message)
    assert "held open" in messages[0] and "below 75%" in messages[0]
    assert "" not in messages[0]
    assert len(set(messages)) == 1 and len(sent) == 1

    state["assigned"] = 82  # firing again: the note goes
    await alerts.evaluate_all(db_session)
    assert "held open" not in (await _event(db_session)).message

    state["assigned"] = 74  # under the floor: resolves
    await alerts.evaluate_all(db_session)
    assert (await _event(db_session)).resolved_at is not None
    assert len(sent) == 1


async def test_pool_held_on_percent_but_firing_on_min_free_is_not_held(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(alerts, "_deliver", _no_delivery)
    state = {"assigned": 95}
    _occupancy(monkeypatch, state)
    db_session.add(
        AlertRule(
            name="p",
            rule_type=alerts.RULE_TYPE_DHCP_POOL_EXHAUSTION,
            severity="warning",
            enabled=True,
            threshold_percent=97,  # 95% is inside the margin…
            min_free_addresses=10,  # …but 5 free fires the min-free leg outright
        )
    )
    await _pool(db_session)
    await db_session.commit()
    await alerts.evaluate_all(db_session)
    await alerts.evaluate_all(db_session)
    ev = await _event(db_session)
    assert ev.resolved_at is None
    assert "held open" not in ev.message


async def test_marker_inside_a_name_never_truncates_the_message(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(alerts, "_deliver", _no_delivery)
    db_session.add(
        AlertRule(
            name="u",
            rule_type=alerts.RULE_TYPE_SUBNET_UTILIZATION,
            severity="info",
            enabled=True,
            threshold_percent=46,
        )
    )
    subnet = await _subnet(db_session, name="labheld open: x")
    await db_session.commit()
    await alerts.evaluate_all(db_session)
    ev = await _event(db_session)
    assert ev.message.endswith("IPs allocated")
    assert "utilisation 50.0%" in ev.message

    subnet.utilization_percent = 42.86  # held: the real note still splits off
    await db_session.commit()
    await alerts.evaluate_all(db_session)
    msg = (await _event(db_session)).message
    assert msg.endswith(
        "held open: under the rule's threshold but not yet below 41%; resolves below that"
    )
    assert "labheld open: x" in msg


async def test_severity_raised_while_held_keeps_the_note_and_a_clean_peak(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    delivered: list[str] = []

    async def capture(rule, event, targets):  # type: ignore[no-untyped-def]
        delivered.append(event.message)
        return (False, False, False)

    monkeypatch.setattr(alerts, "_deliver", capture)
    rule = AlertRule(
        name="u",
        rule_type=alerts.RULE_TYPE_SUBNET_UTILIZATION,
        severity="info",
        enabled=True,
        threshold_percent=46,
    )
    db_session.add(rule)
    subnet = await _subnet(db_session)
    await db_session.commit()
    await alerts.evaluate_all(db_session)

    subnet.utilization_percent = 42.86
    rule.severity = "warning"  # the operator raises it while the alert is held
    await db_session.commit()
    await alerts.evaluate_all(db_session)
    ev = await _event(db_session)
    assert ev.severity == "warning"
    assert len(delivered) == 2 and "held open" in delivered[1]
    assert "held open" in ev.message
    assert "held open" not in (ev.last_observed_value or {})["peak_message"]

    first = ev.message
    await alerts.evaluate_all(db_session)
    assert (await _event(db_session)).message == first
    assert len(delivered) == 2
