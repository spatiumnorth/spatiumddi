"""``decom_expiring`` alert rule (#46).

Verifies the matcher surfaces subnets whose planned ``decom_date`` falls
inside the threshold window, excludes far-future / NULL / soft-deleted
rows, escalates severity as the date nears, and surfaces a past-due
message at critical severity.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertEvent, AlertRule
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services import alerts as alerts_svc
from app.services.alerts import _matching_decom_expiring_subjects, evaluate_all


async def _make_subnet(
    db: AsyncSession,
    *,
    network: str,
    decom_days: int | None,
    soft_deleted: bool = False,
) -> Subnet:
    """Create a subnet whose ``decom_date`` is ``decom_days`` from today
    (None = no scheduled decom). ``decom_days`` may be negative (past-due).
    """
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="b")
    db.add(block)
    await db.flush()
    decom_date = None
    if decom_days is not None:
        decom_date = (datetime.now(UTC) + timedelta(days=decom_days)).date()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network=network,
        name=f"sn-{uuid.uuid4().hex[:6]}",
        total_ips=254,
        decom_date=decom_date,
    )
    if soft_deleted:
        subnet.deleted_at = datetime.now(UTC)
    db.add(subnet)
    await db.flush()
    return subnet


async def test_decom_expiring_matches_and_excludes(db_session: AsyncSession) -> None:
    now = datetime.now(UTC)
    rule = AlertRule(
        name="Decom expiry",
        rule_type="decom_expiring",
        severity="info",
        threshold_days=30,
        enabled=True,
    )
    db_session.add(rule)

    near = await _make_subnet(db_session, network="10.0.1.0/24", decom_days=10)  # inside
    far = await _make_subnet(db_session, network="10.0.2.0/24", decom_days=365)  # must NOT match
    none = await _make_subnet(db_session, network="10.0.3.0/24", decom_days=None)  # NULL
    deleted = await _make_subnet(
        db_session, network="10.0.4.0/24", decom_days=5, soft_deleted=True
    )  # must NOT match
    await db_session.commit()

    subjects = await _matching_decom_expiring_subjects(db_session, rule, now)
    ids = {sid for sid, _disp, _msg, _sev in subjects}

    assert str(near.id) in ids
    assert str(far.id) not in ids
    assert str(none.id) not in ids
    assert str(deleted.id) not in ids


async def test_decom_expiring_severity_escalates(db_session: AsyncSession) -> None:
    """Base severity is a floor; the actual decom proximity escalates it.

    threshold/4 (30/4 = 7.5) → warning, threshold/12 (30/12 = 2.5) → critical.
    """
    now = datetime.now(UTC)
    rule = AlertRule(
        name="Decom expiry",
        rule_type="decom_expiring",
        severity="info",
        threshold_days=30,
        enabled=True,
    )
    db_session.add(rule)

    warn = await _make_subnet(db_session, network="10.1.1.0/24", decom_days=6)  # ≤ 7.5 → warning
    crit = await _make_subnet(db_session, network="10.1.2.0/24", decom_days=2)  # ≤ 2.5 → critical
    await db_session.commit()

    subjects = await _matching_decom_expiring_subjects(db_session, rule, now)
    sev_by_id = {sid: sev for sid, _disp, _msg, sev in subjects}

    assert sev_by_id[str(warn.id)] == "warning"
    assert sev_by_id[str(crit.id)] == "critical"


async def test_decom_expiring_past_due_is_critical(db_session: AsyncSession) -> None:
    now = datetime.now(UTC)
    rule = AlertRule(
        name="Decom expiry",
        rule_type="decom_expiring",
        severity="info",
        threshold_days=30,
        enabled=True,
    )
    db_session.add(rule)

    overdue = await _make_subnet(db_session, network="10.2.1.0/24", decom_days=-3)  # past-due
    await db_session.commit()

    subjects = await _matching_decom_expiring_subjects(db_session, rule, now)
    by_id = {sid: (msg, sev) for sid, _disp, msg, sev in subjects}

    assert str(overdue.id) in by_id
    msg, sev = by_id[str(overdue.id)]
    assert sev == "critical"
    assert "overdue" in msg.lower()


# ── End-to-end escalation through evaluate_all (the #46 bug fix) ─────


async def _open_events_for(db: AsyncSession, rule: AlertRule) -> list[AlertEvent]:
    rows = (
        (
            await db.execute(
                select(AlertEvent).where(
                    AlertEvent.rule_id == rule.id,
                    AlertEvent.resolved_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


class _DeliverSpy:
    """Wraps ``alerts.evaluate_all``'s ``_deliver`` so the test can count
    how many times an event was dispatched. Returns all-False (matching
    the real no-targets-configured path) so nothing leaves the process.
    """

    def __init__(self) -> None:
        self.calls = 0
        self.severities: list[str] = []

    async def __call__(self, rule, event, targets):  # type: ignore[no-untyped-def]
        self.calls += 1
        self.severities.append(event.severity)
        return (False, False, False)


async def _set_decom(db: AsyncSession, subnet: Subnet, *, days: int) -> None:
    subnet.decom_date = (datetime.now(UTC) + timedelta(days=days)).date()
    db.add(subnet)
    await db.commit()


async def test_decom_expiring_escalates_through_evaluate_all(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end #46: an open ``decom_expiring`` event opened at ``info``
    (decom far out) escalates to ``warning`` then ``critical`` across
    successive ``evaluate_all`` runs as ``decom_date`` nears, re-delivering
    on every increase — and does NOT re-deliver when severity is unchanged.

    threshold_days=30 → warning boundary at 30/4 = 7.5 d, critical at
    30/12 = 2.5 d.
    """
    spy = _DeliverSpy()
    monkeypatch.setattr(alerts_svc, "_deliver", spy)

    rule = AlertRule(
        name="Decom expiry",
        rule_type="decom_expiring",
        severity="info",
        threshold_days=30,
        enabled=True,
    )
    db_session.add(rule)

    # Far out but still inside the 30 d window → opens at info.
    subnet = await _make_subnet(db_session, network="10.3.1.0/24", decom_days=20)
    await db_session.commit()

    # Tick 1: open at info, one delivery.
    await evaluate_all(db_session)
    events = await _open_events_for(db_session, rule)
    assert len(events) == 1
    assert events[0].severity == "info"
    assert spy.calls == 1
    assert spy.severities[-1] == "info"

    # Tick 2: decom_date unchanged-severity (still info, 15 d > 7.5) →
    # the already-open event must NOT re-deliver.
    await _set_decom(db_session, subnet, days=15)
    await evaluate_all(db_session)
    events = await _open_events_for(db_session, rule)
    assert len(events) == 1  # not re-opened
    assert events[0].severity == "info"
    assert spy.calls == 1  # NO re-delivery on unchanged severity

    # Tick 3: pull decom in to 6 d (≤ 7.5) → escalate info → warning,
    # re-deliver.
    await _set_decom(db_session, subnet, days=6)
    await evaluate_all(db_session)
    events = await _open_events_for(db_session, rule)
    assert len(events) == 1
    assert events[0].severity == "warning"
    assert "decommission" in events[0].message.lower()
    assert spy.calls == 2  # re-delivered on the bump
    assert spy.severities[-1] == "warning"

    # Tick 4: warning stays warning (5 d, still > 2.5) → no re-delivery.
    await _set_decom(db_session, subnet, days=5)
    await evaluate_all(db_session)
    events = await _open_events_for(db_session, rule)
    assert events[0].severity == "warning"
    assert spy.calls == 2  # unchanged → no re-delivery

    # Tick 5: pull in to 2 d (≤ 2.5) → escalate warning → critical,
    # re-deliver.
    await _set_decom(db_session, subnet, days=2)
    await evaluate_all(db_session)
    events = await _open_events_for(db_session, rule)
    assert len(events) == 1
    assert events[0].severity == "critical"
    assert spy.calls == 3
    assert spy.severities[-1] == "critical"

    # Tick 6: critical stays critical (past-due) → severity never
    # downgrades and there is no spurious re-delivery.
    await _set_decom(db_session, subnet, days=-1)
    await evaluate_all(db_session)
    events = await _open_events_for(db_session, rule)
    assert events[0].severity == "critical"
    assert spy.calls == 3  # no further delivery


async def test_decom_expiring_never_downgrades_severity(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Once escalated, an event must not drop back down even if the decom
    date is pushed further out (operator rescheduled the decom). The bump
    is one-way; only resolution clears it.
    """
    spy = _DeliverSpy()
    monkeypatch.setattr(alerts_svc, "_deliver", spy)

    rule = AlertRule(
        name="Decom expiry",
        rule_type="decom_expiring",
        severity="info",
        threshold_days=30,
        enabled=True,
    )
    db_session.add(rule)

    subnet = await _make_subnet(db_session, network="10.4.1.0/24", decom_days=2)  # critical
    await db_session.commit()

    await evaluate_all(db_session)
    events = await _open_events_for(db_session, rule)
    assert events[0].severity == "critical"
    assert spy.calls == 1

    # Push the decom date back out — severity must stay critical and not
    # re-deliver (no downgrade, no spam).
    await _set_decom(db_session, subnet, days=20)
    await evaluate_all(db_session)
    events = await _open_events_for(db_session, rule)
    assert len(events) == 1
    assert events[0].severity == "critical"
    assert spy.calls == 1


async def test_non_escalating_rule_open_event_not_re_delivered(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Guard the shared-loop semantics for NON-``*_expiring`` rules: an
    already-open event for a rule that always emits the same severity
    (``subnet_utilization`` here, ``severity_override=None`` → stable
    ``rule.severity``) must NOT re-open and must NOT re-deliver across
    ticks. This is the "already-open event is not re-opened" invariant
    the #46 fix must preserve.
    """
    spy = _DeliverSpy()
    monkeypatch.setattr(alerts_svc, "_deliver", spy)

    rule = AlertRule(
        name="Subnet util",
        rule_type="subnet_utilization",
        severity="warning",
        threshold_percent=50,
        enabled=True,
    )
    db_session.add(rule)

    # 100% utilization, well over the 50% threshold, so the rule fires
    # and stays firing at the same severity across ticks.
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.5.0.0/16", name="b")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.5.0.0/24",
        name="util-sn",
        total_ips=254,
        allocated_ips=254,
        utilization_percent=100.0,
    )
    db_session.add(subnet)
    await db_session.commit()

    # Tick 1: opens once.
    await evaluate_all(db_session)
    first = await _open_events_for(db_session, rule)
    assert len(first) == 1
    first_severity = first[0].severity
    assert spy.calls == 1

    # Tick 2 + 3: subject still matches at the same severity → the open
    # event is neither re-opened nor re-delivered.
    await evaluate_all(db_session)
    await evaluate_all(db_session)
    again = await _open_events_for(db_session, rule)
    assert len(again) == 1
    assert again[0].id == first[0].id
    assert again[0].severity == first_severity
    assert spy.calls == 1  # NO spurious re-delivery for a non-escalating rule


async def test_decom_expiring_open_event_follows_current_countdown_4934(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A date moving closer rewrites the whole message; no bare-digit
    "[now: ...]" suffix is appended (#4934)."""
    monkeypatch.setattr(alerts_svc, "_deliver", _DeliverSpy())
    rule = AlertRule(
        name="Decom expiry",
        rule_type="decom_expiring",
        severity="info",
        threshold_days=30,
        enabled=True,
    )
    db_session.add(rule)
    subnet = await _make_subnet(db_session, network="10.5.1.0/24", decom_days=29)
    await db_session.commit()
    await evaluate_all(db_session)

    await _set_decom(db_session, subnet, days=27)
    await evaluate_all(db_session)
    events = await _open_events_for(db_session, rule)
    assert len(events) == 1
    msg = events[0].message
    assert "[now:" not in msg
    assert "in 27 day(s)" in msg and "in 29 day(s)" not in msg
    assert (datetime.now(UTC) + timedelta(days=27)).date().isoformat() in msg
