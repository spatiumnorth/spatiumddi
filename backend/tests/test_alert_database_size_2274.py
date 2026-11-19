"""``database_size_high`` alert rule (#2274)."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertEvent, AlertRule
from app.services import alerts as alerts_svc

GIB = 1024**3


def _rule(threshold: int | None = 50) -> AlertRule:
    return AlertRule(
        name="Database size high (test)",
        rule_type=alerts_svc.RULE_TYPE_DATABASE_SIZE_HIGH,
        severity="warning",
        enabled=True,
        threshold_percent=threshold,
    )


def _size(monkeypatch: pytest.MonkeyPatch, n: int | Exception) -> None:
    async def _fake(db):  # type: ignore[no-untyped-def]
        if isinstance(n, Exception):
            raise n
        return n

    monkeypatch.setattr(alerts_svc, "_database_size_bytes", _fake)


async def _no_delivery(rule, event, targets):  # type: ignore[no-untyped-def]
    return (False, False, False)


async def _open(db: AsyncSession, rule: AlertRule) -> list[AlertEvent]:
    return list(
        (
            await db.execute(
                select(AlertEvent).where(
                    AlertEvent.rule_id == rule.id, AlertEvent.resolved_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )


def test_registered_and_catalogued() -> None:
    from app.services.alert_rule_catalogue import build_catalogue

    assert alerts_svc.RULE_TYPE_DATABASE_SIZE_HIGH in alerts_svc.RULE_TYPES
    spec = next(s for s in build_catalogue() if s.rule_type == "database_size_high")
    assert [p.name for p in spec.params] == ["threshold_percent"]
    assert spec.params[0].default == 50


async def test_below_warning_critical_by_headroom(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    rule = _rule(50)
    _size(monkeypatch, 49 * GIB)
    assert await alerts_svc._matching_database_size_subjects(db_session, rule) == []
    _size(monkeypatch, 50 * GIB)
    ((sid, _d, msg, sev),) = await alerts_svc._matching_database_size_subjects(db_session, rule)
    assert (sid, sev) == ("database", "warning")
    assert "50.0 GiB" in msg and "50 GiB threshold" in msg
    _size(monkeypatch, 75 * GIB)
    ((_s, _d, _m, sev),) = await alerts_svc._matching_database_size_subjects(db_session, rule)
    assert sev == "critical"


async def test_null_threshold_uses_default(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _size(monkeypatch, 51 * GIB)
    got = await alerts_svc._matching_database_size_subjects(db_session, _rule(None))
    assert len(got) == 1


async def test_no_reading_raises_unavailable_never_matches(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _size(monkeypatch, alerts_svc.AlertDataUnavailable("gone"))
    with pytest.raises(alerts_svc.AlertDataUnavailable):
        await alerts_svc._matching_database_size_subjects(db_session, _rule())


async def test_evaluate_all_opens_escalates_holds_and_resolves(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(alerts_svc, "_deliver", _no_delivery)
    rule = _rule(10)
    db_session.add(rule)
    await db_session.commit()

    _size(monkeypatch, 11 * GIB)
    await alerts_svc.evaluate_all(db_session)
    events = await _open(db_session, rule)
    assert [(e.subject_type, e.severity) for e in events] == [("database", "warning")]

    _size(monkeypatch, 16 * GIB)
    await alerts_svc.evaluate_all(db_session)
    events = await _open(db_session, rule)
    assert len(events) == 1 and events[0].severity == "critical"

    # No reading this pass: the open event stands (unknown is not recovered).
    _size(monkeypatch, alerts_svc.AlertDataUnavailable("gone"))
    await alerts_svc.evaluate_all(db_session)
    assert len(await _open(db_session, rule)) == 1

    # Just under the threshold: inside the resolve margin, still open.
    _size(monkeypatch, int(9.7 * GIB))
    await alerts_svc.evaluate_all(db_session)
    assert len(await _open(db_session, rule)) == 1

    _size(monkeypatch, 5 * GIB)
    await alerts_svc.evaluate_all(db_session)
    assert await _open(db_session, rule) == []


async def test_seed_is_enabled_idempotent_and_respects_the_operator(
    db_session: AsyncSession,
) -> None:
    await alerts_svc.seed_database_size_alert_rule()
    await alerts_svc.seed_database_size_alert_rule()
    rules = (
        (
            await db_session.execute(
                select(AlertRule).where(AlertRule.rule_type == "database_size_high")
            )
        )
        .scalars()
        .all()
    )
    assert len(rules) == 1 and rules[0].enabled is True
    assert rules[0].threshold_percent == 50
    rules[0].enabled = False
    await db_session.commit()
    await alerts_svc.seed_database_size_alert_rule()
    await db_session.refresh(rules[0])
    assert rules[0].enabled is False
