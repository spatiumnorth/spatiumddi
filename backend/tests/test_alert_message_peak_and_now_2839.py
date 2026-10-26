"""#2839 — an open alert keeps its peak message and says what the reading is now."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertEvent
from app.services import alerts as alerts_svc

from .test_alert_appliance_disk_usage import GIB, _node, _parts, _pct_of, _rule

pytestmark = pytest.mark.asyncio


async def _open_events(db: AsyncSession, rule_id: uuid.UUID) -> list[AlertEvent]:
    rows = await db.execute(
        select(AlertEvent).where(AlertEvent.rule_id == rule_id, AlertEvent.resolved_at.is_(None))
    )
    return list(rows.scalars().all())


async def _setup(db: AsyncSession, monkeypatch: pytest.MonkeyPatch, pct: float):
    sent: list[str] = []

    async def deliver(rule, event, targets):  # type: ignore[no-untyped-def]
        sent.append(event.message)
        return (False, False, False)

    monkeypatch.setattr(alerts_svc, "_deliver", deliver)
    rule = _rule()
    db.add(rule)
    node = await _node(db, var=_pct_of(40 * GIB, pct))
    await db.commit()
    return rule.id, node, sent


async def _tick(db: AsyncSession, node, pct: float) -> None:
    await db.refresh(node)
    node.cluster_health = {"host_disk_partitions": _parts(_pct_of(40 * GIB, pct))}
    node.last_seen_at = datetime.now(UTC)
    await db.commit()
    await alerts_svc.evaluate_all(db)


async def test_improving_reading_keeps_peak_and_shows_now(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    rule, node, sent = await _setup(db_session, monkeypatch, 86)
    await alerts_svc.evaluate_all(db_session)
    ev = (await _open_events(db_session, rule))[0]
    fired_at = ev.fired_at
    assert "86%" in ev.message

    await _tick(db_session, node, 82)
    db_session.expire_all()
    ev = (await _open_events(db_session, rule))[0]
    assert ev.severity == "warning" and ev.fired_at == fired_at
    assert "86%" in ev.message  # the peak survives
    assert "[now: 82%" in ev.message
    assert len(sent) == 1  # a text change never re-notifies


async def test_worsening_at_the_same_severity_keeps_the_peak_and_shows_now(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Severity is the only measure of "worst": nothing is inferred from numbers."""
    rule, node, sent = await _setup(db_session, monkeypatch, 84)
    await alerts_svc.evaluate_all(db_session)
    await _tick(db_session, node, 81)
    await _tick(db_session, node, 86)
    db_session.expire_all()
    ev = (await _open_events(db_session, rule))[0]
    assert ev.severity == "warning"
    assert "84%" in ev.message  # still the message from when it fired
    assert "[now: 86%" in ev.message
    assert len(sent) == 1


async def test_unchanged_reading_does_not_write_or_notify(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    rule, node, sent = await _setup(db_session, monkeypatch, 86)
    await alerts_svc.evaluate_all(db_session)
    await _tick(db_session, node, 82)
    ev = (await _open_events(db_session, rule))[0]
    before = (ev.message, dict(ev.last_observed_value or {}))
    db_session.expire_all()
    await _tick(db_session, node, 82)
    ev = (await _open_events(db_session, rule))[0]
    assert (ev.message, dict(ev.last_observed_value or {})) == before
    assert not db_session.dirty
    assert len(sent) == 1
    assert "[now: 82%" in ev.message


async def test_severity_raise_still_notifies_with_the_new_message(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    rule, node, sent = await _setup(db_session, monkeypatch, 86)
    await alerts_svc.evaluate_all(db_session)
    await _tick(db_session, node, 82)
    await _tick(db_session, node, 92)
    db_session.expire_all()
    ev = (await _open_events(db_session, rule))[0]
    assert ev.severity == "critical"
    assert "92%" in ev.message and "[now:" not in ev.message
    assert len(sent) == 2 and "92%" in sent[1]


async def test_nothing_is_inferred_from_numbers() -> None:
    # Lower is worse here ("N of M healthy"): the display must not care.
    peak, now = "3 of 8 nodes healthy", "5 of 8 nodes healthy"
    assert alerts_svc._compose_peak_and_now(peak, peak) == peak
    assert alerts_svc._compose_peak_and_now(peak, now) == f"{peak} [now: 5]"
    assert alerts_svc._compose_peak_and_now(peak, now) != alerts_svc._compose_peak_and_now(
        now, peak
    )
    assert alerts_svc._compose_peak_and_now("a 1", "b 2") == "a 1 [now: b 2]"
    assert not hasattr(alerts_svc, "_reading_is_worse")
