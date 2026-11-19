"""#2498 — a manually resolved alert stays resolved while its subject still matches."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.alerts import AlertEvent, AlertRule
from app.models.auth import User
from app.services import alerts

pytestmark = pytest.mark.asyncio


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"a-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="A",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _matching(monkeypatch, subjects: list[str]) -> None:
    async def matcher(_db, _rule, _s):
        return [(sid, "10.0.0.0/24", "95% used") for sid in subjects]

    monkeypatch.setattr(alerts, "_matching_subnet_subjects", matcher)


async def _rule(db: AsyncSession) -> AlertRule:
    rule = AlertRule(
        name="r",
        description="",
        rule_type=alerts.RULE_TYPE_SUBNET_UTILIZATION,
        severity="critical",
        enabled=True,
        threshold_percent=1,
    )
    db.add(rule)
    await db.commit()
    return rule


async def _events(db: AsyncSession) -> list[AlertEvent]:
    db.expire_all()
    return list(
        (await db.execute(select(AlertEvent).order_by(AlertEvent.fired_at))).scalars().all()
    )


async def test_manual_resolve_of_still_firing_event_stays_resolved(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
) -> None:
    h = await _admin(db_session)
    await _rule(db_session)
    _matching(monkeypatch, ["subj-1", "subj-2"])
    await alerts.evaluate_all(db_session)
    evs = await _events(db_session)
    assert len(evs) == 2
    target = next(e for e in evs if e.subject_id == "subj-1")

    r = await client.post(f"/api/v1/alerts/events/{target.id}/resolve", headers=h)
    assert r.status_code == 200

    await alerts.evaluate_all(db_session)
    await alerts.evaluate_all(db_session)
    evs = await _events(db_session)
    assert len(evs) == 2  # no duplicate event / delivery for subj-1
    open_ids = {e.subject_id for e in evs if e.resolved_at is None}
    assert open_ids == {"subj-2"}


async def test_rematch_after_clearing_opens_a_new_event(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
) -> None:
    h = await _admin(db_session)
    await _rule(db_session)
    _matching(monkeypatch, ["subj-1"])
    await alerts.evaluate_all(db_session)
    (ev,) = await _events(db_session)
    await client.post(f"/api/v1/alerts/events/{ev.id}/resolve", headers=h)

    await alerts.evaluate_all(db_session)
    assert len(await _events(db_session)) == 1

    _matching(monkeypatch, [])  # condition clears
    await alerts.evaluate_all(db_session)
    _matching(monkeypatch, ["subj-1"])  # and comes back
    await alerts.evaluate_all(db_session)
    evs = await _events(db_session)
    assert len(evs) == 2
    assert [e.resolved_at is None for e in evs] == [False, True]
    # Still firing: stays one open event, nothing further opens.
    await alerts.evaluate_all(db_session)
    assert len(await _events(db_session)) == 2


async def test_auto_resolve_then_rematch_still_reopens(
    db_session: AsyncSession, monkeypatch
) -> None:
    """The evaluator's own resolve path is unchanged."""
    await _rule(db_session)
    _matching(monkeypatch, ["subj-1"])
    await alerts.evaluate_all(db_session)
    _matching(monkeypatch, [])
    await alerts.evaluate_all(db_session)
    (ev,) = await _events(db_session)
    assert ev.resolved_at is not None
    _matching(monkeypatch, ["subj-1"])
    await alerts.evaluate_all(db_session)
    evs = await _events(db_session)
    assert len(evs) == 2 and evs[1].resolved_at is None
