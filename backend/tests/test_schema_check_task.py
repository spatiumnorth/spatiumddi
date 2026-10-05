"""#565 — Celery-side DB-schema-at-head guard.

The api gates ``/health/ready`` on the schema being at the bundled
Alembic head (#299); the worker/beat had no equivalent and failed
tasks silently against a behind schema. These tests cover the two
Celery-side surfaces built on the shared ``schema_at_head`` helper:

* the periodic ``check_schema_at_head`` task opens a
  ``schema-behind-head`` ``AlertEvent`` on drift and auto-resolves it
  once the schema is back at head;
* the opt-in ``STRICT_SCHEMA_CHECK`` ``task_prerun`` gate ``Reject``s
  tasks while behind (and no-ops when disabled / for exempt tasks).
"""

from __future__ import annotations

import pytest
from celery.exceptions import Reject
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings as app_settings
from app.core.schema_check import SchemaCheck
from app.models.alerts import AlertEvent, AlertRule
from app.tasks import schema_check as sc

_BEHIND = SchemaCheck(False, "headrev", "oldrev", "schema at oldrev, image expects headrev")
_OK = SchemaCheck(True, "headrev", "headrev", "schema at head headrev")


class _Sender:
    def __init__(self, name: str) -> None:
        self.name = name


@pytest.mark.asyncio
async def test_periodic_check_opens_and_resolves_alert(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.alerts import seed_schema_behind_head_alert_rule

    await seed_schema_behind_head_alert_rule()
    # Capture the id as a plain local — task_session (a separate
    # session) commits between queries, and a lazy reload of an ORM
    # attribute while building later query expressions would raise
    # MissingGreenlet. The ``resolved_at IS NULL`` SQL filter already
    # reflects committed cross-session state, so no expire is needed.
    rule_id = (
        await db_session.execute(select(AlertRule.id).where(AlertRule.name == "schema-behind-head"))
    ).scalar_one()

    async def _behind(**_: object) -> SchemaCheck:
        return _BEHIND

    monkeypatch.setattr(sc, "schema_at_head", _behind)
    out = await sc._async_check_and_alert()
    assert out["ok"] is False

    open_events = (
        (
            await db_session.execute(
                select(AlertEvent)
                .where(AlertEvent.rule_id == rule_id)
                .where(AlertEvent.resolved_at.is_(None))
            )
        )
        .scalars()
        .all()
    )
    assert len(open_events) == 1
    assert open_events[0].subject_id == "oldrev"

    # A second behind-check dedupes onto the same open event.
    assert (await sc._async_check_and_alert())["deduped"] is True
    still_open = (
        await db_session.execute(
            select(AlertEvent.id)
            .where(AlertEvent.rule_id == rule_id)
            .where(AlertEvent.resolved_at.is_(None))
        )
    ).all()
    assert len(still_open) == 1

    # Schema catches up → the open event auto-resolves.
    async def _ok(**_: object) -> SchemaCheck:
        return _OK

    monkeypatch.setattr(sc, "schema_at_head", _ok)
    assert (await sc._async_check_and_alert())["ok"] is True
    remaining = (
        await db_session.execute(
            select(AlertEvent.id)
            .where(AlertEvent.rule_id == rule_id)
            .where(AlertEvent.resolved_at.is_(None))
        )
    ).all()
    assert remaining == []


def _arm_gate(monkeypatch: pytest.MonkeyPatch, result: SchemaCheck, *, strict: bool) -> None:
    async def _fake(**_: object) -> SchemaCheck:
        return result

    monkeypatch.setattr(sc, "schema_at_head", _fake)
    monkeypatch.setattr(app_settings, "strict_schema_check", strict)
    sc._strict_cache.checked_at = None
    sc._strict_cache.behind = False


def test_strict_gate_rejects_when_behind(monkeypatch: pytest.MonkeyPatch) -> None:
    _arm_gate(monkeypatch, _BEHIND, strict=True)
    with pytest.raises(Reject):
        sc._strict_schema_gate(sender=_Sender("app.tasks.some.task"))


def test_strict_gate_allows_when_at_head(monkeypatch: pytest.MonkeyPatch) -> None:
    _arm_gate(monkeypatch, _OK, strict=True)
    assert sc._strict_schema_gate(sender=_Sender("app.tasks.some.task")) is None


def test_strict_gate_noop_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    # Behind, but strict mode off → never rejects (default posture).
    _arm_gate(monkeypatch, _BEHIND, strict=False)
    assert sc._strict_schema_gate(sender=_Sender("app.tasks.some.task")) is None


def test_strict_gate_exempts_self_and_heartbeat(monkeypatch: pytest.MonkeyPatch) -> None:
    # Behind + strict, but the check task + beat heartbeat must still
    # run so the gate can clear itself.
    _arm_gate(monkeypatch, _BEHIND, strict=True)
    sc._strict_cache.behind = True  # pretend a prior check already saw it
    assert (
        sc._strict_schema_gate(sender=_Sender("app.tasks.schema_check.check_schema_at_head"))
        is None
    )
    assert sc._strict_schema_gate(sender=_Sender("app.tasks.heartbeat.beat_tick")) is None


@pytest.mark.asyncio
async def test_periodic_check_delivers_alert_to_forward_targets(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1576 — the schema-behind-head event must reach forward targets,
    not just the in-app alerts page."""
    from app.services import alerts as alert_service
    from app.services import audit_forward

    await alert_service.seed_schema_behind_head_alert_rule()
    rule_id = (
        await db_session.execute(select(AlertRule.id).where(AlertRule.name == "schema-behind-head"))
    ).scalar_one()

    async def _behind(**_: object) -> SchemaCheck:
        return _BEHIND

    monkeypatch.setattr(sc, "schema_at_head", _behind)

    async def _fake_load() -> list[dict]:
        return [{"name": "stub", "kind": "webhook"}]

    async def _fake_deliver(rule: object, event: object, targets: list) -> tuple[bool, bool, bool]:
        return False, True, False

    monkeypatch.setattr(audit_forward, "_load_targets", _fake_load)
    monkeypatch.setattr(alert_service, "_deliver", _fake_deliver)

    out = await sc._async_check_and_alert()
    assert out["ok"] is False

    event = (
        await db_session.execute(select(AlertEvent).where(AlertEvent.rule_id == rule_id))
    ).scalar_one()
    assert event.delivered_webhook is True
    assert event.delivered_syslog is False
