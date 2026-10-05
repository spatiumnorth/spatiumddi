"""Externally driven alert rules are skipped by the evaluator, quietly (#1469).

``audit_chain_broken``, ``schema_behind_head`` and ``cluster_upgrade_failed``
are seeded singleton rules whose events are opened and resolved by their own
task (audit-chain verify, schema check, upgrade orchestrator). ``evaluate_all``
has nothing to evaluate for them. Before #1469 only ``audit_chain_broken`` had
a pass-through branch, so the other two fell into the ``else`` and logged
``alert_unknown_rule_type`` on every 60 s tick — the bulk of the worker's
warnings on an appliance.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.testing import capture_logs

from app.core.security import create_access_token, hash_password
from app.models.alerts import AlertEvent, AlertRule
from app.models.auth import User
from app.services import alerts, audit_forward
from app.services.audit_chain import ChainBreak, ChainVerifyResult
from app.services.upgrades.alerts import RULE_TYPE_CLUSTER_UPGRADE_FAILED
from app.tasks import audit_chain_verify as acv

_EXTERNAL = [
    alerts.RULE_TYPE_AUDIT_CHAIN_BROKEN,
    alerts.RULE_TYPE_SCHEMA_BEHIND_HEAD,
    RULE_TYPE_CLUSTER_UPGRADE_FAILED,
]


async def _seed(db: AsyncSession, rule_type: str) -> AlertEvent:
    rule = AlertRule(
        name=f"test-{rule_type}",
        description="",
        rule_type=rule_type,
        severity="critical",
        enabled=True,
    )
    db.add(rule)
    await db.flush()
    event = AlertEvent(
        rule_id=rule.id,
        subject_type="platform",
        subject_id="platform",
        subject_display="platform",
        severity="critical",
        message="raised by the owning task",
        fired_at=datetime.now(UTC),
    )
    db.add(event)
    await db.flush()
    return event


@pytest.mark.asyncio
@pytest.mark.parametrize("rule_type", _EXTERNAL)
async def test_evaluator_skips_externally_driven_rule_without_warning(
    db_session: AsyncSession, rule_type: str
) -> None:
    event = await _seed(db_session, rule_type)

    with capture_logs() as logs:
        summary = await alerts.evaluate_all(db_session)

    unknown = [e for e in logs if e.get("event") == "alert_unknown_rule_type"]
    assert unknown == [], f"{rule_type} is externally driven, not unknown: {unknown}"

    # Skipping must not touch the event the owning task opened.
    await db_session.refresh(event)
    assert event.resolved_at is None
    assert summary["resolved"] == 0


@pytest.mark.asyncio
async def test_a_genuinely_unknown_rule_type_still_warns(db_session: AsyncSession) -> None:
    await _seed(db_session, "no_such_rule_type")

    with capture_logs() as logs:
        await alerts.evaluate_all(db_session)

    assert any(
        e.get("event") == "alert_unknown_rule_type" and e.get("type") == "no_such_rule_type"
        for e in logs
    )


# ── #1576 — externally-driven emitters deliver to forward targets ──


@pytest.mark.asyncio
async def test_audit_chain_broken_event_reaches_forward_target(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await alerts.seed_audit_chain_alert_rule()
    rule_id = (
        await db_session.execute(select(AlertRule.id).where(AlertRule.name == "audit-chain-broken"))
    ).scalar_one()

    async def _broken(db: AsyncSession, **_: object) -> ChainVerifyResult:
        return ChainVerifyResult(
            ok=False,
            rows_checked=3,
            breaks=[
                ChainBreak(
                    seq=1,
                    audit_id=str(uuid.uuid4()),
                    expected_hash="exp",
                    actual_hash="act",
                    reason="row_hash_mismatch",
                )
            ],
        )

    monkeypatch.setattr(acv, "verify_chain", _broken)

    delivered: list[tuple[object, object]] = []

    async def _fake_load() -> list[dict]:
        return [{"name": "stub", "kind": "syslog"}]

    async def _fake_deliver(rule: object, event: object, targets: list) -> tuple[bool, bool, bool]:
        delivered.append((rule, event))
        return True, False, False

    monkeypatch.setattr(audit_forward, "_load_targets", _fake_load)
    monkeypatch.setattr(alerts, "_deliver", _fake_deliver)

    out = await acv._async_verify_and_alert()
    assert out["ok"] is False
    assert len(delivered) == 1

    event = (
        await db_session.execute(select(AlertEvent).where(AlertEvent.rule_id == rule_id))
    ).scalar_one()
    assert event.delivered_syslog is True
    assert event.delivered_webhook is False


# ── #1580 — compliance_change without a classification ─────────────


async def _admin(db: AsyncSession) -> str:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("pw"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


@pytest.mark.asyncio
async def test_compliance_change_rule_requires_classification_on_create(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _admin(db_session)
    h = {"Authorization": f"Bearer {token}"}
    r = await client.post(
        "/api/v1/alerts/rules",
        headers=h,
        json={"name": "dead rule", "rule_type": "compliance_change"},
    )
    assert r.status_code == 422, r.text

    r = await client.post(
        "/api/v1/alerts/rules",
        headers=h,
        json={
            "name": "live rule",
            "rule_type": "compliance_change",
            "classification": "pci_scope",
        },
    )
    assert r.status_code == 201, r.text
    rule_id = r.json()["id"]

    # Clearing the classification on update is rejected too.
    r = await client.patch(
        f"/api/v1/alerts/rules/{rule_id}", headers=h, json={"classification": None}
    )
    assert r.status_code == 422, r.text
    # An unrelated update that leaves the classification alone is fine.
    r = await client.patch(f"/api/v1/alerts/rules/{rule_id}", headers=h, json={"enabled": False})
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_compliance_unknown_classification_warns_once_per_rule(
    db_session: AsyncSession,
) -> None:
    rule = AlertRule(
        name="test-compliance-no-classification",
        description="",
        rule_type=alerts.RULE_TYPE_COMPLIANCE_CHANGE,
        severity="warning",
        enabled=True,
        classification=None,
    )
    db_session.add(rule)
    await db_session.flush()

    with capture_logs() as logs:
        await alerts._evaluate_compliance_change_rule(db_session, rule, datetime.now(UTC))
        await alerts._evaluate_compliance_change_rule(db_session, rule, datetime.now(UTC))

    warnings = [e for e in logs if e.get("event") == "alert_compliance_unknown_classification"]
    assert len(warnings) == 1


# ── #1578 — conformity events are not the generic evaluator's ──────


@pytest.mark.asyncio
async def test_evaluator_does_not_resolve_conformity_events(db_session: AsyncSession) -> None:
    rule = AlertRule(
        name="test-ip-blocklisted-with-conformity",
        description="",
        rule_type=alerts.RULE_TYPE_IP_BLOCKLISTED,
        severity="warning",
        enabled=True,
    )
    db_session.add(rule)
    await db_session.flush()
    now = datetime.now(UTC)
    conformity = AlertEvent(
        rule_id=rule.id,
        subject_type="conformity",
        subject_id="policy-1:subnet:row-1",
        subject_display="policy :: subnet",
        severity="warning",
        message="conformity failing",
        fired_at=now,
    )
    ordinary = AlertEvent(
        rule_id=rule.id,
        subject_type="ip_blocklist",
        subject_id="203.0.113.9",
        subject_display="203.0.113.9",
        severity="warning",
        message="listed",
        fired_at=now,
    )
    db_session.add_all([conformity, ordinary])
    await db_session.flush()

    await alerts.evaluate_all(db_session)

    await db_session.refresh(conformity)
    await db_session.refresh(ordinary)
    assert conformity.resolved_at is None
    # Control: the evaluator's own event for an unmatched subject resolves.
    assert ordinary.resolved_at is not None


@pytest.mark.asyncio
async def test_compliance_auto_resolve_skips_conformity_events(db_session: AsyncSession) -> None:
    now = datetime.now(UTC)
    rule = AlertRule(
        name="test-compliance-with-conformity",
        description="",
        rule_type=alerts.RULE_TYPE_COMPLIANCE_CHANGE,
        severity="warning",
        enabled=True,
        classification="pci_scope",
        last_scanned_audit_at=now,
    )
    db_session.add(rule)
    await db_session.flush()
    old = now - timedelta(days=2)
    conformity = AlertEvent(
        rule_id=rule.id,
        subject_type="conformity",
        subject_id="policy-1:subnet:row-1",
        subject_display="policy :: subnet",
        severity="warning",
        message="conformity failing",
        fired_at=old,
    )
    own = AlertEvent(
        rule_id=rule.id,
        subject_type="audit:subnet",
        subject_id=str(uuid.uuid4()),
        subject_display="subnet x",
        severity="warning",
        message="changed",
        fired_at=old,
    )
    db_session.add_all([conformity, own])
    await db_session.flush()

    _, resolved, *_ = await alerts._evaluate_compliance_change_rule(db_session, rule, now)

    await db_session.refresh(conformity)
    await db_session.refresh(own)
    assert conformity.resolved_at is None
    assert own.resolved_at is not None
    assert resolved == 1
