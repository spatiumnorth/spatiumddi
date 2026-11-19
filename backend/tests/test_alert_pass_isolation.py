"""#2261 — an evaluator pass must be safe to fail, retry and overlap.

The alert evaluator used to run every rule in one transaction and deliver
each new event as it opened, before the single commit at the end. One rule
whose query failed aborted the transaction, the commit discarded every event
the pass had already paged for, and the next tick (plus Celery's autoretry)
paged again. The conformity engine had the same shape.

Every assertion here is on what an operator sees: how many pages went out,
which events are stored, which results are stored.
"""

from __future__ import annotations

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertEvent, AlertRule
from app.models.conformity import ConformityPolicy, ConformityResult
from app.services import alerts
from app.services.conformity import checks as conformity_checks
from app.services.conformity import engine as conformity_engine
from app.services.conformity.checks import CheckOutcome

pytestmark = pytest.mark.asyncio


async def _two_rules(db: AsyncSession) -> tuple[AlertRule, AlertRule]:
    good = AlertRule(
        name="a-good",
        description="",
        rule_type=alerts.RULE_TYPE_SUBNET_UTILIZATION,
        severity="critical",
        enabled=True,
        threshold_percent=1,
    )
    bad = AlertRule(
        name="b-bad",
        description="",
        rule_type=alerts.RULE_TYPE_STALE_IP_COUNT,
        severity="warning",
        enabled=True,
    )
    db.add_all([good, bad])
    await db.commit()
    return good, bad


async def _open_events(db: AsyncSession) -> list[AlertEvent]:
    res = await db.execute(select(AlertEvent).where(AlertEvent.resolved_at.is_(None)))
    return list(res.scalars().all())


def _patch_matchers(monkeypatch: pytest.MonkeyPatch, *, bad_fails: bool = True) -> None:
    async def good_matcher(_db, _rule, _settings):  # type: ignore[no-untyped-def]
        return [("subj-1", "subnet 10.0.0.0/24", "95% used")]

    async def bad_matcher(_db, _rule):  # type: ignore[no-untyped-def]
        if bad_fails:
            await _db.execute(text("select 1/0"))  # any DB-level error in a matcher
        return []

    monkeypatch.setattr(alerts, "_matching_subnet_subjects", good_matcher)
    monkeypatch.setattr(alerts, "_matching_stale_ip_count_subjects", bad_matcher)


async def _run_ticks(db: AsyncSession, n: int) -> list[str]:
    """Run ``n`` passes the way beat + autoretry would: a pass that raises is
    rolled back and the next one runs anyway."""
    outcomes: list[str] = []
    for _ in range(n):
        try:
            await alerts.evaluate_all(db)
            outcomes.append("ok")
        except Exception as exc:  # noqa: BLE001
            outcomes.append(type(exc).__name__)
            await db.rollback()
    return outcomes


async def test_failing_rule_does_not_roll_back_or_redeliver_other_rules(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = db_session
    await _two_rules(db)
    _patch_matchers(monkeypatch)

    deliveries: list[str] = []

    async def fake_deliver(rule, event, targets):  # type: ignore[no-untyped-def]
        deliveries.append(event.subject_id)
        return (False, True, False)

    monkeypatch.setattr(alerts, "_deliver", fake_deliver)

    outcomes = await _run_ticks(db, 3)

    assert outcomes == ["ok", "ok", "ok"]
    # Paged exactly once across three ticks…
    assert deliveries == ["subj-1"]
    # …for an event that is actually stored, with its receipt.
    await db.rollback()
    events = await _open_events(db)
    assert [e.subject_id for e in events] == ["subj-1"]
    assert events[0].delivered_webhook is True


async def test_event_is_committed_before_it_is_delivered(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = db_session
    await _two_rules(db)
    _patch_matchers(monkeypatch, bad_fails=False)

    seen_from_other_connection: list[int] = []

    async def fake_deliver(rule, event, targets):  # type: ignore[no-untyped-def]
        # A different connection only sees committed rows.
        async with db.bind.connect() as conn:
            n = (
                await conn.execute(
                    select(func.count()).select_from(AlertEvent).where(AlertEvent.id == event.id)
                )
            ).scalar_one()
        seen_from_other_connection.append(n)
        return (True, False, False)

    monkeypatch.setattr(alerts, "_deliver", fake_deliver)

    result = await alerts.evaluate_all(db)

    assert seen_from_other_connection == [1]
    assert result["opened"] == 1
    assert result["delivered_syslog"] == 1


async def test_pass_that_fails_to_commit_sends_nothing_and_retry_sends_once(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The autoretry case: a pass whose commit fails must not have paged, so
    the retry is the first and only page."""
    db = db_session
    await _two_rules(db)
    _patch_matchers(monkeypatch, bad_fails=False)

    deliveries: list[str] = []

    async def fake_deliver(rule, event, targets):  # type: ignore[no-untyped-def]
        deliveries.append(event.subject_id)
        return (False, True, False)

    monkeypatch.setattr(alerts, "_deliver", fake_deliver)

    real_commit = db.commit
    calls = {"n": 0}

    async def flaky_commit() -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise OperationalError("COMMIT", {}, Exception("connection lost"))
        await real_commit()

    monkeypatch.setattr(db, "commit", flaky_commit)

    outcomes = await _run_ticks(db, 3)

    assert outcomes[0] == "OperationalError"
    assert deliveries == ["subj-1"]
    await db.rollback()
    assert [e.subject_id for e in await _open_events(db)] == ["subj-1"]


async def test_overlapping_pass_is_skipped(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = db_session
    await _two_rules(db)
    _patch_matchers(monkeypatch, bad_fails=False)

    deliveries: list[str] = []

    async def fake_deliver(rule, event, targets):  # type: ignore[no-untyped-def]
        deliveries.append(event.subject_id)
        return (False, True, False)

    monkeypatch.setattr(alerts, "_deliver", fake_deliver)

    # Another pass is running: it holds the evaluator lock on its own
    # connection.
    async with db.bind.connect() as other:
        await other.execute(
            text("SELECT pg_advisory_lock(:k)"), {"k": alerts._EVALUATE_LOCK_KEY}  # noqa: SLF001
        )
        try:
            skipped = await alerts.evaluate_all(db)
        finally:
            await other.execute(
                text("SELECT pg_advisory_unlock(:k)"),
                {"k": alerts._EVALUATE_LOCK_KEY},  # noqa: SLF001
            )
    await db.rollback()

    assert skipped["opened"] == 0
    assert deliveries == []
    assert await _open_events(db) == []

    # With the lock free the next pass does the work, once.
    ran = await alerts.evaluate_all(db)
    assert ran["opened"] == 1
    assert deliveries == ["subj-1"]


async def test_matcher_listing_a_subject_twice_opens_one_event(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = db_session
    await _two_rules(db)

    async def dup_matcher(_db, _rule, _settings):  # type: ignore[no-untyped-def]
        return [("subj-1", "a", "m"), ("subj-1", "a", "m")]

    async def empty(_db, _rule):  # type: ignore[no-untyped-def]
        return []

    deliveries: list[str] = []

    async def fake_deliver(rule, event, targets):  # type: ignore[no-untyped-def]
        deliveries.append(event.subject_id)
        return (False, False, False)

    monkeypatch.setattr(alerts, "_matching_subnet_subjects", dup_matcher)
    monkeypatch.setattr(alerts, "_matching_stale_ip_count_subjects", empty)
    monkeypatch.setattr(alerts, "_deliver", fake_deliver)

    await alerts.evaluate_all(db)

    assert [e.subject_id for e in await _open_events(db)] == ["subj-1"]
    assert deliveries == ["subj-1"]


async def test_two_open_events_for_one_subject_are_refused(db_session: AsyncSession) -> None:
    db = db_session
    good, _ = await _two_rules(db)
    rule_id = good.id  # read now: the rollback below expires ``good``
    now = datetime.now(UTC)
    for _ in range(2):
        db.add(
            AlertEvent(
                rule_id=rule_id,
                subject_type="subnet",
                subject_id="subj-1",
                subject_display="x",
                severity="warning",
                message="m",
                fired_at=now,
            )
        )
    with pytest.raises(IntegrityError):
        await db.flush()
    await db.rollback()

    # Resolved history for the same subject is unconstrained.
    for _ in range(2):
        db.add(
            AlertEvent(
                rule_id=rule_id,
                subject_type="subnet",
                subject_id="subj-1",
                subject_display="x",
                severity="warning",
                message="m",
                fired_at=now,
                resolved_at=now,
            )
        )
    await db.flush()


def _migration_statements(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """The SQL the #2261 migration's upgrade() executes, index DDL aside."""
    from alembic import op as alembic_op

    path = next(Path(__file__).parents[1].glob("alembic/versions/b4d81f2e6a93_*.py"))
    spec = importlib.util.spec_from_file_location("mig_2261", path)
    assert spec is not None and spec.loader is not None
    mig = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mig)
    statements: list[str] = []
    monkeypatch.setattr(alembic_op, "execute", statements.append, raising=False)
    monkeypatch.setattr(alembic_op, "drop_index", lambda *a, **k: None, raising=False)
    monkeypatch.setattr(alembic_op, "create_index", lambda *a, **k: None, raising=False)
    monkeypatch.setattr(alembic_op, "add_column", lambda *a, **k: None, raising=False)
    mig.upgrade()
    return statements


async def test_migration_resolves_duplicate_open_events_keeping_the_earliest(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The upgrade's dedupe statement, run against real duplicates."""
    statements = _migration_statements(monkeypatch)
    assert len(statements) == 1
    db = db_session
    good, _ = await _two_rules(db)
    # Recreate the pre-#2261 world: a non-unique index admitting duplicates.
    await db.execute(text("DROP INDEX ix_alert_event_rule_subject_open"))
    early = datetime(2026, 1, 1, tzinfo=UTC)
    late = datetime(2026, 2, 1, tzinfo=UTC)
    rows = [
        AlertEvent(
            rule_id=good.id,
            subject_type="subnet",
            subject_id="dup",
            subject_display="x",
            severity="warning",
            message="m",
            fired_at=ts,
        )
        for ts in (late, early, late)
    ] + [
        AlertEvent(
            rule_id=good.id,
            subject_type="subnet",
            subject_id="single",
            subject_display="x",
            severity="warning",
            message="m",
            fired_at=late,
        )
    ]
    db.add_all(rows)
    await db.flush()

    await db.execute(text(statements[0]))
    db.expire_all()

    open_rows = await _open_events(db)
    assert sorted((e.subject_id, e.fired_at) for e in open_rows) == [
        ("dup", early),
        ("single", late),
    ]
    # The unique index now builds.
    await db.execute(
        text(
            "CREATE UNIQUE INDEX ix_alert_event_rule_subject_open ON alert_event "
            "(rule_id, subject_type, subject_id) WHERE resolved_at IS NULL"
        )
    )
    await db.rollback()


async def test_upgrade_run_failing_twice_pages_twice_with_one_open_event(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A resumed run that fails again must still page, without tripping the
    unique open-event index."""
    import uuid

    from app.services.upgrades import alerts as upgrade_alerts

    db = db_session
    db.add(
        AlertRule(
            name=upgrade_alerts.CLUSTER_UPGRADE_FAILED_RULE,
            description="",
            rule_type=alerts.RULE_TYPE_COMPLIANCE_CHANGE,
            severity="critical",
            enabled=True,
        )
    )
    await db.commit()

    class _Run:
        id = uuid.uuid4()
        target_version = "2026.10.01-1"
        last_error = "boom"

    deliveries: list[str] = []

    async def fake_deliver(rule, event, targets):  # type: ignore[no-untyped-def]
        deliveries.append(event.subject_id)
        return (False, False, False)

    monkeypatch.setattr(alerts, "_deliver", fake_deliver)

    for _ in range(2):
        await upgrade_alerts.emit_upgrade_failed_alert(
            db,
            _Run(),  # type: ignore[arg-type]
            failed_node=None,
            failed_at_step="drain",
            category=upgrade_alerts.CATEGORY_OTHER,
        )
        await db.commit()

    assert deliveries == [str(_Run.id), str(_Run.id)]
    total = (await db.execute(select(func.count()).select_from(AlertEvent))).scalar_one()
    assert total == 2
    assert len(await _open_events(db)) == 1


# ── Conformity engine ───────────────────────────────────────────────


async def test_conformity_crashing_check_keeps_other_policies_and_pages_once(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = db_session
    rule = AlertRule(
        name="conformity-sink",
        description="",
        rule_type=alerts.RULE_TYPE_COMPLIANCE_CHANGE,
        severity="warning",
        enabled=True,
    )
    db.add(rule)
    await db.flush()

    async def check_fail(_db, **_kw):  # type: ignore[no-untyped-def]
        return CheckOutcome.fail("nope")

    async def check_crash(_db, **_kw):  # type: ignore[no-untyped-def]
        await _db.execute(text("select 1/0"))
        return CheckOutcome.passed()

    monkeypatch.setitem(conformity_checks.CHECK_REGISTRY, "t2261_fail", check_fail)
    monkeypatch.setitem(conformity_checks.CHECK_REGISTRY, "t2261_crash", check_crash)

    failing = ConformityPolicy(
        name="a-failing",
        target_kind="platform",
        check_kind="t2261_fail",
        severity="warning",
        fail_alert_rule_id=rule.id,
        enabled=True,
        eval_interval_hours=24,
    )
    crashing = ConformityPolicy(
        name="b-crashing",
        target_kind="platform",
        check_kind="t2261_crash",
        severity="warning",
        enabled=True,
        eval_interval_hours=24,
    )
    db.add_all([failing, crashing])
    await db.commit()

    deliveries: list[str] = []

    async def fake_deliver(rule, event, targets):  # type: ignore[no-untyped-def]
        deliveries.append(event.subject_id)
        return (False, True, False)

    monkeypatch.setattr(alerts, "_deliver", fake_deliver)
    # Pre-#2261 the engine imported ``_deliver`` by name.
    monkeypatch.setattr(conformity_engine, "_deliver", fake_deliver, raising=False)

    for _ in range(3):
        try:
            await conformity_engine.evaluate_due_policies(db)
        except Exception:  # noqa: BLE001
            await db.rollback()

    await db.rollback()
    assert deliveries == [f"{failing.id}:platform:platform"]
    events = await _open_events(db)
    assert [e.subject_type for e in events] == ["conformity"]
    assert events[0].delivered_webhook is True

    statuses = dict(
        (await db.execute(select(ConformityResult.policy_id, ConformityResult.status))).all()
    )
    # The failing policy's result is stored; the crashing one is recorded as
    # not applicable rather than lost.
    assert statuses == {failing.id: "fail", crashing.id: "not_applicable"}
    for p in (failing, crashing):
        await db.refresh(p)
        assert p.last_evaluated_at is not None


async def test_rule_failing_at_savepoint_release_rolls_back_only_itself(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rule that ``continue``s out of the dispatch with a change the flush
    rejects fails at its savepoint's release, not at the pass's commit."""
    db = db_session
    await _two_rules(db)
    _patch_matchers(monkeypatch, bad_fails=False)
    broken = AlertRule(
        name="c-broken",
        description="",
        rule_type=alerts.RULE_TYPE_COMPLIANCE_CHANGE,
        severity="warning",
        enabled=True,
    )
    db.add(broken)
    await db.commit()
    broken_id = broken.id

    async def bad_transition(_db, rule, _now):  # type: ignore[no-untyped-def]
        rule.name = None  # NOT NULL — rejected only when the savepoint flushes
        return 0, 0, 0, 0, 0

    monkeypatch.setattr(alerts, "_evaluate_compliance_change_rule", bad_transition)

    deliveries: list[str] = []

    async def fake_deliver(rule, event, targets):  # type: ignore[no-untyped-def]
        deliveries.append(event.subject_id)
        return (False, True, False)

    monkeypatch.setattr(alerts, "_deliver", fake_deliver)

    outcomes = await _run_ticks(db, 2)

    assert outcomes == ["ok", "ok"]
    assert deliveries == ["subj-1"]
    await db.rollback()
    assert [e.subject_id for e in await _open_events(db)] == ["subj-1"]
    name = (await db.execute(select(AlertRule.name).where(AlertRule.id == broken_id))).scalar_one()
    assert name == "c-broken"


# ── Stranded deliveries (#2261) ─────────────────────────────────────


async def _backdate_pending(db: AsyncSession, minutes: int) -> None:
    await db.execute(
        text(
            "UPDATE alert_event SET delivery_pending_since = delivery_pending_since "
            f"- interval '{minutes} minutes' WHERE delivery_pending_since IS NOT NULL"
        )
    )
    await db.commit()


async def test_delivery_stranded_by_a_dead_worker_is_sent_once(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The worker dies after the pass commits and before it sends. A later
    pass sends the event once, and only once it is clearly stranded."""
    db = db_session
    await _two_rules(db)
    _patch_matchers(monkeypatch, bad_fails=False)

    deliveries: list[str] = []

    async def fake_deliver(rule, event, targets):  # type: ignore[no-untyped-def]
        deliveries.append(event.subject_id)
        return (False, True, False)

    monkeypatch.setattr(alerts, "_deliver", fake_deliver)

    real_deliver_deferred = alerts.deliver_deferred

    async def killed(_db, _pending, _targets=None):  # type: ignore[no-untyped-def]
        return 0, 0, 0

    monkeypatch.setattr(alerts, "deliver_deferred", killed)
    await alerts.evaluate_all(db)
    monkeypatch.setattr(alerts, "deliver_deferred", real_deliver_deferred)

    await db.rollback()
    [event] = await _open_events(db)
    assert event.delivery_pending_since is not None
    assert event.delivered_webhook is False
    assert deliveries == []

    # A pass right after does not race the (possibly just slow) sender.
    await alerts.evaluate_all(db)
    assert deliveries == []

    await _backdate_pending(db, 11)
    result = await alerts.evaluate_all(db)
    assert deliveries == ["subj-1"]
    assert result["delivered_webhook"] == 1

    # Nothing left to claim: later passes send nothing more.
    await alerts.evaluate_all(db)
    await alerts.redeliver_stranded(db)
    assert deliveries == ["subj-1"]
    await db.rollback()
    [event] = await _open_events(db)
    await db.refresh(event)
    assert event.delivery_pending_since is None
    assert event.delivered_webhook is True


async def test_sweep_and_slow_sender_never_both_send(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pass so slow that the sweep took its event first: the claim makes
    the original sender skip it."""
    db = db_session
    await _two_rules(db)
    _patch_matchers(monkeypatch, bad_fails=False)

    deliveries: list[str] = []

    async def fake_deliver(rule, event, targets):  # type: ignore[no-untyped-def]
        deliveries.append(event.subject_id)
        return (True, False, False)

    monkeypatch.setattr(alerts, "_deliver", fake_deliver)

    captured: list[list[tuple[AlertRule, AlertEvent]]] = []

    async def slow(_db, pending, _targets=None):  # type: ignore[no-untyped-def]
        captured.append(list(pending))
        return 0, 0, 0

    real_deliver_deferred = alerts.deliver_deferred
    monkeypatch.setattr(alerts, "deliver_deferred", slow)
    await alerts.evaluate_all(db)
    monkeypatch.setattr(alerts, "deliver_deferred", real_deliver_deferred)

    await _backdate_pending(db, 11)
    await alerts.redeliver_stranded(db)
    assert deliveries == ["subj-1"]

    # The slow sender finally gets round to it.
    sent = await alerts.deliver_deferred(db, captured[0], [])
    assert sent == (0, 0, 0)
    assert deliveries == ["subj-1"]


async def test_stranded_delivery_for_a_resolved_event_is_dropped(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = db_session
    good, _ = await _two_rules(db)
    old = datetime.now(UTC) - timedelta(hours=1)
    db.add_all(
        [
            AlertEvent(
                rule_id=good.id,
                subject_type="subnet",
                subject_id="gone",
                subject_display="x",
                severity="warning",
                message="m",
                fired_at=old,
                resolved_at=datetime.now(UTC),
                delivery_pending_since=old,
            ),
            # Delivered inline (no stamp): never the sweep's business.
            AlertEvent(
                rule_id=good.id,
                subject_type="subnet",
                subject_id="inline",
                subject_display="x",
                severity="warning",
                message="m",
                fired_at=old,
            ),
        ]
    )
    await db.commit()

    deliveries: list[str] = []

    async def fake_deliver(rule, event, targets):  # type: ignore[no-untyped-def]
        deliveries.append(event.subject_id)
        return (True, False, False)

    monkeypatch.setattr(alerts, "_deliver", fake_deliver)

    assert await alerts.redeliver_stranded(db, []) == (0, 0, 0)
    assert deliveries == []
    pending = (
        await db.execute(
            select(func.count())
            .select_from(AlertEvent)
            .where(AlertEvent.delivery_pending_since.is_not(None))
        )
    ).scalar_one()
    assert pending == 0


async def test_copilot_conformity_evaluate_pages_only_after_commit(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The Copilot's ``evaluate_conformity_policy`` write op opens the same
    alert events as the beat pass, so it must commit them before paging."""
    from app.core.security import hash_password
    from app.models.auth import User
    from app.services.ai.operations import get_operation
    from app.services.ai.operations_writes import EvaluateConformityPolicyArgs

    db = db_session
    rule = AlertRule(
        name="conformity-sink",
        description="",
        rule_type=alerts.RULE_TYPE_COMPLIANCE_CHANGE,
        severity="warning",
        enabled=True,
    )
    db.add(rule)
    await db.flush()

    async def check_fail(_db, **_kw):  # type: ignore[no-untyped-def]
        return CheckOutcome.fail("nope")

    monkeypatch.setitem(conformity_checks.CHECK_REGISTRY, "t2261_fail", check_fail)
    policy = ConformityPolicy(
        name="copilot-failing",
        target_kind="platform",
        check_kind="t2261_fail",
        severity="warning",
        fail_alert_rule_id=rule.id,
        enabled=True,
        eval_interval_hours=0,
    )
    user = User(
        username="copilot-2261",
        email="copilot-2261@example.test",
        display_name="Copilot",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db.add_all([policy, user])
    await db.commit()

    seen_from_other_connection: list[int] = []

    async def fake_deliver(rule, event, targets):  # type: ignore[no-untyped-def]
        async with db.bind.connect() as conn:
            n = (
                await conn.execute(
                    select(func.count()).select_from(AlertEvent).where(AlertEvent.id == event.id)
                )
            ).scalar_one()
        seen_from_other_connection.append(n)
        return (False, True, False)

    monkeypatch.setattr(alerts, "_deliver", fake_deliver)

    op = get_operation("evaluate_conformity_policy")
    assert op is not None
    summary = await op.apply(db, user, EvaluateConformityPolicyArgs(policy_id=policy.id))

    assert summary["failed"] == 1
    assert seen_from_other_connection == [1]
    [event] = await _open_events(db)
    await db.refresh(event)
    assert event.delivered_webhook is True
    assert event.delivery_pending_since is None
