"""``backup_failed`` / ``backup_stale`` alerts + ``get_backup_health`` (#1262).

Covered here:

* the stale deadline: counted from the last success, never from before
  the schedule was set, N runs plus the grace;
* ``backup_failed`` fires on a failed run of a watched target, resolves
  on success, ignores manual-only and disabled targets, and never puts
  the run's error text in the message;
* ``backup_stale`` fires when nothing succeeded for N runs (also when
  nothing ran at all), not before the first expected run, not for
  manual-only or disabled targets; a dead ``in_progress`` run counts as
  no run, a live one holds;
* the last success survives a later failure (read from the audit row
  the real runner writes);
* end to end through ``evaluate_all``: one event, one delivery, held
  while a retry is in progress, resolved on success;
* both rules are registered and seeded enabled, once;
* the copilot tool is superadmin-only and agrees with the alert.

``_deliver`` is always patched, so nothing leaves the process.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.models.alerts import AlertEvent, AlertRule
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.backup import BackupTarget
from app.services import alerts as alerts_mod
from app.services.alerts import (
    RULE_TYPE_BACKUP_FAILED,
    RULE_TYPE_BACKUP_STALE,
    RULE_TYPES,
    _matching_backup_failed_subjects,
    _matching_backup_stale_subjects,
    evaluate_all,
)
from app.services.backup.health import (
    RUN_PRESUMED_DEAD_AFTER,
    STALE_GRACE,
    evaluate_backup_health,
    stale_deadline,
)
from app.services.backup.schedule import compute_next_run

NIGHTLY = "0 2 * * *"
# A fixed "now" for the matcher tests: 2026-10-10 12:00 UTC.
NOW = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)


def _at(day: int, hour: int = 2, minute: int = 0) -> datetime:
    return datetime(2026, 10, day, hour, minute, tzinfo=UTC)


class _DeliverSpy:
    def __init__(self) -> None:
        self.calls = 0

    async def __call__(self, rule, event, targets):  # type: ignore[no-untyped-def]
        self.calls += 1
        return (False, False, False)


async def _target(
    db: AsyncSession,
    *,
    name: str = "vault",
    cron: str | None = NIGHTLY,
    enabled: bool = True,
    status: str = "success",
    last_run_at: datetime | None = None,
    next_run_at: datetime | None = None,
    created_at: datetime | None = None,
    error: str | None = None,
) -> BackupTarget:
    t = BackupTarget(
        name=name,
        description="",
        kind="local_volume",
        enabled=enabled,
        config={"path": "/var/lib/spatiumddi/backups"},
        passphrase_encrypted=encrypt_str("hunter2hunter2"),
        schedule_cron=cron,
        last_run_status=status,
        last_run_at=last_run_at,
        next_run_at=next_run_at,
        last_run_error=error,
    )
    db.add(t)
    await db.flush()
    t.created_at = created_at or datetime(2026, 1, 1, tzinfo=UTC)
    await db.flush()
    return t


async def _success_audit(db: AsyncSession, target: BackupTarget, when: datetime) -> None:
    db.add(
        AuditLog(
            action="backup_target_run_success",
            resource_type="backup_target",
            resource_id=str(target.id),
            resource_display=target.name,
            user_display_name="system (schedule)",
            result="success",
            timestamp=when,
        )
    )
    await db.flush()


async def _rule(db: AsyncSession, rule_type: str, **kw: Any) -> AlertRule:
    rule = AlertRule(
        name=rule_type,
        rule_type=rule_type,
        severity="critical" if rule_type == RULE_TYPE_BACKUP_STALE else "warning",
        enabled=True,
        **kw,
    )
    db.add(rule)
    await db.flush()
    return rule


# ══════════════════════════════════════════════════════════════════════
# The deadline
# ══════════════════════════════════════════════════════════════════════


def test_deadline_counts_runs_from_last_success() -> None:
    success = _at(1, 2, 1)
    deadline = stale_deadline(
        schedule_cron=NIGHTLY,
        last_success_at=success,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        last_run_at=success,
        next_run_at=_at(2),
        runs=2,
    )
    assert deadline == _at(3) + STALE_GRACE


def test_deadline_never_before_first_run_after_schedule_set() -> None:
    """A schedule added to an old target that last succeeded long ago
    (or never) gets its first expected run before it can go stale."""
    for last_success in (None, datetime(2025, 6, 1, tzinfo=UTC)):
        deadline = stale_deadline(
            schedule_cron=NIGHTLY,
            last_success_at=last_success,
            created_at=datetime(2025, 1, 1, tzinfo=UTC),
            last_run_at=last_success,
            next_run_at=_at(11),  # schedule set on 2026-10-10
            runs=1,
        )
        assert deadline == _at(11) + STALE_GRACE


# ══════════════════════════════════════════════════════════════════════
# backup_failed
# ══════════════════════════════════════════════════════════════════════


async def test_failed_run_fires_without_error_text(db_session: AsyncSession) -> None:
    secret_ish = "PUT https://backup-user:pw@nas.example.internal/share refused"
    t = await _target(
        db_session,
        status="failed",
        last_run_at=_at(10, 2, 1),
        next_run_at=_at(11),
        error=secret_ish,
    )
    await _success_audit(db_session, t, _at(9, 2, 2))
    rule = await _rule(db_session, RULE_TYPE_BACKUP_FAILED)

    matches = await _matching_backup_failed_subjects(db_session, rule, NOW)
    assert len(matches) == 1
    subject_id, display, message, severity = matches[0]
    assert subject_id == str(t.id)
    assert display == "vault"
    assert severity is None
    assert "FAILED" in message
    assert "2026-10-09 02:02 UTC" in message  # last success, from the audit row
    assert "nas.example.internal" not in message
    assert "pw@" not in message


async def test_failed_resolves_on_success(db_session: AsyncSession) -> None:
    await _target(db_session, status="success", last_run_at=_at(10, 2, 1), next_run_at=_at(11))
    rule = await _rule(db_session, RULE_TYPE_BACKUP_FAILED)
    assert await _matching_backup_failed_subjects(db_session, rule, NOW) == []


async def test_failed_ignores_manual_only_and_disabled(db_session: AsyncSession) -> None:
    await _target(db_session, name="manual", cron=None, status="failed", last_run_at=_at(10))
    await _target(
        db_session,
        name="off",
        enabled=False,
        status="failed",
        last_run_at=_at(10, 2, 1),
        next_run_at=_at(11),
    )
    rule = await _rule(db_session, RULE_TYPE_BACKUP_FAILED)
    assert await _matching_backup_failed_subjects(db_session, rule, NOW) == []
    stale = await _rule(db_session, RULE_TYPE_BACKUP_STALE)
    assert await _matching_backup_stale_subjects(db_session, stale, NOW) == []


# ══════════════════════════════════════════════════════════════════════
# backup_stale
# ══════════════════════════════════════════════════════════════════════


async def test_stale_when_nothing_ran(db_session: AsyncSession) -> None:
    """Beat or worker down: the last run succeeded, then nothing ran."""
    t = await _target(db_session, status="success", last_run_at=_at(7, 2, 1), next_run_at=_at(8))
    rule = await _rule(db_session, RULE_TYPE_BACKUP_STALE)

    matches = await _matching_backup_stale_subjects(db_session, rule, NOW)
    assert [m[0] for m in matches] == [str(t.id)]
    assert "no successful run since 2026-10-07 02:01 UTC" in matches[0][2]
    assert "has not started" in matches[0][2]


async def test_not_stale_within_n_runs(db_session: AsyncSession) -> None:
    # Last success 10-09 02:01, one run (10-10 02:00) missed so far.
    await _target(db_session, status="success", last_run_at=_at(9, 2, 1), next_run_at=_at(10))
    rule = await _rule(db_session, RULE_TYPE_BACKUP_STALE)
    assert await _matching_backup_stale_subjects(db_session, rule, NOW) == []
    # N=1 on the rule: one missed run is enough.
    rule.threshold_percent = 1
    assert len(await _matching_backup_stale_subjects(db_session, rule, NOW)) == 1


async def test_new_target_not_stale_before_first_run(db_session: AsyncSession) -> None:
    await _target(
        db_session,
        status="never",
        created_at=_at(10, 11),
        next_run_at=_at(11),
    )
    rule = await _rule(db_session, RULE_TYPE_BACKUP_STALE, threshold_percent=1)
    assert await _matching_backup_stale_subjects(db_session, rule, NOW) == []
    # ...but it is once the first run plus the grace have passed with nothing.
    later = _at(11) + STALE_GRACE + timedelta(minutes=1)
    assert len(await _matching_backup_stale_subjects(db_session, rule, later)) == 1


async def test_failing_target_goes_stale_from_last_success(db_session: AsyncSession) -> None:
    """Runs keep happening and keep failing: stale counts from the last
    success in the audit log, not from the last attempt."""
    t = await _target(db_session, status="failed", last_run_at=_at(10, 2, 1), next_run_at=_at(11))
    await _success_audit(db_session, t, _at(7, 2, 3))
    rule = await _rule(db_session, RULE_TYPE_BACKUP_STALE)
    matches = await _matching_backup_stale_subjects(db_session, rule, NOW)
    assert len(matches) == 1
    assert "The last run failed." in matches[0][2]


async def test_dead_in_progress_run_is_stale(db_session: AsyncSession) -> None:
    """A process that died mid-run leaves ``in_progress`` behind and the
    sweep skips the target from then on. That is not a success."""
    # Last success 10-09; the 10-10 02:00 run died ten hours ago. With
    # N=1 that is stale now, and would not be if the dead run counted.
    t = await _target(
        db_session, status="in_progress", last_run_at=_at(10, 2, 1), next_run_at=_at(10)
    )
    await _success_audit(db_session, t, _at(9, 2, 2))
    rule = await _rule(db_session, RULE_TYPE_BACKUP_STALE, threshold_percent=1)
    matches = await _matching_backup_stale_subjects(db_session, rule, NOW)
    assert len(matches) == 1
    assert "marked in progress since 2026-10-10 02:01 UTC" in matches[0][2]

    health = {
        h.name: h for h in await evaluate_backup_health(db_session, now=NOW, stale_after_runs=1)
    }
    assert health["vault"].state == "stale"
    assert health["vault"].run_presumed_dead is True


async def test_live_in_progress_run_does_not_open(db_session: AsyncSession) -> None:
    started = NOW - RUN_PRESUMED_DEAD_AFTER + timedelta(minutes=5)
    t = await _target(db_session, status="in_progress", last_run_at=started, next_run_at=_at(8))
    await _success_audit(db_session, t, _at(1, 2, 2))
    rule = await _rule(db_session, RULE_TYPE_BACKUP_STALE)
    assert await _matching_backup_stale_subjects(db_session, rule, NOW) == []
    (health,) = await evaluate_backup_health(db_session, now=NOW)
    assert (health.state, health.stale) == ("running", False)


# ══════════════════════════════════════════════════════════════════════
# The real runner keeps the last success visible after a failure
# ══════════════════════════════════════════════════════════════════════


async def test_runner_success_then_failure_keeps_last_success(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.backup import runner
    from app.services.backup.archive import BackupArchiveError

    class _Driver:
        def validate_config(self, config: dict[str, Any]) -> None:
            return None

        async def write(
            self, *, config: dict[str, Any], filename: str, archive_bytes: bytes
        ) -> None:
            return None

    outcome: dict[str, bool] = {"fail": False}

    async def _build(db: AsyncSession, **kw: Any) -> tuple[bytes, str]:
        if outcome["fail"]:
            raise BackupArchiveError("disk full")
        return b"zip", "spatiumddi-backup-20261010-020000.zip"

    monkeypatch.setattr(runner, "get_destination", lambda kind: _Driver())
    monkeypatch.setattr(runner, "decrypt_config_secrets", lambda driver, cfg: cfg)
    monkeypatch.setattr(runner, "build_backup_archive", _build)

    t = await _target(db_session, status="never", next_run_at=_at(10))
    await runner.run_backup_for_target(db_session, target=t, triggered_by="schedule")
    first = {h.name: h for h in await evaluate_backup_health(db_session, now=datetime.now(UTC))}
    succeeded_at = first["vault"].last_success_at
    assert succeeded_at is not None

    outcome["fail"] = True
    await runner.run_backup_for_target(db_session, target=t, triggered_by="schedule")
    after = {h.name: h for h in await evaluate_backup_health(db_session, now=datetime.now(UTC))}
    assert after["vault"].last_run_status == "failed"
    assert after["vault"].failed is True
    # From the audit row now; the row itself only remembers the failure.
    assert after["vault"].last_success_at is not None
    assert abs((after["vault"].last_success_at - succeeded_at).total_seconds()) < 60


# ══════════════════════════════════════════════════════════════════════
# End to end through evaluate_all
# ══════════════════════════════════════════════════════════════════════


async def _open_events(db: AsyncSession, rule_id: uuid.UUID) -> list[AlertEvent]:
    return list(
        (
            await db.execute(
                select(AlertEvent).where(
                    AlertEvent.rule_id == rule_id, AlertEvent.resolved_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )


async def test_failed_one_event_held_during_retry_then_resolved(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = _DeliverSpy()
    monkeypatch.setattr("app.services.alerts._deliver", spy)
    now = datetime.now(UTC)
    t = await _target(
        db_session,
        status="failed",
        last_run_at=now - timedelta(minutes=10),
        next_run_at=compute_next_run(NIGHTLY, after=now),
        created_at=now - timedelta(hours=1),
    )
    rule = await _rule(db_session, RULE_TYPE_BACKUP_FAILED)
    rule_id, target_id = rule.id, str(t.id)
    await db_session.commit()

    await evaluate_all(db_session)
    await evaluate_all(db_session)
    events = await _open_events(db_session, rule_id)
    assert len(events) == 1
    assert events[0].subject_type == "backup_target"
    assert events[0].subject_id == target_id
    assert spy.calls == 1

    # A retry is running: the event stands, nothing new is delivered.
    t.last_run_status = "in_progress"
    t.last_run_at = datetime.now(UTC)
    await db_session.commit()
    await evaluate_all(db_session)
    assert len(await _open_events(db_session, rule_id)) == 1
    assert spy.calls == 1

    # ...and it failed again: still the same one event.
    t.last_run_status = "failed"
    await db_session.commit()
    await evaluate_all(db_session)
    assert len(await _open_events(db_session, rule_id)) == 1
    assert spy.calls == 1

    t.last_run_status = "success"
    await db_session.commit()
    await evaluate_all(db_session)
    assert await _open_events(db_session, rule_id) == []


async def test_stale_held_while_a_run_is_live_then_resolved(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = _DeliverSpy()
    monkeypatch.setattr("app.services.alerts._deliver", spy)
    now = datetime.now(UTC)
    last = compute_next_run(NIGHTLY, after=now - timedelta(days=5))
    t = await _target(
        db_session,
        status="success",
        last_run_at=last,
        next_run_at=compute_next_run(NIGHTLY, after=last),
    )
    rule = await _rule(db_session, RULE_TYPE_BACKUP_STALE, threshold_percent=2)
    rule_id = rule.id
    await db_session.commit()

    await evaluate_all(db_session)
    assert len(await _open_events(db_session, rule_id)) == 1
    assert spy.calls == 1

    # Someone hit "Run now": the event stands while the run is live.
    t.last_run_status = "in_progress"
    t.last_run_at = datetime.now(UTC)
    await db_session.commit()
    await evaluate_all(db_session)
    assert len(await _open_events(db_session, rule_id)) == 1
    assert spy.calls == 1

    t.last_run_status = "success"
    t.next_run_at = compute_next_run(NIGHTLY, after=datetime.now(UTC))
    await db_session.commit()
    await evaluate_all(db_session)
    assert await _open_events(db_session, rule_id) == []


# ══════════════════════════════════════════════════════════════════════
# Registration + seeding
# ══════════════════════════════════════════════════════════════════════


def test_rule_types_registered() -> None:
    assert RULE_TYPE_BACKUP_FAILED in RULE_TYPES
    assert RULE_TYPE_BACKUP_STALE in RULE_TYPES


async def test_seed_enabled_and_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Session:
        def __init__(self, existing: object | None) -> None:
            self._existing = existing
            self.added: list[Any] = []
            self.committed = False

        async def scalar(self, *args: Any, **kwargs: Any) -> Any:
            return self._existing

        def add(self, obj: Any) -> None:
            self.added.append(obj)

        async def commit(self) -> None:
            self.committed = True

        async def __aenter__(self) -> Any:
            return self

        async def __aexit__(self, *exc: Any) -> None:
            return None

    first = _Session(existing=None)
    monkeypatch.setattr("app.db.AsyncSessionLocal", lambda: first)
    await alerts_mod.seed_backup_alert_rules()
    by_type = {r.rule_type: r for r in first.added}
    assert set(by_type) == {RULE_TYPE_BACKUP_FAILED, RULE_TYPE_BACKUP_STALE}
    assert all(r.enabled is True for r in first.added)
    assert by_type[RULE_TYPE_BACKUP_FAILED].severity == "warning"
    assert by_type[RULE_TYPE_BACKUP_STALE].severity == "critical"
    assert by_type[RULE_TYPE_BACKUP_STALE].threshold_percent == 2
    assert first.committed is True

    second = _Session(existing=object())
    monkeypatch.setattr("app.db.AsyncSessionLocal", lambda: second)
    await alerts_mod.seed_backup_alert_rules()
    assert second.added == []
    assert second.committed is False


# ══════════════════════════════════════════════════════════════════════
# Copilot tool
# ══════════════════════════════════════════════════════════════════════


async def _user(db: AsyncSession, *, superadmin: bool) -> User:
    user = User(
        username=f"u-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="u",
        hashed_password="x",
        auth_source="local",
        is_superadmin=superadmin,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return user


async def test_tool_is_superadmin_only_and_agrees_with_alert(db_session: AsyncSession) -> None:
    from app.services.ai.tools.backup import BackupHealthArgs, get_backup_health

    now = datetime.now(UTC)
    last = compute_next_run(NIGHTLY, after=now - timedelta(days=5))
    await _target(
        db_session,
        name="stale-one",
        status="success",
        last_run_at=last,
        next_run_at=compute_next_run(NIGHTLY, after=last),
    )
    await _target(db_session, name="manual", cron=None, status="never")
    rule = await _rule(db_session, RULE_TYPE_BACKUP_STALE, threshold_percent=2)

    denied = await get_backup_health(
        db_session, await _user(db_session, superadmin=False), BackupHealthArgs()
    )
    assert "error" in denied

    out = await get_backup_health(
        db_session, await _user(db_session, superadmin=True), BackupHealthArgs()
    )
    states = {t["name"]: t["state"] for t in out["targets"]}
    assert states == {"manual": "manual_only", "stale-one": "stale"}
    assert out["stale"] == 1
    assert all("config" not in t and "passphrase" not in str(t) for t in out["targets"])

    alerted = await _matching_backup_stale_subjects(db_session, rule, datetime.now(UTC))
    assert [m[1] for m in alerted] == ["stale-one"]

    only = await get_backup_health(
        db_session,
        await _user(db_session, superadmin=True),
        BackupHealthArgs(problems_only=True),
    )
    assert [t["name"] for t in only["targets"]] == ["stale-one"]
