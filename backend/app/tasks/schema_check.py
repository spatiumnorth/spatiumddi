"""Celery-side DB-schema-at-head guard (issue #565).

The api already gates on the schema being at the bundled Alembic head
via ``/health/ready`` (#299 / #301) — a pod stays out of the Service
endpoint set until the migrate Job lands head. The Celery **worker +
beat** had no equivalent: they start on whatever schema is present and
fail tasks silently in the background. An operator's env logged the
same ``UndefinedColumnError`` ~2440× in a tight retry loop because the
DHCP config long-poll hammers ``db.get(PlatformSettings, 1)`` while the
DB was still on the old schema.

This module reuses the framework-agnostic
``app.core.schema_check.schema_at_head`` comparison for Celery:

1. **Startup check** — ``worker_ready`` / ``beat_init`` run the check
   once and log a loud structured warning if the DB is behind.
2. **Periodic re-check** — the ``check_schema_at_head`` beat task
   re-runs the comparison, logs a warning + opens/refreshes an
   ``AlertEvent`` against the ``schema-behind-head`` rule on drift, and
   auto-resolves it once the schema is back at head. Covers "worker
   started before migrate finished" and "worker running a stale image"
   where a one-shot startup check would miss a later divergence.
3. **Opt-in strict mode** — ``STRICT_SCHEMA_CHECK=true`` makes the
   ``task_prerun`` gate ``Reject(requeue=True)`` tasks while the schema
   is behind. Default off so a
   transient mid-rollout window doesn't hard-stop the worker.

Because the check compares packaged migration files against the DB's
``alembic_version``, the exact same helper works in docker-compose and
k8s with zero orchestration-specific branching.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from time import monotonic

import structlog
from celery import shared_task
from celery.exceptions import Reject
from celery.signals import beat_init, task_prerun, worker_ready
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.config import settings
from app.core.schema_check import SchemaCheck, schema_at_head

logger = structlog.get_logger(__name__)

_RULE_NAME = "schema-behind-head"


# Per-process throttle for the strict ``task_prerun`` gate — a fresh
# ``schema_at_head`` DB round-trip on *every* task would defeat the
# purpose. Cache the last verdict for this long; the periodic task +
# startup check keep the operator-facing signal fresh independently.
_STRICT_CACHE_TTL_SECONDS = 30.0


@dataclass(slots=True)
class _StrictCache:
    checked_at: float | None = None
    behind: bool = False


_strict_cache = _StrictCache()

# Tasks that must run even while the schema is behind — the strict
# gate would otherwise deadlock the very check that clears it (and the
# beat heartbeat that proves beat is alive).
_STRICT_EXEMPT_TASKS = frozenset(
    {
        "app.tasks.schema_check.check_schema_at_head",
        "app.tasks.heartbeat.beat_tick",
    }
)


async def _check() -> SchemaCheck:
    """Run the schema comparison on a per-call engine.

    Celery's ``asyncio.run(...)`` pattern spins a fresh event loop per
    invocation; the shared ``AsyncSessionLocal`` engine binds asyncpg
    connections to the *first* loop, so a later reuse raises
    ``RuntimeError: Future attached to a different loop`` (see
    ``app.db.task_session``). Every Celery-side caller here must use
    ``task_session`` (a throwaway engine scoped to the current loop),
    not the default ``AsyncSessionLocal`` the FastAPI readiness probe
    uses.
    """
    from app.db import task_session  # noqa: PLC0415

    return await schema_at_head(session_factory=task_session)


def _log_startup(result: SchemaCheck, *, who: str) -> None:
    if result.ok:
        logger.info("schema_check_startup_ok", who=who, detail=result.detail)
    else:
        # Loud — this is the "code deployed before migrate ran" footgun
        # that would otherwise be a silent background retry storm.
        logger.warning(
            "schema_behind_bundled_head",
            who=who,
            detail=result.detail,
            expected=result.expected,
            actual=result.actual,
            strict=settings.strict_schema_check,
        )


@worker_ready.connect
def _worker_ready_schema_check(**_: object) -> None:
    """One-shot schema-at-head check when the worker finishes booting."""
    try:
        result = asyncio.run(_check())
    except Exception as exc:  # noqa: BLE001 — never block worker start
        logger.warning("schema_check_startup_failed", who="worker", error=str(exc))
        return
    _log_startup(result, who="worker")
    _strict_cache.checked_at = monotonic()
    _strict_cache.behind = not result.ok


@beat_init.connect
def _beat_init_schema_check(**_: object) -> None:
    """One-shot schema-at-head check when beat starts."""
    try:
        result = asyncio.run(_check())
    except Exception as exc:  # noqa: BLE001 — never block beat start
        logger.warning("schema_check_startup_failed", who="beat", error=str(exc))
        return
    _log_startup(result, who="beat")


@task_prerun.connect
def _strict_schema_gate(sender: object | None = None, **_: object) -> None:
    """Refuse to run tasks while the schema is behind, when strict.

    Off by default. When ``STRICT_SCHEMA_CHECK=true`` and a throttled
    check finds the DB behind the bundled head, ``Reject(requeue=True)``
    sends the message back to the broker for redelivery instead of
    running the task against a schema it can't satisfy. The exempt set
    keeps the check task + beat heartbeat runnable so the gate can
    clear itself.
    """
    if not settings.strict_schema_check:
        return
    task_name = getattr(sender, "name", None)
    if task_name in _STRICT_EXEMPT_TASKS:
        return

    checked_at = _strict_cache.checked_at
    now = monotonic()
    if checked_at is None or (now - checked_at) > _STRICT_CACHE_TTL_SECONDS:
        try:
            result = asyncio.run(_check())
        except Exception as exc:  # noqa: BLE001 — fail open, don't wedge on a blip
            logger.warning("strict_schema_gate_check_failed", error=str(exc))
            return
        _strict_cache.checked_at = now
        _strict_cache.behind = not result.ok

    if _strict_cache.behind:
        logger.warning(
            "strict_schema_gate_rejecting_task",
            task=task_name,
            detail="DB schema behind bundled head; STRICT_SCHEMA_CHECK deferring task",
        )
        # Reject raised from a task_prerun receiver IS honored: Celery's
        # tracer sends the prerun signal inside the same try/except that
        # catches Reject, so requeue=True bounces the message back to the
        # broker (not a permanent failure). TRADEOFF: requeue has no
        # delay, so during the (short, opt-in) behind-schema window
        # non-exempt tasks redeliver-and-re-reject in a busy loop until
        # migrate lands head. That's the deliberate cost of a hard-stop
        # — STRICT_SCHEMA_CHECK is off by default precisely so the
        # common mid-rollout window just warns + alerts instead.
        raise Reject("schema behind bundled head (STRICT_SCHEMA_CHECK)", requeue=True)


async def _async_check_and_alert() -> dict:
    from app.db import task_session  # noqa: PLC0415
    from app.models.alerts import AlertEvent, AlertRule  # noqa: PLC0415

    result = await _check()

    # Refresh the strict-gate cache off the periodic check too so a
    # drift/recovery is reflected without waiting for the TTL to lapse
    # in the prerun path.
    _strict_cache.checked_at = monotonic()
    _strict_cache.behind = not result.ok

    async with task_session() as db:
        rule = (
            await db.execute(select(AlertRule).where(AlertRule.name == _RULE_NAME))
        ).scalar_one_or_none()

        if result.ok:
            logger.info("schema_check_ok", detail=result.detail)
            # Auto-resolve EVERY open drift event now the schema caught
            # up — the drift path keys dedupe on subject_id (the behind
            # revision), so passing through several behind revisions
            # (A → B → head) can leave more than one open event. Resolve
            # them all in one OK tick, not one-per-tick.
            if rule is not None:
                open_events = (
                    (
                        await db.execute(
                            select(AlertEvent)
                            .where(AlertEvent.rule_id == rule.id)
                            .where(AlertEvent.resolved_at.is_(None))
                        )
                    )
                    .scalars()
                    .all()
                )
                if open_events:
                    resolved_at = datetime.now(UTC)
                    for open_evt in open_events:
                        open_evt.resolved_at = resolved_at
                    await db.commit()
            return {"ok": True, "detail": result.detail}

        logger.warning(
            "schema_behind_bundled_head",
            who="periodic",
            detail=result.detail,
            expected=result.expected,
            actual=result.actual,
            strict=settings.strict_schema_check,
        )

        if rule is None:
            # Seeder ran late / operator deleted the rule. The drift
            # itself is the important signal — log it, don't crash.
            logger.error("schema_behind_head_no_rule", detail=result.detail)
            return {"ok": False, "detail": result.detail, "no_rule": True}

        # Dedupe: one open event covers the drift. Subject id is the
        # observed (behind) version so a fresh drift to a *different*
        # actual version opens a distinct event.
        subject_id = result.actual or "uninitialised"
        existing = (
            await db.execute(
                select(AlertEvent)
                .where(AlertEvent.rule_id == rule.id)
                .where(AlertEvent.resolved_at.is_(None))
                .where(AlertEvent.subject_id == subject_id)
                .limit(1)
            )
        ).scalar_one_or_none()
        if existing is not None:
            return {"ok": False, "detail": result.detail, "deduped": True}

        evt = AlertEvent(
            rule_id=rule.id,
            subject_type="platform",
            subject_id=subject_id,
            subject_display="database schema",
            severity="critical",
            message=(
                f"Celery worker/beat found the DB schema behind the bundled "
                f"Alembic head: {result.detail}. Run 'alembic upgrade head' "
                f"(the migrate step). Background tasks may fail against missing "
                f"tables/columns until the schema catches up."
            ),
            fired_at=datetime.now(UTC),
            last_observed_value={
                "expected_head": result.expected,
                "actual_version": result.actual,
                "detail": result.detail,
            },
        )
        db.add(evt)
        await db.flush()
        # #1576 — deliver to forward targets; the generic evaluator
        # skips externally-driven rule types, so without this the
        # event only ever showed in-app.
        try:
            from app.services import alerts as alert_service  # noqa: PLC0415
            from app.services import audit_forward  # noqa: PLC0415

            targets = await audit_forward._load_targets()  # noqa: SLF001
            ds, dw, dm = await alert_service._deliver(rule, evt, targets)  # noqa: SLF001
            evt.delivered_syslog = ds
            evt.delivered_webhook = dw
            evt.delivered_smtp = dm
        except Exception as exc:  # noqa: BLE001 — delivery must not lose the alert
            logger.warning("schema_behind_head_delivery_failed", error=str(exc))
        await db.commit()
        return {"ok": False, "detail": result.detail}


@shared_task(
    name="app.tasks.schema_check.check_schema_at_head",
    bind=True,
    autoretry_for=(SQLAlchemyError, ConnectionError, OSError),
    retry_backoff=True,
    retry_backoff_max=300,
    retry_jitter=True,
    max_retries=3,
)
def check_schema_at_head(self: object) -> dict:  # type: ignore[type-arg]
    """Periodic beat entry point. Idempotent + self-resolving."""
    return asyncio.run(_async_check_and_alert())
