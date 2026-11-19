"""Cron-string parsing + next-run computation for scheduled
backups (issue #117 Phase 1b).

Thin wrapper over :mod:`croniter` so the rest of the backup
surface doesn't have to import it directly. Two operations:

* :func:`compute_next_run` — given a cron string + a ``from``
  timestamp, return the next firing in UTC. Raises
  :class:`InvalidCronExpression` for unparseable input.
* :func:`is_due` — convenience wrapper that answers "should this
  target run now?" given its persisted ``next_run_at`` + the
  current time.
"""

from __future__ import annotations

from datetime import UTC, datetime

from croniter import CroniterBadCronError, croniter


class InvalidCronExpression(ValueError):
    """Raised when the operator-supplied cron string can't be
    parsed. The API layer 422s on it with the message verbatim
    so the operator sees what was wrong.
    """


def validate_cron(expression: str) -> None:
    """Raise :class:`InvalidCronExpression` if ``expression``
    isn't a valid 5-field cron string.
    """
    if not expression or not expression.strip():
        raise InvalidCronExpression("cron expression is empty")
    try:
        croniter(expression, datetime.now(UTC))
    except (CroniterBadCronError, ValueError, TypeError) as exc:
        raise InvalidCronExpression(f"invalid cron expression: {exc}") from exc


def compute_next_run(expression: str, *, after: datetime | None = None) -> datetime:
    """Return the next firing of ``expression`` strictly after
    ``after`` (defaults to now). UTC-aware.
    """
    base = (after or datetime.now(UTC)).astimezone(UTC)
    try:
        it = croniter(expression, base)
    except (CroniterBadCronError, ValueError, TypeError) as exc:
        raise InvalidCronExpression(f"invalid cron expression: {exc}") from exc
    return it.get_next(datetime).astimezone(UTC)


def compute_prev_run(expression: str, *, before: datetime) -> datetime:
    """Return the last firing of ``expression`` strictly before
    ``before``. UTC-aware. The mirror of :func:`compute_next_run`.
    """
    base = before.astimezone(UTC)
    try:
        it = croniter(expression, base)
    except (CroniterBadCronError, ValueError, TypeError) as exc:
        raise InvalidCronExpression(f"invalid cron expression: {exc}") from exc
    return it.get_prev(datetime).astimezone(UTC)


def is_due(next_run_at: datetime | None, *, now: datetime | None = None) -> bool:
    """Cheap predicate for the beat sweep — "should this target
    run right now?". A NULL ``next_run_at`` means "manual only";
    a future ``next_run_at`` means "wait"; a past ``next_run_at``
    means "fire".
    """
    if next_run_at is None:
        return False
    current = (now or datetime.now(UTC)).astimezone(UTC)
    return next_run_at.astimezone(UTC) <= current
