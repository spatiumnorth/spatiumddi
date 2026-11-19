"""Shared "has the configured interval elapsed?" gate for beat-ticked tasks.

Several tasks are fired by Celery Beat on a fixed tick (60 s, or 10 s for the
DHCP lease pull) and decide for themselves whether their *operator-configured*
interval has elapsed, so a cadence change in the UI needs no beat restart.
They stamp ``last_run_at`` from a clock read a variable fraction of a second
into the task, and beat fires on a fixed grid -- so at an interval equal to
the tick, the elapsed time between two consecutive beats comes out a little
*under* the interval about half the time, the beat is skipped, and the run
slips a whole tick later (a 1-minute interval ran every 2 minutes, #2346).

The fix is a small tolerance, sized to the start-of-task jitter rather than
to the interval: a run is due once ``elapsed >= interval - tolerance``. The
tolerance is capped to half the interval so it can never turn a 10 s
interval into "always due".
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

# Start-of-task jitter on a 60 s beat (queue wait + the module / settings
# reads before ``now`` is taken). Generous, still tiny next to any interval
# an operator would choose.
BEAT_JITTER_TOLERANCE = timedelta(seconds=5)
# Same, for the 10 s beat tick (dhcp lease pull).
FAST_BEAT_JITTER_TOLERANCE = timedelta(seconds=2)


def interval_skip(
    now: datetime,
    last_run_at: datetime | None,
    interval: timedelta,
    tolerance: timedelta = BEAT_JITTER_TOLERANCE,
) -> dict[str, Any] | None:
    """Return the ``skipped`` result when the interval has not elapsed, else None."""
    if last_run_at is None:
        return None
    tolerance = min(tolerance, interval / 2)
    elapsed = now - last_run_at
    if elapsed >= interval - tolerance:
        return None
    return {
        "status": "skipped",
        "reason": "interval_not_elapsed",
        "wait_seconds": max(0, int((interval - elapsed).total_seconds())),
    }
