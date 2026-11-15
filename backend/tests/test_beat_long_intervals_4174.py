"""Long beat intervals must be fixed-time crontabs (#4174).

Beat keeps no state, so ``schedule(run_every=N)`` restarts its timer on every
beat restart; with N of a day or more, restarts more often than that starve
the job.  Crontab entries fire at a wall-clock time regardless.
"""

from __future__ import annotations

import pytest
from celery.schedules import crontab, schedule

from app import celery_app as ca

# An interval at or below this is a frequent tick: a restart delays it at most
# this long, and the tasks are self-gating sweeps.
MAX_INTERVAL_SECONDS = 3600.0


def _entries() -> dict:
    return ca.celery_app.conf.beat_schedule


def test_no_beat_interval_longer_than_an_hour() -> None:
    bad = {
        name: e["schedule"].run_every.total_seconds()
        for name, e in _entries().items()
        if isinstance(e["schedule"], schedule)
        and not isinstance(e["schedule"], crontab)
        and e["schedule"].run_every.total_seconds() > MAX_INTERVAL_SECONDS
    }
    assert not bad, f"use crontab(...) for long beat intervals: {bad}"


@pytest.mark.parametrize(
    ("name", "hours", "minutes"),
    [
        ("subnet-utilization-snapshot", {2}, {15}),
        ("metric-samples-prune", {2}, {45}),
        ("e911-resolution-log-prune", {4}, {10}),
        ("update-check", {5}, {0}),
        ("acme-renew-due", {0, 12}, {20}),
        ("log-entries-prune", set(range(24)), {5}),
    ],
)
def test_daily_jobs_are_fixed_time_crontabs(name: str, hours: set, minutes: set) -> None:
    sched = _entries()[name]["schedule"]
    assert isinstance(sched, crontab)
    assert sched.hour == hours
    assert sched.minute == minutes
