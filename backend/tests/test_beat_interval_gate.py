"""Beat-ticked tasks must run on every tick at an interval equal to the tick (#2346).

Beat fires on a fixed grid, but each task stamps ``last_run_at`` from a clock
read a variable fraction of a second into the run, so consecutive beats are
often a hair under the interval apart.  The gate used to skip those, doubling
a 1-minute cadence to 2 minutes.  These tests drive the real task bodies with
a stand-in session and assert on the observable outcome: ran vs skipped.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from app.tasks import (
    dhcp_health,
    dhcp_mac_blocks,
    dhcp_pull_leases,
    dns_pull,
    ipam_dns_sync,
    reverse_dns,
)


class _Reached(Exception):
    """Raised by the fake session the moment a task gets past its gate."""


class _FakeSession:
    def __init__(self, ps: Any) -> None:
        self._ps = ps

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def get(self, *_a: Any, **_k: Any) -> Any:
        return self._ps

    async def execute(self, *_a: Any, **_k: Any) -> Any:
        raise _Reached

    async def commit(self) -> None:
        return None


class _FakeEngine:
    async def dispose(self) -> None:
        return None


def _patch(monkeypatch: pytest.MonkeyPatch, module: Any, ps: Any) -> None:
    monkeypatch.setattr(module, "create_async_engine", lambda *a, **k: _FakeEngine())
    monkeypatch.setattr(module, "async_sessionmaker", lambda *a, **k: lambda: _FakeSession(ps))

    async def _enabled(*_a: Any, **_k: Any) -> bool:
        return True

    if hasattr(module, "is_module_enabled"):
        monkeypatch.setattr(module, "is_module_enabled", _enabled)


def _ago(**kw: float) -> datetime:
    return datetime.now(UTC) - timedelta(**kw)


async def _outcome(coro: Any) -> str:
    try:
        result = await coro
    except _Reached:
        return "ran"
    return "skipped" if result.get("status") == "skipped" else str(result)


CASES = [
    (
        ipam_dns_sync,
        ipam_dns_sync._run_auto_sync,
        dict(
            dns_auto_sync_enabled=True,
            dns_auto_sync_interval_minutes=1,
            dns_auto_sync_last_run_at=None,
        ),
        "dns_auto_sync_last_run_at",
        {"minutes": 1},
    ),
    (
        dns_pull,
        dns_pull._run_sync,
        dict(
            dns_pull_from_server_enabled=True,
            dns_pull_from_server_interval_minutes=1,
            dns_pull_from_server_last_run_at=None,
        ),
        "dns_pull_from_server_last_run_at",
        {"minutes": 1},
    ),
    (
        reverse_dns,
        reverse_dns._run_sweep,
        dict(
            reverse_dns_enabled=True,
            reverse_dns_interval_minutes=1,
            reverse_dns_resolvers=None,
            reverse_dns_last_run_at=None,
        ),
        "reverse_dns_last_run_at",
        {"minutes": 1},
    ),
    (
        dhcp_pull_leases,
        dhcp_pull_leases._run_pull,
        dict(
            dhcp_pull_leases_enabled=True,
            dhcp_pull_leases_interval_seconds=10,
            dhcp_pull_leases_last_run_at=None,
        ),
        "dhcp_pull_leases_last_run_at",
        {"seconds": 10},
    ),
    (
        dhcp_health,
        dhcp_health._enqueue_all,
        dict(
            dhcp_health_check_interval_seconds=60,
            dhcp_health_check_last_run_at=None,
        ),
        "dhcp_health_check_last_run_at",
        {"seconds": 60},
    ),
    (
        dhcp_mac_blocks,
        dhcp_mac_blocks._run_sync,
        dict(
            dhcp_mac_blocks_sync_interval_seconds=60,
            dhcp_mac_blocks_sync_last_run_at=None,
        ),
        "dhcp_mac_blocks_sync_last_run_at",
        {"seconds": 60},
    ),
]
IDS = [
    "ipam_dns_sync",
    "dns_pull",
    "reverse_dns",
    "dhcp_pull_leases",
    "dhcp_health",
    "dhcp_mac_blocks",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("module,fn,fields,stamp,interval", CASES, ids=IDS)
async def test_run_slightly_under_interval_after_last_run_still_runs(
    monkeypatch: pytest.MonkeyPatch, module: Any, fn: Any, fields: dict, stamp: str, interval: dict
) -> None:
    # The previous run was stamped 0.7 s short of one interval ago: a beat that
    # landed a touch early.  It must run, not wait a whole extra tick.
    ps = SimpleNamespace(**fields)
    setattr(ps, stamp, _ago(**interval) + timedelta(seconds=0.7))
    _patch(monkeypatch, module, ps)
    assert await _outcome(fn()) == "ran"


@pytest.mark.asyncio
@pytest.mark.parametrize("module,fn,fields,stamp,interval", CASES, ids=IDS)
async def test_run_well_inside_interval_is_still_skipped(
    monkeypatch: pytest.MonkeyPatch, module: Any, fn: Any, fields: dict, stamp: str, interval: dict
) -> None:
    # The tolerance must not defeat the gate: a run only a third of the way
    # through the interval still skips.
    ps = SimpleNamespace(**fields)
    setattr(ps, stamp, datetime.now(UTC) - timedelta(**interval) / 3)
    _patch(monkeypatch, module, ps)
    assert await _outcome(fn()) == "skipped"


# #4759 — the agentless DHCP health sweep and MAC-block sync gate on their
# own configured interval instead of running on every 60 s beat tick.
AGENTLESS_JOBS = [
    (
        dhcp_health,
        dhcp_health._enqueue_all,
        "dhcp_health_check_interval_seconds",
        "dhcp_health_check_last_run_at",
    ),
    (
        dhcp_mac_blocks,
        dhcp_mac_blocks._run_sync,
        "dhcp_mac_blocks_sync_interval_seconds",
        "dhcp_mac_blocks_sync_last_run_at",
    ),
]
AGENTLESS_IDS = ["dhcp_health", "dhcp_mac_blocks"]


@pytest.mark.asyncio
@pytest.mark.parametrize("module,fn,interval_field,stamp", AGENTLESS_JOBS, ids=AGENTLESS_IDS)
@pytest.mark.parametrize(
    "seconds_ago,expected", [(None, "ran"), (120, "skipped"), (299, "ran"), (301, "ran")]
)
async def test_agentless_dhcp_job_honours_a_longer_interval(
    monkeypatch: pytest.MonkeyPatch,
    module: Any,
    fn: Any,
    interval_field: str,
    stamp: str,
    seconds_ago: int | None,
    expected: str,
) -> None:
    # 300 s configured: two ticks after the last run is still too early, a run
    # at (or a jitter short of) five minutes goes ahead.
    ps = SimpleNamespace(**{interval_field: 300})
    setattr(ps, stamp, None if seconds_ago is None else _ago(seconds=seconds_ago))
    _patch(monkeypatch, module, ps)
    assert await _outcome(fn()) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("module,fn,interval_field,stamp", AGENTLESS_JOBS, ids=AGENTLESS_IDS)
async def test_agentless_dhcp_job_interval_is_floored_to_the_beat_tick(
    monkeypatch: pytest.MonkeyPatch, module: Any, fn: Any, interval_field: str, stamp: str
) -> None:
    # A value below the 60 s tick (only reachable by writing the row directly;
    # the API refuses it) behaves as 60 s, not as "every tick at any spacing".
    ps = SimpleNamespace(**{interval_field: 10, stamp: _ago(seconds=30)})
    _patch(monkeypatch, module, ps)
    assert await _outcome(fn()) == "skipped"


@pytest.mark.asyncio
@pytest.mark.parametrize("module,fn,interval_field,stamp", AGENTLESS_JOBS, ids=AGENTLESS_IDS)
async def test_agentless_dhcp_job_stamps_before_reaching_servers(
    monkeypatch: pytest.MonkeyPatch, module: Any, fn: Any, interval_field: str, stamp: str
) -> None:
    # The stamp is written before the servers are read, so the next tick sees
    # this run even while it is still in progress.
    ps = SimpleNamespace(**{interval_field: 300, stamp: None})
    _patch(monkeypatch, module, ps)
    assert await _outcome(fn()) == "ran"
    assert getattr(ps, stamp) is not None
