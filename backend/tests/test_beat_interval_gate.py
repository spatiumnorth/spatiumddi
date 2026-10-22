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

from app.tasks import dhcp_pull_leases, dns_pull, ipam_dns_sync, reverse_dns


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
]
IDS = ["ipam_dns_sync", "dns_pull", "reverse_dns", "dhcp_pull_leases"]


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
