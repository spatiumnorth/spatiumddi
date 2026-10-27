"""A drive whose worker is stopped releases the run's Lease on its way out (#2865, #2869).

The Celery worker that runs a Rolling Upgrade's drive is stopped like any pod:
SIGTERM, a warm shutdown that waits for the running tasks, then SIGKILL at the
end of the grace period (90 s). A drive runs for as long as its run, so it went
on renewing the run's Lease through the grace period and was killed with the
Lease held. Nothing drove the run until the 600 s Lease lapsed and the orphan
sweep re-drove it: about 12 minutes on qa-review's roll of #2852 (#2865, the
seed's mid-run re-render rolled the worker) and 11 on its roll of #2863
(#2869, the rollout to the new version stopped a stray copy of the drive).

The worker's main process now sends SIGTERM to the pool process running a
drive as soon as its own shutdown starts. billiard's handler there raises
SystemExit, which unwinds the drive, and the drive releases its Lease (only its
own) on the way out, so the drive put back on the queue (``acks_late`` with
``reject_on_worker_lost``), or else the orphan sweep, takes the run over at once.
"""

from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import sys
import textwrap
import time
import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.tasks import upgrade_orchestrator as task

ME = "spatium-control-spatiumddi-worker-x_abcdefabcdef"


class _Session:
    async def __aenter__(self) -> _Session:
        return self

    async def __aexit__(self, *_a: Any) -> None:
        return None


@pytest.fixture
def lease(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    from app.services.upgrades import mutex

    release = MagicMock(return_value=True)
    monkeypatch.setattr(mutex, "release_if_held", release)
    monkeypatch.setattr(mutex, "drive_identity", lambda: ME)
    monkeypatch.setattr(task, "task_session", lambda: _Session())
    return release


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stop",
    [
        SystemExit(-241),  # billiard's SIGTERM handler in a pool process
        asyncio.CancelledError(),  # asyncio.run cancelling the drive as that unwinds
        KeyboardInterrupt(),
    ],
    ids=["system-exit", "cancelled", "keyboard-interrupt"],
)
async def test_a_stopped_drive_releases_its_own_lease(
    lease: MagicMock, monkeypatch: pytest.MonkeyPatch, stop: BaseException
) -> None:
    async def _drive(*_a: Any, **_k: Any) -> Any:
        raise stop

    monkeypatch.setattr(task, "drive_upgrade", _drive)

    with pytest.raises(type(stop)):
        await task._async_drive(str(uuid.uuid4()))

    lease.assert_called_once()
    assert lease.call_args.kwargs["holder"] == ME


@pytest.mark.asyncio
async def test_a_drive_that_ends_leaves_the_lease_to_the_drive(
    lease: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The drive's own paths release or hand off the Lease; nothing else does."""

    async def _drive(_db: Any, rid: uuid.UUID, **_k: Any) -> Any:
        return SimpleNamespace(id=rid, state="succeeded")

    monkeypatch.setattr(task, "drive_upgrade", _drive)

    out = await task._async_drive(str(uuid.uuid4()))

    assert out["state"] == "succeeded"
    lease.assert_not_called()


def test_sigterm_to_a_pool_process_releases_the_lease_through_asyncio_run(
    tmp_path: Any,
) -> None:
    """The real path, in a process of its own: billiard's handler for SIGTERM
    in a pool process (``reset_signals``) raises SystemExit while the drive
    awaits, ``asyncio.run`` cancels the drive as it unwinds, and the drive
    releases its Lease before the process exits."""
    out = tmp_path / "released.txt"
    script = textwrap.dedent(f"""
        import asyncio, sys, uuid
        from billiard.common import reset_signals
        from app.services.upgrades import mutex
        from app.tasks import upgrade_orchestrator as task

        def _release(*, holder, **_kw):
            with open({str(out)!r}, "a") as f:
                f.write(holder + "\\n")
            return True

        class _Session:
            async def __aenter__(self):
                return self
            async def __aexit__(self, *_a):
                return None

        async def _drive(*_a, **_k):
            print("driving", flush=True)
            await asyncio.sleep(60)

        mutex.release_if_held = _release
        mutex.drive_identity = lambda: {ME!r}
        task.task_session = lambda: _Session()
        task.drive_upgrade = _drive
        reset_signals()  # what billiard does in every pool process
        asyncio.run(task._async_drive(str(uuid.uuid4())))
        """)
    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=dict(os.environ),
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )
    try:
        assert proc.stdout is not None
        line = proc.stdout.readline()
        assert line.strip() == "driving", proc.stderr.read() if proc.stderr else ""
        time.sleep(0.2)
        proc.send_signal(signal.SIGTERM)
        code = proc.wait(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
    assert code != 0  # it exited because it was stopped, not because it finished
    assert out.read_text().splitlines() == [ME]


# ── the worker's shutdown stops the drives it runs ────────────────────────


def _request(name: str, pid: int | None) -> Any:
    return SimpleNamespace(name=name, worker_pid=pid, id=str(uuid.uuid4()), args=("run-1",))


def test_a_worker_shutdown_sends_sigterm_to_the_pool_process_running_a_drive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from celery.worker import state

    drive = "app.tasks.upgrade_orchestrator.drive_upgrade_run"
    requests = [
        _request(drive, 4101),
        _request("app.tasks.dns.something_else", 4102),
        _request(drive, None),  # not yet accepted by a pool process
        _request(drive, os.getpid()),  # solo/threads pool: the main process itself
        _request(drive, 4103),  # already gone
    ]
    monkeypatch.setattr(state, "active_requests", requests)
    sent: list[tuple[int, int]] = []

    def _kill(pid: int, sig: int) -> None:
        if pid == 4103:
            raise ProcessLookupError(pid)
        sent.append((pid, sig))

    monkeypatch.setattr(task.os, "kill", _kill)

    task._stop_drives_on_worker_shutdown(sig="TERM", how="Warm", exitcode=0)

    assert sent == [(4101, signal.SIGTERM)]


def test_the_workers_shutdown_signal_reaches_the_hook(monkeypatch: pytest.MonkeyPatch) -> None:
    from celery.signals import worker_shutting_down
    from celery.worker import state

    monkeypatch.setattr(
        state,
        "active_requests",
        [_request("app.tasks.upgrade_orchestrator.drive_upgrade_run", 4201)],
    )
    sent: list[tuple[int, int]] = []
    monkeypatch.setattr(task.os, "kill", lambda pid, sig: sent.append((pid, sig)))

    worker_shutting_down.send(sender="celery@worker-x", sig="TERM", how="Warm", exitcode=0)

    assert sent == [(4201, signal.SIGTERM)]
