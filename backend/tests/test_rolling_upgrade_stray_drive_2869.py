"""A stray copy of the drive leaves a run that handed off to the new version alone (#2869).

At a Redis failover the worker running a Rolling Upgrade's drive loses its
broker connection, and Celery puts the running drive task back on the queue
("Restoring 1 unacknowledged message(s)"). The run then holds a second copy of
its own drive, with none of the hand-off's arguments. On qa-review's drill of
#2863 that copy ran on an old-version worker the moment the first copy flipped
the shared tags and handed the run to the new version
(``drive_version_handoff``, the Lease released): it took the run's Lease over
(``lease_takeover``), went on to the settle wait on the old version, and the
rollout stopped its worker with the Lease held. The new version's drive was
refused until the 600 s Lease lapsed and the orphan sweep re-drove the run.

A drive still on the version the run handed off from is now not the run's
carrier unless it is the hand-off's own continuation (``avoid_version``), which
runs on the old version only once it has been passed on its whole budget. A
stray copy leaves the Lease alone; a Resume made after the hand-off is passed
on to the new version as the hand-off's continuation was.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.system_upgrade import SystemUpgradeRun
from app.services.upgrades import orchestrator
from app.services.upgrades.orchestrator import OrchestratorError

FROM = "2026.10.26-1"
TO = "2026.10.27-900"
HANDING = "worker-old-a_aaaaaaaaaaaa"  # the drive that flipped and handed off
STRAY = "worker-old-a_bbbbbbbbbbbb"  # the restored copy, same old worker
NEW = "worker-new-b_cccccccccccc"  # a drive on the new version
NODES = ["member-1", "member-2", "seed"]


def _handed_off_progress(*, extra_events: tuple[str, ...] = ()) -> dict[str, Any]:
    events: list[dict[str, Any]] = [{"event": "started", "at": "2026-10-27T08:20:00+00:00"}]
    for node in NODES:
        events.append({"event": "node_started", "node": node, "at": "2026-10-27T08:21:00+00:00"})
    events.append({"event": "shared_tags_flipped", "from_tag": FROM, "to_tag": TO})
    events.append({"event": "drive_version_handoff", "from_tag": FROM})
    events.extend({"event": e, "at": "2026-10-27T08:39:00+00:00"} for e in extra_events)
    return {
        "per_node": {n: {"ok": True} for n in NODES},
        "events": events,
        "shared_tags": {
            "mode": "hold",
            "from_tag": FROM,
            "to_tag": TO,
            "nodes": NODES,
            "released_at": "2026-10-27T08:37:42+00:00",
            "release_reason": "flip",
            "flip": {
                "state": "flipped",
                "workloads": [],
                "handed_off_at": "2026-10-27T08:37:42.410000+00:00",
            },
        },
    }


async def _run(db: AsyncSession, progress: dict[str, Any]) -> SystemUpgradeRun:
    run = SystemUpgradeRun(
        kind="cluster_rolling",
        state="running",
        target_version=TO,
        source_versions={},
        plan={"node_order": NODES, "slot_image_url": "http://x"},
        progress=progress,
        lease_holder=HANDING,
        started_at=datetime.now(UTC),
    )
    db.add(run)
    await db.commit()
    return run


class _Lease:
    """The run's Lease as the drive sees it: free after the hand-off released it."""

    def __init__(self, holder: str | None = None) -> None:
        self.holder = holder
        self.acquired: list[str] = []

    def acquire(self, *, holder: str, **_kw: Any) -> tuple[bool, str | None]:
        if self.holder not in (None, holder):
            return False, f"held by {self.holder}"
        self.holder = holder
        self.acquired.append(holder)
        return True, None


@pytest.fixture
def drive(monkeypatch: pytest.MonkeyPatch) -> Any:
    """The drive's own machinery stubbed: the Lease, the continuation, and the
    loop it would go on to (recorded, not run)."""
    lease = _Lease()
    continued: list[tuple[uuid.UUID, str]] = []
    loop = AsyncMock(return_value=None)

    async def _no_renewal(stop: asyncio.Event, *_a: Any, **_k: Any) -> None:
        return None

    monkeypatch.setattr(orchestrator.mutex, "acquire", lease.acquire)
    monkeypatch.setattr(
        orchestrator,
        "_enqueue_continuation",
        lambda rid, *, avoid_version: continued.append((rid, avoid_version)),
    )
    monkeypatch.setattr(orchestrator, "_drive_loop", loop)
    monkeypatch.setattr(orchestrator, "_lease_renewal_loop", _no_renewal)

    class _Drive:
        pass

    d = _Drive()
    d.lease, d.continued, d.loop = lease, continued, loop
    return d


def _events(run: SystemUpgradeRun) -> list[str]:
    return [str(e.get("event")) for e in (run.progress or {}).get("events") or []]


@pytest.mark.asyncio
async def test_a_stray_copy_on_the_old_version_leaves_the_handed_off_run_alone(
    db_session: AsyncSession, drive: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#2869's copy: on the old version, after the hand-off, no avoid_version."""
    monkeypatch.setattr(settings, "version", FROM)
    run = await _run(db_session, _handed_off_progress())

    out = await orchestrator.drive_upgrade(db_session, run.id, holder=STRAY)

    assert drive.lease.acquired == []  # the Lease stays free for the new version
    assert drive.loop.await_count == 0
    await db_session.refresh(out)
    assert out.state == "running"
    assert out.lease_holder == HANDING
    assert "lease_takeover" not in _events(out)
    # The hand-off's own continuation carries the run; no second one is sent.
    assert drive.continued == []


@pytest.mark.asyncio
async def test_the_handoffs_continuation_out_of_hops_still_takes_the_run_on_the_old_version(
    db_session: AsyncSession, drive: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fallback #1710 designed: a continuation that no worker on the new
    version took within its pass-on budget runs where it is."""
    monkeypatch.setattr(settings, "version", FROM)
    run = await _run(db_session, _handed_off_progress())

    out = await orchestrator.drive_upgrade(db_session, run.id, holder=STRAY, avoid_version=FROM)

    assert drive.lease.acquired == [STRAY]
    assert drive.loop.await_count == 1
    await db_session.refresh(out)
    assert out.lease_holder == STRAY
    assert _events(out)[-1] == "lease_takeover"
    assert drive.continued == []


@pytest.mark.asyncio
async def test_a_copy_on_the_new_version_takes_the_handed_off_run(
    db_session: AsyncSession, drive: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Any drive on the new version may carry the run: that is where it goes."""
    monkeypatch.setattr(settings, "version", TO)
    run = await _run(db_session, _handed_off_progress())

    out = await orchestrator.drive_upgrade(db_session, run.id, holder=NEW)

    assert drive.lease.acquired == [NEW]
    assert drive.loop.await_count == 1
    await db_session.refresh(out)
    assert out.lease_holder == NEW
    assert _events(out)[-1] == "lease_takeover"


@pytest.mark.asyncio
async def test_a_resume_after_the_handoff_is_passed_on_to_the_new_version(
    db_session: AsyncSession, drive: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Halt then Resume after the hand-off: the Resume's drive is the run's
    carrier now, so on the old version it goes on to the new one rather than
    stopping, and rather than settling the run on the old version."""
    monkeypatch.setattr(settings, "version", FROM)
    run = await _run(db_session, _handed_off_progress(extra_events=("halted", "resumed")))

    out = await orchestrator.drive_upgrade(db_session, run.id, holder=STRAY)

    assert drive.lease.acquired == []
    assert drive.loop.await_count == 0
    assert drive.continued == [(run.id, FROM)]
    await db_session.refresh(out)
    assert out.state == "running"
    assert "lease_takeover" not in _events(out)


@pytest.mark.asyncio
async def test_before_the_handoff_a_copy_is_judged_by_the_lease_as_before(
    db_session: AsyncSession, drive: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing changes before the flip hands off: a copy is refused while the
    live drive holds the Lease (#1512)."""
    monkeypatch.setattr(settings, "version", FROM)
    progress = _handed_off_progress()
    progress["events"] = [e for e in progress["events"] if e["event"] != "drive_version_handoff"]
    progress["shared_tags"]["flip"].pop("handed_off_at")
    run = await _run(db_session, progress)
    drive.lease.holder = HANDING

    with pytest.raises(OrchestratorError, match="can't take over upgrade lease"):
        await orchestrator.drive_upgrade(db_session, run.id, holder=STRAY)
    assert drive.lease.acquired == []
    assert drive.continued == []


# ── the task hands the hand-off's request to the drive ────────────────────


def test_the_task_gives_the_drive_its_avoid_version(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.tasks import upgrade_orchestrator as task_mod

    seen: list[tuple[str, str | None]] = []

    async def _drive(rid: str, *, avoid_version: str | None = None) -> dict[str, str]:
        seen.append((rid, avoid_version))
        return {"run_id": rid, "state": "running"}

    monkeypatch.setattr(task_mod, "_async_drive", _drive)
    monkeypatch.setattr(settings, "version", FROM)
    # Out of hops on the old version: it runs here, as the continuation.
    task_mod.drive_upgrade_run.run(
        "run-1", avoid_version=FROM, hops=getattr(task_mod, "_MAX_VERSION_HOPS", 0)
    )
    # A drive with no hand-off behind it (Start, Resume, a redelivered copy).
    task_mod.drive_upgrade_run.run("run-2")

    assert seen == [("run-1", FROM), ("run-2", None)]


@pytest.mark.asyncio
async def test_the_session_passes_avoid_version_to_drive_upgrade(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.tasks import upgrade_orchestrator as task_mod

    seen: list[dict[str, Any]] = []

    class _Session:
        async def __aenter__(self) -> _Session:
            return self

        async def __aexit__(self, *_a: Any) -> None:
            return None

    async def _drive(_db: Any, rid: uuid.UUID, **kw: Any) -> Any:
        seen.append(kw)

        class _Row:
            id = rid
            state = "succeeded"

        return _Row()

    monkeypatch.setattr(task_mod, "task_session", lambda: _Session())
    monkeypatch.setattr(task_mod, "drive_upgrade", _drive)

    out = await task_mod._async_drive(str(uuid.uuid4()), avoid_version=FROM)

    assert out["state"] == "succeeded"
    assert seen[0]["avoid_version"] == FROM
    assert seen[0]["holder"]
