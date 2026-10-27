"""#2868 — per-node orphan sweep of the pcaps directory."""

from __future__ import annotations

import os
import time
import uuid
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.pcap import PacketCapture
from app.services.pcap import orphan_sweep
from app.services.pcap.orphan_sweep import sweep_orphans


@pytest.fixture
def pdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("SPATIUM_PCAP_DIR", str(tmp_path))
    return tmp_path


def _mk(d: Path, name: str, age_s: int = 7200) -> Path:
    p = d / name
    p.write_bytes(b"x")
    t = time.time() - age_s
    os.utime(p, (t, t))
    return p


async def test_orphan_old_file_deleted(db_session: AsyncSession, pdir: Path) -> None:
    f = _mk(pdir, f"{uuid.uuid4()}.pcap")
    part = _mk(pdir, f"{uuid.uuid4()}.pcap.partial")
    res = await sweep_orphans(db_session)
    assert res["deleted"] == 2
    assert not f.exists() and not part.exists()


async def test_file_with_row_kept(db_session: AsyncSession, pdir: Path) -> None:
    row = PacketCapture(
        vantage_kind="server", interface="eth0", status="completed", max_duration_s=10
    )
    db_session.add(row)
    await db_session.flush()
    f = _mk(pdir, f"{row.id}.pcap")
    res = await sweep_orphans(db_session)
    assert res["deleted"] == 0 and f.exists()


async def test_young_file_kept(db_session: AsyncSession, pdir: Path) -> None:
    f = _mk(pdir, f"{uuid.uuid4()}.pcap", age_s=60)
    res = await sweep_orphans(db_session)
    assert res["deleted"] == 0 and f.exists()


async def test_db_error_deletes_nothing(pdir: Path) -> None:
    class Boom:
        async def execute(self, *_a: object, **_k: object) -> None:
            raise RuntimeError("db down")

    f = _mk(pdir, f"{uuid.uuid4()}.pcap")
    res = await sweep_orphans(Boom())  # type: ignore[arg-type]
    assert res["deleted"] == 0 and f.exists()


async def test_foreign_names_symlinks_dirs_untouched(
    db_session: AsyncSession, pdir: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    other = _mk(pdir, "notes.txt")
    bad = _mk(pdir, f"{uuid.uuid4()}.pcap.bak")
    upper = _mk(pdir, f"{uuid.uuid4()}.PCAP")
    outside = tmp_path_factory.mktemp("outside") / "secret"
    outside.write_bytes(b"s")
    link = pdir / f"{uuid.uuid4()}.pcap"
    link.symlink_to(outside)
    t = time.time() - 7200
    os.utime(link, (t, t), follow_symlinks=False)
    sub = pdir / f"{uuid.uuid4()}.pcap"
    sub.mkdir()
    os.utime(sub, (t, t))
    res = await sweep_orphans(db_session)
    assert res["deleted"] == 0
    assert all(p.exists() for p in (other, bad, upper, outside, sub))
    assert link.is_symlink()


async def test_enoent_race_is_harmless(
    db_session: AsyncSession, pdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    f = _mk(pdir, f"{uuid.uuid4()}.pcap")
    real = Path.unlink

    def racing(self: Path, *a: object, **k: object) -> None:
        real(self)
        raise FileNotFoundError

    monkeypatch.setattr(Path, "unlink", racing)
    res = await sweep_orphans(db_session)
    assert res["deleted"] == 0 and not f.exists()


async def test_missing_dir_is_noop(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SPATIUM_PCAP_DIR", "/nonexistent/pcaps-2868")
    assert (await sweep_orphans(db_session))["scanned"] == 0
    assert not Path("/nonexistent").exists()
    assert orphan_sweep.GRACE_SECONDS == 3600


async def test_mixed_batch_deletes_only_rowless(db_session: AsyncSession, pdir: Path) -> None:
    """One pass, both kinds: the row-backed file and its ``.partial`` stay,
    the row-less pair goes. Guards against a sweep keyed on the wrong set."""
    row = PacketCapture(
        vantage_kind="appliance", interface="eth0", status="running", max_duration_s=10
    )
    db_session.add(row)
    await db_session.flush()
    kept = [_mk(pdir, f"{row.id}.pcap"), _mk(pdir, f"{row.id}.pcap.partial")]
    orphan_id = uuid.uuid4()
    gone = [_mk(pdir, f"{orphan_id}.pcap"), _mk(pdir, f"{orphan_id}.pcap.partial")]
    res = await sweep_orphans(db_session)
    assert res == {"scanned": 4, "deleted": 2, "kept": 2}
    assert all(p.exists() for p in kept)
    assert not any(p.exists() for p in gone)


def test_worker_thread_runs_a_pass_and_stops(monkeypatch: pytest.MonkeyPatch) -> None:
    """The worker's runner: a thread that passes on its own schedule and
    exits when asked. A beat task would land on one worker on one node."""
    import threading

    passes = threading.Event()
    calls: list[int] = []

    def fake_once() -> dict[str, int]:
        calls.append(1)
        passes.set()
        return {"scanned": 0, "deleted": 0, "kept": 0}

    monkeypatch.setattr(orphan_sweep, "run_worker_sweep_once", fake_once)
    t = orphan_sweep.start_worker_sweep(initial_delay=0, interval=3600)
    try:
        assert t is not None and t.daemon
        assert passes.wait(5), "no sweep pass ran"
        # Idempotent: a second start does not spawn a second thread.
        assert orphan_sweep.start_worker_sweep(initial_delay=0, interval=3600) is None
    finally:
        orphan_sweep.stop_worker_sweep()
    assert not t.is_alive()
    assert calls == [1]


def test_worker_pass_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    async def boom() -> dict[str, int]:
        raise RuntimeError("db down")

    monkeypatch.setattr(orphan_sweep, "_sweep_with_task_session", boom)
    assert orphan_sweep.run_worker_sweep_once() is None


def test_worker_ready_starts_the_sweep() -> None:
    """Wired to ``worker_ready`` (main process, once), not left for someone
    to remember."""
    from celery.signals import worker_ready

    import app.celery_app as ca

    receivers = [r[1]() for r in worker_ready.receivers]
    assert ca._start_pcap_orphan_sweep in receivers
