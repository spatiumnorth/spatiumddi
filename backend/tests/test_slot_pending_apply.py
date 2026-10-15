"""#1825 / #1288 — a slot-upgrade apply the host runner has not started.

#1825: a trigger that lands while systemd is in a ``daemon-reload`` is never
seen by the ``PathChanged=`` watch, so the runner never starts. The status
must not read ``in-flight`` for good (which 409s apply and rollback): it is
stamped so #421's heal ages it out, and the watcher is re-fired after a pickup
grace.

#1288: the api cannot unlink the root-owned ``.state`` in the sticky
release-state directory, so a previous run's ``done`` sat beside the new
trigger and was served as the new apply's state.

Every assertion goes through the public surface — ``get_slot_status()``,
``is_apply_in_flight()`` or the HTTP endpoints — and the re-arm is observed
with a real inotify watch for IN_CLOSE_WRITE, the event ``PathChanged=``
fires on.
"""

from __future__ import annotations

import ctypes
import os
import select
import struct
import sys
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.services.appliance import slot

IN_CLOSE_WRITE = 0x00000008
linux_only = pytest.mark.skipif(sys.platform != "linux", reason="inotify is Linux-only")


@pytest.fixture
def paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Path]:
    state = tmp_path / "slot-upgrade-pending.state"
    trigger = tmp_path / "slot-upgrade-pending"
    monkeypatch.setattr(slot, "_STATE_FILE", state)
    monkeypatch.setattr(slot, "_TRIGGER_FILE", trigger)
    monkeypatch.setattr(settings, "appliance_mode", True)
    # The re-arm is rate-limited per process; start every test unthrottled.
    # raising=False: on a tree without the re-arm this is a no-op, and the
    # tests fail on their assertions rather than erroring here.
    monkeypatch.setattr(slot, "_last_rearm_at", 0.0, raising=False)
    return {"state": state, "trigger": trigger}


def _write(path: Path, body: str, age_seconds: float) -> float:
    path.write_text(body)
    t = time.time() - age_seconds
    os.utime(path, (t, t))
    return t


class _Inotify:
    """A real IN_CLOSE_WRITE watch on one file."""

    def __init__(self, path: Path) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        self.fd = libc.inotify_init1(os.O_NONBLOCK)
        assert self.fd >= 0
        assert libc.inotify_add_watch(self.fd, os.fsencode(path), IN_CLOSE_WRITE) >= 0

    def close_writes(self, timeout: float = 0.5) -> int:
        count = 0
        while True:
            ready, _, _ = select.select([self.fd], [], [], timeout)
            if not ready:
                return count
            buf = os.read(self.fd, 4096)
            off = 0
            while off < len(buf):
                _wd, mask, _cookie, length = struct.unpack_from("iIII", buf, off)
                if mask & IN_CLOSE_WRITE:
                    count += 1
                off += 16 + length
            timeout = 0.1


@pytest.fixture
def watch() -> Iterator[type[_Inotify]]:
    opened: list[_Inotify] = []

    class _Tracked(_Inotify):
        def __init__(self, path: Path) -> None:
            super().__init__(path)
            opened.append(self)

    yield _Tracked
    for w in opened:
        os.close(w.fd)


# ── #1825: a trigger the watcher never started ─────────────────────────────


def test_unstarted_trigger_ages_out_so_apply_and_rollback_unlock(
    paths: dict[str, Path],
) -> None:
    # main: ("in-flight", None) for good — no stamp to age, 409 forever.
    _write(paths["trigger"], "https://example/img.raw.xz\n", slot._STALE_INFLIGHT_SECONDS + 60)
    status = slot.get_slot_status()
    assert status.upgrade_state == "failed"
    assert status.upgrade_state_at is not None
    assert slot.is_apply_in_flight() is False


def test_fresh_unstarted_trigger_is_in_flight_stamped_with_its_write_time(
    paths: dict[str, Path],
) -> None:
    written = _write(paths["trigger"], "https://example/img.raw.xz\n", 5)
    status = slot.get_slot_status()
    assert status.upgrade_state == "in-flight"
    assert status.upgrade_state_at is not None
    assert abs(datetime.fromisoformat(status.upgrade_state_at).timestamp() - written) < 1
    assert slot.is_apply_in_flight() is True


@linux_only
def test_unclaimed_trigger_is_rearmed_after_the_grace_without_moving_it(
    paths: dict[str, Path], watch: type[_Inotify]
) -> None:
    body = "https://example/img.raw.xz\n"
    _write(paths["trigger"], body, 45)
    before = paths["trigger"].stat().st_mtime_ns
    w = watch(paths["trigger"])

    assert slot.get_slot_status().upgrade_state == "in-flight"
    assert w.close_writes() == 1
    # The heal's clock and the trigger's body stay where they were.
    assert paths["trigger"].stat().st_mtime_ns == before
    assert paths["trigger"].read_text() == body

    # A poll loop must not hammer the watcher: one re-arm per grace window.
    slot.get_slot_status()
    slot.is_apply_in_flight()
    assert w.close_writes(timeout=0.2) == 0


@linux_only
def test_trigger_inside_the_grace_is_not_rearmed(
    paths: dict[str, Path], watch: type[_Inotify]
) -> None:
    _write(paths["trigger"], "x\n", 2)
    w = watch(paths["trigger"])
    assert slot.get_slot_status().upgrade_state == "in-flight"
    assert w.close_writes(timeout=0.2) == 0


@linux_only
def test_trigger_the_runner_claimed_is_not_rearmed(
    paths: dict[str, Path], watch: type[_Inotify]
) -> None:
    _write(paths["trigger"], "x\n", 120)
    # The runner's mark_inflight: a fresh stamp, written after the trigger.
    paths["state"].write_text(f"in-flight {datetime.now(UTC).isoformat()}\n")
    w = watch(paths["trigger"])
    assert slot.get_slot_status().upgrade_state == "in-flight"
    assert w.close_writes(timeout=0.2) == 0


@linux_only
def test_a_symlinked_trigger_is_not_opened_through(
    paths: dict[str, Path], watch: type[_Inotify], tmp_path: Path
) -> None:
    target = tmp_path / "elsewhere"
    _write(target, "not ours\n", 45)
    paths["trigger"].symlink_to(target)
    w = watch(target)
    slot.get_slot_status()
    assert w.close_writes(timeout=0.2) == 0
    assert target.read_text() == "not ours\n"


def test_runner_state_newer_than_the_trigger_is_served_as_is(paths: dict[str, Path]) -> None:
    _write(paths["trigger"], "x\n", 20)
    paths["state"].write_text("done 2026-10-01T00:00:00+00:00\n")
    status = slot.get_slot_status()
    assert (status.upgrade_state, status.upgrade_state_at) == (
        "done",
        "2026-10-01T00:00:00+00:00",
    )


# ── #1288 and the 409 lock, through the endpoints ──────────────────────────


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"admin-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test Admin",
        hashed_password=hash_password("test-pw-slot"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.mark.asyncio
async def test_get_after_apply_202_reads_the_new_apply_not_the_previous_done(
    client: AsyncClient,
    db_session: AsyncSession,
    paths: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    headers = await _superadmin(db_session)
    previous = "done 2026-10-01T00:00:00+00:00\n"
    _write(paths["state"], previous, 3600)

    # On an appliance the sidecar is root's, in a sticky directory: the api
    # (uid 1000) gets EPERM unlinking it. Model the filesystem, not the code.
    real_unlink = Path.unlink

    def sticky_unlink(self: Path, missing_ok: bool = False) -> None:
        if self == paths["state"]:
            raise PermissionError(1, "Operation not permitted", str(self))
        real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", sticky_unlink)

    r = await client.post(
        "/api/v1/appliance/slot-upgrade/apply",
        headers=headers,
        json={"image_url": "https://example/slot.raw.xz"},
    )
    assert r.status_code == 202, r.text

    r = await client.get("/api/v1/appliance/slot-upgrade", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["upgrade_state"] == "in-flight"
    assert body["upgrade_state_at"] != "2026-10-01T00:00:00+00:00"
    assert paths["state"].read_text() == previous

    # And a second apply is refused while that one is pending.
    r = await client.post(
        "/api/v1/appliance/slot-upgrade/apply",
        headers=headers,
        json={"image_url": "https://example/slot.raw.xz"},
    )
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_apply_unlocks_once_an_unstarted_trigger_ages_out(
    client: AsyncClient, db_session: AsyncSession, paths: dict[str, Path]
) -> None:
    # main: the stranded trigger reads in-flight with no stamp, so this is 409
    # until someone touches the file on the host.
    headers = await _superadmin(db_session)
    _write(paths["trigger"], "https://example/old.raw.xz\n", slot._STALE_INFLIGHT_SECONDS + 60)

    r = await client.post(
        "/api/v1/appliance/slot-upgrade/apply",
        headers=headers,
        json={"image_url": "https://example/slot.raw.xz"},
    )
    assert r.status_code == 202, r.text
    assert paths["trigger"].read_text() == "https://example/slot.raw.xz\n"
