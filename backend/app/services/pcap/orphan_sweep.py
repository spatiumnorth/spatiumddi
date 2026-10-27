"""Per-node orphan sweep for the packet-capture store (issue #2868).

On a multi-node appliance the ``.pcap`` of a capture lives on the
``pcaps`` hostPath of ONE node. Delete, bulk delete and the retention
prune run on whichever api / worker pod happened to take the request and
can only ``unlink`` on that pod's own node, so a file held elsewhere is
left behind once its row is gone. This sweep closes the gap from the
other side: every pod that can WRITE a capture file periodically deletes
files in its own pcaps directory that no ``packet_capture`` row names.

There are two writers, so there are two runners, and each covers the
node it writes on by construction rather than by a placement convention:

* the worker (server-vantage captures, ``runner.run_pcap``) runs it from
  a thread started on ``worker_ready`` (:func:`start_worker_sweep`);
* the api (appliance-vantage uploads, ``/supervisor/pcap/upload``) runs
  it from a loop in the lifespan.

Neither is gated on appliance mode. On Compose the two share one volume
and the second pass finds nothing; on a plain multi-replica Helm install
each pod has its own directory, where the same leak applies.

Safety, in the order it is applied:

* only ``<uuid>.pcap`` / ``<uuid>.pcap.partial`` directly inside the
  directory, regular files only (no symlinks, no subdirectories);
* the file must be older than a grace period by mtime;
* the UUID must have no ``packet_capture`` row (any status);
* if the row lookup raises, NOTHING is deleted (fail closed).

The row is the authority, not the mtime: every writer reads a COMMITTED
row before it creates the file (the runner ``db.get``s it and returns on
None; the upload route 404s without it), and capture ids are uuid4, so a
file with no row is one whose row has been deleted. The grace period is
belt-and-braces on top of that.

Idempotent and race-free: two pods on one node, or api + worker sharing
a Compose volume, may both unlink the same file; ``ENOENT`` is a no-op.
"""

from __future__ import annotations

import asyncio
import os
import re
import stat
import threading
import time
import uuid
from pathlib import Path

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.pcap import PacketCapture

logger = structlog.get_logger(__name__)

# Files younger than this are never touched (mtime).
GRACE_SECONDS = 3600
SWEEP_INTERVAL_SECONDS = 6 * 3600
# First pass this long after the process starts, so a restart storm does
# not add a directory scan + query to every boot.
INITIAL_DELAY_SECONDS = 300

_NAME_RE = re.compile(
    r"^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.pcap(\.partial)?$"
)


def _pcap_root() -> Path:
    # Same variable as ``runner.pcap_dir`` but without creating the dir:
    # a sweep must not conjure a directory on a node that has none.
    return Path(os.environ.get("SPATIUM_PCAP_DIR", "/var/lib/spatiumddi/pcaps"))


def _candidates(root: Path, now: float, grace_s: int) -> dict[uuid.UUID, list[Path]]:
    found: dict[uuid.UUID, list[Path]] = {}
    try:
        entries = list(os.scandir(root))
    except OSError:
        return found
    for entry in entries:
        m = _NAME_RE.match(entry.name)
        if m is None:
            continue
        try:
            st = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode) or now - st.st_mtime < grace_s:
            continue
        found.setdefault(uuid.UUID(m.group(1)), []).append(Path(entry.path))
    return found


def _unlink_orphans(
    candidates: dict[uuid.UUID, list[Path]], known: set[uuid.UUID], result: dict[str, int]
) -> None:
    for cap_id, paths in candidates.items():
        if cap_id in known:
            result["kept"] += len(paths)
            continue
        for path in paths:
            try:
                path.unlink()
                result["deleted"] += 1
            except FileNotFoundError:
                continue  # another pod on this node got there first
            except OSError as exc:
                result["kept"] += 1
                logger.warning("pcap_orphan_unlink_failed", path=str(path), error=str(exc))


async def sweep_orphans(
    db: AsyncSession,
    *,
    grace_s: int = GRACE_SECONDS,
    now: float | None = None,
) -> dict[str, int]:
    """Delete unreferenced capture files on this node. Returns counters."""
    root = _pcap_root()
    # Filesystem work off the event loop: in the api this runs beside
    # request handling.
    candidates = await asyncio.to_thread(
        _candidates, root, time.time() if now is None else now, grace_s
    )
    result = {"scanned": sum(len(v) for v in candidates.values()), "deleted": 0, "kept": 0}
    if not candidates:
        return result

    try:
        known = set(
            (
                await db.execute(
                    select(PacketCapture.id).where(PacketCapture.id.in_(list(candidates)))
                )
            )
            .scalars()
            .all()
        )
    except Exception as exc:  # noqa: BLE001 — fail closed: delete nothing
        logger.warning("pcap_orphan_sweep_db_error", error=str(exc))
        result["kept"] = result["scanned"]
        return result

    await asyncio.to_thread(_unlink_orphans, candidates, known, result)
    if result["deleted"]:
        logger.info("pcap_orphans_deleted", directory=str(root), **result)
    return result


async def _sweep_with_task_session() -> dict[str, int]:
    from app.db import task_session  # noqa: PLC0415

    async with task_session() as db:
        return await sweep_orphans(db)


def run_worker_sweep_once() -> dict[str, int] | None:
    """One pass from a Celery process: own loop, own throwaway engine.
    Never raises; a failed pass is logged and the next one is on schedule."""
    try:
        return asyncio.run(_sweep_with_task_session())
    except Exception as exc:  # noqa: BLE001 — a background pass must not die
        logger.warning("pcap_orphan_sweep_failed", where="worker", error=str(exc))
        return None


_worker_stop = threading.Event()
_worker_thread: threading.Thread | None = None


def _worker_loop(stop: threading.Event, initial_delay: float, interval: float) -> None:
    if stop.wait(initial_delay):
        return
    while True:
        run_worker_sweep_once()
        if stop.wait(interval):
            return


def start_worker_sweep(
    *,
    initial_delay: float = INITIAL_DELAY_SECONDS,
    interval: float = SWEEP_INTERVAL_SECONDS,
) -> threading.Thread | None:
    """Start the worker's sweep thread, once per process.

    A thread rather than a beat task: beat hands a task to any one worker,
    on any node, and this has to run on EVERY node that holds captures.
    Started from ``worker_ready`` in the worker's main process, so there is
    one thread per worker pod, not one per prefork child."""
    global _worker_thread
    if _worker_thread is not None and _worker_thread.is_alive():
        return None
    _worker_stop.clear()
    _worker_thread = threading.Thread(
        target=_worker_loop,
        args=(_worker_stop, initial_delay, interval),
        name="pcap-orphan-sweep",
        daemon=True,
    )
    _worker_thread.start()
    return _worker_thread


def stop_worker_sweep(timeout: float = 5.0) -> None:
    """Ask the worker's sweep thread to exit (it is a daemon either way)."""
    _worker_stop.set()
    if _worker_thread is not None:
        _worker_thread.join(timeout=timeout)
