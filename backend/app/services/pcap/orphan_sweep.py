"""Per-node orphan sweep for the packet-capture store (issue #2868).

On a multi-node appliance the ``.pcap`` of a capture lives on the
``pcaps`` hostPath of ONE node. Delete, bulk delete and the retention
prune run on whichever api / worker pod happened to take the request and
can only ``unlink`` on that pod's own node, so a file held elsewhere is
left behind once its row is gone. This sweep closes the gap from the
other side: every api pod (one per control-plane node under hard
anti-affinity, each mounting its node's hostPath) periodically deletes
files in its own pcaps directory that no ``packet_capture`` row names.

Safety, in the order it is applied:

* only ``<uuid>.pcap`` / ``<uuid>.pcap.partial`` directly inside the
  directory, regular files only (no symlinks, no subdirectories);
* the file must be older than a grace period by mtime, so a capture or
  upload that is being written is never touched;
* the UUID must have no ``packet_capture`` row (any status);
* if the row lookup raises, NOTHING is deleted (fail closed).

Idempotent and race-free: two pods on one node, or api + worker sharing
a Compose volume, may both unlink the same file; ``ENOENT`` is a no-op.
"""

from __future__ import annotations

import os
import re
import stat
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


async def sweep_orphans(
    db: AsyncSession,
    *,
    grace_s: int = GRACE_SECONDS,
    now: float | None = None,
) -> dict[str, int]:
    """Delete unreferenced capture files on this node. Returns counters."""
    root = _pcap_root()
    candidates = _candidates(root, time.time() if now is None else now, grace_s)
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
    if result["deleted"]:
        logger.info("pcap_orphans_deleted", directory=str(root), **result)
    return result
