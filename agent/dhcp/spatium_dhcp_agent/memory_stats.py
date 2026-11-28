"""The agent's actual memory use, for the heartbeat's ``memory`` block (#4193).

Container usage and peak come from the cgroup the agent runs in, the limit is
:func:`oom_watch.cgroup_memory_limit_bytes` (#3551), and the resident set of
the daemon (kea-dhcp4 and kea-dhcp6) and of this agent comes from
``/proc/<pid>/status`` ``VmRSS``.

Best effort throughout: a file that is missing or unparseable omits its field
(never reports 0 for it), and :func:`memory_report` answers None when nothing
at all could be read so the heartbeat leaves the block out. Usage is the
cgroup's own counter, page cache included (``memory.current`` /
``memory.usage_in_bytes``), which is what the limit is enforced against.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .oom_watch import cgroup_memory_limit_bytes

#: cgroup v2 first, then v1 (a v1 host has no /sys/fs/cgroup/memory.current).
CGROUP_USED_FILES: tuple[str, ...] = (
    "/sys/fs/cgroup/memory.current",
    "/sys/fs/cgroup/memory/memory.usage_in_bytes",
)
#: ``memory.peak`` needs kernel 5.19; older v2 kernels simply omit the field.
CGROUP_PEAK_FILES: tuple[str, ...] = (
    "/sys/fs/cgroup/memory.peak",
    "/sys/fs/cgroup/memory/memory.max_usage_in_bytes",
)


def _read_first_int(files: tuple[str, ...]) -> int | None:
    for path in files:
        try:
            raw = Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            continue
        try:
            val = int(raw)
        except ValueError:
            continue
        if val >= 0:
            return val
    return None


def process_rss_bytes(pid: int | None, proc_root: str = "/proc") -> int | None:
    """``VmRSS`` of ``pid`` in bytes, or None (no pid, gone, a kernel thread)."""
    if not pid:
        return None
    try:
        text = Path(proc_root, str(pid), "status").read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("VmRSS:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1]) * 1024  # the field is in kB
            return None
    return None


def daemon_rss_bytes(pids: Iterable[int | None], proc_root: str = "/proc") -> int | None:
    """Summed RSS of the daemon's processes; None when none could be read."""
    found = [r for r in (process_rss_bytes(p, proc_root) for p in pids) if r is not None]
    return sum(found) if found else None


def memory_report(
    daemon_pids: Iterable[int | None],
    *,
    used_files: tuple[str, ...] = CGROUP_USED_FILES,
    peak_files: tuple[str, ...] = CGROUP_PEAK_FILES,
    proc_root: str = "/proc",
    limit_bytes: int | None | str = "read",
) -> dict[str, Any] | None:
    """The ``memory`` heartbeat block, with every unreadable field left out."""
    limit = cgroup_memory_limit_bytes() if limit_bytes == "read" else limit_bytes
    fields: dict[str, int | None] = {
        "used_bytes": _read_first_int(used_files),
        "peak_bytes": _read_first_int(peak_files),
        "limit_bytes": limit if isinstance(limit, int) else None,
        "daemon_rss_bytes": daemon_rss_bytes(daemon_pids, proc_root),
        "agent_rss_bytes": process_rss_bytes(os.getpid(), proc_root),
    }
    out = {k: v for k, v in fields.items() if v is not None}
    return out or None
