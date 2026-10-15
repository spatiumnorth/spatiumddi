"""Say so when the container's memory limit killed the DNS daemon (#1725).

The DNS pod carries a memory limit, so an overload (a large RPZ blocklist,
mostly) now kills ``named`` inside the container's own cgroup instead of
pushing the node into evicting the control plane. That trade is only a good
one if it is visible. Without this module it was not: the supervisor loop
saw the daemon gone and exited 2, the orchestrator restarted the container,
the agent re-applied the same cached bundle, the daemon came up long enough
for a heartbeat to say ``ok``, and the limit killed it again. Every surface
read healthy between restarts while the server was a crash loop.

So the agent reads the cgroup's own OOM-kill counter. When the daemon dies
and the counter rose since the agent started, it persists a record in the
state dir (which survives the restart) and, from then on, reports the daemon
as ``degraded`` with a reason that names the limit. That is the
``agent_daemon_degraded`` alert's input (on by default, 5 min grace) and the
red "not serving" chip on the server row. The record is cleared once the
daemon has stayed up for :data:`STABLE_SECONDS`, longer than Kubernetes'
5 min crash-loop back-off, so a container that only survives between
back-offs never reads as recovered.

Limit: the kernel kills the largest process in the cgroup, which with a big
RPZ is ``named``. If it picks the agent instead, the container dies before
anything can be written, and only the orchestrator (``OOMKilled`` as the
container's last state) records it.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)

#: cgroup v2 ``memory.events`` and cgroup v1 ``memory.oom_control`` both carry
#: an ``oom_kill <n>`` line (v1 since kernel 4.13). With a private cgroup
#: namespace, which Docker and containerd use on cgroup v2, both are the
#: container's own cgroup.
OOM_EVENT_FILES: tuple[str, ...] = (
    "/sys/fs/cgroup/memory.events",
    "/sys/fs/cgroup/memory/memory.oom_control",
)

#: How long the daemon has to stay up before an OOM record is cleared. Above
#: Kubernetes' 300 s maximum crash-loop back-off plus a zone load.
STABLE_SECONDS = 600.0

#: The heartbeat ``daemon.reason`` prefix. Deliberately NOT ``config_apply_``:
#: the control plane reads that prefix as a config verdict (#1067) and would
#: not call the daemon "not serving".
REASON_PREFIX = "oom_killed:"


#: Where the container's own memory limit is read from. ``memory.max`` reads
#: ``max`` when there is none; cgroup v1 reports "none" as a huge
#: page-aligned number instead.
CGROUP_MEMORY_LIMIT_FILES: tuple[str, ...] = (
    "/sys/fs/cgroup/memory.max",  # cgroup v2
    "/sys/fs/cgroup/memory/memory.limit_in_bytes",  # cgroup v1
)
_CGROUP_UNLIMITED_BYTES = 1 << 55


def cgroup_memory_limit_bytes(
    files: tuple[str, ...] = CGROUP_MEMORY_LIMIT_FILES,
) -> int | None:
    """The container's memory limit in bytes, or None when it has none."""
    for path in files:
        try:
            raw = Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if not raw or raw == "max":
            return None
        try:
            val = int(raw)
        except ValueError:
            continue
        return val if 0 < val < _CGROUP_UNLIMITED_BYTES else None
    return None


def read_oom_kill_count(files: tuple[str, ...] = OOM_EVENT_FILES) -> int | None:
    """The cgroup's ``oom_kill`` counter, or None when no file carries one."""
    for path in files:
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError:
            continue
        for line in text.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] == "oom_kill":
                try:
                    return int(parts[1])
                except ValueError:
                    break
    return None


def _fmt_limit(limit_bytes: int | None) -> str:
    if not limit_bytes:
        return "the container's memory limit"
    gib = limit_bytes / (1 << 30)
    if gib >= 1:
        return f"the container's {gib:g} GiB memory limit"
    return f"the container's {limit_bytes // (1 << 20)} MiB memory limit"


class OomWatch:
    """The OOM-kill baseline for this agent process plus the persisted record."""

    def __init__(
        self,
        state_dir: Path,
        daemon: str = "named",
        files: tuple[str, ...] = OOM_EVENT_FILES,
        limit_bytes: int | None = None,
    ) -> None:
        self._path = state_dir / "daemon_oom.json"
        self._daemon = daemon
        self._files = files
        self._limit_bytes = limit_bytes
        self.baseline = read_oom_kill_count(files)
        self.record: dict[str, Any] | None = self._load()

    def _load(self) -> dict[str, Any] | None:
        try:
            data = json.loads(self._path.read_text())
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) and data.get("count") else None

    def fired(self, consume: bool = False) -> bool:
        """Whether the cgroup's OOM killer has fired since this agent started
        (or since the last ``consume=True`` call that saw it fire, so one kill
        is not blamed for every later failure)."""
        now = read_oom_kill_count(self._files)
        if now is None:
            return False
        moved = now > (self.baseline or 0)
        if moved and consume:
            self.baseline = now
        return moved

    def note_daemon_killed(self, now: float | None = None) -> None:
        """Persist that the daemon died to the OOM killer."""
        stamp = time.time() if now is None else now
        rec = dict(self.record or {})
        rec["count"] = int(rec.get("count") or 0) + 1
        rec.setdefault("first_at", stamp)
        rec["last_at"] = stamp
        rec["limit_bytes"] = self._limit_bytes
        self.record = rec
        try:
            tmp = self._path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(rec))
            tmp.replace(self._path)
        except OSError:
            log.warning("daemon_oom_record_write_failed", path=str(self._path))
        log.error(
            "dns_daemon_oom_killed",
            daemon=self._daemon,
            count=rec["count"],
            limit_bytes=self._limit_bytes,
        )

    def clear(self) -> None:
        self.record = None
        try:
            self._path.unlink()
        except FileNotFoundError:
            pass  # nothing recorded, nothing to clear
        except OSError:
            log.warning("daemon_oom_record_clear_failed", path=str(self._path))

    def daemon_status(self) -> dict[str, str] | None:
        """The heartbeat ``daemon`` field while a record stands, else None."""
        if not self.record:
            return None
        rec = self.record
        count = int(rec.get("count") or 0)
        when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(rec.get("last_at") or 0)))
        times = "once" if count == 1 else f"{count} times"
        return {
            "status": "degraded",
            "reason": (
                f"{REASON_PREFIX} {self._daemon} was killed for exceeding "
                f"{_fmt_limit(rec.get('limit_bytes'))} ({times}, last at {when}) and "
                "restarts into the same config. Large RPZ blocklists are the usual "
                "cause: raise the limit or shrink the lists (docs/features/DNS.md 8.0)."
            ),
        }


def is_oom_status(status: dict[str, Any]) -> bool:
    return str(status.get("reason") or "").startswith(REASON_PREFIX)
