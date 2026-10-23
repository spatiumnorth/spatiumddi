"""Say so when the container's memory limit killed Kea (#2023).

The DHCP twin of the DNS agent's ``oom_watch`` (#1725). Without it an
OOM-killed Kea is invisible: the entrypoint's supervise loop restarts the
daemon within two seconds, the agent heartbeats ``ok`` the whole time, and the
server row reads healthy through every kill.

Kea runs beside the agent under the entrypoint's shell supervisors, not as a
child of this process, so there is no exit status to read. The cgroup's own
``oom_kill`` counter is the signal instead: the agent samples it on every
tick of its supervisor loop, and when it moved since the last look something
in the container was killed by the OOM killer. That is not always Kea: the
agent's own ``kea-dhcpX -t`` config preflight loads the whole config and can be
the victim, as can radvd. So a move is only recorded when Kea did not survive
it, read from the entrypoint's pid files: a pid that is gone, or that changed
since the previous tick, is a killed Kea (the supervise loop restarts it two
seconds later, under a new pid). Both Kea daemons alive under the pids of the
previous tick means the kill took something else; that is logged and not
reported, because ``degraded`` here means *not serving* and Kea is serving. A
pid file that cannot be read proves nothing either way, so the kill is
recorded, as it would be with no pid check at all. The agent itself being the
victim is not seen at all: it dies, the entrypoint takes the container down,
and the restarted container is a new cgroup.
The kill is persisted in the state dir and reported on the heartbeat
as ``degraded`` with an ``oom_killed:`` reason, which the control plane reads
as *not serving* (the default-on ``agent_daemon_degraded`` alert and the red
server chip, ``backend/app/services/agents/daemon_state.py``).

The record clears once the counter has not moved for :data:`STABLE_SECONDS`,
above Kubernetes' 300 s maximum crash-loop back-off, so a container that
only survives between back-offs never reads as recovered. It is kept across
an agent restart (a restarted container is a new process in the same state
dir), and it takes precedence over the sync loop's own ``daemon_status``
writes, which is why the heartbeat overlays it rather than the sync loop
clearing it.

Where this works: Docker (Compose) kills the single largest process in the
cgroup, so the agent survives to write the record. The kubelet (cgroup v2,
Kubernetes 1.28+) sets ``memory.oom.group`` on every container instead, so on
the appliance and on any Kubernetes install the whole container dies at once,
the agent with Kea, and nothing here runs; the restarted container is a new
cgroup whose counter starts at zero, so the baseline cannot see the kill
either. There the kubelet's ``OOMKilled`` (the container's last state) is the
record: the appliance supervisor reports it on its heartbeat and the control
plane turns it into the same ``oom_killed:`` state
(``backend/app/services/agents/container_oom.py``). A plain Helm install
(the umbrella chart) has no supervisor and is not covered; see
``docs/features/DHCP.md``.
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

#: The container's own memory limit: ``memory.max`` reads ``max`` when there
#: is none; cgroup v1 reports "none" as a huge page-aligned number instead.
CGROUP_MEMORY_LIMIT_FILES: tuple[str, ...] = (
    "/sys/fs/cgroup/memory.max",
    "/sys/fs/cgroup/memory/memory.limit_in_bytes",
)
_CGROUP_UNLIMITED_BYTES = 1 << 55

#: The entrypoint's Kea pid files (``images/kea/entrypoint.sh``). Kea writes
#: them; the supervise loop deletes them before each restart.
KEA_PID_FILES: tuple[str, ...] = (
    "/run/kea/kea-dhcp4.kea-dhcp4.pid",
    "/run/kea/kea-dhcp6.kea-dhcp6.pid",
)

#: How long the counter has to stay still before an OOM record is cleared.
STABLE_SECONDS = 600.0

#: The heartbeat ``daemon.reason`` prefix, shared with the control plane's
#: ``container_oom.REASON_PREFIX``. Deliberately NOT ``config_apply_``: the
#: control plane reads that prefix as a config verdict and would not call the
#: daemon "not serving".
REASON_PREFIX = "oom_killed:"


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
    """The cgroup's ``oom_kill`` counter, or None when no file carries one
    (UNKNOWN, never "no kills")."""
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


def read_kea_pids(files: tuple[str, ...] = KEA_PID_FILES) -> tuple[int | None, ...]:
    """The pid in each of ``files``; None for one that is absent or unreadable."""
    out: list[int | None] = []
    for path in files:
        try:
            out.append(int(Path(path).read_text(encoding="utf-8").strip()))
        except (OSError, ValueError):
            out.append(None)
    return tuple(out)


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
        files: tuple[str, ...] = OOM_EVENT_FILES,
        limit_bytes: int | None = None,
        pid_files: tuple[str, ...] = KEA_PID_FILES,
        proc_root: str = "/proc",
    ) -> None:
        self._path = state_dir / "daemon_oom.json"
        self._files = files
        self._limit_bytes = limit_bytes
        self._pid_files = pid_files
        self._proc_root = Path(proc_root)
        self.baseline = read_oom_kill_count(files)
        self._kea_pids = read_kea_pids(pid_files)
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
        is not counted twice)."""
        now = read_oom_kill_count(self._files)
        if now is None:
            return False
        moved = now > (self.baseline or 0)
        if moved and consume:
            self.baseline = now
        return moved

    def kea_survived(self, pids: tuple[int | None, ...]) -> bool:
        """Whether every Kea daemon is provably the same live process it was
        at the previous tick. False whenever that cannot be shown (a pid file
        missing or unreadable, now or then), so an unknown never hides a kill."""
        if not pids or len(pids) != len(self._kea_pids):
            return False
        for pid, before in zip(pids, self._kea_pids, strict=True):
            if pid is None or pid != before:
                return False
            if not (self._proc_root / str(pid)).exists():
                return False
        return True

    def poll(self, now: float | None = None) -> None:
        """One look: record a kill the counter shows (when Kea did not survive
        it), clear a record that has outlived :data:`STABLE_SECONDS`. Called
        from the supervisor's tick: three small reads, no process scan."""
        stamp = time.time() if now is None else now
        pids = read_kea_pids(self._pid_files)
        try:
            if self.fired(consume=True):
                if self.kea_survived(pids):
                    # Something else in the container (the config preflight,
                    # radvd) was the victim; Kea is serving.
                    log.warning(
                        "dhcp_oom_kill_not_kea",
                        hint="the OOM killer fired in the container but both Kea "
                        "daemons survived it",
                        limit_bytes=self._limit_bytes,
                    )
                else:
                    # Confirmed when the pid files were readable and one of
                    # them showed Kea gone; otherwise the victim is unproven.
                    self.note_daemon_killed(
                        now=stamp,
                        kea_confirmed=all(p is not None for p in self._kea_pids),
                    )
                    return
        finally:
            self._kea_pids = pids
        if self.record is not None:
            last = float(self.record.get("last_at") or 0)
            if stamp - last >= STABLE_SECONDS:
                log.info("dhcp_daemon_oom_record_cleared", stable_s=STABLE_SECONDS)
                self.clear()

    def note_daemon_killed(self, now: float | None = None, kea_confirmed: bool = True) -> None:
        """Persist that the OOM killer fired in the container. ``kea_confirmed``
        is False when the pid files could not say whether Kea was the victim."""
        stamp = time.time() if now is None else now
        rec = dict(self.record or {})
        rec["kea_confirmed"] = kea_confirmed
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
        log.error("dhcp_daemon_oom_killed", count=rec["count"], limit_bytes=self._limit_bytes)

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
        rec = self.record
        if not rec:
            return None
        count = int(rec.get("count") or 0)
        when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(rec.get("last_at") or 0)))
        times = "once" if count == 1 else f"{count} times"
        victim = (
            "Kea was killed by the OOM killer in the DHCP container"
            if rec.get("kea_confirmed", True)
            else "the OOM killer fired in the DHCP container (Kea, almost certainly)"
        )
        return {
            "status": "degraded",
            "reason": (
                f"{REASON_PREFIX} {victim} "
                f"for exceeding {_fmt_limit(rec.get('limit_bytes'))} "
                f"({times}, last at {when}) and it restarts into the same config. "
                "Raise the container's memory limit, or shrink what Kea holds "
                "(lease table, subnets, reservations); see docs/features/DHCP.md."
            ),
        }
