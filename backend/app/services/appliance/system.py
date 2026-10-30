"""System info, maintenance mode, reboot trigger (Phase 4f).

Three surfaces:

* ``get_system_info()`` — read-only snapshot (hostname, host IPs,
  uptime, reboot-pending, maintenance flag, kernel + memory). Powers
  the Network tab.
* ``set_maintenance_mode(enabled)`` — flips a flag file in the shared
  state dir; a future task can read it to refuse DNS/DHCP changes or
  drain traffic. Today the flag is just operator-visible — actual
  drain logic is a follow-up.
* ``request_reboot()`` — writes ``reboot-pending`` to the same state
  dir; the host's ``spatiumddi-reboot.path`` unit notices and, after a
  10 s grace, runs ``spatium-power-action reboot``: on a cluster node
  holding the PostgreSQL primary that first hands the primary off (up to
  a few minutes, #2974), then ``systemctl reboot``. Fire-and-forget: the
  caller never waits on the host.

All file paths live in ``/var/lib/spatiumddi-host/release-state/``
(the same bind-mounted RW dir used for the release trigger in 4c)
so we don't need a second compose mount.
"""

from __future__ import annotations

import fcntl
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import structlog

from app.config import settings

logger = structlog.get_logger(__name__)

_STATE_DIR = Path("/var/lib/spatiumddi-host/release-state")
_MAINT_FLAG = _STATE_DIR / "maintenance.flag"
_REBOOT_TRIGGER = _STATE_DIR / "reboot-pending"
# #3008 — spatium-power-action holds an flock on the release-state directory
# itself for as long as a reboot or poweroff is under way (the primary
# handoff, then systemctl). The trigger is renamed before the handoff, so
# ``reboot_scheduled`` alone reads false while it runs. A lock dies with its
# holder, so a killed wrapper never leaves this stuck; a pid check would be
# wrong from here, the api has its own pid namespace. The directory, not a
# file in it: the wrapper runs as root, and a file the api can write could be
# a symlink aimed anywhere on the host.
_POWER_ACTION_LOCK = _STATE_DIR
# #3008 — the rest of the window, from the request reaching this node until it
# goes down. The lock alone covered under two seconds of it on one node:
#   * ``reboot-pending-fleet``: the supervisor's Fleet trigger, until the
#     host's reboot agent takes it;
#   * ``reboot-fleet-grace``: "<pid> <boot_id>", the agent's own marker from
#     taking the trigger through its 5 s grace and the wrapper's run (the
#     agent renames the trigger first). It counts only in the current boot
#     and for _GRACE_MARKER_MAX_AGE_S, so one left by an agent killed outright
#     cannot pin the flag: past that the wrapper's lock is the answer;
#   * ``power-action-issued``: "<action> <boot_id>", written by the wrapper
#     while it still holds the lock, just before ``systemctl reboot``, and left
#     behind: the lock ends with the wrapper moments later, while the node is
#     still going down and this pod still answers. The host's boot id changes
#     with the reboot, so it expires by itself; _ISSUED_MAX_AGE_S only covers a
#     shutdown job that was cancelled after it was queued.
# /proc/sys/kernel/random/boot_id is not namespaced: a pod reads the host's.
_FLEET_TRIGGER = _STATE_DIR / "reboot-pending-fleet"
_FLEET_GRACE_MARKER = _STATE_DIR / "reboot-fleet-grace"
_POWER_ACTION_ISSUED = _STATE_DIR / "power-action-issued"
_BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
_GRACE_MARKER_MAX_AGE_S = 120.0
_ISSUED_MAX_AGE_S = 900.0
# Debian uses /var/run/reboot-required; we expose the host's via a
# bind mount on the appliance compose. Falls back to a non-existent
# path if the bind isn't mounted (dev), so is_reboot_pending() just
# returns False.
_HOST_REBOOT_REQUIRED = Path("/var/run-host/reboot-required")


@dataclass
class SystemInfo:
    hostname: str
    host_ips: list[str]
    uptime_seconds: float | None
    maintenance_mode: bool
    reboot_pending_from_host: bool
    reboot_scheduled: bool
    # A reboot or poweroff of the host is under way, from the request being
    # accepted on it until it goes down (the grace and the handoff of the
    # database primary included), whichever path started it: web UI, Fleet
    # or console (#3008, ``reboot_in_progress()``).
    reboot_in_progress: bool
    # Which node the three reboot fields and maintenance_mode describe: they
    # are read from the host directory of the node whose api pod served the
    # request (settings.node_name, from the downward API), the same node a
    # POST /reboot would reboot. None off-appliance / without NODE_NAME,
    # where there is only one host. On a multi-node control plane the
    # Service picks that pod per request, so the per-node answer is Fleet's
    # (``reboot_requested`` on the appliance row).
    node: str | None
    # None = unknown (the pods were not given APPLIANCE_VERSION); same
    # representation as /api/v1/version.
    appliance_version: str | None
    appliance_mode: bool


def get_system_info() -> SystemInfo:
    return SystemInfo(
        hostname=settings.appliance_hostname or "spatiumddi",
        host_ips=[ip.strip() for ip in settings.appliance_host_ips.split(",") if ip.strip()],
        uptime_seconds=_read_uptime_seconds(),
        maintenance_mode=is_maintenance_mode(),
        reboot_pending_from_host=_HOST_REBOOT_REQUIRED.exists(),
        reboot_scheduled=_REBOOT_TRIGGER.exists(),
        reboot_in_progress=reboot_in_progress(),
        node=settings.node_name or None,
        appliance_version=settings.appliance_version or None,
        appliance_mode=settings.appliance_mode,
    )


def reboot_in_progress() -> bool:
    """True from the moment a reboot or poweroff request is accepted on this
    node's host until the host goes down (#3008), whichever path started it:
    a pending web-UI or Fleet trigger, the Fleet agent's grace, the wrapper's
    run (its lock), or a ``systemctl reboot`` already issued in this boot."""
    return (
        _REBOOT_TRIGGER.exists()
        or _FLEET_TRIGGER.exists()
        or _marker_in_this_boot(_FLEET_GRACE_MARKER, 1, _GRACE_MARKER_MAX_AGE_S)
        or power_action_in_progress()
        or _marker_in_this_boot(_POWER_ACTION_ISSUED, 1, _ISSUED_MAX_AGE_S)
    )


def _marker_in_this_boot(path: Path, boot_field: int, max_age_s: float) -> bool:
    """A "<x> <boot_id>" marker written in the host's current boot, no older
    than ``max_age_s``. Unreadable, malformed, from another boot, or with no
    boot id to compare against: False."""
    try:
        fields = path.read_text(encoding="utf-8").split()
        age = datetime.now(UTC).timestamp() - path.stat().st_mtime
        current = _BOOT_ID.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return False
    if len(fields) <= boot_field or not current:
        return False
    return fields[boot_field] == current and age <= max_age_s


def power_action_in_progress() -> bool:
    """True while the host's spatium-power-action holds its lock (#3008).

    Tries a shared, non-blocking lock on the release-state directory, and
    drops it at once: it fails only while the wrapper holds its exclusive
    one, and never blocks. flock(2), not lockf/fcntl locks, which on Linux
    do not see an flock. Opened read-only: nothing is created. A missing or
    unreadable directory (not an appliance, the mount absent) is False."""
    try:
        fd = os.open(_POWER_ACTION_LOCK, os.O_RDONLY)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    except OSError:
        return False
    finally:
        os.close(fd)
    return False


def is_maintenance_mode() -> bool:
    """True when the maintenance flag file is present."""
    return _MAINT_FLAG.exists()


def set_maintenance_mode(enabled: bool) -> bool:
    """Create / remove the flag file. Returns the new state."""
    if not settings.appliance_mode:
        raise RuntimeError("maintenance mode is only supported on the SpatiumDDI OS appliance")
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    if enabled:
        _MAINT_FLAG.write_text(
            datetime.now(tz=UTC).isoformat() + "\n",
            encoding="utf-8",
        )
    else:
        try:
            _MAINT_FLAG.unlink()
        except FileNotFoundError:
            pass
    logger.info("appliance_maintenance_mode_set", enabled=enabled)
    return is_maintenance_mode()


def request_reboot(grace_seconds: int = 10) -> None:
    """Drop the reboot-pending trigger file.

    The host's spatiumddi-reboot.path notices, waits ``grace_seconds``
    (configured in the service unit, not here) so in-flight HTTP
    responses can flush, then runs ``spatium-power-action reboot``, which
    hands the PostgreSQL primary off first when this node holds it (#2974)
    and then runs ``systemctl reboot``. The unit renames the trigger
    before that handoff, so ``reboot_scheduled`` reads false while it
    runs.
    """
    if not settings.appliance_mode:
        raise RuntimeError("reboot is only supported on the SpatiumDDI OS appliance")
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    _REBOOT_TRIGGER.write_text(
        f"requested_at={datetime.now(tz=UTC).isoformat()}\n" f"grace_seconds={grace_seconds}\n",
        encoding="utf-8",
    )
    logger.info("appliance_reboot_requested", grace=grace_seconds)


def _read_uptime_seconds() -> float | None:
    """Parse /proc/uptime — first whitespace-separated number is seconds
    since boot. /proc is in the container's namespace but the kernel
    counter is host-wide, so this works regardless of mount strategy.
    """
    try:
        with open("/proc/uptime") as f:
            first = f.read().split(maxsplit=1)[0]
        return float(first)
    except (OSError, ValueError):
        return None
