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

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import structlog

from app.config import settings

logger = structlog.get_logger(__name__)

_STATE_DIR = Path("/var/lib/spatiumddi-host/release-state")
_MAINT_FLAG = _STATE_DIR / "maintenance.flag"
_REBOOT_TRIGGER = _STATE_DIR / "reboot-pending"
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
        appliance_version=settings.appliance_version or None,
        appliance_mode=settings.appliance_mode,
    )


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
