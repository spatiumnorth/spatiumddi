"""Write + reload the managed radvd.conf on the DHCP agent (issue #524).

The control plane renders the full ``radvd.conf`` text and ships it in the DHCP
ConfigBundle (``radvd_conf``). This module stages it, validates it with ``radvd -c``, then
atomically swaps it into the managed path and asks a running radvd to re-read
it (SIGHUP). radvd management is opt-in: nothing happens unless ``RADVD_MANAGED=1`` (radvd needs CAP_NET_RAW +
CAP_NET_ADMIN to emit RAs, and most deployments don't run it), matching the
default-off posture of the passive sniffers.

Non-negotiable #5 (config caching) is satisfied for free: ``radvd_conf`` rides
the same on-disk bundle cache the Kea config uses, so the agent re-applies the
last-known-good radvd config on restart even if the control plane is
unreachable.

Best-effort throughout — a missing radvd binary, a failed validation, or an
absent pidfile never aborts the Kea apply; they log and move on.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess  # noqa: S404 — local radvd -c validation, fixed argv
from pathlib import Path

import structlog

log = structlog.get_logger(__name__)


def _managed() -> bool:
    return os.environ.get("RADVD_MANAGED", "0") == "1"


def _config_path() -> Path:
    return Path(os.environ.get("RADVD_CONFIG_PATH", "/etc/radvd/radvd.conf"))


def _pidfile() -> Path:
    return Path(os.environ.get("RADVD_PIDFILE", "/run/radvd/radvd.pid"))


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text)
    tmp.replace(path)


def _discard(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        log.warning("radvd_staged_cleanup_failed", path=str(path), error=str(exc))


def _validate(path: Path) -> bool:
    """Run ``radvd -c -C <path>`` if the binary exists. Returns True on pass
    (or when radvd isn't installed — nothing to validate against)."""
    radvd = shutil.which("radvd")
    if not radvd:
        return True
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
            [radvd, "-c", "-C", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("radvd_validate_error", error=str(exc))
        return False
    if proc.returncode != 0:
        log.warning("radvd_config_rejected", stderr=(proc.stderr or "").strip())
        return False
    return True


def _reload() -> None:
    """SIGHUP a running radvd so it re-reads its config."""
    pidfile = _pidfile()
    try:
        pid = int(pidfile.read_text().strip())
    except (OSError, ValueError):
        log.info("radvd_no_pidfile", path=str(pidfile), hint="radvd not running yet")
        return
    try:
        os.kill(pid, signal.SIGHUP)
        log.info("radvd_reloaded", pid=pid)
    except OSError as exc:
        log.warning("radvd_reload_failed", pid=pid, error=str(exc))


def _stop() -> None:
    """Gracefully stop a running radvd so it stops advertising RAs.

    Sends SIGTERM to the pid from the pidfile, then blanks the managed config
    so a later empty apply stays a no-op and radvd never re-reads stale
    prefixes. No-op when radvd isn't running (no/invalid pidfile). Mirrors
    :func:`_reload`.
    """
    pidfile = _pidfile()
    try:
        pid = int(pidfile.read_text().strip())
    except (OSError, ValueError):
        log.info("radvd_no_pidfile", path=str(pidfile), hint="radvd not running")
        return
    try:
        os.kill(pid, signal.SIGTERM)
        log.info("radvd_stopped", pid=pid)
    except ProcessLookupError:
        # Already gone — treat as stopped.
        log.info("radvd_already_stopped", pid=pid)
    except OSError as exc:
        log.warning("radvd_stop_failed", pid=pid, error=str(exc))
        return
    # Blank the managed config so the disable is durable across restarts.
    path = _config_path()
    try:
        if path.exists():
            _atomic_write(path, "")
    except OSError as exc:
        log.warning("radvd_config_blank_failed", path=str(path), error=str(exc))


def apply_radvd(radvd_conf: str | None) -> None:
    """Write the managed radvd.conf + reload radvd. No-op unless RADVD_MANAGED=1.

    An empty ``radvd_conf`` is an *intentional disable* (the operator turned
    off ``ra_enabled`` on the last RA scope, or toggled off the
    ``ipv6.router_advertisements`` feature module) — distinct from a
    control-plane-unreachable event, where the agent keeps serving the cached
    non-empty bundle (non-negotiable #5). So on empty we STOP radvd and blank
    the managed config rather than leaving stale RAs advertised.
    """
    if not _managed():
        return
    if not radvd_conf or not radvd_conf.strip():
        log.info("radvd_disable", note="no RA-enabled scopes; stopping radvd")
        _stop()
        return
    path = _config_path()
    # Stage next to the live file (same filesystem → atomic rename), validate
    # the STAGED copy, and only then swap it in: a rejected config must never
    # replace a working one, or radvd would load it on its next start.
    staged = path.with_name(path.name + ".staged")
    try:
        _atomic_write(staged, radvd_conf)
    except OSError as exc:
        log.warning("radvd_write_failed", path=str(staged), error=str(exc))
        return
    if not _validate(staged):
        _discard(staged)
        return
    try:
        staged.replace(path)
    except OSError as exc:
        log.warning("radvd_write_failed", path=str(path), error=str(exc))
        _discard(staged)
        return
    log.info("radvd_config_written", path=str(path))
    _reload()


__all__ = ["apply_radvd", "_stop"]
