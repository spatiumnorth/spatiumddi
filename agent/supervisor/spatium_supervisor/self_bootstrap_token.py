"""One-time token that proves a self-bootstrap call came from this host.

The control-plane appliance's supervisor mints its own pairing code through
``POST /api/v1/appliance/self-register-bootstrap``. That endpoint is also
reachable from the LAN through the frontend's ``/api/`` proxy, so the api
needs something only the local supervisor can show it. This is it: a fresh
random value written to the host release-state directory just before the
call and removed straight after.

The directory is ``/var/lib/spatiumddi/release-state`` on the host, mode
1770 ``root:2770``. The supervisor (in group ``spatium-host`` 2770) and the
api pod (``supplementalGroups: [2770]``) both mount it; nothing on the
network can read it. The file is written 0640 and re-grouped to the
directory's group so the api, which runs as a different uid, can read it.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import structlog

TOKEN_PATH = Path("/var/lib/spatiumddi-host/release-state/self-bootstrap.token")

log = structlog.get_logger(__name__)


def write(path: Path | None = None) -> str | None:
    """Write a fresh token to ``path`` and return it, or None on failure.

    Written to a sibling temp file and renamed into place, so the api never
    reads a half-written value.
    """
    path = path or TOKEN_PATH
    token = secrets.token_hex(32)
    tmp = path.with_name(path.name + ".tmp")
    try:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass  # no leftover from an interrupted earlier write
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            try:
                # The api reads this as another uid in the directory's group.
                os.fchown(fd, -1, path.parent.stat().st_gid)
                os.fchmod(fd, 0o640)
            except OSError:
                # Not a member of the directory's group (a layout older than
                # the 1770 root:2770 one): the directory's own mode is then
                # the only gate, and the api needs other-read to see it.
                os.fchmod(fd, 0o644)
            with os.fdopen(fd, "w", encoding="ascii") as fh:
                fd = -1
                fh.write(token)
        finally:
            if fd != -1:
                os.close(fd)
        os.replace(tmp, path)
    except OSError as exc:
        log.warning(
            "supervisor.self_bootstrap.token_write_failed",
            path=str(path),
            error=str(exc),
        )
        return None
    return token


def remove(path: Path | None = None) -> None:
    """Delete the token. Missing is fine; anything else is logged, not raised."""
    path = path or TOKEN_PATH
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        log.warning(
            "supervisor.self_bootstrap.token_remove_failed",
            path=str(path),
            error=str(exc),
        )
