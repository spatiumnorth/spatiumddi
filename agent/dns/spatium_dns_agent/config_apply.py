"""Last-known-good revert + poison-pill quarantine for config applies (#882).

Non-negotiable #5 says the agent caches its config and keeps serving from
that cache when the control plane is unreachable. That covers a *missing*
control plane. It does not cover a *wrong* one: a bundle that parses fine
but renders config the daemon rejects used to overwrite the cache and leave
the agent with nothing to fall back to.

This module is the other half. Two pieces:

:class:`ApplyStatus`
    What the agent tells the control plane about its last apply. Without
    it a revert is silent, which is arguably worse than the crash it
    replaces — the operator sees a saved config and a healthy daemon and
    has no way to learn the two do not correspond.

:class:`Quarantine`
    Remembers the etag that failed so the agent stops re-applying it.
    The long-poll wakes on a 12 s tick and falls back to a 2 s poll, so
    without this a bad bundle is not a single failure — it is a retry
    loop for as long as it stays saved.

    Quarantine is not permanent. An apply can fail for reasons that have
    nothing to do with the bundle (a full disk during render, a daemon
    still starting), and those clear on their own; refusing to ever retry
    would strand the agent on old config after the real problem went away.
    So a quarantined etag is retried on a bounded backoff, and any bundle
    that applies cleanly clears the record.

The three agents (DNS / DHCP / looking-glass) are separate Python packages
with no shared import path, so this module exists three times. Keep the
semantics identical; the file is deliberately small to make that cheap.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)

# Outcome vocabulary, shared with the control plane's
# ``*_server.config_apply_status`` column. Keep in sync with
# ``backend/app/services/agents/config_apply.py``.
STATUS_OK = "ok"
"""The bundle applied. Steady state."""

STATUS_REVERTED = "reverted"
"""The bundle failed and the agent is running the previous good config.

The daemon is healthy but is NOT serving what the operator saved.
"""

STATUS_REVERT_FAILED = "revert_failed"
"""The bundle failed AND restoring the previous config also failed.

The worst case: the daemon may be down or serving a half-applied config.
"""

STATUS_NO_PREVIOUS = "no_previous"
"""The bundle failed and there was no known-good config to fall back to.

A first-ever bundle that does not work. There is nothing to revert TO, so
the daemon is unconfigured until the operator fixes the config.
"""

FAILED_STATUSES = frozenset({STATUS_REVERTED, STATUS_REVERT_FAILED, STATUS_NO_PREVIOUS})

# Backoff before a quarantined etag is retried. Bounded at both ends: short
# enough that a transient failure (disk pressure, a daemon mid-restart)
# recovers without operator involvement, long enough that a genuinely bad
# bundle costs one apply attempt every 15 minutes instead of one per poll.
RETRY_BACKOFF_SECONDS: tuple[float, ...] = (60.0, 300.0, 900.0)

# Truncate the daemon's error text before it goes on the wire. Kea and named
# can both emit a long block, and this lands in a String/Text column that is
# read in a UI chip tooltip — the first line or two is the diagnostic part.
MAX_ERROR_LEN = 2000


# ── Apply phases ──────────────────────────────────────────────────────────
#
# The boundary that matters is between VALIDATE and RELOAD. Everything up to
# and including validation happens against a staging copy — BIND renders into
# ``rendered.new`` and runs ``named-checkconf`` there; Kea's file is checked
# with ``kea-dhcp4 -t`` before ``config-reload`` — so the running daemon has
# not been touched and there is nothing to undo. Only a failure at RELOAD means
# the live config has already been replaced, and only then does recovering
# require re-rendering the previous bundle.

PHASE_RENDER = "render"
PHASE_VALIDATE = "validate"
PHASE_RELOAD = "reload"

DAEMON_DISTURBING_PHASES = frozenset({PHASE_RELOAD})


class ConfigApplyError(RuntimeError):
    """An apply that failed, tagged with the phase it failed in (#882)."""

    def __init__(self, phase: str, cause: BaseException):
        super().__init__(f"{phase} failed: {cause}")
        self.phase = phase
        self.cause = cause

    @property
    def daemon_disturbed(self) -> bool:
        return self.phase in DAEMON_DISTURBING_PHASES


def truncate_error(text: str) -> str:
    """Bound an error string for the heartbeat, marking that it was cut."""
    text = " ".join(text.split())
    if len(text) <= MAX_ERROR_LEN:
        return text
    return text[: MAX_ERROR_LEN - 1] + "…"


@dataclass
class ApplyStatus:
    """The agent's verdict on its most recent config apply."""

    status: str = STATUS_OK
    #: etag of the bundle actually live right now. On a revert this is the
    #: PREVIOUS bundle's etag, not the one the operator just saved — which
    #: is the whole point: it is what lets the control plane show that the
    #: server has not converged.
    etag: str | None = None
    #: etag of the bundle that was rejected. ``None`` while healthy.
    failed_etag: str | None = None
    #: Which step failed — ``render`` / ``validate`` / ``reload``. Tells the
    #: operator whether the daemon was ever disturbed.
    phase: str | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "etag": self.etag,
            "failed_etag": self.failed_etag,
            "phase": self.phase,
            "error": self.error,
        }

    @property
    def healthy(self) -> bool:
        return self.status == STATUS_OK


class Quarantine:
    """Persisted record of an etag whose apply failed.

    Persisted rather than in-memory because the failure survives a restart:
    the agent re-applies ``current.json`` at boot, so an in-memory record
    would let a crash-looping container re-break itself on every start.
    """

    def __init__(self, state_dir: Path):
        self._path = state_dir / "config" / "quarantine.json"
        self.etag: str | None = None
        self.reason: str | None = None
        self.failures: int = 0
        self.retry_at: float = 0.0
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text())
        except (OSError, json.JSONDecodeError):
            # A corrupt quarantine file must not stop the agent starting.
            # Losing the record means at worst one extra apply attempt of a
            # bad bundle, which is exactly what happens without this file.
            log.warning("quarantine_unreadable_ignoring", path=str(self._path))
            return
        if not isinstance(data, dict):
            return
        self.etag = data.get("etag")
        self.reason = data.get("reason")
        self.failures = int(data.get("failures") or 0)
        # ``retry_at`` is stored as a monotonic-independent wall clock so it
        # survives a restart. A clock that jumps backwards would delay the
        # retry; a clock that jumps forwards brings it early. Both are
        # acceptable — this is a backoff, not a deadline.
        self.retry_at = float(data.get("retry_at") or 0.0)

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".json.tmp")
            tmp.write_text(
                json.dumps(
                    {
                        "etag": self.etag,
                        "reason": self.reason,
                        "failures": self.failures,
                        "retry_at": self.retry_at,
                    },
                    indent=2,
                )
            )
            tmp.replace(self._path)
        except OSError:
            # Best-effort. An unwritable state dir is its own (louder)
            # problem; failing the apply path over it would be worse.
            log.warning("quarantine_write_failed", path=str(self._path))

    def record(self, etag: str, reason: str) -> None:
        """Mark ``etag`` as failed and schedule its retry."""
        if etag != self.etag:
            # A different bundle — restart the backoff ladder rather than
            # inheriting the previous one's.
            self.failures = 0
        self.etag = etag
        self.reason = reason
        self.failures += 1
        idx = min(self.failures - 1, len(RETRY_BACKOFF_SECONDS) - 1)
        self.retry_at = time.time() + RETRY_BACKOFF_SECONDS[idx]
        self._save()
        log.warning(
            "config_quarantined",
            etag=etag,
            failures=self.failures,
            retry_in_seconds=RETRY_BACKOFF_SECONDS[idx],
            reason=reason,
        )

    def clear(self) -> None:
        if self.etag is None:
            return
        log.info("config_quarantine_cleared", etag=self.etag)
        self.etag = None
        self.reason = None
        self.failures = 0
        self.retry_at = 0.0
        try:
            self._path.unlink(missing_ok=True)
        except OSError:
            # Stale file on disk only costs one skipped apply after a
            # restart, and the next successful apply rewrites it away.
            log.warning("quarantine_unlink_failed", path=str(self._path))

    def blocks(self, etag: str | None) -> bool:
        """Should this etag be skipped rather than applied right now?"""
        if etag is None or self.etag is None or etag != self.etag:
            return False
        return time.time() < self.retry_at

    def retry_due(self) -> bool:
        """Is a quarantined bundle due for another attempt?"""
        return self.etag is not None and time.time() >= self.retry_at
