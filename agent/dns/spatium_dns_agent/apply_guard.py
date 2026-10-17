"""Crash-loop guard for config applies (#2019).

#882's :class:`~.config_apply.Quarantine` remembers a bundle whose apply
FAILED, and that covers every failure the agent lives to see. It does not
cover the one it does not: a bundle too big for the container's memory limit
(a blocklist set of hundreds of thousands of RPZ entries per view) applies
cleanly, and then the kernel kills ``named`` while it loads the zones, a few
seconds to half a minute later. The agent exits with its daemon, nothing was
caught, nothing was quarantined, and the restarted agent applies the same
cached bundle from its constructor, BEFORE the sync thread exists. So the
server crash-loops on the cached bundle even after the operator has removed
the cause on the control plane: the fixed bundle is never fetched.

The guard is a marker in the state dir (a hostPath, so it outlives the
container), written before every config apply and cleared once the daemon has
stayed up for :data:`SETTLE_SECONDS` after it. A process that dies while the
marker is armed, however it died (named OOM-killed and the agent exiting with
it, the whole container killed, a node lost), leaves it behind, and the next
start counts that as one death of that bundle. Exits the agent chooses (a
SIGTERM, a re-bootstrap) disarm it first and are not counted.

What a count means is decided in ``sync.SyncLoop``:

* :data:`SYNC_FIRST_AFTER_DEATHS` deaths: the cached bundle is not applied at
  startup. The agent asks the control plane first, and only re-applies the
  cache when the control plane cannot be reached (non-negotiable #5: one
  death may be a power cut, and a cache that is never used is no cache).
* :data:`QUARANTINE_AFTER_DEATHS` deaths: the bundle is quarantined (#882) as
  well. Offline it falls back to the last-known-good bundle when that is a
  different one, and otherwise retries the cache on the quarantine's backoff
  rather than on every container start.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import structlog

log = structlog.get_logger(__name__)

#: How long the daemon has to stay up after an apply before the bundle is
#: trusted again. The kill in #2019 came about 30 s after a steady-state apply
#: and about 3 s after a startup one; a much larger RPZ set loads for longer.
#: A death after this window is not blamed on the bundle.
SETTLE_SECONDS = 300.0

#: Deaths of the same bundle after which startup syncs before using the cache.
SYNC_FIRST_AFTER_DEATHS = 1

#: Deaths of the same bundle after which it is quarantined.
QUARANTINE_AFTER_DEATHS = 2

#: Death counts kept for this many bundles (the newest win). A bundle that
#: matters is the cached one or the last-known-good one; a few more is slack.
_MAX_TRACKED = 4


class ApplyGuard:
    """The persisted death-during-apply marker plus per-bundle death counts."""

    def __init__(self, state_dir: Path):
        self._path = state_dir / "config" / "apply_guard.json"
        self._lock = threading.Lock()
        #: etag being applied or settling; ``None`` when nothing is pending.
        self.armed: str | None = None
        #: etag → deaths while that bundle was being applied or settling.
        self.deaths: dict[str, int] = {}
        self.last_death_at: float | None = None
        # Monotonic time the armed apply returned. In memory only: a restart
        # has no settle clock to resume, and the death is what it records.
        self._applied_at: float | None = None
        self._load()

    # ── persistence ──────────────────────────────────────────────────────

    def _load(self) -> None:
        try:
            data = json.loads(self._path.read_text())
        except FileNotFoundError:
            return
        except (OSError, ValueError):
            # Same trade as the quarantine file: an unreadable marker costs at
            # most the protection it would have given, never the start.
            log.warning("apply_guard_unreadable_ignoring", path=str(self._path))
            return
        if not isinstance(data, dict):
            return
        armed = data.get("armed")
        self.armed = str(armed) if armed else None
        deaths = data.get("deaths")
        if isinstance(deaths, dict):
            for etag, n in deaths.items():
                try:
                    if int(n) > 0:
                        self.deaths[str(etag)] = int(n)
                except (TypeError, ValueError):
                    continue
        stamp = data.get("last_death_at")
        self.last_death_at = float(stamp) if isinstance(stamp, (int, float)) else None

    def _save(self) -> None:
        if not self.armed and not self.deaths:
            try:
                self._path.unlink(missing_ok=True)
            except OSError:
                log.warning("apply_guard_unlink_failed", path=str(self._path))
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".json.tmp")
            tmp.write_text(
                json.dumps(
                    {
                        "armed": self.armed,
                        "deaths": self.deaths,
                        "last_death_at": self.last_death_at,
                    }
                )
            )
            tmp.replace(self._path)
        except OSError:
            # Best-effort, like the quarantine: an unwritable state dir is its
            # own louder problem and must not fail the apply.
            log.warning("apply_guard_write_failed", path=str(self._path))

    # ── lifecycle ────────────────────────────────────────────────────────

    def startup(self) -> str | None:
        """Count the death the previous process left armed, if it did.

        Returns the etag that died, or ``None``. Called once, before anything
        is applied."""
        with self._lock:
            died = self.armed
            if died is None:
                return None
            self.deaths[died] = self.deaths.get(died, 0) + 1
            self.last_death_at = time.time()
            self.armed = None
            # Bound the record: drop the bundles with the fewest deaths.
            while len(self.deaths) > _MAX_TRACKED:
                victim = min((e for e in self.deaths if e != died), key=lambda e: self.deaths[e])
                del self.deaths[victim]
            self._save()
            count = self.deaths[died]
        log.error(
            "dns_agent_died_during_config_apply",
            etag=died,
            deaths=count,
            note="the previous process exited while this bundle was being applied "
            f"or within {int(SETTLE_SECONDS)} s of it",
        )
        return died

    def deaths_for(self, etag: str | None) -> int:
        if not etag:
            return 0
        with self._lock:
            return self.deaths.get(etag, 0)

    def arm(self, etag: str | None) -> None:
        """Persist "applying ``etag``" before the apply starts."""
        if not etag:
            return
        with self._lock:
            self.armed = etag
            self._applied_at = None
            self._save()

    def applied(self) -> None:
        """The armed apply returned: start its settle clock."""
        with self._lock:
            if self.armed is not None:
                self._applied_at = time.monotonic()

    def disarm(self) -> None:
        """The process is exiting by choice, or the apply failed and was
        caught (the quarantine takes that one): not a death. Counts stay."""
        with self._lock:
            if self.armed is None:
                return
            self.armed = None
            self._applied_at = None
            self._save()

    def settle_due(self) -> bool:
        with self._lock:
            return (
                self.armed is not None
                and self._applied_at is not None
                and time.monotonic() - self._applied_at >= SETTLE_SECONDS
            )

    def settled(self) -> str | None:
        """The daemon stayed up: the armed bundle is trusted again."""
        with self._lock:
            etag = self.armed
            if etag is None:
                return None
            self.armed = None
            self._applied_at = None
            self.deaths.pop(etag, None)
            self._save()
        log.info("config_apply_settled", etag=etag, settle_s=int(SETTLE_SECONDS))
        return etag
