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
SIGTERM, a critical thread ending) disarm it first and are not counted. A
re-registration after a 401 or 404 is not an exit at all (#2052): the daemon
keeps running, and a bundle still settling goes on settling.

What a count means is decided in ``sync.SyncLoop``:

* :data:`SYNC_FIRST_AFTER_DEATHS` deaths: the cached bundle is not applied at
  startup. The agent asks the control plane first, and only re-applies the
  cache when the control plane cannot be reached (non-negotiable #5: one
  death may be a power cut, and a cache that is never used is no cache).
  A control plane that answers but sends no bundle within
  :data:`BOOT_HOLD_MAX_WAIT_SECONDS` counts as unreachable (#2241).
* :data:`QUARANTINE_AFTER_DEATHS` deaths the agent WATCHED (the daemon exited
  while the agent was alive to see it, :meth:`ApplyGuard.daemon_died`): the
  bundle is quarantined (#882) as well. Offline it falls back to the
  last-known-good bundle when that is a different one, and otherwise retries
  the cache on the quarantine's backoff rather than on every container start.

Why the quarantine needs WATCHED deaths. A marker left armed says only that
the process ended without an orderly exit inside the window: a power cut, a
node reboot that SIGKILLed the container, a hard eviction and an OOM kill of
the whole container all look the same. Two of those within five minutes of an
apply of a perfectly good bundle would otherwise quarantine it and leave the
server dark while the control plane is unreachable, which is the one case
non-negotiable #5 exists for. Unwatched deaths therefore only ever buy "ask
the control plane first, then serve the cache"; the dark state needs the agent
to have seen the daemon die on the bundle, twice. On the appliance today the
kubelet's ``memory.oom.group`` kills the agent with named (#2018), so there the
guard stops at sync-first: the crash loop on a bundle the control plane still
serves is the kubelet's to back off, and the operator's fix is fetched on the
next start, which is what #2019 needed.
"""

from __future__ import annotations

import json
import os
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

#: Default of :data:`BOOT_HOLD_MAX_WAIT_SECONDS` (#2241).
DEFAULT_BOOT_HOLD_MAX_WAIT_SECONDS = 600.0


def _boot_hold_max_wait_from_env() -> float:
    """``AGENT_BOOT_HOLD_MAX_WAIT_S``, or the default when unset or unusable.

    A value that is not a positive number is ignored rather than honoured:
    zero would turn the hold back into the pre-#2019 behaviour (the cache
    applied on the first poll), and a typo must not leave a server dark for
    longer than the default."""
    raw = os.environ.get("AGENT_BOOT_HOLD_MAX_WAIT_S", "").strip()
    if not raw:
        return DEFAULT_BOOT_HOLD_MAX_WAIT_SECONDS
    try:
        value = float(raw)
    except ValueError:
        value = 0.0
    if not value > 0 or value == float("inf"):
        log.warning(
            "boot_hold_max_wait_invalid_using_default",
            value=raw,
            default_s=DEFAULT_BOOT_HOLD_MAX_WAIT_SECONDS,
        )
        return DEFAULT_BOOT_HOLD_MAX_WAIT_SECONDS
    return value


#: How long a startup hold waits for the control plane to send a bundle before
#: the held cache is served anyway (#2241). The hold asks the control plane
#: first, and falls back to the cache at once when it cannot be reached. A
#: control plane that IS reachable but cannot produce a bundle (renders
#: OOM-killed or timed out at scale, a re-registration backing off, a long-poll
#: that only ever answers 304) used to keep the server dark for as long as that
#: lasted: hours in the #2240 scale lab, on servers holding a valid cache. Past
#: this wait the control plane counts as unreachable for the hold. A bundle the
#: daemon was SEEN to die on twice is still never re-applied by it.
BOOT_HOLD_MAX_WAIT_SECONDS = _boot_hold_max_wait_from_env()

#: WATCHED deaths of the same bundle (the agent saw the daemon exit) after
#: which it is quarantined. Unwatched deaths never quarantine (module doc).
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
        #: etag → those of the deaths the agent watched happen: the daemon
        #: exited while the agent was alive (:meth:`daemon_died`). The
        #: evidence the quarantine needs; see the module docstring.
        self.observed: dict[str, int] = {}
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
        for key, into in (("deaths", self.deaths), ("observed", self.observed)):
            counts = data.get(key)
            if not isinstance(counts, dict):
                continue
            for etag, n in counts.items():
                try:
                    if int(n) > 0:
                        into[str(etag)] = int(n)
                except (TypeError, ValueError):
                    continue
        stamp = data.get("last_death_at")
        self.last_death_at = float(stamp) if isinstance(stamp, (int, float)) else None

    def _save(self) -> None:
        if not self.armed and not self.deaths and not self.observed:
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
                        "observed": self.observed,
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
            for etag in [e for e in self.observed if e not in self.deaths]:
                del self.observed[etag]
            self._save()
            count = self.deaths[died]
            watched = self.observed.get(died, 0)
        log.error(
            "dns_agent_died_during_config_apply",
            etag=died,
            deaths=count,
            watched=watched,
            note="the previous process exited while this bundle was being applied "
            f"or within {int(SETTLE_SECONDS)} s of it",
        )
        return died

    def deaths_for(self, etag: str | None) -> int:
        if not etag:
            return 0
        with self._lock:
            return self.deaths.get(etag, 0)

    def observed_for(self, etag: str | None) -> int:
        if not etag:
            return 0
        with self._lock:
            return self.observed.get(etag, 0)

    def condemned(self, etag: str | None) -> bool:
        """The daemon was SEEN to die on this bundle often enough to quarantine
        it, rather than merely having the process end inside the window."""
        return self.observed_for(etag) >= QUARANTINE_AFTER_DEATHS

    def daemon_died(self) -> str | None:
        """The agent watched the daemon exit while a bundle was armed.

        Recorded before the agent exits with it; the marker stays armed so the
        next start counts the death as usual, now with evidence attached."""
        with self._lock:
            etag = self.armed
            if etag is None:
                return None
            self.observed[etag] = self.observed.get(etag, 0) + 1
            self._save()
            return etag

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
            self.observed.pop(etag, None)
            self._save()
        log.info("config_apply_settled", etag=etag, settle_s=int(SETTLE_SECONDS))
        return etag
