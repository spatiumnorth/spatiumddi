"""Config long-poll loop + op execution.

Hits GET /dns/agents/config with If-None-Match; on 200 applies the new
bundle (atomic disk swap, daemon-specific reload) and dispatches any
pending_record_ops through the active driver. On 304 it just loops back.
"""

from __future__ import annotations

import shutil
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import httpx
import structlog

from . import features
from .admin_pusher import push_rendered_config
from .apply_guard import (
    BOOT_HOLD_MAX_WAIT_SECONDS,
    SETTLE_SECONDS,
    SYNC_FIRST_AFTER_DEATHS,
    ApplyGuard,
)
from .bootstrap import reauth_generation, reauthenticate
from .cache import commit_config, load_config, load_previous_config, save_config
from .config import AgentConfig
from .config_apply import (
    PHASE_RELOAD,
    PHASE_VALIDATE,
    STATUS_NO_PREVIOUS,
    STATUS_OK,
    STATUS_REVERT_FAILED,
    STATUS_REVERTED,
    ApplyStatus,
    ConfigApplyError,
    Quarantine,
    truncate_error,
)
from .drivers.base import DriverBase, HeldZone
from .fetch import get_config
from .instance import AGENT_INSTANCE, AGENT_INSTANCE_HEADER
from .oom_watch import OomWatch, is_oom_status

log = structlog.get_logger(__name__)

# #2042 / #2044 — ``AGENT_INSTANCE`` (imported from ``instance``) names this
# process on every config poll; re-exported here for older callers.

# #2044 — set on the 409 the control plane answers when ANOTHER live agent
# process owns this server identity (a cloned VM or a copied state dir keeps
# the agent_id). Only the most recent process is served; this one keeps
# serving its cached config and asks again on a slow backoff, taking the
# server back by itself once the other one stops polling.
DUPLICATE_INSTANCE_HEADER = "X-Spatium-Duplicate-Agent-Instance"
DUPLICATE_INSTANCE_BACKOFF = 30.0


def _touch_ready_marker(state_dir: Path) -> None:
    """Stamp ``<state_dir>/.ready`` after the first successful sync (#296 A2).

    The K8s DaemonSet readinessProbe execs a marker-file check + a light
    daemon ping; the marker representing "I have synced at least once" plus
    the hostPath bundle cache lets a pod that restarts into warm state be
    Ready immediately. Idempotent — ``touch`` on an existing file is fine
    and a no-op once stamped. Caller MUST only invoke after a successful
    fetch + persist + driver-apply; a failed sync must not flip readiness
    true. Best-effort: a marker write that races a filesystem error never
    blocks the daemon — we just log and move on, and the next successful
    apply retries.
    """
    try:
        marker = state_dir / ".ready"
        marker.touch(exist_ok=True)
    except OSError:
        log.exception("ready_marker_touch_failed", path=str(state_dir / ".ready"))


# #1854 — how often the DNSSEC state of signed zones is re-read between
# structural reloads. BIND's key-state transitions run on TTL-scale timers
# (an hour and up on the default policy), so minutes are plenty.
DNSSEC_REFRESH_SECONDS = 300.0

# #1934 — the re-read interval while a signed zone's key set is still
# settling: right after a structural reload or pod start (BIND generates the
# keys a few seconds AFTER it loads the zone, and a re-keyed zone — #1855 —
# serves its new key only then), after the keys changed, when BIND could not
# be asked yet, or when the control plane did not take the report. The slow
# cadence above is for a quiet zone; using it here left the control plane
# showing the old key (and a DS made from it) for a full interval.
DNSSEC_SETTLE_SECONDS = 20.0

# #1968 — how many polls a startup apply's served-serial report is retried on
# before it is dropped (see ``SyncLoop._flush_boot_report``).
BOOT_REPORT_MAX_ATTEMPTS = 10

# #2019 — the read timeout of the first fetch while a cached bundle is held
# back at startup. That fetch carries no If-None-Match, so the control plane
# answers at once; waiting the long-poll's minute would leave the server dark
# for a minute longer when it is unreachable.
BOOT_FETCH_TIMEOUT = 20.0

# #2241 — the clock a startup hold is timed on (``BOOT_HOLD_MAX_WAIT_SECONDS``).
# Its own name so a test can move it without moving every other monotonic
# reading in the process (the apply guard's settle window among them).
_hold_clock = time.monotonic


def _ack(op: dict[str, Any], result: str, message: str | None = None) -> dict[str, Any]:
    """One op ack. Echoes the page's ``dispatch`` stamp when it has one
    (#1232), so the control plane can tell a late ack for an earlier dispatch
    from this one and not charge a failure twice."""
    ack: dict[str, Any] = {"op_id": op["op_id"], "result": result}
    if message is not None:
        ack["message"] = message
    if "dispatch" in op:
        ack["dispatch"] = op["dispatch"]
    return ack


def _serial_later(new: int, old: int) -> bool:
    """RFC 1982 serial arithmetic: ``new`` is later than ``old``."""
    return 0 < (new - old) % 2**32 < 2**31


def _zone_key(name: Any) -> str:
    """A zone name as the zone-state bookkeeping keys it: the bundle names
    zones with the trailing dot, and nothing here depends on whether an op
    does."""
    return str(name or "").rstrip(".")


def _note_reached(reached: dict[str, int], op: dict[str, Any]) -> None:
    """Note the serial an applied op brought its zone to (#1373).

    Each op carries ``target_serial``, the zone's serial after the change it
    makes. Ops are paged oldest first; the latest serial wins either way."""
    zone, target = _zone_key(op.get("zone_name")), op.get("target_serial")
    if not zone or not isinstance(target, int) or isinstance(target, bool):
        return
    prev = reached.get(zone)
    if prev is None or _serial_later(target, prev):
        reached[zone] = target


# Starts the error of an apply that landed with zones left unserved: refused by
# the daemon (#1280) or held back by BIND9's zone check (#1403). The control
# plane has no "partial" status (it reports ``reverted``), so the chip, banner
# and ``agent_config_rejected`` alert read this prefix to say what really
# happened: nothing rolled back, every other zone served. Mirrored in
# backend/app/services/agents/config_apply.py and frontend/src/lib/configApply.ts.
PARTIAL_APPLY_PREFIX = "partial apply: "


def _partial_apply_error(held: Sequence[HeldZone], refused: Sequence[str]) -> str:
    """The operator-facing account of the zones an apply left unserved.

    ``held``: zones the BIND9 zone check held back (#1403). ``refused``: zones
    or records the daemon refused, one ``"<zone>: <reason>"`` each (#1280,
    and per record on Technitium, #1608).
    No driver produces both today; if one ever did, both are named here.
    """
    parts: list[str] = []
    if held:
        zones = "; ".join(
            f"{h.zone}{f' (view {h.view})' if h.view else ''}: {h.reason} ("
            + ("still served from its last good copy" if h.served else "not served")
            + ")"
            for h in held
        )
        count = "a zone file" if len(held) == 1 else f"{len(held)} zone files"
        parts.append(
            f"named-checkzone refused {count}, held back until the data loads; "
            f"every other change in this config is live: {zones}"
        )
    if refused:
        parts.append(
            f"the daemon refused {len(refused)} item(s); everything else is served: "
            + "; ".join(refused)
        )
    return truncate_error(PARTIAL_APPLY_PREFIX + "; and ".join(parts))


class SyncLoop:
    def __init__(
        self,
        cfg: AgentConfig,
        token_ref: list[str],
        driver: DriverBase,
        heartbeat: Any,
        oom_watch: OomWatch | None = None,
    ):
        self.cfg = cfg
        self.token_ref = token_ref
        self.driver = driver
        self.heartbeat = heartbeat
        self._stop = threading.Event()
        self._current_etag: str | None = None
        # Tracks the structural-only fingerprint of the last applied bundle.
        # We re-render config + reload the daemon only when this changes.
        # Record-only changes rotate the full etag (so we get 200 not 304)
        # but leave structural_etag alone — the agent then drains record ops
        # via RFC 2136 over loopback without bouncing the daemon.
        self._current_structural_etag: str | None = None
        # #1373 — the serial last reported per zone (zone-state), so the late
        # retry of an older op can never report a zone backwards.
        self._reported_serials: dict[str, int] = {}
        # #1968 — a bundle applied at startup (the cached one, or the
        # last-known-good) whose served serials have not been reported yet.
        # A driver that can move a zone to a serial of its own (PowerDNS
        # floors it above the one it served) changes what is served on that
        # apply, and the control plane only adopts it from a report; with no
        # structural change pending, nothing else would send one. Reported at
        # the top of the next polls until it lands.
        self._boot_report_bundle: dict[str, Any] | None = None
        self._boot_report_attempts = 0
        # #882 — last-known-good revert. ``quarantine`` remembers an etag
        # whose apply failed so we stop re-applying it every poll;
        # ``apply_status`` is what the heartbeat reports upward.
        self._quarantine = Quarantine(self.cfg.state_dir)
        self.apply_status = ApplyStatus()
        # True while the live bundle applied with zones the daemon refused or
        # the zone check held back (see ``_report_partial_apply``). Those zones
        # stay unserved until the next structural apply, so a record-op-only
        # poll must not read the degraded verdict as stale and clear it.
        self._zones_refused = False
        self.heartbeat.config_apply = self.apply_status
        # #1854 — the bundle last applied structurally, so the DNSSEC state
        # (DS + per-key) can be re-read between reloads. BIND moves a key's
        # DS from not-submittable to submittable hours after signing, and
        # withdraws the old one at the end of a rollover, with no config
        # change in between; reading only after a reload would freeze both.
        self._dnssec_bundle: dict[str, Any] | None = None
        self._dnssec_reported: list[dict[str, Any]] | None = None
        self._dnssec_refresh_at = 0.0
        # #1934 — consecutive reads that ended unsettled (a report, a refused
        # report, an unreadable zone); drives the settling backoff.
        self._dnssec_settle_streak = 0
        # #1725 — the supervisor's; ``None`` in tests that build a loop
        # directly. Only read on a failed apply, to name an OOM kill.
        self.oom_watch = oom_watch
        # #2052 — the re-registration this loop last caught up with.
        self._reauth_gen = reauth_generation()

        # #2019 — the death-during-apply marker. Read before anything is
        # applied: a process that died with it armed counts a death of the
        # bundle it names, whatever killed it.
        self._guard = ApplyGuard(self.cfg.state_dir)
        died = self._guard.startup()
        # #2019 — set while the cached bundle is held back at startup because
        # the daemon died on it: ``(bundle, etag, deaths)``. Resolved by the
        # first bundle that applies (fetched, cached or last-known-good).
        self._boot_hold: tuple[dict[str, Any], str, int] | None = None
        # True once the hold put the last-known-good bundle live offline.
        self._boot_hold_on_previous = False
        # Whether the last ``_handle_apply_failure`` re-applied the previous
        # bundle (so something is live again), for the hold to read.
        self._revert_landed = False
        # #2241 — when the hold began (``_hold_clock``), and whether the
        # max-wait fallback has been announced. See ``_boot_hold_max_wait``.
        self._boot_hold_since: float | None = None
        self._boot_hold_max_wait_logged = False

        # Preload cached bundle (offline-operation guarantee)
        bundle, etag = load_config(self.cfg.state_dir)
        deaths = self._guard.deaths_for(etag) if bundle is not None else 0
        if bundle is not None and etag and deaths >= SYNC_FIRST_AFTER_DEATHS:
            # #2019 — the daemon died while this bundle was being applied, or
            # just after: re-applying it here, before the sync thread exists,
            # is what kept a server crash-looping after the operator removed
            # the cause. Ask the control plane first (the first poll). Only
            # deaths the agent WATCHED quarantine it (``apply_guard`` module
            # doc): an unexplained end of the process can be a power cut.
            if self._guard.condemned(etag) and (died == etag or self._quarantine.etag != etag):
                self._quarantine.record(etag, self._death_reason(etag, deaths))
            self._begin_boot_hold(bundle, etag, deaths)
            self._boot_hold_since = _hold_clock()
            return

        # #882 — a restart must not re-break the daemon with the same bundle
        # that failed before it. ``current.json`` is what the control plane
        # last SENT, which is not necessarily what worked; if that bundle is
        # quarantined, boot from the last-known-good instead.
        booting_from_previous = False
        if bundle is not None and self._quarantine.blocks(etag):
            prev_bundle, prev_etag = load_previous_config(self.cfg.state_dir)
            # #2019 — "the last-known-good" can be the very bundle that is
            # quarantined (it applied, was committed, and the daemon died a
            # moment later), and then it is no fallback at all.
            if prev_bundle is not None and self._previous_usable(prev_etag, etag, before_sync=True):
                log.warning(
                    "bootstrap_skipping_quarantined_bundle",
                    failed_etag=etag,
                    booting_etag=prev_etag,
                    reason=self._quarantine.reason,
                )
                self.apply_status = ApplyStatus(
                    status=STATUS_REVERTED,
                    etag=prev_etag,
                    failed_etag=etag,
                    error=self._quarantine.reason,
                )
                self.heartbeat.config_apply = self.apply_status
                bundle, etag = prev_bundle, prev_etag
                booting_from_previous = True
        if bundle is not None:
            self._bootstrap_apply(bundle, etag, booting_from_previous)

    def _bootstrap_apply(
        self,
        bundle: dict[str, Any],
        etag: str | None,
        booting_from_previous: bool,
        before_sync: bool = True,
    ) -> bool:
        """Apply a cached bundle with no control plane involved. True if live.

        The startup path, and (#2019) the offline end of a startup hold, where
        ``before_sync`` is False: the control plane has been asked already."""
        self._current_etag = etag
        try:
            self._guarded_apply(bundle, etag)
            self._current_structural_etag = self._applied_fingerprint(bundle)
            if not booting_from_previous:
                # Zones refused or held back are reported, not reverted —
                # see ``_report_partial_apply`` — and the bundle is still
                # committed: everything else in it is being served. Otherwise
                # ``ok``, which (#2019) also replaces a startup hold's verdict
                # when the held cache is applied after all.
                self._report_applied(etag)
                # #882 — ``current`` demonstrably works, so it becomes the
                # bundle we fall back TO. Skipped when we booted from
                # ``previous``: committing there would copy the still-bad
                # ``current.json`` over the only good config we have.
                commit_config(self.cfg.state_dir, etag or "")
            # #296 A2 — warm-restart readiness. The hostPath cache carries
            # the bundle we just successfully re-applied; the marker tells
            # the K8s readinessProbe this pod is ready to serve without
            # waiting for the next control-plane long-poll round-trip.
            _touch_ready_marker(self.cfg.state_dir)
            self._dnssec_bundle = bundle
            self._arm_boot_report(bundle)
            log.info("dns_agent_bootstrap_from_cache", etag=etag)
            # #170 Wave C1 — fleet-upgrade / reboot / SNMP / NTP
            # trigger-file writes moved to the supervisor's
            # heartbeat loop. The DNS service container drops its
            # host bind mounts (``/etc/spatiumddi-host``,
            # ``/boot/efi-host``, ``/var/lib/spatiumddi-host/
            # release-state``, ``/run/udev``) in C1 so it can no
            # longer write the trigger surface anyway; the
            # supervisor's appliance-state module is the single
            # producer.
            # Push the rendered tree once at bootstrap so operators
            # get a Config-tab snapshot the moment the agent comes
            # up — without this, the snapshot only lands on the
            # next structural reload (could be hours away on a
            # quiet group).
            try:
                push_rendered_config(self.cfg, self.token_ref[0])
            except Exception:
                log.exception("rendered_config_bootstrap_push_failed")
            return True
        except Exception as e:
            # #882 — the cached bundle itself no longer applies. Quarantine
            # it and fall back, rather than leaving the daemon on whatever
            # half-state the failed apply produced.
            log.exception("bootstrap_cache_apply_failed")
            if booting_from_previous:
                # It was the last-known-GOOD bundle that just failed, not
                # ``current`` — ``etag`` was rebound to ``prev_etag`` above.
                # Do NOT quarantine it: that would overwrite the record
                # naming the bundle which actually broke us, un-quarantining
                # the poison pill so the next poll applies it again.
                self.apply_status = ApplyStatus(
                    status=STATUS_REVERT_FAILED,
                    etag=None,
                    failed_etag=self._quarantine.etag,
                    error=truncate_error(str(e)),
                )
                self.heartbeat.config_apply = self.apply_status
                log.error(
                    "bootstrap_last_known_good_apply_failed",
                    failed_etag=self._quarantine.etag,
                    previous_etag=etag,
                )
            else:
                if etag:
                    self._quarantine.record(etag, truncate_error(str(e)))
                self._bootstrap_fallback(etag, e, before_sync=before_sync)
            return False

    def _guarded_apply(self, bundle: dict[str, Any], etag: str | None) -> None:
        """``driver.apply_config`` under the #2019 death-during-apply marker.

        Armed (persisted) before the apply, so a process killed during it, or
        during the settle window after it, leaves a death for the next start
        to count. A failure the apply RAISES is #882's to handle and disarms."""
        self._guard.arm(etag)
        try:
            self.driver.apply_config(bundle)
        except BaseException:
            self._guard.disarm()
            raise
        self._guard.applied()

    def _previous_usable(
        self,
        prev_etag: str | None,
        failed_etag: str | None,
        *,
        before_sync: bool = False,
    ) -> bool:
        """Whether the last-known-good bundle is a fallback for ``failed_etag``.

        Not when it IS the failing bundle, and not when the daemon was seen to
        die on it (#2019): ``previous`` is committed as soon as an apply
        returns, so a bundle that is killed a moment later can be both.

        ``before_sync``: at startup, before the control plane has been asked,
        any death at all disqualifies it, the same rule that holds the cached
        bundle back (re-applying a bundle that preceded a kill before syncing
        is #2019 itself). After a sync attempt an unwatched death (it may have
        been a power cut) does not: a server serving its last-known-good beats
        a dark one, and if that bundle is the killer the next start holds it."""
        if prev_etag is not None and prev_etag == failed_etag:
            return False
        if self._guard.condemned(prev_etag):
            return False
        return not before_sync or self._guard.deaths_for(prev_etag) == 0

    def _death_reason(self, etag: str, deaths: int) -> str:
        times = "once" if deaths == 1 else f"{deaths} times"
        watched = self._guard.observed_for(etag)
        seen = ""
        if watched:
            seen = f" (the agent saw it exit {'once' if watched == 1 else f'{watched} times'})"
        oom = ""
        if self.oom_watch is not None and self.oom_watch.record:
            oom = (
                " (the container's OOM killer: the daemon ran out of memory under "
                "its limit; large RPZ blocklists are the usual cause, see "
                "docs/features/DNS.md 8.0)"
            )
        return truncate_error(
            f"the DNS daemon died {times} while this bundle was being applied or "
            f"within {int(SETTLE_SECONDS)} s of it{seen}{oom}"
        )

    def _report_boot_hold(self, status: ApplyStatus) -> None:
        self.apply_status = status
        self.heartbeat.config_apply = status
        # The ``config_apply_`` prefix is load-bearing (#1067): see
        # ``_handle_apply_failure``.
        self.heartbeat.daemon_status = {
            **self.heartbeat.daemon_status,
            "status": "degraded",
            "reason": f"config_apply_{status.status}: {status.error}",
        }

    def _begin_boot_hold(self, bundle: dict[str, Any], etag: str, deaths: int) -> None:
        """Hold the cached bundle back at startup (#2019).

        The daemon must not come up on it either: ``start_daemon`` launches
        from the live rendered tree, which is that bundle's. It is set aside,
        so the start defers (#1056) until a bundle applies and launches it."""
        self._boot_hold = (bundle, etag, deaths)
        self._set_aside_live_tree()
        reason = self._death_reason(etag, deaths)
        self._report_boot_hold(
            ApplyStatus(
                status=STATUS_NO_PREVIOUS,
                etag=None,
                failed_etag=etag,
                phase=PHASE_RELOAD,
                error=truncate_error(
                    f"{reason}; held back at startup, so the server is not serving "
                    "until the control plane sends a bundle"
                    + (
                        " (it is quarantined: re-applied only on the backoff)"
                        if self._guard.condemned(etag)
                        else " (re-applied from the cache if the control plane "
                        "cannot be reached, or sends no bundle within "
                        f"{int(BOOT_HOLD_MAX_WAIT_SECONDS)} s)"
                    )
                ),
            )
        )
        log.warning(
            "bootstrap_cache_held_after_daemon_death",
            etag=etag,
            deaths=deaths,
            quarantined=self._guard.condemned(etag),
        )

    def _set_aside_live_tree(self) -> None:
        live = self.cfg.state_dir / "rendered"
        if not live.exists():
            return
        held = self.cfg.state_dir / "rendered.held"
        try:
            if held.exists():
                shutil.rmtree(held)
            live.rename(held)
        except OSError:
            log.exception("bootstrap_set_aside_rendered_failed", path=str(live))

    def _end_boot_hold(self) -> None:
        if self._boot_hold is None:
            return
        log.info(
            "bootstrap_hold_resolved",
            held_etag=self._boot_hold[1],
            live_etag=self.apply_status.etag,
        )
        self._boot_hold = None
        self._boot_hold_on_previous = False
        shutil.rmtree(self.cfg.state_dir / "rendered.held", ignore_errors=True)

    def _boot_hold_fallback(self, failed_etag: str | None = None) -> None:
        """No usable bundle from the control plane while the cache is held.

        Reached offline (unreachable, or not answering 200 — a 401/404 too,
        while ``reauthenticate`` registers again, #2182), when the control
        plane is serving the held bundle itself and that bundle is
        quarantined, and (``failed_etag``) when the control plane's own bundle
        failed to apply: the hold set the live tree aside, so without this the
        server would sit dark on a failure the cache would have survived.
        Non-negotiable #5 decides what serves meanwhile:

        * not condemned (fewer than two deaths the agent watched, however many
          unexplained ones): the cached bundle. An unexplained death can be a
          power cut or a node lost mid-apply, and a healthy server must not
          stay dark over it.
        * condemned: the last-known-good one when it is a different bundle the
          daemon was not seen to die on; otherwise the cached bundle again,
          but only on the quarantine's backoff (60 s, 5 min, then 15 min), so a
          bundle that does not fit costs one crash per interval, not a
          crash loop, and the server is not left with no config forever.
        """
        hold = self._boot_hold
        if hold is None or self._boot_hold_on_previous:
            return
        bundle, etag, deaths = hold
        # Condemned by watched deaths, or quarantined by an apply of it that
        # failed and was caught since (not to be retried on every offline poll).
        if not self._guard.condemned(etag) and self._quarantine.etag != etag:
            if failed_etag is None:
                log.warning("bootstrap_hold_applying_cache_offline", etag=etag, deaths=deaths)
                if self._bootstrap_apply(
                    bundle, etag, booting_from_previous=False, before_sync=False
                ):
                    self._end_boot_hold()
                return
            # The control plane's bundle is what ``current.json`` holds now, so
            # the held one serves as a revert: not committed, not ``ok``.
            failure = self.apply_status
            status = ApplyStatus(
                status=STATUS_REVERTED,
                etag=etag,
                failed_etag=failed_etag,
                phase=failure.phase,
                error=failure.error,
            )
            log.warning(
                "bootstrap_hold_reverting_to_cache",
                held_etag=etag,
                failed_etag=failed_etag,
            )
            if self._bootstrap_apply(bundle, etag, booting_from_previous=True, before_sync=False):
                self._report_boot_hold(status)
                self._end_boot_hold()
            return
        prev_bundle, prev_etag = load_previous_config(self.cfg.state_dir)
        if (
            prev_bundle is not None
            and prev_etag != failed_etag
            and self._previous_usable(prev_etag, etag)
        ):
            status = ApplyStatus(
                status=STATUS_REVERTED,
                etag=prev_etag,
                failed_etag=etag,
                phase=PHASE_RELOAD,
                error=self._quarantine.reason or self._death_reason(etag, deaths),
            )
            self.apply_status = status
            self.heartbeat.config_apply = status
            if self._bootstrap_apply(
                prev_bundle, prev_etag, booting_from_previous=True, before_sync=False
            ):
                self._report_boot_hold(status)
                self._boot_hold_on_previous = True
                log.warning(
                    "bootstrap_hold_serving_last_known_good",
                    held_etag=etag,
                    live_etag=prev_etag,
                )
            return
        if self._quarantine.retry_due():
            log.warning(
                "bootstrap_hold_retrying_quarantined_cache",
                etag=etag,
                failures=self._quarantine.failures,
            )
            if self._bootstrap_apply(bundle, etag, booting_from_previous=False, before_sync=False):
                self._end_boot_hold()

    def _boot_hold_max_wait(self) -> None:
        """Serve the held cache once the control plane has had long enough (#2241).

        The hold asks the control plane first and serves the cache only when it
        cannot be reached. A control plane that answers but cannot produce a
        bundle (the renders OOM-killed or timed out at scale, a long-poll that
        only ever ends in 304, a re-registration backing off) never reads as
        unreachable, and kept the #2240 scale lab's servers dark for hours on a
        valid cache. Past ``BOOT_HOLD_MAX_WAIT_SECONDS`` it counts as
        unreachable: every poll from then on goes through the offline fallback,
        until something is live. Nothing is started here: the apply launches
        the deferred daemon (#1056), and a bundle that arrives later is applied
        by the normal path as a reload.

        A bundle the daemon was SEEN to die on twice is never re-applied by
        this path, not even on the quarantine's backoff: the control plane is
        reachable, so the operator's fix can still arrive, and a timer must not
        start a crash loop on the bundle that caused it. Only a different
        last-known-good may serve; with none the server stays down, and the
        backoff retry stays where #882 / #2019 put it (an unreachable control
        plane).
        """
        hold = self._boot_hold
        if hold is None or self._boot_hold_on_previous:
            return
        since = self._boot_hold_since
        if since is None:
            return
        waited = _hold_clock() - since
        if waited < BOOT_HOLD_MAX_WAIT_SECONDS:
            return
        etag = hold[1]
        condemned = self._guard.condemned(etag)
        usable_previous = not condemned or self._previous_serves_hold(etag)
        if not condemned:
            serving = "cache"
        elif usable_previous:
            serving = "last_known_good"
        else:
            serving = "nothing: the cache is condemned and there is no other last-known-good"
        if not self._boot_hold_max_wait_logged:
            self._boot_hold_max_wait_logged = True
            log.warning(
                "bootstrap_hold_max_wait_elapsed_applying_cache",
                etag=etag,
                waited_s=int(waited),
                max_wait_s=int(BOOT_HOLD_MAX_WAIT_SECONDS),
                serving=serving,
            )
        if not usable_previous:
            return
        self._boot_hold_fallback()
        if self._boot_hold is not None and self.apply_status.status == STATUS_REVERTED:
            # The held cache failed to apply and ``_bootstrap_fallback`` put the
            # last-known-good live instead: the hold is now served by it, as
            # after the fallback's own last-known-good branch. Without this the
            # next poll would apply (and reload) the same bundle again.
            self._boot_hold_on_previous = True

    def _previous_serves_hold(self, held_etag: str) -> bool:
        """Whether the last-known-good could serve in place of a condemned hold.

        Checked before ``_boot_hold_fallback`` is asked, because when it cannot
        that method retries the condemned bundle itself once its backoff is
        due, which the max-wait path must never do. The etag is read first so
        an unusable ``previous`` is not parsed on every poll.

        A ``previous`` with no etag (a missing or empty ``previous.etag``, as
        agents upgraded in the field can carry) does not serve: nothing says it
        is not the condemned bundle itself, and ``_boot_hold_fallback`` would
        not use it either (it compares the etag with ``failed_etag``, None
        here) but fall through to retrying the condemned bundle."""
        cfg_dir = self.cfg.state_dir / "config"
        etag_path = cfg_dir / "previous.etag"
        try:
            prev_etag = etag_path.read_text().strip() if etag_path.exists() else None
        except OSError:
            return False
        if not prev_etag or not self._previous_usable(prev_etag, held_etag):
            return False
        prev_bundle, _ = load_previous_config(self.cfg.state_dir)
        return prev_bundle is not None

    def _bootstrap_fallback(
        self, failed_etag: str | None, exc: BaseException, *, before_sync: bool = True
    ) -> None:
        """Boot from the last-known-good bundle after ``current`` failed (#882).

        Only reached at startup, where there is no running daemon to protect
        — so unlike the steady-state revert this is about getting the server
        answering at all, on the newest config that is known to work.
        """
        prev_bundle, prev_etag = load_previous_config(self.cfg.state_dir)
        if prev_bundle is None or not self._previous_usable(
            prev_etag, failed_etag, before_sync=before_sync
        ):
            self.apply_status = ApplyStatus(
                status=STATUS_NO_PREVIOUS,
                etag=None,
                failed_etag=failed_etag,
                error=truncate_error(str(exc)),
            )
            self.heartbeat.config_apply = self.apply_status
            log.error("bootstrap_no_last_known_good", failed_etag=failed_etag)
            return
        try:
            self._guarded_apply(prev_bundle, prev_etag)
        except Exception as revert_exc:
            self.apply_status = ApplyStatus(
                status=STATUS_REVERT_FAILED,
                etag=None,
                failed_etag=failed_etag,
                error=truncate_error(f"{exc} (revert also failed: {revert_exc})"),
            )
            self.heartbeat.config_apply = self.apply_status
            log.exception("bootstrap_last_known_good_apply_failed")
            return
        self._current_etag = prev_etag
        self._current_structural_etag = self._applied_fingerprint(prev_bundle)
        self._arm_boot_report(prev_bundle)
        self.apply_status = ApplyStatus(
            status=STATUS_REVERTED,
            etag=prev_etag,
            failed_etag=failed_etag,
            error=truncate_error(str(exc)),
        )
        self.heartbeat.config_apply = self.apply_status
        _touch_ready_marker(self.cfg.state_dir)
        log.warning(
            "bootstrap_from_last_known_good",
            failed_etag=failed_etag,
            booted_etag=prev_etag,
        )

    # #2029 — ``_dnssec_bundle`` keeps only what a DNSSEC re-read needs. It
    # used to hold the whole applied bundle until the next structural apply
    # replaced it, so every fetch parsed the new bundle while the old one —
    # blocklist entries and all, ~500 MB for 1.4M RPZ entries — was still
    # alive: the agent briefly held two bundles. The collectors read each
    # zone's name, type and DNSSEC flag; zone records and the blocklists are
    # dropped here, so the previous bundle is freed as soon as the poll that
    # applied it returns.
    @property
    def _dnssec_bundle(self) -> dict[str, Any] | None:
        return self._dnssec_zones

    @_dnssec_bundle.setter
    def _dnssec_bundle(self, bundle: dict[str, Any] | None) -> None:
        if bundle is None:
            self._dnssec_zones: dict[str, Any] | None = None
            return
        self._dnssec_zones = {
            "zones": [
                {k: v for k, v in zone.items() if k != "records"}
                for zone in bundle.get("zones") or []
            ]
        }

    def stop(self) -> None:
        self._stop.set()

    def _arm_boot_report(self, bundle: dict[str, Any]) -> None:
        """Queue the served-serial report for a bundle applied at startup.

        Only for a driver that reads back what it serves
        (``served_zone_serials``): its serials can differ from the bundle's.
        A driver without the hook serves the bundle's serials, which the
        control plane already has."""
        if callable(getattr(self.driver, "served_zone_serials", None)):
            self._boot_report_bundle = bundle
            self._boot_report_attempts = 0

    def _flush_boot_report(self) -> None:
        """Report the serials the startup apply left served (#1968).

        Retried at the top of each poll until a report lands: right after the
        apply the daemon may still be starting (an unreadable API reports
        nothing) and the control plane may not be reachable yet. Bounded, so a
        group whose zones the server never reports (forward zones only) does
        not read the API on every poll forever. Re-sending is harmless: the
        control plane's adoption only moves forward."""
        bundle = self._boot_report_bundle
        if bundle is None:
            return
        self._boot_report_attempts += 1
        done = self._report_zone_state(bundle, skip=self._unconverged_zone_keys())
        if done or self._boot_report_attempts >= BOOT_REPORT_MAX_ATTEMPTS:
            if not done:
                log.warning(
                    "zone_state_boot_report_gave_up",
                    attempts=self._boot_report_attempts,
                )
            self._boot_report_bundle = None

    def _client(self, timeout: float = 60.0) -> httpx.Client:
        verify = self.cfg.httpx_verify()
        # server holds for ~30s, give client a bit more
        return httpx.Client(
            base_url=self.cfg.control_plane_url,
            verify=verify,
            timeout=timeout,
            headers=features.headers(),
        )

    def _on_reregistered(self) -> None:
        """Resend what a fresh process sends at startup, to the new row (#2052).

        Re-registering after a 404 lands on a NEW server row. A container
        restart used to give it the cache apply's zone-state report, a DNSSEC
        state report and the rendered-config push; in process, none of them
        would be sent until the next structural change — the structural etag
        carries no server id, so the new row's bundle re-renders nothing, and
        its zone-state, Config tab and DS state would read empty until then.
        The serials already reported are forgotten: they were the old row's
        (a reset control plane may number its zones lower), and the report
        re-arms them. Nothing here touches the daemon.
        """
        self._current_etag = None
        if self._dnssec_bundle is not None:
            zones = []
            for zone in self._dnssec_bundle.get("zones") or []:
                served = self._reported_serials.get(_zone_key(zone.get("name")))
                serial = zone.get("serial")
                if served is not None and (serial is None or _serial_later(served, int(serial))):
                    # Record ops moved it past the structural apply's serial.
                    zone = {**zone, "serial": served}
                zones.append(zone)
            self._boot_report_bundle = {"zones": zones}
            self._boot_report_attempts = 0
        self._reported_serials = {}
        self._dnssec_reported = None
        self._dnssec_settle_streak = 0
        self._dnssec_refresh_at = 0.0
        try:
            push_rendered_config(self.cfg, self.token_ref[0])
        except Exception:
            log.exception("rendered_config_reregister_push_failed")

    def _maybe_settle(self) -> None:
        """Disarm the #2019 marker once the daemon outlived the settle window.

        Checked from this thread, at the top of each poll (at most a long-poll,
        about 30 s, late). A daemon that died meanwhile has already taken the
        process with it (the supervisor exits on a daemon death), so it never
        gets here to be trusted."""
        if self._guard.settle_due() and self.driver.daemon_running():
            etag = self._guard.settled()
            # A quarantined bundle that was retried (a backoff retry, a boot
            # while its retry was due) and has now stayed up is trusted again:
            # nothing else clears it when its structural etag is unchanged, and
            # ``retry_due`` would then drop If-None-Match on every poll, turning
            # the long-poll into a busy loop against the control plane.
            if etag is not None and self._quarantine.etag == etag:
                self._quarantine.clear()

    def note_daemon_death(self) -> None:
        """The supervisor watched the daemon exit while the agent lives: the
        evidence that lets a bundle be quarantined for it (#2019)."""
        etag = self._guard.daemon_died()
        if etag is not None:
            log.error("dns_daemon_died_during_config_apply_watched", etag=etag)

    def note_orderly_exit(self) -> None:
        """The process is exiting by choice (SIGTERM, a critical thread
        ending): an apply still settling did not kill anything, so it is not a
        death. A 401/404 re-registration does not exit (#2052)."""
        self._guard.disarm()

    def _poll_once(self) -> None:
        gen = reauth_generation()
        if gen != self._reauth_gen:
            self._reauth_gen = gen
            log.info("sync_reregistered_resending_reports")
            self._on_reregistered()
        self._maybe_settle()
        self._flush_boot_report()
        self._boot_hold_max_wait()
        headers = {
            "Authorization": f"Bearer {self.token_ref[0]}",
            AGENT_INSTANCE_HEADER: AGENT_INSTANCE,
        }
        # #882 — a quarantined bundle is parked on a 304 by the etag we sent
        # last time, so the only way to give it another attempt is to stop
        # sending that etag. Dropping If-None-Match makes the server answer
        # 200 with whatever it holds now: the corrected bundle if the operator
        # has saved one, otherwise the same bundle for one more try.
        # Not while the quarantined bundle is the one live and settling (it was
        # just retried): it is being given its attempt, and #2019's settle
        # clears the record above when it survives.
        if self._quarantine.retry_due() and self._guard.armed != self._quarantine.etag:
            log.info(
                "sync_quarantine_retry_due",
                etag=self._quarantine.etag,
                failures=self._quarantine.failures,
            )
            self._current_etag = None
        if self._current_etag:
            headers["If-None-Match"] = self._current_etag
        try:
            if self._boot_hold is not None and not self._current_etag:
                # #2019 — nothing is serving while the cache is held, and with
                # no If-None-Match the control plane answers at once rather
                # than holding the long-poll, so a short timeout decides
                # "unreachable" quickly and the fallback below can serve.
                with self._client(timeout=BOOT_FETCH_TIMEOUT) as c:
                    resp = get_config(c, headers, self.cfg.state_dir)
            else:
                with self._client() as c:
                    resp = get_config(c, headers, self.cfg.state_dir)
        # #2029 — OSError: the body is spooled to the state dir, and a full
        # disk there fails this fetch exactly as an unreachable control plane
        # does (the partial spool is already removed, the cache untouched)
        # rather than ending the sync thread.
        except (httpx.HTTPError, OSError) as e:
            log.warning("sync_http_error", error=str(e))
            self._boot_hold_fallback()
            time.sleep(5.0)
            return

        if resp.status_code == 304:
            return
        if resp.status_code in (401, 404):
            # 401 = token expired/invalid. 404 = the server row was deleted
            # on the control plane (e.g. operator wiped it, or a fresh
            # control-plane install with cached creds). Both recover by
            # the same path: drop cached token and re-bootstrap from PSK.
            log.warning(
                "sync_will_rebootstrap",
                status=resp.status_code,
                reason="token_invalid" if resp.status_code == 401 else "server_missing",
            )
            # #2182 — during a #2019 boot hold nothing is serving, and
            # ``reauthenticate`` can back off for up to 5 min before it
            # registers. The control plane is unusable meanwhile, so the held
            # cache serves under the offline rules (#5), through the same
            # ``_boot_hold_fallback`` the unreachable path takes (it declines a
            # condemned bundle). Nothing was fetched, so ``current.json`` is
            # still the held bundle; the fresh 200 forced below then goes
            # through the normal path, re-rendering only if its structural
            # etag differs from what the fallback put live.
            self._boot_hold_fallback()
            # #2052 — re-register in this thread; do NOT stop it. Stopping
            # made the supervisor exit the container and take the daemon down.
            reauthenticate(self.cfg, self.token_ref, headers["Authorization"][7:])
            # Force a fresh 200. The next poll also sees the generation move
            # and resends the startup reports to the new row
            # (``_on_reregistered``), whichever thread registered.
            self._current_etag = None
            return
        if resp.status_code == 409 and resp.headers.get(DUPLICATE_INSTANCE_HEADER):
            # #2044 — not a re-registration case: a new token would not change
            # which process owns the row. Loud, because this agent now serves
            # a configuration that no longer changes.
            try:
                detail = resp.json().get("detail")
            except ValueError:
                detail = None
            log.error(
                "sync_duplicate_agent_instance",
                instance=AGENT_INSTANCE,
                detail=detail,
                retry_in_seconds=DUPLICATE_INSTANCE_BACKOFF,
            )
            self._boot_hold_fallback()
            # An Event wait, not a sleep: a stop request ends it at once.
            self._stop.wait(DUPLICATE_INSTANCE_BACKOFF)
            return
        if resp.status_code != 200:
            log.warning("sync_unexpected_status", status=resp.status_code)
            self._boot_hold_fallback()
            time.sleep(5.0)
            return

        bundle = resp.json()
        if bundle.get("pending_approval"):
            log.info("sync_pending_approval_waiting")
            time.sleep(10.0)
            return

        etag = bundle.get("etag") or resp.headers.get("ETag")
        if not etag:
            log.warning("sync_bundle_missing_etag")
            return

        # #882 — the quarantine names ONE bundle. If the control plane is no
        # longer serving it, the operator has saved something else and the
        # record is moot: drop it now rather than let ``retry_due`` keep
        # forcing If-None-Match off on every poll for a bundle that no
        # longer exists.
        if self._quarantine.etag is not None and etag != self._quarantine.etag:
            self._quarantine.clear()

        # Atomic-swap cache always (cache is the source of truth for restarts)
        save_config(self.cfg.state_dir, bundle, etag)

        # #170 Wave C1 — fleet-upgrade / reboot / SNMP / NTP trigger
        # writes moved to the supervisor's heartbeat loop. The
        # ConfigBundle's ``fleet_upgrade`` / ``snmp_settings`` /
        # ``ntp_settings`` blocks are still emitted by the control
        # plane (the bundle shape is stable; pre-C1 agents in the
        # field still consume them) but the C1+ DNS service container
        # ignores them — the supervisor's appliance_state module is
        # the only producer of appliance-host trigger files now.

        # Re-render + reload daemon ONLY when structural fingerprint changes.
        # Record CRUD bumps the full etag but not structural_etag, so the
        # daemon stays running and ops are applied incrementally below.
        new_structural = bundle.get("structural_etag")
        if new_structural != self._current_structural_etag:
            # #882 — a bundle that already failed is not retried on every
            # poll. Advancing ``_current_etag`` parks the long-poll on a 304
            # until either the operator saves something different or the
            # quarantine backoff expires, instead of re-rendering the same
            # broken config as fast as the wake tick fires.
            if self._quarantine.blocks(etag):
                log.info("sync_skipping_quarantined_bundle", etag=etag)
                self._return_unapplied_ops(bundle, "the bundle carrying it is quarantined")
                # #2019 — the control plane still serves the bundle the daemon
                # died on: serve the last-known-good meanwhile, if there is one.
                # Before parking on the etag below: the fallback's apply sets
                # ``_current_etag`` to the bundle it put live.
                self._boot_hold_fallback()
                self._current_etag = etag
                return
            if not self._apply_with_revert(bundle, etag):
                if self._boot_hold is not None:
                    # #2019 — nothing is live while the cache is held. A revert
                    # that put the last-known-good back ends the hold; otherwise
                    # the held cache serves, under the same rules as offline.
                    if self._revert_landed:
                        self._end_boot_hold()
                    else:
                        self._boot_hold_fallback(failed_etag=etag)
                self._current_etag = etag
                self._return_unapplied_ops(bundle, "the structural apply failed")
                return
            self._current_structural_etag = self._applied_fingerprint(bundle)
            log.info("structural_reload_applied", structural_etag=new_structural)

            # Post the serials we just rendered so the control plane can
            # show per-server drift. Best-effort — a failed POST doesn't
            # roll back the apply (we already serve the new config). A zone
            # held back (#1403) is not serving the serial it was rendered
            # with, so it is left out and keeps the serial it last reported.
            self._report_zone_state(bundle, skip=self._unconverged_zone_keys())
            # This bundle replaces the one applied at startup, and its report
            # covers the same question.
            self._boot_report_bundle = None

            # DNSSEC (issue #49): BIND9 signs inline from the rendered
            # config, so after a structural reload we read each signed
            # zone's DS + per-key state and report it. PowerDNS reports via
            # the op path below instead (so its driver has no collector).
            self._dnssec_bundle = bundle
            self._refresh_dnssec_state(force=True)

            # Push the on-disk rendered config snapshot so the Server
            # Detail modal's Config tab can show "what's actually live
            # right now" — operators no longer need to SSH in to verify.
            try:
                push_rendered_config(self.cfg, self.token_ref[0])
            except Exception:
                log.exception("rendered_config_push_failed")

        self._current_etag = etag

        # Drain pending record ops via RFC 2136 (no daemon reload)
        dnssec_states: list[dict[str, Any]] = []
        # #1373 — per zone, the serial the ops applied below brought it to,
        # and the zones an op failed for in this pass.
        reached: dict[str, int] = {}
        failed_zones: set[str] = set()
        for op in bundle.get("pending_record_ops", []):
            try:
                result = self.driver.apply_record_op(op)
                self.heartbeat.pending_acks.append(_ack(op, "ok"))
                log.info(
                    "record_op_applied",
                    op_id=op["op_id"],
                    op=op.get("op"),
                    zone=op.get("zone_name"),
                )
                _note_reached(reached, op)
                # A driver that moves a zone to a serial of its own (PowerDNS
                # never goes backwards from the one it serves, #1968) reports
                # THAT serial, not the op's target.
                actual_hook = getattr(self.driver, "reached_serial", None)
                if callable(actual_hook):
                    actual = actual_hook(str(op.get("zone_name") or ""))
                    if isinstance(actual, int) and not isinstance(actual, bool):
                        reached[_zone_key(op.get("zone_name"))] = actual
                # PowerDNS DNSSEC ops return the DS rrset so we can ship
                # it back to the control plane in one batched POST below.
                if isinstance(result, dict) and "dnssec_state" in result:
                    dnssec_states.append(result["dnssec_state"])
            except Exception as e:
                log.exception("op_apply_failed", op_id=op.get("op_id"))
                self.heartbeat.pending_acks.append(_ack(op, "error", str(e)))
                self.heartbeat.failed_ops_count += 1
                failed_zones.add(_zone_key(op.get("zone_name")))
        if dnssec_states:
            self._report_dnssec_state(dnssec_states)
            # #1934 — a manual rollover (``rndc dnssec -rollover``) makes BIND
            # generate the successor key AFTER the op returns, so the state
            # just reported is the pre-rollover set. Look again soon.
            self._dnssec_settle_streak = 0
            self._dnssec_recheck_soon()
        # A zone the structural apply left partly refused (#2060) is not
        # reported converged by an op that landed beside the refusal either.
        unconverged = self._unconverged_zone_keys()
        self._report_reached_serials(
            {
                zone: serial
                for zone, serial in reached.items()
                if zone not in failed_zones and zone.lower() not in unconverged
            }
        )

        # #882 — we got here with nothing quarantined and nothing to
        # re-render, so whatever the control plane is serving is what we are
        # running. Clear a stale ``reverted`` verdict: the operator's fix has
        # landed and leaving the chip up would report a divergence that no
        # longer exists. Not while zones are held back (#1403) or refused
        # (#1280): that verdict was set by this very apply, and is true until
        # they load.
        if (
            self._quarantine.etag is None
            and not self.apply_status.healthy
            and not self.driver.held_back
            and not self._zones_refused
        ):
            self.apply_status = ApplyStatus(status=STATUS_OK, etag=etag)
            self.heartbeat.config_apply = self.apply_status
            log.info("config_apply_recovered", etag=etag)

        # #882 — a poll that got all the way here had no apply failure, so
        # whatever is cached as ``current`` is known to work and becomes the
        # bundle we fall back TO.
        #
        # This is NOT redundant with the commit inside ``_apply_with_revert``.
        # A structural etag that is unchanged skips the apply entirely — which
        # is exactly what happens when an operator UNDOES the change that
        # broke the config: the rendered result is byte-identical to what is
        # already running, so nothing re-renders and the commit inside the
        # apply path never fires. Without this, ``previous`` would keep
        # pointing at an older etag indefinitely.
        commit_config(self.cfg.state_dir, etag)
        # #2019 — a bundle from the control plane is live: the startup hold,
        # if there was one, is over.
        self._end_boot_hold()

        # #296 A2 — stamp readiness marker AFTER the bundle was fetched,
        # persisted to the hostPath cache, and the driver-apply path
        # completed (either structural reload, record-op dispatch, or
        # both — or neither if the bundle had no work, which is still a
        # confirmed-in-sync state). A failed apply returns early above
        # so we never reach this point on error.
        _touch_ready_marker(self.cfg.state_dir)

    def _apply_with_revert(self, bundle: dict[str, Any], etag: str) -> bool:
        """Apply ``bundle``; on failure fall back to the last-known-good (#882).

        Returns True when ``bundle`` is live, False when it was rejected —
        in which case the daemon is either untouched (the failure happened
        while rendering or validating into the staging tree) or has been
        put back onto the previous bundle.

        The phase distinction is what keeps the revert honest. BIND renders
        and validates into ``rendered.new``, so a ``named-checkconf`` failure
        never reached ``named``: re-rendering the previous bundle there would
        bounce a healthy daemon to reach a state it is already in. Only a
        failure at swap/reload — where the live directory has been replaced —
        needs the previous config put back on disk.
        """
        try:
            self._guarded_apply(bundle, etag)
        except ConfigApplyError as e:
            self._handle_apply_failure(etag, e.phase, e.cause, e.daemon_disturbed)
            return False
        except Exception as e:
            # A driver that raised outside the phased wrapper. Unknown phase,
            # so assume the worst and treat the daemon as disturbed.
            self._handle_apply_failure(etag, None, e, True)
            return False

        self._quarantine.clear()
        # Committed even when some zones were refused: the bundle IS what is
        # being served, as far as the daemon allows, and the last-known-good
        # must not lag behind it.
        commit_config(self.cfg.state_dir, etag)
        self._report_applied(etag)
        return True

    def _report_applied(self, etag: str | None) -> None:
        """The verdict on a bundle the daemon took: whole, or partially."""
        if self._report_partial_apply(etag):
            return
        self.apply_status = ApplyStatus(status=STATUS_OK, etag=etag)
        self.heartbeat.config_apply = self.apply_status
        if self.heartbeat.daemon_status.get("status") == "degraded" and not is_oom_status(
            self.heartbeat.daemon_status
        ):
            # Clear a degraded verdict this loop set on a previous cycle;
            # leaving it would make a recovered server look broken forever.
            # An OOM-kill verdict (#1725) is not this loop's to clear: an apply
            # succeeding says nothing about whether the daemon then survives
            # the config, so the supervisor clears it once the daemon has
            # stayed up (``oom_watch.STABLE_SECONDS``).
            self.heartbeat.daemon_status = {"status": "ok"}

    def _applied_fingerprint(self, bundle: dict[str, Any]) -> str | None:
        """The structural etag to record for a bundle the driver just applied.

        ``None`` while the apply held zones back (#1403): the daemon is not
        running that bundle whole, so the next bundle must re-render even
        when its structural etag is the same one. On a group without views,
        deleting the record that made a zone unloadable is a record-only
        change that moves no structural etag, and would otherwise leave the
        zone held, and reported held, until some unrelated structural edit.
        """
        if self.driver.held_back:
            return None
        return bundle.get("structural_etag")

    def _report_partial_apply(self, etag: str | None) -> bool:
        """Report an apply that landed with some zones unserved. True if so.

        Drivers get there two ways. PowerDNS takes zones one at a time, and
        Technitium records one at a time, so either can accept most of a
        bundle and refuse a few zones' data or individual records (see
        ``DriverBase.refused_zones``, #1280, #1608). BIND9's zone check holds back a
        zone ``named-checkzone`` refuses and applies the rest
        (``DriverBase.held_back``, #1403). Either way that is neither ``ok`` —
        those zones are not served as saved — nor a reason to revert:
        re-applying the last-known-good cannot make the data load, and it
        would undo the zones that did.

        #882's vocabulary has no "partial" status, and the control plane
        ignores one it does not know, so this reports ``reverted``: the
        status whose meaning — "the daemon is healthy and serving, but not
        everything the operator saved" — is the honest one here, and whose
        severity (warning) and ``agent_config_rejected`` alert fit. Unlike a
        real revert, ``etag`` is the NEW bundle (it is live) and so is
        ``failed_etag``; the error starts with :data:`PARTIAL_APPLY_PREFIX`,
        which is how the UI and the alert tell it from a rollback, and names
        each zone with the checker's or the daemon's own reason.
        """
        held = tuple(self.driver.held_back)
        fn = getattr(self.driver, "refused_zones", None)
        refused = [str(z) for z in (fn() if callable(fn) else [])]
        if not held and not refused:
            self._zones_refused = False
            return False
        error = _partial_apply_error(held, refused)
        self._zones_refused = True
        self.apply_status = ApplyStatus(
            status=STATUS_REVERTED,
            etag=etag,
            failed_etag=etag,
            # A held zone was stopped at validation; a refused one by the
            # daemon as it loaded the bundle.
            phase=PHASE_RELOAD if refused else PHASE_VALIDATE,
            error=error,
        )
        self.heartbeat.config_apply = self.apply_status
        # The ``config_apply_`` prefix is load-bearing (#1067): the control
        # plane reads it as an apply verdict, not as a daemon that is down.
        self.heartbeat.daemon_status = {
            **self.heartbeat.daemon_status,
            "status": "degraded",
            "reason": f"config_apply_{STATUS_REVERTED}: {error}",
        }
        log.warning(
            "sync_apply_partial",
            etag=etag,
            held_back=[f"{h.zone} ({h.view})" if h.view else h.zone for h in held][:5],
            refused=refused[:5],
        )
        return True

    def _return_unapplied_ops(self, bundle: dict[str, Any], reason: str) -> None:
        """NACK every record op in ``bundle``: none of them was applied.

        The control plane marked them ``in_flight`` when it shipped this
        bundle, and an op that is never acked sits there until the 5-minute
        unacknowledged reset — and a delete that sits there is a name still
        answering. An error ack puts each op straight back on the retry path
        (``apply_acks`` → ``fail_attempts``), so it is re-sent once the apply
        works again. It costs one of the op's retry attempts, which is the
        truth: this attempt did not apply it.
        """
        ops = [op for op in bundle.get("pending_record_ops") or [] if op.get("op_id")]
        for op in ops:
            self.heartbeat.pending_acks.append(_ack(op, "error", f"not applied: {reason}"))
        if ops:
            log.warning("record_ops_returned_unapplied", count=len(ops), reason=reason)

    def _handle_apply_failure(
        self,
        etag: str,
        phase: str | None,
        cause: BaseException,
        daemon_disturbed: bool,
    ) -> None:
        if self.oom_watch is not None and self.oom_watch.fired(consume=True):
            # #1725 — the error the daemon left (an rndc refusal, a dead
            # control channel) does not say why it died. Say it.
            cause = RuntimeError(
                f"{cause} (the container's OOM killer fired: the daemon ran out of "
                "memory under its limit; large RPZ blocklists are the usual cause, "
                "see docs/features/DNS.md 8.0)"
            )
        log.error(
            "sync_apply_failed",
            etag=etag,
            phase=phase,
            error=str(cause),
            daemon_disturbed=daemon_disturbed,
        )
        self._quarantine.record(etag, truncate_error(f"{phase or 'apply'}: {cause}"))
        self._revert_landed = False
        # The failure verdict below supersedes any partial-refusal one.
        self._zones_refused = False

        prev_bundle, prev_etag = load_previous_config(self.cfg.state_dir)
        if prev_bundle is not None and not self._previous_usable(prev_etag, etag):
            # #2019 — the last-known-good is the bundle the daemon died on (it
            # was committed the moment its apply returned). Reverting to it
            # would put the daemon back on the config that kills it.
            log.warning("sync_previous_unusable_daemon_died_on_it", previous_etag=prev_etag)
            prev_bundle = None
        if prev_bundle is None:
            if daemon_disturbed:
                # The live config directory was already replaced and we have
                # nothing to put back, so we no longer know what ``named`` is
                # running. Forget the structural fingerprint: leaving it would
                # let a LATER bundle whose structural etag happens to match it
                # (the operator undoing the change that broke this one) skip
                # the apply entirely, and the agent would then report ``ok``
                # for a daemon still sitting on the half-applied config.
                self._current_structural_etag = None
            status = ApplyStatus(
                status=STATUS_NO_PREVIOUS,
                etag=None,
                failed_etag=etag,
                phase=phase,
                error=truncate_error(str(cause)),
            )
            log.error("sync_no_last_known_good", failed_etag=etag)
        elif not daemon_disturbed:
            # The staging tree failed; the daemon is still serving the config
            # it was already serving, which IS the previous bundle. Nothing to
            # re-render — record what is live and leave the daemon alone.
            status = ApplyStatus(
                status=STATUS_REVERTED,
                etag=prev_etag,
                failed_etag=etag,
                phase=phase,
                error=truncate_error(str(cause)),
            )
            log.warning(
                "sync_reverted_without_reload",
                failed_etag=etag,
                live_etag=prev_etag,
                phase=phase,
            )
        else:
            try:
                self._guarded_apply(prev_bundle, prev_etag)
            except Exception as revert_exc:
                # Same reasoning as the no-previous branch above: the revert
                # did not land either, so the running config is unknown and
                # the structural fingerprint must not be trusted to skip the
                # next apply.
                self._current_structural_etag = None
                status = ApplyStatus(
                    status=STATUS_REVERT_FAILED,
                    etag=None,
                    failed_etag=etag,
                    phase=phase,
                    error=truncate_error(f"{cause} (revert also failed: {revert_exc})"),
                )
                log.exception("sync_revert_failed", failed_etag=etag)
            else:
                self._revert_landed = True
                self._current_structural_etag = self._applied_fingerprint(prev_bundle)
                status = ApplyStatus(
                    status=STATUS_REVERTED,
                    etag=prev_etag,
                    failed_etag=etag,
                    phase=phase,
                    error=truncate_error(str(cause)),
                )
                log.warning(
                    "sync_reverted_to_last_known_good",
                    failed_etag=etag,
                    live_etag=prev_etag,
                )

        self.apply_status = status
        self.heartbeat.config_apply = status
        self.heartbeat.daemon_status = {
            **self.heartbeat.daemon_status,
            "status": "degraded",
            "reason": f"config_apply_{status.status}: {status.error}",
        }

    def _unconverged_zone_keys(self) -> set[str]:
        """Zones (lowercase, no trailing dot) the live apply did not converge,
        whose serial is therefore not reported as served (#1403, #2060).

        A zone held back serves an older serial than it was rendered with. A
        zone whose data the daemon refused in part may serve the NEW serial —
        PowerDNS applies the rest of such a zone piecemeal, SOA last — with
        records missing, and reporting that serial would make per-server sync
        status read "in sync" beside the very refusal the apply status names.
        Left out, the zone keeps the serial it last reported and reads behind
        until an apply serves it whole.
        """
        keys = {h.zone.rstrip(".").lower() for h in self.driver.held_back}
        hook = getattr(self.driver, "unconverged_zones", None)
        if callable(hook):
            keys |= {str(z).rstrip(".").lower() for z in hook()}
        return keys

    def _report_zone_state(self, bundle: dict[str, Any], skip: set[str] | None = None) -> bool:
        """POST ``{zones: [{zone_name, serial}, ...]}`` after a successful apply.

        Best-effort. A dead control plane or transient 5xx never blocks
        the daemon — the next structural reload will try again. ``skip``:
        zone names (lowercase, no trailing dot) the apply held back (#1403).
        Returns whether the report landed (or there was nothing to report);
        False when the post failed or the driver could read nothing back.
        """
        entries: list[dict[str, Any]] = []
        # A driver that can read back what it actually serves (PowerDNS,
        # via its API) reports THOSE serials: the bundle's serial made
        # per-server sync status read "in sync" whatever the server
        # served, and reported zones the agent never served at all
        # (forward zones on PowerDNS, #1521 / #1522). Drivers without
        # the hook keep the bundle-serial behaviour.
        served: dict[str, int] | None = None
        hook = getattr(self.driver, "served_zone_serials", None)
        if callable(hook):
            try:
                served = hook(bundle)
            except Exception as e:  # noqa: BLE001 — reporting is best-effort
                log.warning("served_zone_serials_hook_failed", error=str(e))
                served = {}
        if served is not None and not served and bundle.get("zones"):
            # An unreadable API (the daemon still starting) reads back as an
            # empty map: nothing was reported, so it is not done.
            return False
        for z in bundle.get("zones") or []:
            name = z.get("name")
            serial = z.get("serial")
            if not name or serial is None:
                continue
            if skip and str(name).rstrip(".").lower() in skip:
                continue
            if served is not None:
                actual = served.get(str(name).rstrip(".").lower())
                if actual is None:
                    continue
                serial = actual
            entries.append({"zone_name": str(name), "serial": int(serial)})
        if not entries:
            return True
        return self._post_zone_state(entries)

    def _report_reached_serials(self, reached: dict[str, int]) -> None:
        """POST the serial each zone reached through the record ops this pass
        applied (#1373).

        In a group without views a record-only change no longer re-renders the
        zone (its serial is not part of the structural fingerprint), so the
        post-reload report above never sees it. The serial is reported here
        instead, once the op that carries it (``target_serial``) has applied.
        A zone moves only forward of what was last reported for it, so the late
        retry of an older op cannot report it backwards.
        """
        entries = [
            {"zone_name": zone, "serial": serial}
            for zone, serial in sorted(reached.items())
            if zone not in self._reported_serials
            or _serial_later(serial, self._reported_serials[zone])
        ]
        if entries:
            self._post_zone_state(entries)

    def _post_zone_state(self, entries: list[dict[str, Any]]) -> bool:
        headers = {"Authorization": f"Bearer {self.token_ref[0]}"}
        try:
            with self._client() as c:
                resp = c.post(
                    "/api/v1/dns/agents/zone-state",
                    headers=headers,
                    json={"zones": entries},
                )
            if resp.status_code != 200:
                log.warning(
                    "zone_state_report_non200",
                    status=resp.status_code,
                    body=resp.text[:200],
                )
                return False
        except httpx.HTTPError as e:
            log.warning("zone_state_report_failed", error=str(e))
            return False
        for entry in entries:
            self._reported_serials[_zone_key(entry["zone_name"])] = int(entry["serial"])
        return True

    def _refresh_dnssec_state(self, force: bool = False) -> None:
        """Re-read the driver's DNSSEC state and POST it when it changed.

        ``force`` posts regardless (after a structural reload, as before
        #1854); the periodic call from ``run`` posts only a change, so an
        unchanged signed zone costs one ``rndc dnssec -status`` per zone
        every ``DNSSEC_REFRESH_SECONDS`` and no control-plane write.
        """
        # Re-arm for the slow cadence first; every path below that has not
        # reached a settled, accepted read pulls it back to the short one.
        self._dnssec_refresh_at = time.monotonic() + DNSSEC_REFRESH_SECONDS
        collect = getattr(self.driver, "collect_dnssec_state", None)
        if collect is None or self._dnssec_bundle is None:
            return
        try:
            states = collect(self._dnssec_bundle)
        except Exception:
            log.exception("dnssec_collect_failed")
            self._dnssec_recheck_soon()
            return
        # The driver could not read (or has not yet got) some zone's keys:
        # named still loading, or the zone not keyed yet. Retry soon.
        settling = bool(getattr(self.driver, "dnssec_incomplete", False))
        if not states or (not force and states == self._dnssec_reported):
            if settling:
                self._dnssec_recheck_soon()
            else:
                # Complete and unchanged: the key set has settled.
                self._dnssec_settle_streak = 0
            return
        if self._report_dnssec_state(states):
            self._dnssec_reported = states
            # The keys just moved (or this is the first look after a reload):
            # a new settling episode, so the next look is the short one again.
            self._dnssec_settle_streak = 0
        # Reported (BIND may still be mid-change) or refused (retry, backing
        # off while it keeps being refused): look again before a quiet-zone
        # interval.
        self._dnssec_recheck_soon()

    def _dnssec_recheck_soon(self) -> None:
        """Arm the next DNSSEC read on the settling cadence.

        ``DNSSEC_SETTLE_SECONDS`` the first time, doubling on each further
        unsettled read up to ``DNSSEC_REFRESH_SECONDS``. A key change settles
        in one or two short reads; a zone that stays unreadable (held back by
        the zone check until the next structural apply, a control plane that
        keeps refusing) must not cost one ``rndc`` per signed zone every 20 s
        for as long as it lasts.
        """
        delay = min(DNSSEC_SETTLE_SECONDS * (2**self._dnssec_settle_streak), DNSSEC_REFRESH_SECONDS)
        self._dnssec_settle_streak = min(self._dnssec_settle_streak + 1, 8)
        self._dnssec_refresh_at = time.monotonic() + delay

    def _report_dnssec_state(self, states: list[dict[str, Any]]) -> bool:
        """POST the DS rrset(s) the driver just produced after a sign /
        unsign op (issue #127, Phase 3c.fe).

        Best-effort. A failed POST never blocks the apply — operators
        re-trigger sign in the UI to retry.
        """
        if not states:
            return False
        headers = {"Authorization": f"Bearer {self.token_ref[0]}"}
        try:
            with self._client() as c:
                resp = c.post(
                    "/api/v1/dns/agents/dnssec-state",
                    headers=headers,
                    json={"zones": states},
                )
            if resp.status_code != 200:
                log.warning(
                    "dnssec_state_report_non200",
                    status=resp.status_code,
                    body=resp.text[:200],
                )
                return False
        except httpx.HTTPError as e:
            log.warning("dnssec_state_report_failed", error=str(e))
            return False
        return True

    def run(self) -> None:
        while not self._stop.is_set():
            self._poll_once()
            if time.monotonic() >= self._dnssec_refresh_at:
                self._refresh_dnssec_state()
