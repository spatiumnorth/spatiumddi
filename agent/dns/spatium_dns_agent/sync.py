"""Config long-poll loop + op execution.

Hits GET /dns/agents/config with If-None-Match; on 200 applies the new
bundle (atomic disk swap, daemon-specific reload) and dispatches any
pending_record_ops through the active driver. On 304 it just loops back.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

import httpx
import structlog

from . import features
from .admin_pusher import push_rendered_config
from .cache import commit_config, load_config, load_previous_config, save_config
from .config import AgentConfig
from .config_apply import (
    PHASE_RELOAD,
    STATUS_NO_PREVIOUS,
    STATUS_OK,
    STATUS_REVERT_FAILED,
    STATUS_REVERTED,
    ApplyStatus,
    ConfigApplyError,
    Quarantine,
    truncate_error,
)
from .drivers.base import DriverBase

log = structlog.get_logger(__name__)


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

class SyncLoop:
    def __init__(
        self, cfg: AgentConfig, token_ref: list[str], driver: DriverBase, heartbeat: Any
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
        # #882 — last-known-good revert. ``quarantine`` remembers an etag
        # whose apply failed so we stop re-applying it every poll;
        # ``apply_status`` is what the heartbeat reports upward.
        self._quarantine = Quarantine(self.cfg.state_dir)
        self.apply_status = ApplyStatus()
        # True while the live bundle applied with zones the daemon refused
        # (see ``_report_refused_zones``). Those zones stay refused until the
        # next structural apply, so a record-op-only poll must not read the
        # degraded verdict as stale and clear it.
        self._zones_refused = False
        self.heartbeat.config_apply = self.apply_status

        # Preload cached bundle (offline-operation guarantee)
        bundle, etag = load_config(self.cfg.state_dir)
        # #882 — a restart must not re-break the daemon with the same bundle
        # that failed before it. ``current.json`` is what the control plane
        # last SENT, which is not necessarily what worked; if that bundle is
        # quarantined, boot from the last-known-good instead.
        booting_from_previous = False
        if bundle is not None and self._quarantine.blocks(etag):
            prev_bundle, prev_etag = load_previous_config(self.cfg.state_dir)
            if prev_bundle is not None:
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
            self._current_etag = etag
            try:
                self.driver.apply_config(bundle)
                self._current_structural_etag = bundle.get("structural_etag")
                if not booting_from_previous:
                    # Zones the daemon refused are reported, not reverted —
                    # see ``_report_refused_zones`` — and the bundle is still
                    # committed: everything else in it is being served.
                    self._report_refused_zones(etag)
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
                    self._bootstrap_fallback(etag, e)

    def _bootstrap_fallback(self, failed_etag: str | None, exc: BaseException) -> None:
        """Boot from the last-known-good bundle after ``current`` failed (#882).

        Only reached at startup, where there is no running daemon to protect
        — so unlike the steady-state revert this is about getting the server
        answering at all, on the newest config that is known to work.
        """
        prev_bundle, prev_etag = load_previous_config(self.cfg.state_dir)
        if prev_bundle is None or prev_etag == failed_etag:
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
            self.driver.apply_config(prev_bundle)
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
        self._current_structural_etag = prev_bundle.get("structural_etag")
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

    def stop(self) -> None:
        self._stop.set()

    def _client(self) -> httpx.Client:
        verify = self.cfg.httpx_verify()
        # server holds for ~30s, give client a bit more
        return httpx.Client(
            base_url=self.cfg.control_plane_url,
            verify=verify,
            timeout=60.0,
            headers=features.headers(),
        )

    def _poll_once(self) -> None:
        headers = {"Authorization": f"Bearer {self.token_ref[0]}"}
        # #882 — a quarantined bundle is parked on a 304 by the etag we sent
        # last time, so the only way to give it another attempt is to stop
        # sending that etag. Dropping If-None-Match makes the server answer
        # 200 with whatever it holds now: the corrected bundle if the operator
        # has saved one, otherwise the same bundle for one more try.
        if self._quarantine.retry_due():
            log.info(
                "sync_quarantine_retry_due",
                etag=self._quarantine.etag,
                failures=self._quarantine.failures,
            )
            self._current_etag = None
        if self._current_etag:
            headers["If-None-Match"] = self._current_etag
        try:
            with self._client() as c:
                resp = c.get("/api/v1/dns/agents/config", headers=headers)
        except httpx.HTTPError as e:
            log.warning("sync_http_error", error=str(e))
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
            from .cache import save_token

            save_token(self.cfg.state_dir, "")
            self._stop.set()
            return
        if resp.status_code != 200:
            log.warning("sync_unexpected_status", status=resp.status_code)
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
                self._current_etag = etag
                self._return_unapplied_ops(bundle, "the bundle carrying it is quarantined")
                return
            if not self._apply_with_revert(bundle, etag):
                self._current_etag = etag
                self._return_unapplied_ops(bundle, "the structural apply failed")
                return
            self._current_structural_etag = new_structural
            log.info("structural_reload_applied", structural_etag=new_structural)

            # Post the serials we just rendered so the control plane can
            # show per-server drift. Best-effort — a failed POST doesn't
            # roll back the apply (we already serve the new config).
            self._report_zone_state(bundle)

            # DNSSEC (issue #49): BIND9 signs inline from the rendered
            # config, so after a structural reload we read each signed
            # zone's DS + per-key state and report it. PowerDNS reports via
            # the op path below instead (so its driver has no collector).
            collect = getattr(self.driver, "collect_dnssec_state", None)
            if collect is not None:
                try:
                    bind_states = collect(bundle)
                    if bind_states:
                        self._report_dnssec_state(bind_states)
                except Exception:
                    log.exception("dnssec_collect_failed")

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
        for op in bundle.get("pending_record_ops", []):
            try:
                result = self.driver.apply_record_op(op)
                self.heartbeat.pending_acks.append(
                    _ack(op, "ok")
                )
                log.info(
                    "record_op_applied",
                    op_id=op["op_id"],
                    op=op.get("op"),
                    zone=op.get("zone_name"),
                )
                # PowerDNS DNSSEC ops return the DS rrset so we can ship
                # it back to the control plane in one batched POST below.
                if isinstance(result, dict) and "dnssec_state" in result:
                    dnssec_states.append(result["dnssec_state"])
            except Exception as e:
                log.exception("op_apply_failed", op_id=op.get("op_id"))
                self.heartbeat.pending_acks.append(
                    _ack(op, "error", str(e))
                )
                self.heartbeat.failed_ops_count += 1
        if dnssec_states:
            self._report_dnssec_state(dnssec_states)

        # #882 — we got here with nothing quarantined and nothing to
        # re-render, so whatever the control plane is serving is what we are
        # running. Clear a stale ``reverted`` verdict: the operator's fix has
        # landed and leaving the chip up would report a divergence that no
        # longer exists.
        if (
            self._quarantine.etag is None
            and not self.apply_status.healthy
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
            self.driver.apply_config(bundle)
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
        if self._report_refused_zones(etag):
            return True
        self.apply_status = ApplyStatus(status=STATUS_OK, etag=etag)
        self.heartbeat.config_apply = self.apply_status
        if self.heartbeat.daemon_status.get("status") == "degraded":
            # Clear a degraded verdict this loop set on a previous cycle;
            # leaving it would make a recovered server look broken forever.
            self.heartbeat.daemon_status = {"status": "ok"}
        return True

    def _report_refused_zones(self, etag: str | None) -> bool:
        """Report an apply that landed with some zones refused. True if so.

        PowerDNS takes zones one at a time, so it can accept most of a bundle
        and refuse a few zones' data (see ``DriverBase.refused_zones``). That
        is neither ``ok`` — those zones are not served — nor a reason to
        revert: re-applying the last-known-good cannot make the daemon accept
        data it refused, and it would undo the zones it did accept.

        #882's vocabulary has no "partial" status, and the control plane
        ignores one it does not know, so this reports ``reverted``: the
        status whose meaning — "the daemon is healthy and serving, but not
        everything the operator saved" — is the honest one here, and whose
        severity (warning) and ``agent_config_rejected`` alert fit. Unlike a
        real revert, ``etag`` is the NEW bundle (it is live) and so is
        ``failed_etag``; the error names each refused zone with the daemon's
        own reason.
        """
        fn = getattr(self.driver, "refused_zones", None)
        refused = [str(z) for z in (fn() if callable(fn) else [])]
        if not refused:
            self._zones_refused = False
            return False
        error = truncate_error(
            f"the daemon refused {len(refused)} zone(s); every other zone is served: "
            + "; ".join(refused)
        )
        self._zones_refused = True
        self.apply_status = ApplyStatus(
            status=STATUS_REVERTED,
            etag=etag,
            failed_etag=etag,
            phase=PHASE_RELOAD,
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
        log.warning("sync_apply_zones_refused", etag=etag, count=len(refused), zones=refused[:5])
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
        log.error(
            "sync_apply_failed",
            etag=etag,
            phase=phase,
            error=str(cause),
            daemon_disturbed=daemon_disturbed,
        )
        self._quarantine.record(etag, truncate_error(f"{phase or 'apply'}: {cause}"))
        # The failure verdict below supersedes any partial-refusal one.
        self._zones_refused = False

        prev_bundle, prev_etag = load_previous_config(self.cfg.state_dir)
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
                self.driver.apply_config(prev_bundle)
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
                self._current_structural_etag = prev_bundle.get("structural_etag")
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

    def _report_zone_state(self, bundle: dict[str, Any]) -> None:
        """POST ``{zones: [{zone_name, serial}, ...]}`` after a successful apply.

        Best-effort. A dead control plane or transient 5xx never blocks
        the daemon — the next structural reload will try again.
        """
        entries: list[dict[str, Any]] = []
        for z in bundle.get("zones") or []:
            name = z.get("name")
            serial = z.get("serial")
            if not name or serial is None:
                continue
            entries.append({"zone_name": str(name), "serial": int(serial)})
        if not entries:
            return
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
        except httpx.HTTPError as e:
            log.warning("zone_state_report_failed", error=str(e))

    def _report_dnssec_state(self, states: list[dict[str, Any]]) -> None:
        """POST the DS rrset(s) the driver just produced after a sign /
        unsign op (issue #127, Phase 3c.fe).

        Best-effort. A failed POST never blocks the apply — operators
        re-trigger sign in the UI to retry.
        """
        if not states:
            return
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
        except httpx.HTTPError as e:
            log.warning("dnssec_state_report_failed", error=str(e))

    def run(self) -> None:
        while not self._stop.is_set():
            self._poll_once()
