"""Config long-poll loop for the DHCP agent.

Hits ``GET /api/v1/dhcp/agents/config`` with ``If-None-Match``. On 200 the
agent:

1. atomically writes the new bundle to the on-disk cache,
2. renders the bundle into a combined Kea ``{"Dhcp4": ..., "Dhcp6": ...}``
   document,
3. SPLITS it and atomically writes ``{"Dhcp4": ...}`` to ``KEA_CONFIG_PATH``
   and ``{"Dhcp6": ...}`` to ``KEA_CONFIG_PATH_V6`` — they MUST be separate
   files because ``kea-dhcp4 -t`` rejects a stray ``Dhcp6`` key (and v.v.),
4. asks BOTH kea-dhcp4 and kea-dhcp6 to reload via their control sockets.

On 304 the loop just continues. The control plane holds the connection open
for ~LONGPOLL_TIMEOUT seconds, so this is cheap.

Non-negotiable #5: after three consecutive failed polls the agent switches
to "offline mode" — logs a single warning, backs off to one retry per 60s,
and keeps serving from cache.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import structlog

from .cache import (
    commit_config,
    load_config,
    load_previous_config,
    save_config,
    save_rendered_kea,
    save_token,
)
from .config import AgentConfig
from .config_apply import (
    PHASE_RELOAD,
    PHASE_RENDER,
    STATUS_NO_PREVIOUS,
    STATUS_OK,
    STATUS_REVERT_FAILED,
    STATUS_REVERTED,
    ApplyStatus,
    ConfigApplyError,
    Quarantine,
    truncate_error,
)
from .kea_ctrl import KeaCtrlError, config_reload, config_test
from .radvd_apply import apply_radvd
from .render_kea import render as render_kea
from .v6_unicast import global_ipv6_addresses

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


def clear_ready_marker(state_dir: Path) -> None:
    """Remove ``<state_dir>/.ready`` so the readinessProbe starts failing (#1043).

    The marker means "I have synced at least once", and nothing ever took it
    back. When the agent's heartbeat thread died the container kept the marker,
    the probe (``test -f .ready && grep -q ':0043 ' /proc/net/udp``) kept
    passing on Kea's still-listening socket, and the pod stayed 1/1 Ready with
    no agent in it — every DHCP change accepted, rendered, and never delivered.

    The container exit is the primary cure; this is the half that makes a dead
    agent VISIBLE to the platform even if the process somehow outlives its
    threads. Best-effort for the same reason the touch is: a marker we cannot
    remove must not stop the shutdown path that is already running.
    """
    marker = state_dir / ".ready"
    try:
        marker.unlink()
    except FileNotFoundError:
        # Already gone — the agent died before its first successful sync, so
        # readiness was never claimed. Nothing to take back.
        pass
    except OSError:
        log.exception("ready_marker_clear_failed", path=str(marker))


_FAILURE_THRESHOLD = 3  # DHCP.md §6: offline after 3 consecutive failures
_OFFLINE_RETRY_SECONDS = 60.0
# Bootstrap reload races Kea's own startup — entrypoint launches kea-dhcp4
# in the background just before the agent, so the control socket may not
# exist for up to a second or two. Retry reload until the socket answers
# or we give up. After ``_BOOTSTRAP_RELOAD_TIMEOUT`` we let Kea keep
# running on its pre-boot config and rely on the next real config change
# (or an operator restart) to pick up the new render.
_BOOTSTRAP_RELOAD_TIMEOUT = 15.0
_BOOTSTRAP_RELOAD_INTERVAL = 1.0

# Outcomes of one daemon's reload attempt. Only REJECTED is a verdict about
# the config itself; UNREACHABLE means we never got to ask (#882).
RELOAD_OK = "ok"
RELOAD_REJECTED = "rejected"
RELOAD_UNREACHABLE = "unreachable"


class SyncLoop:
    def __init__(
        self,
        cfg: AgentConfig,
        token_ref: list[str],
        heartbeat: Any,
        ha_poller: Any | None = None,
        peer_watcher: Any | None = None,
    ):
        self.cfg = cfg
        self.token_ref = token_ref
        self.heartbeat = heartbeat
        self.ha_poller = ha_poller
        self.peer_watcher = peer_watcher
        self._stop = threading.Event()
        self._current_etag: str | None = None
        self._consecutive_failures = 0
        self._offline = False
        # #882 — last-known-good revert. ``quarantine`` remembers an etag
        # whose apply Kea refused so we stop re-applying it every poll;
        # ``apply_status`` is what the heartbeat reports upward.
        self._quarantine = Quarantine(self.cfg.state_dir)
        self.apply_status = ApplyStatus()
        self.heartbeat.config_apply = self.apply_status
        # Set by _reload_socket so the raised ConfigApplyError can carry
        # Kea's own words rather than a generic "rejected".
        self._last_reload_error: str | None = None
        # #882 — did a Kea daemon actually ACCEPT the config we just wrote?
        # An unreachable control socket is not a rejection (Kea may be
        # restarting) so it must not revert — but it is not an acceptance
        # either, and only an accepted bundle may be promoted to
        # ``previous.json``. Without this the "last-known-GOOD" fallback can
        # end up holding a document no daemon has ever loaded.
        self._reload_confirmed = False
        # #1140 — the host global IPv6 addresses the last render gave
        # kea-dhcp6 as unicast sockets, or None when the render served no v6
        # scope (then the addresses don't matter). ``run`` re-renders when
        # the live set drifts from this: an entry for an address the host
        # no longer holds makes kea-dhcp6 refuse its whole config the next
        # time it loads it.
        self._v6_unicast_applied: tuple[tuple[str, str], ...] | None = None

        # Preload cached bundle — offline-operation guarantee.
        #
        # Kea was just launched by the entrypoint with the Dockerfile-baked
        # config and will not pick up the rendered bundle unless we issue a
        # config-reload. Retry the reload for a few seconds to cover Kea's
        # own startup (socket may not exist yet). Without this retry, if
        # the control plane later returns 304 on /config, Kea would stay
        # on its baked config forever — in particular losing HA state on
        # any agent restart.
        bundle, etag = load_config(self.cfg.state_dir)
        # #882 — a restart must not re-break Kea with the bundle that broke
        # it. ``current.json`` is what the control plane last SENT, which is
        # not necessarily what loaded; if that bundle is quarantined, boot
        # from the last-known-good instead.
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
                self._set_status(
                    ApplyStatus(
                        status=STATUS_REVERTED,
                        etag=prev_etag,
                        failed_etag=etag,
                        error=self._quarantine.reason,
                    )
                )
                bundle, etag = prev_bundle, prev_etag
                booting_from_previous = True
        if bundle is not None:
            self._current_etag = etag
            try:
                self._apply_bundle(
                    bundle,
                    reload_kea=True,
                    reload_retry_timeout=_BOOTSTRAP_RELOAD_TIMEOUT,
                )
                if not booting_from_previous and self._reload_confirmed:
                    # #882 — ``current`` demonstrably loads, so it becomes the
                    # bundle we fall back TO. Skipped when we booted from
                    # ``previous``: committing there would copy the still-bad
                    # ``current.json`` over the only good config we have — and
                    # skipped when no daemon confirmed the config (every
                    # control socket unreachable), since an unverified bundle
                    # is not a safe revert target.
                    commit_config(self.cfg.state_dir, etag or "")
                # #296 A2 — warm-restart readiness. The hostPath cache carries
                # the bundle we just successfully re-applied; the marker tells
                # the K8s readinessProbe this pod is ready to serve without
                # waiting for the next control-plane long-poll round-trip.
                _touch_ready_marker(self.cfg.state_dir)
                log.info("dhcp_agent_bootstrap_from_cache", etag=etag)
                # #170 Wave C1 — fleet-upgrade / reboot / SNMP / NTP
                # trigger-file writes moved to the supervisor's
                # heartbeat loop. The DHCP service container drops its
                # host bind mounts (``/etc/spatiumddi-host``,
                # ``/boot/efi-host``, ``/var/lib/spatiumddi-host/
                # release-state``, ``/run/udev``) in C1 so it can no
                # longer write the trigger surface anyway; the
                # supervisor's appliance-state module is the single
                # producer of appliance-host trigger files now.
            except Exception as e:
                # #882 — the cached bundle no longer loads. Quarantine it and
                # fall back rather than leave Kea on the baked image config.
                log.exception("bootstrap_cache_apply_failed")
                if booting_from_previous:
                    # It was the last-known-GOOD bundle that just failed, not
                    # ``current`` — ``etag`` was rebound to ``prev_etag`` above.
                    # Do NOT quarantine it: that would overwrite the record
                    # naming the bundle which actually broke us, un-quarantining
                    # the poison pill so the next poll applies it again.
                    self._set_status(
                        ApplyStatus(
                            status=STATUS_REVERT_FAILED,
                            failed_etag=self._quarantine.etag,
                            error=truncate_error(str(e)),
                        )
                    )
                    log.error(
                        "bootstrap_last_known_good_apply_failed",
                        failed_etag=self._quarantine.etag,
                        previous_etag=etag,
                    )
                else:
                    if etag:
                        self._quarantine.record(etag, truncate_error(str(e)))
                    self._bootstrap_fallback(etag, e)

    def _set_status(self, status: ApplyStatus) -> None:
        self.apply_status = status
        self.heartbeat.config_apply = status

    def _bootstrap_fallback(self, failed_etag: str | None, exc: BaseException) -> None:
        """Boot from the last-known-good bundle after ``current`` failed (#882)."""
        prev_bundle, prev_etag = load_previous_config(self.cfg.state_dir)
        if prev_bundle is None or prev_etag == failed_etag:
            self._set_status(
                ApplyStatus(
                    status=STATUS_NO_PREVIOUS,
                    failed_etag=failed_etag,
                    error=truncate_error(str(exc)),
                )
            )
            log.error("bootstrap_no_last_known_good", failed_etag=failed_etag)
            return
        try:
            self._apply_bundle(
                prev_bundle,
                reload_kea=True,
                reload_retry_timeout=_BOOTSTRAP_RELOAD_TIMEOUT,
            )
        except Exception as revert_exc:
            self._set_status(
                ApplyStatus(
                    status=STATUS_REVERT_FAILED,
                    failed_etag=failed_etag,
                    error=truncate_error(f"{exc} (revert also failed: {revert_exc})"),
                )
            )
            log.exception("bootstrap_last_known_good_apply_failed")
            return
        self._current_etag = prev_etag
        self._set_status(
            ApplyStatus(
                status=STATUS_REVERTED,
                etag=prev_etag,
                failed_etag=failed_etag,
                error=truncate_error(str(exc)),
            )
        )
        _touch_ready_marker(self.cfg.state_dir)
        log.warning(
            "bootstrap_from_last_known_good",
            failed_etag=failed_etag,
            booted_etag=prev_etag,
        )

    def _apply_with_revert(self, bundle: dict[str, Any], etag: str) -> bool:
        """Apply ``bundle``; on failure fall back to the last-known-good (#882).

        Returns True when ``bundle`` is live, False when it was rejected.

        Unlike the DNS agent, a revert here always rewrites the on-disk Kea
        documents even when the running daemon was never disturbed. Kea's
        ``config-test`` rejects without touching the running server, so the
        daemon is fine — but ``_apply_bundle`` has already written the
        refused document to ``kea_config_path``, and that file is what Kea
        reads on its next start. Leaving it would turn a rejected apply into
        a crash loop the next time the container restarts.
        """
        try:
            self._apply_bundle(bundle, reload_kea=True)
        except ConfigApplyError as e:
            self._handle_apply_failure(etag, e.phase, e.cause)
            return False
        except Exception as e:
            self._handle_apply_failure(etag, None, e)
            return False

        self._quarantine.clear()
        if self._reload_confirmed:
            commit_config(self.cfg.state_dir, etag)
        else:
            # Written, not confirmed — every control socket was unreachable,
            # so nothing has validated this document. Keep the previous
            # last-known-good rather than promoting a bundle Kea may refuse
            # the moment it comes back.
            log.info("config_not_committed_unconfirmed", etag=etag)
        self._set_status(ApplyStatus(status=STATUS_OK, etag=etag))
        return True

    def _handle_apply_failure(
        self, etag: str, phase: str | None, cause: BaseException
    ) -> None:
        log.error("sync_apply_failed", etag=etag, phase=phase, error=str(cause))
        self._quarantine.record(etag, truncate_error(f"{phase or 'apply'}: {cause}"))

        prev_bundle, prev_etag = load_previous_config(self.cfg.state_dir)
        if prev_bundle is None:
            self._set_status(
                ApplyStatus(
                    status=STATUS_NO_PREVIOUS,
                    failed_etag=etag,
                    phase=phase,
                    error=truncate_error(str(cause)),
                )
            )
            log.error("sync_no_last_known_good", failed_etag=etag)
            return

        try:
            self._apply_bundle(prev_bundle, reload_kea=True)
        except Exception as revert_exc:
            self._set_status(
                ApplyStatus(
                    status=STATUS_REVERT_FAILED,
                    failed_etag=etag,
                    phase=phase,
                    error=truncate_error(f"{cause} (revert also failed: {revert_exc})"),
                )
            )
            log.exception("sync_revert_failed", failed_etag=etag)
            return

        self._set_status(
            ApplyStatus(
                status=STATUS_REVERTED,
                etag=prev_etag,
                failed_etag=etag,
                phase=phase,
                error=truncate_error(str(cause)),
            )
        )
        self.heartbeat.daemon_status = {
            "status": "degraded",
            "reason": f"config_apply_reverted: {truncate_error(str(cause))}",
        }
        log.warning(
            "sync_reverted_to_last_known_good", failed_etag=etag, live_etag=prev_etag
        )

    def stop(self) -> None:
        self._stop.set()

    def _client(self) -> httpx.Client:
        # server holds for ~longpoll_timeout seconds, give client a bit more
        return httpx.Client(
            base_url=self.cfg.control_plane_url,
            verify=self.cfg.httpx_verify(),
            timeout=self.cfg.longpoll_timeout + 15.0,
        )

    @staticmethod
    def _atomic_write_json(path: Path, doc: dict[str, Any]) -> None:
        """Write ``doc`` to ``path`` via the temp-write-then-rename pattern.

        The rename is atomic on POSIX so a reader (or a crash mid-write)
        never sees a half-written Kea config.
        """
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(doc, indent=2, sort_keys=True))
        tmp.replace(path)

    def _reload_socket(
        self,
        socket_path: Path,
        config_doc: dict[str, Any],
        daemon: str,
        reload_retry_timeout: float,
    ) -> str:
        """Preflight (config-test) then reload one Kea daemon.

        Returns ``RELOAD_OK`` / ``RELOAD_REJECTED`` / ``RELOAD_UNREACHABLE``.
        Never raises, so a v6 failure can't abort the v4 apply (and
        vice-versa). Two failure modes are distinguished (#477), and #882
        makes that distinction load-bearing rather than only cosmetic: a
        REJECTED config is known-bad and triggers a revert to the last
        config Kea accepted, while an UNREACHABLE socket says nothing about
        the config — reverting there would discard a perfectly good bundle
        because Kea happened to be restarting.

        * **Config rejected** — config-test / reload answers with a non-zero
          result. Terminal (retrying won't fix a bad render), so surface Kea's
          *actual* error text in ``daemon_status`` and skip the reload rather
          than disturb a running daemon with a config it will reject. This is
          what turns an opaque "degraded" into "pool 10.0.0.0/24 is not part
          of the subnet …".
        * **Socket not ready** — an ``OSError`` connecting to the control
          socket during Kea's startup window. Retry until the deadline.
        """
        deadline = time.monotonic() + reload_retry_timeout
        last_err: Exception | None = None
        while True:
            try:
                # config-test validates WITHOUT applying and returns the real
                # reason on rejection; only reload once it passes.
                config_test(socket_path, config_doc)
                config_reload(socket_path)
                return RELOAD_OK
            except (KeaCtrlError, OSError) as e:
                # Retry BOTH classes through the deadline. An OSError is the
                # control socket not being up yet; and during Kea's startup
                # window the command channel can answer config-test with a
                # *transient* KeaCtrlError (empty / non-JSON / not-ready) that a
                # moment later succeeds — so a rejection is only treated as
                # terminal once the retry window is exhausted. In the steady-
                # state apply path reload_retry_timeout is 0, so a genuinely bad
                # config still reports immediately without a spurious reload.
                last_err = e
                if time.monotonic() >= deadline:
                    break
                log.debug(
                    "kea_reload_socket_retry",
                    daemon=daemon,
                    error=str(e),
                    wait=_BOOTSTRAP_RELOAD_INTERVAL,
                )
                if self._stop.wait(_BOOTSTRAP_RELOAD_INTERVAL):
                    break
        # Deadline exhausted — report the reason that fits the last error: a
        # config Kea rejected (surface its text) vs a socket we never reached.
        if isinstance(last_err, KeaCtrlError):
            log.warning("kea_config_rejected", daemon=daemon, error=str(last_err))
            self.heartbeat.daemon_status = {
                "status": "degraded",
                "reason": f"{daemon}_config_rejected: {last_err}",
            }
            self._last_reload_error = f"{daemon}: {last_err}"
            return RELOAD_REJECTED
        log.warning("kea_config_reload_failed", daemon=daemon, error=str(last_err))
        self.heartbeat.daemon_status = {
            "status": "degraded",
            "reason": f"{daemon}_socket_unreachable: {last_err}",
        }
        self._last_reload_error = f"{daemon}: {last_err}"
        return RELOAD_UNREACHABLE

    def _apply_bundle(
        self,
        bundle: dict[str, Any],
        *,
        reload_kea: bool,
        reload_retry_timeout: float = 0.0,
    ) -> None:
        """Render bundle → write Kea config → reload daemon.

        The control-plane long-poll returns an envelope ``{server_id,
        etag, bundle: {...}, pending_ops}``. The render expects the
        inner dict. Fall back to the envelope if ``bundle`` isn't
        there so cached v0 responses (pre-envelope) still render.
        """
        # #882 — reset per apply; set below once a daemon accepts the doc.
        self._reload_confirmed = False
        # Issue #258 — explicit narrowing. Pre-#258 the inline
        # ternary fell through to ``bundle`` for ANY non-dict value
        # of ``bundle["bundle"]`` (list, str, None, …) and the
        # downstream ``render_kea`` would render against the
        # envelope shape, producing a blank ``subnet4: []`` config.
        # Now we narrow explicitly: only the dict shape becomes
        # ``inner``; anything else (including a v0 cached response
        # with no envelope wrapper) falls back to the outer bundle
        # only when it is itself a dict.
        inner_candidate = bundle.get("bundle")
        if isinstance(inner_candidate, dict):
            inner = inner_candidate
        elif isinstance(bundle, dict):
            inner = bundle
        else:
            log.warning(
                "dhcp_sync_unexpected_bundle_shape",
                outer_type=type(bundle).__name__,
                inner_type=type(inner_candidate).__name__,
            )
            return
        # ``leases6`` mirrors the v4 lease file with the family digit
        # swapped (``kea-leases4.csv`` → ``kea-leases6.csv``) so the v6
        # daemon never writes the v4 lease store.
        lease_file_v6 = str(self.cfg.kea_lease_file_v6)
        # #1140 — detected immediately before the write, so the document
        # names only addresses the host holds now. A stale one would not
        # just miss a socket: kea-dhcp6 refuses the whole config.
        v6_unicast = global_ipv6_addresses()
        try:
            rendered = render_kea(
                inner,
                control_socket=str(self.cfg.kea_control_socket),
                lease_file=str(self.cfg.kea_lease_file),
                control_socket_v6=str(self.cfg.kea_control_socket_v6),
                lease_file_v6=lease_file_v6,
                v6_unicast=v6_unicast,
            )
        except Exception as e:
            # #882 — tag the phase. A render failure never reached Kea, so
            # the caller knows the running config is untouched.
            raise ConfigApplyError(PHASE_RENDER, e) from e
        # Keep the HA poller aligned with whether Kea is about to load
        # the HA hook — when the bundle has no failover block the hook
        # won't be loaded, so we don't want the poller spamming
        # ha-status-get (and logging errors) against a daemon that
        # won't answer.
        if self.ha_poller is not None:
            self.ha_poller.set_enabled(bool(inner.get("failover")))

        # Split the combined render into the two daemon-specific files.
        # kea-dhcp4 rejects a doc containing a stray ``Dhcp6`` key (and
        # kea-dhcp6 a stray ``Dhcp4``), so each file carries exactly one
        # top-level block. ``render_kea`` always emits both blocks (the
        # Dhcp6 one is an idle skeleton when there are no v6 scopes).
        dhcp4_doc = {"Dhcp4": rendered.get("Dhcp4", {})}
        dhcp6_doc = {"Dhcp6": rendered.get("Dhcp6", {})}
        self._v6_unicast_applied = (
            tuple(v6_unicast) if dhcp6_doc["Dhcp6"].get("subnet6") else None
        )

        # Write the combined render to rendered/ (for audit/debug) and
        # then atomically write each split doc to its live config path.
        save_rendered_kea(self.cfg.state_dir, rendered)
        self._atomic_write_json(self.cfg.kea_config_path, dhcp4_doc)
        self._atomic_write_json(self.cfg.kea_config_path_v6, dhcp6_doc)
        log.info(
            "dhcp_config_written",
            path=str(self.cfg.kea_config_path),
            path_v6=str(self.cfg.kea_config_path_v6),
            subnets=len(dhcp4_doc["Dhcp4"].get("subnet4", [])),
            subnets_v6=len(dhcp6_doc["Dhcp6"].get("subnet6", [])),
        )
        if reload_kea:
            # Reload both daemons independently. A v6 reload failure must
            # not abort the v4 apply (and vice-versa) — each is wrapped in
            # the same retry / tolerate-missing-socket logic, and the
            # heartbeat daemon_status reflects the worst of the two.
            self._last_reload_error = None
            r4 = self._reload_socket(
                self.cfg.kea_control_socket, dhcp4_doc, "dhcp4", reload_retry_timeout
            )
            r6 = self._reload_socket(
                self.cfg.kea_control_socket_v6, dhcp6_doc, "dhcp6", reload_retry_timeout
            )
            # At least one daemon ran config-test against this document and
            # accepted it, which is what makes it a legitimate revert target.
            self._reload_confirmed = RELOAD_OK in (r4, r6)
            if r4 == RELOAD_OK and r6 == RELOAD_OK:
                self.heartbeat.daemon_status = {"status": "ok"}
            elif RELOAD_REJECTED in (r4, r6):
                # #882 — Kea told us the config is wrong. Pre-#882 this fell
                # through: the caller advanced ``_current_etag``, called
                # ``_record_success()``, logged ``dhcp_config_applied`` and
                # stamped the readiness marker, all for a config that had
                # been refused. Worse, the refused document was left at
                # ``kea_config_path``, so the next container restart booted
                # Kea straight into it. Raise so the caller reverts the
                # files as well as the verdict.
                raise ConfigApplyError(
                    PHASE_RELOAD,
                    RuntimeError(self._last_reload_error or "Kea rejected the config"),
                )
            # An UNREACHABLE socket is NOT a verdict on the config — Kea may
            # simply be starting. daemon_status already says degraded; leave
            # the rendered files in place so the next reload picks them up.
        # IPv6 Router Advertisements (issue #524) — write + reload the
        # managed radvd.conf the control plane rendered. No-op unless
        # RADVD_MANAGED=1; best-effort so a radvd failure never disturbs
        # the Kea apply above.
        try:
            apply_radvd(inner.get("radvd_conf"))
        except Exception:  # noqa: BLE001 — defensive; never block apply
            log.exception("radvd_apply_failed")

        # Feed the peer-resolve watcher the bundle so it can track
        # hostname → IP drift and trigger a re-render if any peer's
        # IP changes. No-op when the bundle has no failover block.
        if self.peer_watcher is not None:
            try:
                self.peer_watcher.set_bundle(bundle)
            except Exception:  # noqa: BLE001 — defensive; never block apply
                log.exception("peer_watcher_set_bundle_failed")

    def _record_failure(self, reason: str) -> None:
        self._consecutive_failures += 1
        if not self._offline and self._consecutive_failures >= _FAILURE_THRESHOLD:
            self._offline = True
            log.warning(
                "control_plane_unreachable",
                reason=reason,
                action="operating_from_cached_config",
            )

    def _record_success(self) -> None:
        if self._offline:
            log.info("control_plane_reconnected")
        self._offline = False
        self._consecutive_failures = 0

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
                resp = c.get("/api/v1/dhcp/agents/config", headers=headers)
        except httpx.HTTPError as e:
            self._record_failure(f"http_error:{e}")
            log.warning("sync_http_error", error=str(e), offline=self._offline)
            self._stop.wait(_OFFLINE_RETRY_SECONDS if self._offline else 5.0)
            return

        if resp.status_code == 304:
            self._record_success()
            return
        if resp.status_code in (401, 404):
            # 401 = token expired/invalid. 404 = server row was deleted on the
            # control plane (user removed it in the UI); re-register to create
            # a fresh row rather than 404-looping forever.
            log.warning(
                "sync_will_rebootstrap",
                status=resp.status_code,
                reason="token_invalid" if resp.status_code == 401 else "server_missing",
            )
            save_token(self.cfg.state_dir, "")
            self._stop.set()
            return
        if resp.status_code != 200:
            self._record_failure(f"status:{resp.status_code}")
            log.warning("sync_unexpected_status", status=resp.status_code)
            self._stop.wait(_OFFLINE_RETRY_SECONDS if self._offline else 5.0)
            return

        try:
            bundle = resp.json()
        except ValueError:
            self._record_failure("invalid_json")
            log.warning("sync_invalid_json")
            self._stop.wait(_OFFLINE_RETRY_SECONDS if self._offline else 5.0)
            return

        if bundle.get("pending_approval"):
            log.info("sync_pending_approval_waiting")
            self._stop.wait(10.0)
            self._record_success()
            return

        etag = bundle.get("etag") or resp.headers.get("ETag")
        if not etag:
            log.warning("sync_bundle_missing_etag")
            self._record_success()
            return

        # #882 — the quarantine names ONE bundle. If the control plane is no
        # longer serving it, the operator has saved something else and the
        # record is moot: drop it now rather than let ``retry_due`` keep
        # forcing If-None-Match off on every poll for a bundle that no
        # longer exists.
        if self._quarantine.etag is not None and etag != self._quarantine.etag:
            self._quarantine.clear()

        save_config(self.cfg.state_dir, bundle, etag)

        # #170 Wave C1 — fleet-upgrade / reboot / SNMP / NTP trigger
        # writes moved to the supervisor's heartbeat loop. The
        # ConfigBundle's ``fleet_upgrade`` / ``snmp_settings`` /
        # ``ntp_settings`` blocks remain in the wire shape for
        # backwards compatibility with pre-C1 in-field agents; C1+
        # DHCP service containers ignore them because the supervisor's
        # appliance_state module is the only producer of appliance-
        # host trigger files now.

        if self._quarantine.blocks(etag):
            # Already known-bad. Park on this etag so the long-poll blocks
            # instead of re-rendering the same refused config every second.
            log.info("sync_skipping_quarantined_bundle", etag=etag)
            self._current_etag = etag
            self._record_success()
            return

        if not self._apply_with_revert(bundle, etag):
            # The bundle was refused. ``_current_etag`` still advances so the
            # loop parks on a 304 rather than spinning; the quarantine
            # decides when to try again. Deliberately no ``_record_success``
            # / readiness marker: the control plane is reachable, but this
            # server has NOT converged and must not look like it has.
            self._current_etag = etag
            return

        self._current_etag = etag
        self._record_success()
        log.info("dhcp_config_applied", etag=etag)

        # #296 A2 — stamp readiness marker AFTER the bundle was fetched,
        # persisted to the hostPath cache, and the Kea reload succeeded.
        # A failed apply returns early above so we never reach this point
        # on error.
        _touch_ready_marker(self.cfg.state_dir)

        # Ack any pending ops included in the bundle so the control plane
        # stops re-delivering them on the next long-poll.
        for op in bundle.get("pending_ops") or []:
            op_id = op.get("op_id")
            if op_id:
                self.heartbeat.pending_acks.append({"op_id": op_id, "result": "ok"})

    def _recheck_v6_unicast(self) -> None:
        """Re-render the current bundle when the host's global IPv6
        addresses no longer match the ones in kea-dhcp6's unicast list (#1140).

        The bundle's ETag cannot say this — the addresses are host state,
        not control-plane state — so nothing else would re-render. And it
        matters beyond a missing socket: an address that is gone from the
        interface makes kea-dhcp6 refuse the whole document the next time
        it loads it (a container restart), taking DHCPv6 down. Checked once
        per loop, which the long-poll paces at ~30 s; reading
        ``/proc/net/if_inet6`` is cheap.
        """
        applied = self._v6_unicast_applied
        etag = self._current_etag
        if applied is None or etag is None or self._quarantine.blocks(etag):
            return
        current = tuple(global_ipv6_addresses())
        if current == applied:
            return
        bundle, cached_etag = load_config(self.cfg.state_dir)
        if bundle is None or cached_etag != etag:
            return
        log.info(
            "dhcp6_unicast_addresses_changed",
            before=[f"{i}/{a}" for i, a in applied],
            after=[f"{i}/{a}" for i, a in current],
        )
        self._apply_with_revert(bundle, etag)

    def run(self) -> None:
        while not self._stop.is_set():
            self._poll_once()
            self._recheck_v6_unicast()
            # Safety net: cap poll rate even if the server returns 200s
            # back-to-back (bad bundle state, clock skew, etc.). The long-poll
            # blocks ~30s when etag matches, so this doesn't add latency in
            # the normal case.
            self._stop.wait(1.0)
