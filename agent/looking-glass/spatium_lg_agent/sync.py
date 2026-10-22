"""Config long-poll loop — fetches the peer-config bundle and re-renders
gobgpd's config on every change.

Cloned from ``agent/dns/spatium_dns_agent/sync.py``'s ``SyncLoop`` shape
(GET with ``If-None-Match``, preload+apply the cached bundle before the
first poll, atomic-swap to disk on 200, 401/404 -> clear token + stop).
Unlike the DNS agent there is no structural-vs-record-only split here —
every ``bgp_lg_peer`` change is a full peer-set re-render (GoBGP's
``apply_config`` is cheap: render + write + SIGHUP, no daemon restart), so
any 200 response with a new etag triggers :func:`spatium_lg_agent.gobgp.
apply_config`.

``GET /api/v1/looking-glass/agents/config`` (see
``backend/app/api/v1/looking_glass/agents.py::agent_config_longpoll``)
returns an envelope, not a bare bundle::

    {"collector_id": "...", "etag": "...", "bundle": {"collector_name": ...,
     "peers": [...]}}

This loop unwraps ``bundle`` before handing it to ``gobgp.py`` /
``rib.py`` — the cache on disk stores the unwrapped inner bundle (that's
what actually gets rendered), with the etag tracked alongside it. There is
no ``pending_approval`` gate here (unlike the DHCP/DNS agent protocol) —
the collector identity row has no approval flow, per the agents.py module
docstring.
"""

from __future__ import annotations

import subprocess
import threading
import time
from typing import Any

import httpx
import structlog

from . import gobgp
from .bootstrap import reauth_generation, reauthenticate
from .cache import (
    commit_config,
    load_config,
    load_previous_config,
    save_config,
)
from .config import AgentConfig
from .config_apply import (
    STATUS_NO_PREVIOUS,
    STATUS_OK,
    STATUS_REVERT_FAILED,
    STATUS_REVERTED,
    ApplyStatus,
    ConfigApplyError,
    Quarantine,
    truncate_error,
)

log = structlog.get_logger(__name__)

# NOTE: the jittered ``_APPLY_BACKOFF_BASE`` / ``_APPLY_BACKOFF_CAP`` sleep
# that used to live here is gone (#882). It kept a persistently-bad bundle
# from pegging the CPU, but it also kept RETRYING that bundle forever at a
# 45 s cap, with the collector stuck on a peer set that does not render and
# nothing said upward. ``Quarantine`` replaces it: park on the etag so the
# long-poll blocks properly, retry on a longer ladder, and report the
# failure on the heartbeat.


class SyncLoop:
    def __init__(
        self,
        cfg: AgentConfig,
        token_ref: list[str],
        heartbeat: Any,
        rib: Any,
        gobgpd_proc: "subprocess.Popen[bytes] | None",
    ):
        self.cfg = cfg
        self.token_ref = token_ref
        self.heartbeat = heartbeat
        self.rib = rib
        self.gobgpd_proc = gobgpd_proc
        self._stop = threading.Event()
        self._current_etag: str | None = None
        # #2052 — the re-registration this loop last caught up with.
        self._reauth_gen = reauth_generation()
        # #882 — last-known-good revert. ``quarantine`` remembers an etag
        # whose apply failed so we stop re-rendering it; ``apply_status`` is
        # what the heartbeat reports upward.
        self._quarantine = Quarantine(self.cfg.state_dir)
        self.apply_status = ApplyStatus()
        self.heartbeat.config_apply = self.apply_status

        # Preload cached bundle (non-negotiable #5 — offline-operation
        # guarantee). Applying it BEFORE the first network poll is what
        # keeps already-configured BGP sessions up if the control plane
        # is unreachable at container start.
        bundle, etag = load_config(self.cfg.state_dir)
        # #882 — a restart must not re-apply the bundle that already failed.
        booting_from_previous = False
        if bundle is not None and self._quarantine.blocks(etag):
            prev_bundle, prev_etag = load_previous_config(self.cfg.state_dir)
            if prev_bundle is not None:
                log.warning(
                    "lg_bootstrap_skipping_quarantined_bundle",
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
                gobgp.apply_config(self.cfg, bundle, self.gobgpd_proc)
                self.rib.set_peers(
                    gobgp.peer_address_map(bundle),
                    gobgp.peer_import_scopes(bundle),
                )
                if not booting_from_previous:
                    # #882 — ``current`` demonstrably renders, so it becomes
                    # the bundle we fall back TO. Skipped when we booted from
                    # ``previous``: committing there would copy the still-bad
                    # ``current.json`` over the only good config we have.
                    commit_config(self.cfg.state_dir, etag or "")
                log.info("lg_agent_bootstrap_from_cache", etag=etag)
            except Exception as e:
                log.exception("lg_bootstrap_cache_apply_failed")
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
                        "lg_bootstrap_last_known_good_apply_failed",
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
            log.error("lg_bootstrap_no_last_known_good", failed_etag=failed_etag)
            return
        try:
            gobgp.apply_config(self.cfg, prev_bundle, self.gobgpd_proc)
            self.rib.set_peers(
                gobgp.peer_address_map(prev_bundle),
                gobgp.peer_import_scopes(prev_bundle),
            )
        except Exception as revert_exc:
            self._set_status(
                ApplyStatus(
                    status=STATUS_REVERT_FAILED,
                    failed_etag=failed_etag,
                    error=truncate_error(f"{exc} (revert also failed: {revert_exc})"),
                )
            )
            log.exception("lg_bootstrap_last_known_good_apply_failed")
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
        log.warning(
            "lg_bootstrap_from_last_known_good",
            failed_etag=failed_etag,
            booted_etag=prev_etag,
        )

    def stop(self) -> None:
        self._stop.set()

    def _client(self) -> httpx.Client:
        # Server holds the long-poll for ~cfg.longpoll_timeout; give the
        # client meaningfully more so a slow-but-alive control plane
        # doesn't look like a network error.
        return httpx.Client(
            base_url=self.cfg.control_plane_url,
            verify=self.cfg.httpx_verify(),
            timeout=60.0,
        )

    def _poll_once(self) -> None:
        gen = reauth_generation()
        if gen != self._reauth_gen:
            # #2052 — another thread re-registered: the row may be new, so
            # ask it for the whole bundle rather than a 304 on the old etag.
            self._reauth_gen = gen
            self._current_etag = None
        headers = {"Authorization": f"Bearer {self.token_ref[0]}"}
        # #882 — a quarantined bundle is parked on a 304 by the etag we sent
        # last time, so the only way to give it another attempt is to stop
        # sending that etag.
        if self._quarantine.retry_due():
            log.info(
                "lg_sync_quarantine_retry_due",
                etag=self._quarantine.etag,
                failures=self._quarantine.failures,
            )
            self._current_etag = None
        if self._current_etag:
            headers["If-None-Match"] = self._current_etag
        try:
            with self._client() as c:
                resp = c.get("/api/v1/looking-glass/agents/config", headers=headers)
        except httpx.HTTPError as e:
            log.warning("lg_sync_http_error", error=str(e))
            time.sleep(5.0)
            return

        if resp.status_code == 304:
            return
        if resp.status_code in (401, 404):
            # 401 = token expired/invalid. 404 = the collector row was
            # deleted on the control plane. #2052 — re-register in this
            # thread and keep polling; stopping it made the supervisor exit
            # the container and take the BGP daemon down with the agent.
            log.warning(
                "lg_sync_will_rebootstrap",
                status=resp.status_code,
                reason=(
                    "token_invalid" if resp.status_code == 401 else "collector_missing"
                ),
            )
            reauthenticate(self.cfg, self.token_ref, headers["Authorization"][7:])
            self._current_etag = None
            return
        if resp.status_code != 200:
            log.warning("lg_sync_unexpected_status", status=resp.status_code)
            time.sleep(5.0)
            return

        envelope = resp.json()
        etag = envelope.get("etag") or resp.headers.get("ETag")
        if not etag:
            log.warning("lg_sync_bundle_missing_etag")
            return
        # Unwrap the envelope — ``bundle`` (collector_name + peers) is what
        # gobgp.py actually renders from; see module docstring.
        inner_bundle = envelope.get("bundle") or {}

        # Atomic-swap cache always — cache is the source of truth across
        # restarts, even before we know the apply below succeeds. We cache
        # the unwrapped inner bundle (matches what the constructor's
        # ``load_config`` preload path expects to hand to ``gobgp.py``).
        # #882 — the quarantine names ONE bundle. If the control plane is no
        # longer serving it, the operator has saved something else and the
        # record is moot.
        if self._quarantine.etag is not None and etag != self._quarantine.etag:
            self._quarantine.clear()

        save_config(self.cfg.state_dir, inner_bundle, etag)

        if self._quarantine.blocks(etag):
            # #882 — already known-bad. Park on this etag so the long-poll
            # blocks on a 304 instead of re-rendering the same broken peer
            # set; the quarantine backoff decides when to try again. This
            # replaces the pre-#882 sleep-and-retry, which held the bundle
            # forever at a 45 s cap with no upward signal.
            log.info("lg_sync_skipping_quarantined_bundle", etag=etag)
            self._current_etag = etag
            return

        if not self._apply_with_revert(inner_bundle, etag):
            self._current_etag = etag
            return

        self.rib.set_peers(
            gobgp.peer_address_map(inner_bundle),
            gobgp.peer_import_scopes(inner_bundle),
        )
        self._current_etag = etag
        log.info(
            "lg_config_applied",
            etag=etag,
            peer_count=len(inner_bundle.get("peers") or []),
        )

    def _apply_with_revert(self, bundle: dict[str, Any], etag: str) -> bool:
        """Apply ``bundle``; on failure fall back to the last-known-good (#882).

        Returns True when ``bundle`` is live, False when it was rejected.

        gobgpd has no dry-run and :func:`gobgp.reload` is a best-effort
        SIGHUP that never raises, so the only failures observable here are
        render and file-write. That is still worth reverting for: the
        rendered document is what gobgpd reads on its next start, so a
        half-written or stale-but-wrong file turns one bad bundle into a
        collector that comes back up with the wrong peer set.
        """
        try:
            gobgp.apply_config(self.cfg, bundle, self.gobgpd_proc)
        except ConfigApplyError as e:
            self._handle_apply_failure(etag, e.phase, e.cause, e.daemon_disturbed)
            return False
        except Exception as e:
            self._handle_apply_failure(etag, None, e, True)
            return False

        self._quarantine.clear()
        commit_config(self.cfg.state_dir, etag)
        self._set_status(ApplyStatus(status=STATUS_OK, etag=etag))
        if self.heartbeat.daemon_status.get("status") == "degraded":
            self.heartbeat.daemon_status = {"status": "ok"}
        return True

    def _handle_apply_failure(
        self,
        etag: str,
        phase: str | None,
        cause: BaseException,
        daemon_disturbed: bool,
    ) -> None:
        log.error(
            "lg_sync_apply_failed",
            etag=etag,
            phase=phase,
            error=str(cause),
            daemon_disturbed=daemon_disturbed,
        )
        self._quarantine.record(etag, truncate_error(f"{phase or 'apply'}: {cause}"))

        prev_bundle, prev_etag = load_previous_config(self.cfg.state_dir)
        if prev_bundle is None:
            status = ApplyStatus(
                status=STATUS_NO_PREVIOUS,
                failed_etag=etag,
                phase=phase,
                error=truncate_error(str(cause)),
            )
            log.error("lg_sync_no_last_known_good", failed_etag=etag)
        elif not daemon_disturbed:
            # Rendering failed, so gobgpd's config file was never replaced —
            # it still holds the previous bundle, which is the state a revert
            # would produce. Rewriting it would be busywork.
            status = ApplyStatus(
                status=STATUS_REVERTED,
                etag=prev_etag,
                failed_etag=etag,
                phase=phase,
                error=truncate_error(str(cause)),
            )
            log.warning(
                "lg_sync_reverted_without_rewrite",
                failed_etag=etag,
                live_etag=prev_etag,
            )
        else:
            try:
                gobgp.apply_config(self.cfg, prev_bundle, self.gobgpd_proc)
                self.rib.set_peers(
                    gobgp.peer_address_map(prev_bundle),
                    gobgp.peer_import_scopes(prev_bundle),
                )
            except Exception as revert_exc:
                status = ApplyStatus(
                    status=STATUS_REVERT_FAILED,
                    failed_etag=etag,
                    phase=phase,
                    error=truncate_error(f"{cause} (revert also failed: {revert_exc})"),
                )
                log.exception("lg_sync_revert_failed", failed_etag=etag)
            else:
                status = ApplyStatus(
                    status=STATUS_REVERTED,
                    etag=prev_etag,
                    failed_etag=etag,
                    phase=phase,
                    error=truncate_error(str(cause)),
                )
                log.warning(
                    "lg_sync_reverted_to_last_known_good",
                    failed_etag=etag,
                    live_etag=prev_etag,
                )

        self._set_status(status)
        self.heartbeat.daemon_status = {
            **self.heartbeat.daemon_status,
            "status": "degraded",
            "reason": f"config_apply_{status.status}: {status.error}",
        }

    def run(self) -> None:
        while not self._stop.is_set():
            self._poll_once()
