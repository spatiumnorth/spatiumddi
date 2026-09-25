"""Heartbeat loop — sends liveness + op ACKs, rotates token if requested."""

from __future__ import annotations

import random
import threading
from typing import Any

import httpx
import structlog

from . import __version__
from .cache import save_token
from .config import AgentConfig
from .config_apply import ApplyStatus
from .drivers.base import DriverBase
from .spool import SpoolManager

log = structlog.get_logger(__name__)


class HeartbeatClient:
    def __init__(
        self,
        cfg: AgentConfig,
        token_ref: list[str],
        driver: DriverBase | None = None,
        spool_manager: SpoolManager | None = None,
    ):
        # token_ref is a 1-element list so the sync loop can swap the token in place
        self.cfg = cfg
        self.token_ref = token_ref
        self._stop = threading.Event()
        self.pending_acks: list[dict[str, Any]] = []
        self.daemon_status: dict[str, Any] = {}
        # #882 — set by SyncLoop (which is constructed after this object and
        # assigns itself in). Its ``as_dict()`` rides the heartbeat's
        # ``config`` field so the control plane can tell a server that is up
        # but running a REVERTED config apart from one that converged.
        # Defaults to a healthy ApplyStatus so a heartbeat sent before the
        # first sync doesn't report a failure that hasn't happened.
        self.config_apply: ApplyStatus = ApplyStatus()
        self.failed_ops_count = 0
        # #638 — the driver is only used to probe the DNS daemon's version.
        # Optional so tests (and any caller that just wants liveness) can build
        # a HeartbeatClient without a driver.
        self.driver = driver
        self._daemon_version_cached: str | None = None
        self._daemon_version_attempts = 0
        # #1077 — the durable push spool; its status() rides the heartbeat's
        # ``spool`` field so the control plane can show a backlog replaying
        # (and alert on trims) instead of a silent hole that fills in later.
        self.spool_manager = spool_manager
        # Set when the control plane 422s the ``spool`` field. Its heartbeat
        # request model is ``extra="forbid"``, so a control plane older than
        # #1077 rejects the whole heartbeat — which would turn a new agent
        # against an old control plane into a stale server. Mirrors the DHCP
        # agent's fallback.
        self._spool_field_unsupported = False

    # A failing probe must not be retried forever. Unlike the DHCP agent's
    # ``_kea_version``, which polls a control socket that is legitimately down
    # during cold start, this probe execs the daemon BINARY — if it can't
    # answer, it almost certainly never will. A couple of retries cover a
    # transient fork failure; after that we stop, because the probe is a
    # blocking subprocess on the thread that carries our liveness signal.
    _DAEMON_VERSION_MAX_ATTEMPTS = 3

    def _daemon_version(self) -> str | None:
        """DNS daemon version, probed once (at most a few times) and cached.

        Same purpose as the DHCP agent's ``_kea_version`` (#637): the daemon
        binary cannot change while this process lives, because a new image
        means a new container and a restarted agent — so there is nothing to
        gain from re-probing on every heartbeat.

        Returns None once the attempt budget is spent; the control plane treats
        that as UNKNOWN.
        """
        if (
            self._daemon_version_cached is None
            and self.driver is not None
            and self._daemon_version_attempts < self._DAEMON_VERSION_MAX_ATTEMPTS
        ):
            self._daemon_version_attempts += 1
            self._daemon_version_cached = self.driver.daemon_version()
            if self._daemon_version_cached is None:
                log.debug(
                    "dns_daemon_version_probe_failed",
                    attempt=self._daemon_version_attempts,
                    max_attempts=self._DAEMON_VERSION_MAX_ATTEMPTS,
                )
        return self._daemon_version_cached

    def stop(self) -> None:
        self._stop.set()

    def _client(self) -> httpx.Client:
        verify: bool | str = True
        if self.cfg.insecure_skip_tls_verify:
            verify = False
        elif self.cfg.tls_ca_path:
            verify = self.cfg.tls_ca_path
        return httpx.Client(
            base_url=self.cfg.control_plane_url, verify=verify, timeout=15.0
        )

    def send_once(self) -> None:
        body: dict[str, Any] = {
            "agent_version": __version__,
            # #638 — the DNS DAEMON's version (e.g. "5.0.5" / "9.20.26"),
            # distinct from ``agent_version`` (this python agent). The
            # rolling-upgrade preflight needs it: crossing PowerDNS 4.x → 5.x
            # performs a one-way LMDB schema migration, so the operator has to
            # be told before they press Start. None = probe failed; the control
            # plane must treat that as "unknown", never as a specific version.
            "daemon_version": self._daemon_version(),
            "daemon": self.daemon_status,
            # #882 — last config-apply verdict. Before #882 this field was
            # sent as a literal ``{}``: declared on the server's request
            # model, accepted, and read by nothing.
            "config": self.config_apply.as_dict(),
            "ops_ack": self.pending_acks,
            "failed_ops_count": self.failed_ops_count,
        }
        if self.spool_manager is not None and not self._spool_field_unsupported:
            try:
                body["spool"] = self.spool_manager.status()
            except Exception as exc:  # noqa: BLE001 — telemetry must never cost liveness
                log.warning("heartbeat_spool_status_failed", error=str(exc))
        # #170 Wave C1 — slot / deployment / upgrade-state telemetry
        # used to ship here per Phase 8f-2; now lives on the
        # supervisor's heartbeat (one producer instead of three).
        # The DNS service container drops the host bind mounts in C1
        # so it can no longer read those signals anyway.
        try:
            with self._client() as c:
                resp = c.post(
                    "/api/v1/dns/agents/heartbeat",
                    json=body,
                    headers={"Authorization": f"Bearer {self.token_ref[0]}"},
                )
                if resp.status_code == 422 and "spool" in body and "spool" in resp.text:
                    log.warning("heartbeat_spool_field_unsupported")
                    self._spool_field_unsupported = True
                    body.pop("spool")
                    resp = c.post(
                        "/api/v1/dns/agents/heartbeat",
                        json=body,
                        headers={"Authorization": f"Bearer {self.token_ref[0]}"},
                    )
            if resp.status_code == 200:
                data = resp.json()
                self.pending_acks.clear()
                rotated = data.get("rotated_token")
                if rotated:
                    self.token_ref[0] = rotated
                    save_token(self.cfg.state_dir, rotated)
                    log.info("dns_agent_token_rotated")
            elif resp.status_code in (401, 404):
                # Issue #248 — mirror sync.py's 401/404 recovery path.
                # 401 = token expired / invalid; 404 = the server row
                # was deleted on the control plane. Both recover by
                # the same path: drop cached token + stop the thread.
                # The supervisor's dead-thread watch exits the
                # container; the next start re-bootstraps from PSK.
                # Pre-#248 the heartbeat just spam-warned until sync
                # noticed the same 401 (could be a full heartbeat
                # interval later).
                log.warning(
                    "heartbeat_will_rebootstrap",
                    status=resp.status_code,
                    reason=(
                        "token_invalid" if resp.status_code == 401 else "server_missing"
                    ),
                )
                save_token(self.cfg.state_dir, "")
                self._stop.set()
            else:
                log.warning("heartbeat_failed", status=resp.status_code)
        except httpx.HTTPError as e:
            log.warning("heartbeat_http_error", error=str(e))

    def run(self) -> None:
        while not self._stop.is_set():
            self.send_once()
            # ±3s jitter on the 30s interval
            interval = self.cfg.heartbeat_interval + random.uniform(-3, 3)
            self._stop.wait(timeout=max(5.0, interval))
