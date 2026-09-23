"""Heartbeat loop — liveness + daemon status + token rotation."""

from __future__ import annotations

import os
import random
import threading
from typing import Any

import httpx
import structlog

from . import __version__, kea_ctrl
from .cache import save_token
from .config import AgentConfig
from .config_apply import ApplyStatus
from .spool import SpoolManager

log = structlog.get_logger(__name__)


class HeartbeatClient:
    def __init__(
        self,
        cfg: AgentConfig,
        token_ref: list[str],
        spool_manager: SpoolManager | None = None,
    ):
        self.cfg = cfg
        self.token_ref = token_ref
        self._stop = threading.Event()
        self.daemon_status: dict[str, Any] = {}
        # #882 — set by SyncLoop (constructed after this object, assigns itself
        # in). Rides the heartbeat's ``config`` field so the control plane can
        # tell a Kea that is up but running a REVERTED config apart from one
        # that converged. Defaults to a healthy ApplyStatus so a heartbeat sent
        # before the first sync doesn't report a failure that hasn't happened.
        self.config_apply: ApplyStatus = ApplyStatus()
        self.lease_count_since_start = 0
        self.pending_acks: list[dict] = []
        # #637 — cached Kea daemon version. See _kea_version(); immutable for the
        # life of this process, so it is probed until it answers and then reused.
        self._kea_version_cached: str | None = None
        # #1077 — the durable push spool; its status() rides the heartbeat's
        # ``spool`` field so the control plane can show a backlog replaying
        # (and alert on trims) instead of a silent hole that fills in later.
        self.spool_manager = spool_manager
        # Set when the control plane 422s the ``spool`` field: its heartbeat
        # model is ``extra="forbid"`` and predates #1077. Dropping the field
        # keeps the agent's liveness signal alive across the version skew.
        self._spool_field_unsupported = False

    def stop(self) -> None:
        self._stop.set()

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.cfg.control_plane_url,
            verify=self.cfg.httpx_verify(),
            timeout=15.0,
        )

    def _kea_version(self) -> str | None:
        """Running Kea daemon version, probed once and cached.

        The Kea binary cannot change while this process lives — a new image means
        a new container, which restarts the agent too. So probe until we get an
        answer, then stop: re-opening the control socket on every heartbeat would
        be a blocking round-trip (``send_command`` waits up to 10s) on the very
        thread that carries our liveness signal, and a wedged Kea would stall the
        heartbeat rather than merely failing to report a version.

        Stays None-and-retrying until the daemon first answers, which covers the
        cold-start window where the agent is up before Kea's socket is.
        """
        if self._kea_version_cached is None:
            self._kea_version_cached = kea_ctrl.version_get(self.cfg.kea_control_socket)
        return self._kea_version_cached

    def send_once(self) -> None:
        # Drain queued op acks (queued by SyncLoop when bundle includes pending_ops).
        ops_ack: list[dict] = []
        while self.pending_acks:
            ops_ack.append(self.pending_acks.pop(0))
        body: dict[str, Any] = {
            "agent_version": __version__,
            "pid": os.getpid(),
            "status": self.daemon_status.get("status", "ok"),
            "daemon": self.daemon_status,
            # #882 — last config-apply verdict. The server's request model has
            # declared a ``config`` field since the beginning; until now the
            # DHCP agent never sent one and the handler never read one.
            "config": self.config_apply.as_dict(),
            "lease_count_since_start": self.lease_count_since_start,
            "ops_ack": ops_ack,
            # #637 — the running Kea daemon's version (e.g. "3.0.3"), read live
            # off the control socket. The rolling-upgrade preflight needs it:
            # Kea 3.0's HA hook cannot talk to a peer older than 2.7, so a
            # node-at-a-time upgrade across that boundary breaks HA mid-run.
            # None = daemon not up yet / didn't answer; the control plane must
            # treat that as "unknown", never as "old".
            "kea_version": self._kea_version(),
        }
        if self.spool_manager is not None and not self._spool_field_unsupported:
            try:
                body["spool"] = self.spool_manager.status()
            except Exception as exc:  # noqa: BLE001 — telemetry must never cost liveness
                log.warning("heartbeat_spool_status_failed", error=str(exc))
        # #170 Wave C1 — slot / deployment / upgrade-state telemetry
        # used to ship here per Phase 8f-2; now lives on the
        # supervisor's heartbeat (one producer instead of three).
        # The DHCP service container drops the host bind mounts in C1
        # so it can no longer read those signals anyway.
        try:
            with self._client() as c:
                resp = c.post(
                    "/api/v1/dhcp/agents/heartbeat",
                    json=body,
                    headers={"Authorization": f"Bearer {self.token_ref[0]}"},
                )
                if resp.status_code == 422 and "spool" in body and "spool" in resp.text:
                    log.warning("heartbeat_spool_field_unsupported")
                    self._spool_field_unsupported = True
                    body.pop("spool")
                    resp = c.post(
                        "/api/v1/dhcp/agents/heartbeat",
                        json=body,
                        headers={"Authorization": f"Bearer {self.token_ref[0]}"},
                    )
            if resp.status_code == 200:
                data = resp.json()
                rotated = data.get("rotated_token")
                if rotated:
                    self.token_ref[0] = rotated
                    save_token(self.cfg.state_dir, rotated)
                    log.info("dhcp_agent_token_rotated")
            elif resp.status_code in (401, 404):
                # Token invalidated or server row deleted — clear token and
                # exit so supervisor restarts the container (→ re-bootstrap).
                log.warning("heartbeat_will_rebootstrap", status=resp.status_code)
                save_token(self.cfg.state_dir, "")
                self._stop.set()
            else:
                log.warning("heartbeat_failed", status=resp.status_code)
        except httpx.HTTPError as e:
            log.warning("heartbeat_http_error", error=str(e))

    def run(self) -> None:
        while not self._stop.is_set():
            self.send_once()
            interval = self.cfg.heartbeat_interval + random.uniform(-3, 3)
            self._stop.wait(timeout=max(5.0, interval))
