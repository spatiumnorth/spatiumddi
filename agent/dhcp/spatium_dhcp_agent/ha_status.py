"""HA-status poller — invokes Kea's ``ha-status-get`` and reports upstream.

When the server is part of a DHCPFailoverChannel, the control plane
emits the HA hook config and the local Kea daemon loads it. This
module then periodically asks Kea for its HA state via the control
socket and POSTs that state to
``/api/v1/dhcp/agents/ha-status`` so the UI can render a live
"HA: normal" / "HA: partner-down" pill. The DHCPv4 and DHCPv6 daemons each
run their own HA hook, so both control sockets are polled and the two states
are reported separately (#1258).

When the server is standalone (no failover block in the last bundle),
the poller is a no-op. We key that off a shared flag set by the
SyncLoop after each successful bundle apply — cheaper than re-parsing
Kea state on every tick just to discover HA isn't configured.
"""

from __future__ import annotations

import random
import threading
from pathlib import Path
from typing import Any

import httpx
import structlog

from .config import AgentConfig
from .kea_ctrl import KeaCtrlError, send_command

log = structlog.get_logger(__name__)


def _extract_state(resp: dict[str, Any]) -> str | None:
    """Pick the local peer's state out of Kea's status-get response.

    Kea 2.6 exposes HA status under ``arguments.high-availability[]``
    in the generic ``status-get`` command — the old standalone
    ``ha-status-get`` was removed from the DHCPv4 unix socket.
    Response shape::

        {"arguments": {"high-availability": [
            {"ha-mode": "hot-standby",
             "ha-servers": {
                "local": {"role": "primary", "state": "hot-standby", ...},
                "remote": {"role": "standby", "last-state": "normal", ...}}}
        ]}}

    Older Kea (pre-2.6) replied to ``ha-status-get`` with either
    ``arguments.ha-servers.local.state`` or ``arguments.local.state``.
    We accept all three shapes so the same poller works across
    versions and a schema drift upstream just renders as "unknown"
    instead of crashing.
    """
    args = resp.get("arguments") or {}
    ha_list = args.get("high-availability")
    if isinstance(ha_list, list) and ha_list:
        first = ha_list[0]
        servers = first.get("ha-servers") if isinstance(first, dict) else None
        local = servers.get("local") if isinstance(servers, dict) else None
        if isinstance(local, dict):
            state = local.get("state")
            if isinstance(state, str) and state:
                return state
    ha = args.get("ha-servers") or args
    local = ha.get("local") if isinstance(ha, dict) else None
    if isinstance(local, dict):
        state = local.get("state")
        if isinstance(state, str) and state:
            return state
    return None


class HAStatusPoller:
    def __init__(self, cfg: AgentConfig, token_ref: list[str]):
        self.cfg = cfg
        self.token_ref = token_ref
        self._stop = threading.Event()
        # Flipped by the SyncLoop after each apply: True when the most
        # recent bundle carried a ``failover`` block, False otherwise.
        # Until we've seen at least one bundle we assume nothing.
        self._enabled = False

    def set_enabled(self, enabled: bool) -> None:
        if enabled != self._enabled:
            log.info("ha_poller_enabled_changed", enabled=enabled)
        self._enabled = enabled

    def stop(self) -> None:
        self._stop.set()

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.cfg.control_plane_url,
            verify=self.cfg.httpx_verify(),
            timeout=10.0,
        )

    def _poll_kea(self, socket: Path | None = None) -> tuple[str | None, dict[str, Any] | None]:
        # ``status-get`` rather than ``ha-status-get``: Kea 2.6 folded
        # HA state into the generic status response (see _extract_state).
        # ``socket`` defaults to the DHCPv4 daemon's; the DHCPv6 daemon is a
        # separate process with its own socket and its own HA state (#1258).
        try:
            resp = send_command(socket or self.cfg.kea_control_socket, "status-get")
        except KeaCtrlError as e:
            # Kea returns an error when the HA hook isn't loaded. That's
            # the common case for standalone servers — log at debug so
            # we don't spam the logs before an HA config gets pushed.
            log.debug("ha_status_kea_err", error=str(e))
            return None, None
        except FileNotFoundError:
            # Socket missing — Kea isn't up yet. Transient; wait.
            return None, None
        except Exception as e:  # noqa: BLE001 — don't let the poller die on network / JSON oddities
            log.warning("ha_status_kea_unexpected", error=str(e))
            return None, None
        return _extract_state(resp), resp.get("arguments")

    def _report(
        self,
        state: str,
        raw: dict[str, Any] | None,
        state_v6: str | None = None,
        raw_v6: dict[str, Any] | None = None,
    ) -> None:
        body: dict[str, Any] = {"state": state, "raw": raw or {}}
        # The v6 keys are sent only when kea-dhcp6 reported one, so a control
        # plane that predates DHCPv6 HA sees exactly the payload it always did.
        if state_v6 is not None:
            body["state_v6"] = state_v6
            body["raw_v6"] = raw_v6 or {}
        try:
            with self._client() as c:
                resp = c.post(
                    "/api/v1/dhcp/agents/ha-status",
                    json=body,
                    headers={"Authorization": f"Bearer {self.token_ref[0]}"},
                )
            if resp.status_code not in (200, 204):
                log.warning("ha_status_report_failed", status=resp.status_code)
        except httpx.HTTPError as e:
            log.warning("ha_status_report_http_error", error=str(e))

    def run(self) -> None:
        while not self._stop.is_set():
            if self._enabled:
                state, raw = self._poll_kea()
                if state is not None:
                    # kea-dhcp6 answers ``status-get`` with no HA section (or
                    # not at all) while its hook is not loaded, which reads as
                    # None here: no v6 HA, not an error.
                    state_v6, raw_v6 = self._poll_kea(self.cfg.kea_control_socket_v6)
                    self._report(state, raw, state_v6, raw_v6)
            # 15s base cadence + small jitter so N paired peers don't
            # hit the control plane in lockstep. HA state changes
            # propagate as fast as heartbeats detect them (Kea's own
            # heartbeat-delay is typically 10s), so polling faster than
            # every 10s gains nothing.
            interval = 15.0 + random.uniform(-2, 2)
            self._stop.wait(timeout=max(5.0, interval))
