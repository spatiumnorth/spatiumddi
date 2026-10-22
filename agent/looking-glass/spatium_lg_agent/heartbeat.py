"""Heartbeat loop — per-peer BGP session state + token rotation.

``peer_states`` is populated by :class:`spatium_lg_agent.rib.RibPoller` after
each ``gobgp neighbor -j`` poll (mirrors the DHCP agent's
``HeartbeatClient.daemon_status`` shared-mutable-dict convention — one
thread writes, the heartbeat thread reads on its own cadence, no lock
needed since dict item assignment is atomic enough for this use).

Body shape matches
``backend/app/api/v1/looking_glass/agents.py``'s
``AgentHeartbeatRequest``/``PeerStateReport`` EXACTLY — both carry
``model_config = ConfigDict(extra="forbid")``, so anything not in the
allowed field set (a stray top-level ``pid``/``status``, say) 422s the
*entire* heartbeat, not just the extra field. ``agent_version``, ``peers[]``
and ``config`` (the #882 config-apply verdict) travel at the top level; each
peer entry is restricted to ``_PEER_STATE_FIELDS`` before being sent. A new
top-level field therefore has to be added to ``AgentHeartbeatRequest`` in
the SAME change, or every heartbeat 422s.

Note: ``rpki_invalid_count`` is never populated here even though
``PeerStateReport`` accepts it — RPKI validation is computed server-side
at route-ingest time (``derive_rpki_status`` — see the routes-push
contract in ``rib.py``'s docstring); the collector itself has no local
RPKI validator to consult, so that counter is backend-owned bookkeeping
derived from ingested ``bgp_lg_route`` rows, not agent-reported telemetry.
"""

from __future__ import annotations

import random
import threading
from typing import Any

import httpx
import structlog

from . import __version__
from .bootstrap import reauthenticate
from .cache import save_token
from .config import AgentConfig
from .config_apply import ApplyStatus

log = structlog.get_logger(__name__)

# Exactly the fields ``PeerStateReport`` accepts besides ``peer_id`` —
# anything else in a ``rib.py``-populated peer_states entry is dropped
# before it hits the wire (extra="forbid" would otherwise 422 the whole
# heartbeat).
_PEER_STATE_FIELDS = (
    "session_state",
    "uptime_started_at",
    "prefixes_received",
    "prefixes_accepted",
    "last_state_change",
    "last_flap_at",
    "rpki_invalid_count",
)


class HeartbeatClient:
    def __init__(self, cfg: AgentConfig, token_ref: list[str]):
        self.cfg = cfg
        self.token_ref = token_ref
        self._stop = threading.Event()
        # Free-form degraded-state note (set by SyncLoop) — logged locally
        # and not sent upstream; the structured half of the same signal now
        # IS sent, as ``config_apply`` below (#882).
        self.daemon_status: dict[str, Any] = {}
        # #882 — last config-apply verdict, assigned by SyncLoop (constructed
        # after this object). Defaults to a healthy ApplyStatus so a
        # heartbeat sent before the first sync doesn't report a failure that
        # hasn't happened.
        self.config_apply: ApplyStatus = ApplyStatus()
        # peer_id -> {session_state, uptime_started_at, prefixes_received,
        #             prefixes_accepted, last_state_change, last_flap_at}.
        # Written by RibPoller.
        self.peer_states: dict[str, dict[str, Any]] = {}

    def stop(self) -> None:
        self._stop.set()

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.cfg.control_plane_url,
            verify=self.cfg.httpx_verify(),
            timeout=15.0,
        )

    def send_once(self) -> None:
        # Snapshot to avoid mutation from RibPoller mid-serialize.
        peers = [
            {
                "peer_id": peer_id,
                **{k: v for k, v in state.items() if k in _PEER_STATE_FIELDS},
            }
            for peer_id, state in dict(self.peer_states).items()
        ]
        body: dict[str, Any] = {
            "agent_version": __version__,
            "peers": peers,
            # #882 — whether the collector is running the peer set the
            # operator saved, or a reverted one. Without this a revert is
            # silent: the collector looks healthy while quietly peering on
            # a config the control plane no longer believes is live.
            "config": self.config_apply.as_dict(),
        }
        sent_token = self.token_ref[0]
        try:
            with self._client() as c:
                resp = c.post(
                    "/api/v1/looking-glass/agents/heartbeat",
                    json=body,
                    headers={"Authorization": f"Bearer {self.token_ref[0]}"},
                )
            if resp.status_code == 200:
                data = resp.json()
                rotated = data.get("rotated_token")
                if rotated:
                    self.token_ref[0] = rotated
                    save_token(self.cfg.state_dir, rotated)
                    log.info("lg_agent_token_rotated")
            elif resp.status_code in (401, 404):
                # Token invalidated or collector row deleted (#2052):
                # re-register from the PSK in this thread; stopping it made
                # the supervisor exit the container.
                log.warning("heartbeat_will_rebootstrap", status=resp.status_code)
                reauthenticate(self.cfg, self.token_ref, sent_token)
            else:
                log.warning("heartbeat_failed", status=resp.status_code)
        except httpx.HTTPError as e:
            log.warning("heartbeat_http_error", error=str(e))

    def run(self) -> None:
        while not self._stop.is_set():
            self.send_once()
            interval = self.cfg.heartbeat_interval + random.uniform(-3, 3)
            self._stop.wait(timeout=max(5.0, interval))
