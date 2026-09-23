"""Kea packet-counter poller — emits per-bucket deltas upstream.

Reads Kea's ``statistic-get-all`` every 60 s over the local control
socket, converts monotonically-increasing packet counters into
per-bucket deltas (subtracting the previous snapshot), and POSTs one
sample to ``/api/v1/dhcp/agents/metrics``. Counter resets caused by a
Kea restart are detected as ``delta < 0``; in that case we discard
the bucket and seed the next snapshot fresh — better to drop one
bucket than emit a spurious negative-turned-positive spike when the
new counters climb back up.

Kea statistic names we care about. The eight column names on
``dhcp_metric_sample`` were v4-shaped originally and now do double
duty for v6 by mapping each v6 message to the v4 column with the
closest role-equivalent semantics (SOLICIT≈DISCOVER, ADVERTISE≈
OFFER, REPLY≈ACK, INFORMATION-REQUEST≈INFORM, RENEW+REBIND fold
into ``request``). Issue #264 — both stacks share one row per
server so operators running v6 finally get per-bucket numbers
without a schema migration.

    pkt4-discover-received                pkt6-solicit-received        → discover
    pkt4-offer-sent                       pkt6-advertise-sent          → offer
    pkt4-request-received                 pkt6-request-received
                                          pkt6-renew-received
                                          pkt6-rebind-received         → request
    pkt4-ack-sent                         pkt6-reply-sent              → ack
    pkt4-nak-sent                                                      → nak
    pkt4-decline-received                 pkt6-decline-received        → decline
    pkt4-release-received                 pkt6-release-received        → release
    pkt4-inform-received                  pkt6-information-request-received → inform
    pkt4-receive-drop                     pkt6-receive-drop            → receive_drop

Two *loss* signals ride alongside those, added for issue #980, and they
name different failures:

* ``receive_drop`` — packets Kea read off the socket and then discarded
  (unparseable, matched the ``DROP`` class, no subnet selected).
* ``socket_drop`` — packets the kernel dropped because Kea's receive
  buffer was full, so Kea never saw them at all. Read from
  ``/proc/net/udp`` by :mod:`.socket_drops`, not from Kea.

The distinction is the point. Measured against kea-dhcp4 3.0.3 on
2026-09-06, a run that lost 9,700 datagrams to buffer overflow reported
``pkt4-receive-drop = 0`` throughout: a server starved of CPU answers
100 % of what it reads, and every Kea-sourced counter agrees it is
healthy. Only ``socket_drop`` moves.

Both are ``None`` — not 0 — when they could not be measured, so an agent
that cannot read them, or one older than this change, is reported as
UNKNOWN rather than as a server with no loss.

Delivery (#1077): a bucket the control plane does not accept is kept in the
``metrics`` stream of the durable spool and replayed, oldest first, when it
answers again. The baseline advances on every poll regardless of whether the
report landed — the interval's delta is queued, not lost — and each bucket
keeps the ``bucket_at`` it was measured at, so a replay fills the gap in the
time series instead of stacking a day of traffic onto the reconnect minute.
The ``batch_id`` the spool stamps is what keeps a replay of the bucket in
flight at the moment of an outage from being counted twice: the ingest
ACCUMULATES per ``(server_id, bucket_at)`` (#980), so without it a lost
response would double that minute.
"""

from __future__ import annotations

import random
import threading
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog

from .config import AgentConfig
from .kea_ctrl import KeaCtrlError, send_command
from .push import CPPoster, disabled_spool, drain_for, late_bound
from .socket_drops import SocketDropCounter
from .spool import RETRY, Shipper, Spool

log = structlog.get_logger(__name__)

# Map Kea's statistic names to the column names on dhcp_metric_sample.
# Multiple v6 message types fold into a single v4-shaped column when
# their roles align — see the module docstring for the mapping
# rationale (issue #264).
_STAT_MAP = {
    "pkt4-discover-received": "discover",
    "pkt4-offer-sent": "offer",
    "pkt4-request-received": "request",
    "pkt4-ack-sent": "ack",
    "pkt4-nak-sent": "nak",
    "pkt4-decline-received": "decline",
    "pkt4-release-received": "release",
    "pkt4-inform-received": "inform",
    "pkt6-solicit-received": "discover",
    "pkt6-advertise-sent": "offer",
    "pkt6-request-received": "request",
    "pkt6-renew-received": "request",
    "pkt6-rebind-received": "request",
    "pkt6-reply-sent": "ack",
    "pkt6-decline-received": "decline",
    "pkt6-release-received": "release",
    "pkt6-information-request-received": "inform",
    "pkt4-receive-drop": "receive_drop",
    "pkt6-receive-drop": "receive_drop",
}

# Column names — the unique set of values from ``_STAT_MAP``, used by
# ``_compute_delta`` so a multi-stat → single-column mapping doesn't
# re-diff the same column twice.
_METRIC_COLUMNS = sorted(set(_STAT_MAP.values()))

METRICS_PATH = "/api/v1/dhcp/agents/metrics"
# #1077 — how long one poll tick may spend replaying a backlog. A day-long
# outage is ~1,440 one-row buckets; at 50 per drain pass the replay would
# otherwise take half an hour of ticks.
DRAIN_BUDGET = 20.0


def _extract_counter(series: Any) -> int | None:
    """Pull the most recent numeric value from one ``statistic-get-all`` entry.

    Kea returns a list of ``[value, timestamp]`` pairs, newest first —
    e.g. ``[[125, "2026-04-22 09:00:00.001"], [120, ...]]``. Shape is
    stable across Kea 2.4-2.6. We tolerate empty lists / missing
    values so a fresh daemon that hasn't ticked a counter yet shows
    up as 0 rather than crashing the poller.
    """
    if not isinstance(series, list) or not series:
        return 0
    first = series[0]
    if isinstance(first, list) and first:
        v = first[0]
        if isinstance(v, int):
            return v
        if isinstance(v, float):
            return int(v)
    return None


def _parse_snapshot(resp: dict[str, Any]) -> dict[str, int]:
    """``statistic-get-all`` → flat ``{column: current_counter}`` dict.

    Multiple stat names can map to the same column (e.g. ``pkt6-
    renew-received`` + ``pkt6-rebind-received`` both feed ``request``);
    in that case we sum the counters so the column carries the
    full per-role activity.
    """
    args = resp.get("arguments") or {}
    out: dict[str, int] = {}
    for stat_name, col in _STAT_MAP.items():
        v = _extract_counter(args.get(stat_name))
        if v is not None:
            out[col] = out.get(col, 0) + v
    return out


class MetricsPoller:
    def __init__(
        self, cfg: AgentConfig, token_ref: list[str], spool: Spool | None = None
    ):
        self.cfg = cfg
        self.token_ref = token_ref
        self._shipper = Shipper(
            spool if spool is not None else disabled_spool("metrics"),
            CPPoster(cfg, token_ref, METRICS_PATH, late_bound(self, "_client")),
            event_prefix="metrics_report",
        )
        self._stop = threading.Event()
        # Previous snapshot. None on first tick — the first post-boot
        # bucket is absorbed (no baseline to diff against).
        self._prev: dict[str, int] | None = None
        # #980 — kernel-side loss, sampled in lockstep with the Kea
        # counters so both deltas always cover the same interval.
        self._socket = SocketDropCounter()

    def stop(self) -> None:
        self._stop.set()

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.cfg.control_plane_url,
            verify=self.cfg.httpx_verify(),
            timeout=15.0,
        )

    def _poll_kea(self) -> dict[str, int] | None:
        try:
            resp = send_command(self.cfg.kea_control_socket, "statistic-get-all")
        except KeaCtrlError as e:
            log.debug("metrics_kea_err", error=str(e))
            return None
        except FileNotFoundError:
            return None
        except Exception as e:  # noqa: BLE001
            log.warning("metrics_kea_unexpected", error=str(e))
            return None
        return _parse_snapshot(resp)

    def _compute_delta(self, current: dict[str, int]) -> dict[str, int] | None:
        prev = self._prev
        self._prev = current
        if prev is None:
            return None  # first bucket — no baseline
        delta: dict[str, int] = {}
        reset = False
        for col in _METRIC_COLUMNS:
            d = current.get(col, 0) - prev.get(col, 0)
            if d < 0:
                reset = True
                break
            delta[col] = d
        if reset:
            log.info("metrics_counter_reset")
            return None
        return delta

    def _report(
        self, bucket_at: datetime, delta: dict[str, int], socket_drop: int | None
    ) -> str:
        """Returns the spool outcome (``sent`` / ``retry`` / ``rejected``)."""
        # Sent now, or spooled (behind any backlog) for replay — never dropped
        # while the spool is enabled and has room.
        return self._shipper.ship(
            {
                "bucket_at": bucket_at.isoformat(),
                "socket_drop": socket_drop,
                **delta,
            }
        )

    def run(self) -> None:
        while not self._stop.is_set():
            self._shipper.last_send_outcome = None
            current = self._poll_kea()
            if current is not None:
                delta = self._compute_delta(current)
                # Sampled unconditionally so its baseline advances in step
                # with the Kea one: a bucket that is dropped (agent start,
                # Kea restart) drops BOTH deltas, and the pair that is
                # reported always covers the same interval. Advancing only
                # one of the two would smear an interval's kernel drops
                # into a bucket whose Kea counters exclude them, and the
                # first comparison anyone makes is drops against DISCOVERs.
                socket_drop = self._socket.sample()
                if delta is not None:
                    # Bucket timestamp is "now, rounded to the poll
                    # interval". The server ACCUMULATES per
                    # (server_id, bucket_at) (#980), so it is the spool's
                    # batch_id — not the timestamp — that stops a replayed
                    # bucket being counted twice (#1077).
                    now = datetime.now(UTC).replace(microsecond=0)
                    bucket = now.replace(second=(now.second // 60) * 60)
                    self._report(bucket, delta, socket_drop)
            # Replay whatever the spool still holds — covers a tick with no
            # bucket to report (first poll, Kea down) as well as a backlog
            # longer than the slice ``ship`` drains ahead of a live bucket.
            # Skipped when a POST this tick already found the control plane
            # down: a second attempt would only cost another timeout. Keyed
            # on the last ATTEMPTED send, not on ``_report``'s return — that
            # is RETRY whenever the live bucket was queued behind a backlog
            # longer than one drain slice, i.e. on exactly the long-outage
            # replay this budget exists for.
            if self._shipper.last_send_outcome != RETRY:
                drain_for(self._shipper, DRAIN_BUDGET)
            # 60s base + small jitter so paired peers don't hit the
            # control plane in lockstep.
            interval = 60.0 + random.uniform(-3, 3)
            self._stop.wait(timeout=max(30.0, interval))
