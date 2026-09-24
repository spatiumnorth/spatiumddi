"""Lease watcher — tail the Kea memfile CSV and batch-post lease events.

Kea's ``lease_cmds`` hook also supports programmatic queries; as a simple and
robust default we tail the lease file (``KEA_LEASE_FILE``). Events are flushed
to the control plane every 5 seconds or every 100 events, whichever comes first.
The hook is used for the backstop instead: a full lease-table walk after start
and after every recovery from an outage (:mod:`.lease_snapshot`).

Delivery (#1077): this is the ONLY way the control plane learns about Kea
leases, so a batch it does not accept is kept in the ``lease_events`` stream of
the durable spool and replayed in order when it answers again — surviving an
agent restart, which the old in-memory retry buffer did not. The #430 bound on
that buffer is now the spool's byte cap (trim oldest, counted on the
heartbeat). ``AGENT_SPOOL_ENABLED=false`` falls back to the pre-#1077
in-memory retry buffer.

Kea memfile CSV format (v4)::

    address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,
    hostname,state,user_context,hwtype,hwaddr_source,pool_id

``state`` values: 0=default (active), 1=declined, 2=expired-reclaimed,
3=released (Kea 3.0 lease affinity).
"""

from __future__ import annotations

import csv
import io
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import structlog

from .config import AgentConfig
from .lease_snapshot import LeaseSnapshot
from .push import CPPoster, disabled_spool, drain_for, late_bound
from .spool import RETRY, SENT, Shipper, Spool, classify_status

log = structlog.get_logger(__name__)

LEASE_EVENTS_PATH = "/api/v1/dhcp/agents/lease-events"
_BATCH_MAX_EVENTS = 100
_BATCH_MAX_SECONDS = 5.0
# #430 — hard cap on the in-memory buffer. With the spool enabled every flush
# empties it (sent, or appended to the spool), so this only bites in the
# spool-disabled fallback, where a persistent failure leaves _pending
# unflushed while run() keeps appending new lease rows. Trim-half on overflow.
_BATCH_MAX_BUFFER = 5000
# #1077 — idle backlog replay cadence, and how long one replay may run before
# the thread goes back to tailing.
_DRAIN_INTERVAL = 5.0
_DRAIN_BUDGET = 5.0

# "3" is Kea 3.0's "released" (lease-affinity) state. It used to fall through
# to "active", mirroring a lease the client had released as live.
_STATE_MAP = {"0": "active", "1": "declined", "2": "expired", "3": "released"}


def _parse_row(row: list[str]) -> dict[str, Any] | None:
    if not row or row[0].startswith("address"):  # header or blank
        return None
    if len(row) < 10:
        return None
    try:
        ip = row[0].strip()
        mac = row[1].strip() or None
        # #428: the server keys leases on (ip, mac) and mac_address is a
        # required field — a MAC-less row can't be mirrored, so skip it
        # rather than 422 the whole batch (mirrors the Windows pull path,
        # which drops leases with no ClientId).
        if not ip or not mac:
            return None
        valid_lifetime = int(row[3]) if row[3] else 0
        expire_epoch = int(row[4]) if row[4] else 0
        hostname = row[8].strip() or None
        state = _STATE_MAP.get(row[9].strip(), "active")
        starts_at = (
            datetime.fromtimestamp(
                expire_epoch - valid_lifetime, tz=timezone.utc
            ).isoformat()
            if expire_epoch and valid_lifetime
            else None
        )
        ends_at = (
            datetime.fromtimestamp(expire_epoch, tz=timezone.utc).isoformat()
            if expire_epoch
            else None
        )
        # #428: emit the server's LeaseEventBatch/LeaseEvent shape exactly —
        # field names ip_address/mac_address (NOT ip/mac) and an explicit
        # expires_at (Kea's CSV `expire` is the absolute reclaim time, same
        # as ends_at). The old {ip,mac,ends_at} shape was silently dropped
        # by the server's Pydantic model (leases defaulted to [], HTTP 200),
        # so no Kea lease ever reached IPAM/DDNS.
        return {
            "ip_address": ip,
            "mac_address": mac,
            "hostname": hostname,
            "state": state,
            "starts_at": starts_at,
            "ends_at": ends_at,
            "expires_at": ends_at,
        }
    except (ValueError, IndexError):
        return None


class LeaseWatcher:
    def __init__(
        self,
        cfg: AgentConfig,
        token_ref: list[str],
        heartbeat: Any,
        spool: Spool | None = None,
        snapshot: LeaseSnapshot | None = None,
    ):
        self.cfg = cfg
        self.token_ref = token_ref
        self.heartbeat = heartbeat
        self._stop = threading.Event()
        self._pending: list[dict[str, Any]] = []
        self._last_flush = time.monotonic()
        self._last_drain = 0.0
        self._offset = 0
        self._poster = CPPoster(cfg, token_ref, LEASE_EVENTS_PATH, late_bound(self, "_client"))
        self._shipper = Shipper(
            spool if spool is not None else disabled_spool("lease_events"),
            self._post_events,
            event_prefix="lease_events",
            retry_backoff_seconds=_BATCH_MAX_SECONDS,
        )
        # Outage tracking for the snapshot trigger: ``_degraded`` is set by any
        # lease POST the control plane did not take, ``_recovered`` by the
        # first one it did take afterwards. The snapshot itself waits until
        # the backlog has fully drained (see ``_maybe_snapshot``).
        self._degraded = False
        self._recovered = False
        if snapshot is None:
            snapshot = LeaseSnapshot(cfg.kea_control_socket, self._post_snapshot)
        self.snapshot = snapshot
        # Always once per start: the tailer re-reads only kea-leases4.csv, and
        # a lease untouched since Kea's last LFC is only in kea-leases4.csv.2.
        self.snapshot.request("agent_start")

    def stop(self) -> None:
        self._stop.set()

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.cfg.control_plane_url,
            verify=self.cfg.httpx_verify(),
            timeout=15.0,
        )

    # ── delivery ─────────────────────────────────────────────────────

    def _post_events(self, payload: dict[str, Any]) -> int:
        """POST one event batch (live or replayed). Counts what landed."""
        try:
            status = self._poster(payload)
        except httpx.HTTPError:
            self._degraded = True
            raise
        outcome = classify_status(status)
        if outcome == SENT:
            if not self._poster.last_duplicate:
                self.heartbeat.lease_count_since_start += len(payload.get("leases") or [])
            if self._degraded:
                self._degraded = False
                self._recovered = True
        elif outcome == RETRY:
            self._degraded = True
        return status

    def _post_snapshot(self, payload: dict[str, Any]) -> int:
        # Snapshot rows are the current lease table, not lease events, so
        # they are deliberately NOT counted in lease_count_since_start.
        return self._poster(payload)

    def _flush(self) -> None:
        if not self._pending:
            self._last_flush = time.monotonic()
            return
        # Posted in slices of _BATCH_MAX_EVENTS: the spool-disabled path lets
        # _pending grow past one batch (tick() skips the per-row flush there),
        # and LeaseEventBatch caps a POST at 500 events — an oversize body is
        # a 422, which the spool classifies as REJECTED and drops whole.
        while self._pending:
            batch = self._pending[:_BATCH_MAX_EVENTS]
            if self._shipper.spool.enabled:
                # Sent, or durably queued behind the backlog — either way no
                # longer this process's to lose.
                self._pending = self._pending[len(batch) :]
                outcome = self._shipper.ship({"leases": batch})
                if outcome == SENT:
                    log.info("lease_events_flushed", count=len(batch))
            else:
                # Pre-#1077 fallback: keep the batch in memory until it lands.
                # A RETRY leaves it in _pending for the next flush.
                outcome = self._shipper.ship({"leases": list(batch)})
                if outcome == SENT:
                    log.info("lease_events_flushed", count=len(batch))
                if outcome == RETRY:
                    break
                self._pending = self._pending[len(batch) :]
        self._last_flush = time.monotonic()

    def _maybe_drain(self) -> None:
        if not len(self._shipper.spool):
            return
        now = time.monotonic()
        if now - self._last_drain < _DRAIN_INTERVAL:
            return
        self._last_drain = now
        drain_for(self._shipper, _DRAIN_BUDGET)

    def _maybe_snapshot(self) -> None:
        """Advance the lease-table snapshot, if one is due and it is safe.

        Held off while any event is unsent or spooled: those are all older
        than a page read now, and replaying them after it would roll leases
        back to a stale state.
        """
        if self._pending or len(self._shipper.spool):
            return
        if self._recovered:
            self._recovered = False
            self.snapshot.request("control_plane_recovered")
        self.snapshot.step()

    # ── tailing ──────────────────────────────────────────────────────

    def _read_new_rows(self, path: Path) -> list[list[str]]:
        if not path.exists():
            return []
        try:
            size = path.stat().st_size
        except OSError:
            return []
        if size < self._offset:
            # File rotated / truncated by Kea LFC
            self._offset = 0
        if size == self._offset:
            return []
        with path.open("r", encoding="utf-8", errors="replace") as f:
            f.seek(self._offset)
            data = f.read()
            self._offset = f.tell()
        if not data:
            return []
        reader = csv.reader(io.StringIO(data))
        return list(reader)

    def tick(self) -> None:
        """One loop iteration: tail, flush, replay, snapshot."""
        rows = self._read_new_rows(self.cfg.kea_lease_file)
        for row in rows:
            evt = _parse_row(row)
            if evt is not None:
                if len(self._pending) >= _BATCH_MAX_BUFFER:
                    drop = _BATCH_MAX_BUFFER // 2
                    self._pending = self._pending[drop:]
                    log.warning("lease_events_buffer_trimmed", dropped=drop)
                self._pending.append(evt)
            if len(self._pending) >= _BATCH_MAX_EVENTS and self._shipper.spool.enabled:
                self._flush()
        if self._pending and (
            len(self._pending) >= _BATCH_MAX_EVENTS
            or (time.monotonic() - self._last_flush) >= _BATCH_MAX_SECONDS
        ):
            self._flush()
        else:
            self._maybe_drain()
        self._maybe_snapshot()

    def run(self) -> None:
        while not self._stop.is_set():
            self.tick()
            self._stop.wait(1.0)
        # Final flush on shutdown — with the spool, a failure here is queued
        # on disk for the next start rather than lost.
        self._flush()
