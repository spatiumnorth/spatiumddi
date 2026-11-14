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

DHCPv6 (#1141) — ``kea-leases6.csv`` beside it, tailed the same way (header
read off a live Kea 3.0.3)::

    address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,
    iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state,user_context,
    hwtype,hwaddr_source,pool_id

A v6 lease is identified by DUID + IAID, not MAC — ``hwaddr`` is usually
empty — so v6 events carry ``duid`` / ``iaid`` and ``mac_address`` only when
Kea learned one. Only IA_NA (``lease_type`` 0) is sent; see
:mod:`.lease_snapshot` for why IA_TA and IA_PD are not.

v6 events are batched SEPARATELY from v4 ones. A control plane older than
#1141 requires ``mac_address`` and rejects the whole batch with a 422 when
one event lacks it — and the spool drops a rejected batch whole. Kept
apart, an older control plane refuses only the v6 batches it could never
have ingested, and the v4 leases beside them still land.
"""

from __future__ import annotations

import csv
import io
import math
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import structlog

from .bootstrap import reauth_generation
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
_DEFAULT_ROW_BYTES = 160  # typical Kea CSV lease row, until some are parsed
# #1077 — idle backlog replay cadence, and how long one replay may run before
# the thread goes back to tailing.
_DRAIN_INTERVAL = 5.0
_DRAIN_BUDGET = 5.0
# #3773 — a lease batch the control plane is still committing is not lost:
# give up on it after 15 s and the resend's batch receipt waits for the
# original's commit anyway (#1077), holding a server connection while it does,
# then answers duplicate. Under a busy Kea HA pair a batch can take longer
# than 15 s, so the read wait matches the frontend proxy's 60 s instead. The
# connect wait stays short, so an unreachable control plane still spools at
# once. Snapshot pages share this client.
_POST_TIMEOUT = httpx.Timeout(60.0, connect=5.0)

# "3" is Kea 3.0's "released" (lease-affinity) state. It used to fall through
# to "active", mirroring a lease the client had released as live.
_STATE_MAP = {"0": "active", "1": "declined", "2": "expired", "3": "released"}


# kea-leases6.csv ``lease_type``: 0 = IA_NA. 1 (IA_TA) and 2 (IA_PD) are skipped.
_LEASE6_IA_NA = "0"


def _rows(data: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(data))) if data else []


def _times(expire_epoch: int, valid_lifetime: int) -> tuple[str | None, str | None]:
    starts_at = (
        datetime.fromtimestamp(expire_epoch - valid_lifetime, tz=timezone.utc).isoformat()
        if expire_epoch and valid_lifetime
        else None
    )
    ends_at = (
        datetime.fromtimestamp(expire_epoch, tz=timezone.utc).isoformat()
        if expire_epoch
        else None
    )
    return starts_at, ends_at


def _parse_row_v6(row: list[str]) -> dict[str, Any] | None:
    """One ``kea-leases6.csv`` row → a v6 lease event, or None to skip."""
    if not row or row[0].startswith("address"):  # header or blank
        return None
    if len(row) < 14:
        return None
    try:
        ip = row[0].strip()
        duid = row[1].strip()
        if not ip or not duid or row[6].strip() != _LEASE6_IA_NA:
            return None
        valid_lifetime = int(row[2]) if row[2] else 0
        expire_epoch = int(row[3]) if row[3] else 0
        iaid = int(row[7]) if row[7].strip() else None
        hostname = row[11].strip() or None
        mac = row[12].strip() or None
        state = _STATE_MAP.get(row[13].strip(), "active")
    except (ValueError, IndexError):
        return None
    starts_at, ends_at = _times(expire_epoch, valid_lifetime)
    return {
        "ip_address": ip,
        "mac_address": mac,
        "duid": duid,
        "iaid": iaid,
        "hostname": hostname,
        "state": state,
        "starts_at": starts_at,
        "ends_at": ends_at,
        "expires_at": ends_at,
    }


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
        starts_at, ends_at = _times(expire_epoch, valid_lifetime)
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


# #3811 — consecutive timed-out / 5xx posts before the control plane counts as
# down (and a snapshot is owed once it answers again). Fewer than this are a
# slow API, retried from the spool as the same batch.
_SLOW_FAILURES_FOR_OUTAGE = 5


def _is_unreachable(exc: httpx.HTTPError) -> bool:
    """True for failures that mean no connection was made (a real outage)."""
    return isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout, httpx.NetworkError)) or (
        isinstance(exc, httpx.TransportError)
        and not isinstance(exc, (httpx.TimeoutException, httpx.ProtocolError))
    )


class LeaseWatcher:
    def __init__(
        self,
        cfg: AgentConfig,
        token_ref: list[str],
        heartbeat: Any,
        spool: Spool | None = None,
        snapshot: LeaseSnapshot | None = None,
        snapshot_v6: LeaseSnapshot | None = None,
    ):
        self.cfg = cfg
        self.token_ref = token_ref
        self.heartbeat = heartbeat
        self._stop = threading.Event()
        self._pending: list[dict[str, Any]] = []
        # #1141 — v6 events, batched apart from v4 (see the module docstring).
        self._pending_v6: list[dict[str, Any]] = []
        # #3782 — events already read from Kea's CSV but not yet delivered or
        # spooled: ``_pending`` plus the slice a flush has taken out of it and
        # is posting right now (``_inflight``, of the list ``_inflight_attr``),
        # plus the rows a read has taken out of the file that ``_tail`` has not
        # yet appended (``_chunks[attr]["held"]``). The on-disk spool counts
        # none of them, so a watcher blocked in a slow POST read as an empty
        # spool while the lease files grew unread behind it.
        self._inflight = 0
        self._inflight_attr = ""
        # Per list: the last file read still being delivered. ``n`` rows that
        # appeared between wall clocks ``lo`` and ``hi``; ``held`` of them not
        # yet appended to the list. The age of the oldest undelivered row is
        # read off that span by how many have been delivered, so it falls as
        # the agent drains instead of waiting for the whole chunk to clear.
        self._chunks: dict[str, dict[str, float]] = {}
        # Row-size observations (bytes / rows actually parsed) turn the unread
        # byte count into an event estimate; ``_read_at`` is when each file
        # was last read to its end, so rows still unread are at most that old.
        self._row_bytes = 0
        self._rows_read = 0
        self._read_at: dict[Path, float] = {}
        self._last_flush = time.monotonic()
        self._last_drain = 0.0
        # Read offset per tailed file (v4 and v6 CSVs rotate independently).
        self._offsets: dict[Path, int] = {}
        # Open handle per tailed file — see _read_new_rows (#4147).
        self._handles: dict[Path, Any] = {}
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
        self._slow_failures = 0
        if snapshot is None:
            snapshot = LeaseSnapshot(cfg.kea_control_socket, self._post_snapshot)
        self.snapshot = snapshot
        if snapshot_v6 is None:
            snapshot_v6 = LeaseSnapshot(cfg.kea_control_socket_v6, self._post_snapshot, family=6)
        self.snapshot_v6 = snapshot_v6
        # Always once per start: the tailer re-reads only kea-leases{4,6}.csv,
        # and a lease untouched since Kea's last LFC is only in the .2 file.
        self.snapshot.request("agent_start")
        self.snapshot_v6.request("agent_start")
        # #2052 — a re-registration in process lands on a NEW server row
        # whose lease table is empty (the old row's leases went with it). A
        # container restart used to cover that with the ``agent_start``
        # snapshot above; now the watcher asks for one when it sees the
        # generation move.
        self._reauth_gen = reauth_generation()
        self._reregistered = False

    def stop(self) -> None:
        self._stop.set()

    def _undelivered(self, attr: str) -> int:
        """Rows of ``attr``'s last read not yet delivered or spooled."""
        chunk = self._chunks.get(attr)
        held = int(chunk["held"]) if chunk else 0
        inflight = self._inflight if self._inflight_attr == attr else 0
        return held + len(getattr(self, attr)) + inflight

    def _chunk_oldest(self, attr: str) -> float | None:
        """Wall clock of the oldest undelivered row of ``attr``'s last read.

        Rows are taken to be evenly spread over the span the read covered, so
        the answer moves forward as rows are delivered."""
        chunk = self._chunks.get(attr)
        undelivered = self._undelivered(attr)
        if not chunk or undelivered <= 0:
            return None
        n = chunk["n"]
        delivered = min(max(n - undelivered, 0), n)
        return chunk["lo"] + (chunk["hi"] - chunk["lo"]) * (delivered / n if n else 0)

    def pending_status(self) -> dict[str, Any]:
        """What the spool cannot see (#3782), for the heartbeat's ``spool``.

        ``pending_events`` is the whole backlog: rows read from Kea's CSV but
        not yet delivered or spooled (held in ``_tail``, buffered, or in
        flight), plus an estimate (``unread_events_estimated``) of the rows
        still unread in the file (``unread_bytes``). ``pending_oldest_at``
        dates the oldest of them and ``pending_lag_seconds`` is that age at
        the moment of this report, so the page need not guess it from a
        heartbeat that is already up to a heartbeat interval old. Both fall as
        the agent catches up.
        """
        now = time.time()
        unread = 0
        oldest_candidates: list[float] = []
        for path in (self.cfg.kea_lease_file, self.cfg.kea_lease_file_v6):
            try:
                size = path.stat().st_size
            except OSError:
                continue
            offset = self._offsets.get(path, 0)
            left = size if size < offset else size - offset
            unread += left
            if left > 0 and path in self._read_at:
                # An unread row is at most as old as the file's last full read.
                oldest_candidates.append(self._read_at[path])
        # An ESTIMATE: unread bytes / the mean row size this agent has parsed
        # (a typical Kea CSV row when it has parsed none yet).
        avg = self._row_bytes / self._rows_read if self._rows_read else _DEFAULT_ROW_BYTES
        est_unread = math.ceil(unread / avg) if unread else 0
        in_hand = self._undelivered("_pending") + self._undelivered("_pending_v6")
        for attr in ("_pending", "_pending_v6"):
            t = self._chunk_oldest(attr)
            if t is not None:
                oldest_candidates.append(t)
        oldest = min(oldest_candidates) if oldest_candidates else None
        return {
            "pending_events": in_hand + est_unread,
            "unread_events_estimated": est_unread,
            "pending_oldest_at": (
                datetime.fromtimestamp(oldest, tz=timezone.utc).isoformat() if oldest else None
            ),
            "pending_lag_seconds": max(0.0, round(now - oldest, 1)) if oldest else None,
            "unread_bytes": unread,
        }

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.cfg.control_plane_url,
            verify=self.cfg.httpx_verify(),
            timeout=_POST_TIMEOUT,
        )

    # ── delivery ─────────────────────────────────────────────────────

    def _post_events(self, payload: dict[str, Any]) -> int:
        """POST one event batch (live or replayed). Counts what landed."""
        try:
            status = self._poster(payload)
        except httpx.HTTPError as exc:
            # #3811 — only a transport failure that says the control plane was
            # unreachable is an outage. A read timeout (or a 5xx below) means
            # the API was reached and merely slow: the batch may have landed,
            # and the spool re-posts it under the SAME batch_id, which the
            # server dedupes. Escalating that to a full-table snapshot adds
            # load exactly when the API is behind.
            if _is_unreachable(exc):
                self._degraded = True
            else:
                self._note_slow_failure()
            raise
        outcome = classify_status(status)
        if outcome == SENT:
            self._slow_failures = 0
            if not self._poster.last_duplicate:
                self.heartbeat.lease_count_since_start += len(payload.get("leases") or [])
            if self._degraded:
                self._degraded = False
                self._recovered = True
        elif outcome == RETRY:
            self._note_slow_failure()
        return status

    def _note_slow_failure(self) -> None:
        """Count a timed-out / 5xx post; a long unbroken run is an outage."""
        self._slow_failures += 1
        if self._slow_failures >= _SLOW_FAILURES_FOR_OUTAGE:
            self._degraded = True

    def _post_snapshot(self, payload: dict[str, Any]) -> int:
        # Snapshot rows are the current lease table, not lease events, so
        # they are deliberately NOT counted in lease_count_since_start.
        return self._poster(payload)

    def _flush(self) -> None:
        # v4 and v6 never share a batch (module docstring).
        self._flush_list("_pending")
        self._flush_list("_pending_v6")
        self._last_flush = time.monotonic()

    def _flush_list(self, attr: str) -> None:
        # Posted in slices of _BATCH_MAX_EVENTS: the spool-disabled path lets
        # the buffer grow past one batch (tick() skips the per-row flush
        # there), and LeaseEventBatch caps a POST at 500 events — an oversize
        # body is a 422, which the spool classifies as REJECTED and drops whole.
        while getattr(self, attr):
            pending: list[dict[str, Any]] = getattr(self, attr)
            batch = pending[:_BATCH_MAX_EVENTS]
            if self._shipper.spool.enabled:
                # Sent, or durably queued behind the backlog — either way no
                # longer this process's to lose.
                # In flight first, so a heartbeat between the two statements
                # never sees the batch in neither place.
                self._inflight_attr = attr
                self._inflight = len(batch)
                setattr(self, attr, pending[len(batch) :])
                try:
                    outcome = self._shipper.ship({"leases": batch})
                finally:
                    self._inflight = 0
                    self._inflight_attr = ""
                if outcome == SENT:
                    log.info("lease_events_flushed", count=len(batch))
            else:
                # Pre-#1077 fallback: keep the batch in memory until it lands.
                # A RETRY leaves it in the buffer for the next flush.
                outcome = self._shipper.ship({"leases": list(batch)})
                if outcome == SENT:
                    log.info("lease_events_flushed", count=len(batch))
                if outcome == RETRY:
                    break
                setattr(self, attr, pending[len(batch) :])

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
        if self._pending or self._pending_v6 or len(self._shipper.spool):
            return
        if self._recovered:
            self._recovered = False
            self.snapshot.request("control_plane_recovered")
            self.snapshot_v6.request("control_plane_recovered")
        if self._reregistered:
            self._reregistered = False
            self.snapshot.request("agent_reregistered")
            self.snapshot_v6.request("agent_reregistered")
        self.snapshot.step()
        self.snapshot_v6.step()

    # ── tailing ──────────────────────────────────────────────────────

    def _drain_handle(self, path: Path, fh: Any) -> str:
        """Read whatever is left in an open lease file, from the saved offset."""
        data: str = fh.read()
        self._offsets[path] = fh.tell()
        return data

    def _read_new_rows(self, path: Path) -> list[list[str]]:
        data = self._read_new_text(path)
        self._read_at[path] = time.time()
        if not data:
            return []
        rows = _rows(data)
        self._row_bytes += len(data.encode("utf-8", errors="replace"))
        self._rows_read += len(rows)
        return rows

    def _read_new_text(self, path: Path) -> str:
        """Text appended to ``path`` since the last call, exactly once each.

        The file is held OPEN between calls (#4147). Kea's lease-file cleanup
        renames the live file to ``.1`` and starts a new one, and its output
        lands in ``.2`` within about a tenth of a second, compacted — so by
        the next read the old file's rows are in no path a byte offset could
        name. The open descriptor keeps the old file readable after the
        rename or delete: the rows Kea appended between our last read and the
        rotation are read from it to the end before the new file is opened
        at offset 0. Rotation is told by inode, so a new file that has
        already outgrown the old offset is not read from the middle; an
        in-place truncation (same inode, shorter file) still restarts at 0.
        """
        fh = self._handles.get(path)
        data = ""
        if fh is not None:
            try:
                data = self._drain_handle(path, fh)
                st = path.stat()
                rotated = st.st_ino != os.fstat(fh.fileno()).st_ino
                truncated = not rotated and st.st_size < fh.tell()
            except FileNotFoundError:
                # Mid-rotation: Kea has renamed the file and not yet created
                # the new one. Keep the handle; the new file is picked up on
                # a later call.
                return data
            except OSError:
                return data
            if rotated:
                fh.close()
                del self._handles[path]
                self._offsets[path] = 0
                fh = None
            elif truncated:
                fh.seek(0)
                self._offsets[path] = 0
        if fh is None:
            try:
                fh = path.open("r", encoding="utf-8", errors="replace")
            except OSError:
                return data
            self._handles[path] = fh
        data += self._drain_handle(path, fh)
        return data

    def _tail(self, path: Path, parse: Any, attr: str) -> None:
        prev_read = self._read_at.get(path)
        rows = self._read_new_rows(path)
        if rows:
            now = self._read_at.get(path, time.time())
            # The rows appeared since the previous read (now, on the first).
            lo = prev_read if prev_read is not None else now
            old = self._chunks.get(attr)
            if self._undelivered(attr) > 0 and old:
                # The last read is still being delivered: its oldest row stays
                # the oldest, and the new rows queue behind it.
                lo = self._chunk_oldest(attr) or lo
                n = self._undelivered(attr) + len(rows)
                held = old["held"] + len(rows)
            else:
                n, held = len(rows), len(rows)
            self._chunks[attr] = {"n": n, "lo": lo, "hi": now, "held": held}
        try:
            for row in rows:
                evt = parse(row)
                if evt is not None:
                    pending: list[dict[str, Any]] = getattr(self, attr)
                    if len(pending) >= _BATCH_MAX_BUFFER:
                        drop = _BATCH_MAX_BUFFER // 2
                        setattr(self, attr, pending[drop:])
                        log.warning("lease_events_buffer_trimmed", dropped=drop)
                    getattr(self, attr).append(evt)
                self._chunks[attr]["held"] -= 1
                if len(getattr(self, attr)) >= _BATCH_MAX_EVENTS and self._shipper.spool.enabled:
                    self._flush()
        finally:
            if rows:
                self._chunks[attr]["held"] = 0

    def tick(self) -> None:
        """One loop iteration: tail, flush, replay, snapshot."""
        gen = reauth_generation()
        if gen != self._reauth_gen:
            self._reauth_gen = gen
            self._reregistered = True
        self._tail(self.cfg.kea_lease_file, _parse_row, "_pending")
        self._tail(self.cfg.kea_lease_file_v6, _parse_row_v6, "_pending_v6")
        buffered = len(self._pending) + len(self._pending_v6)
        if buffered and (
            buffered >= _BATCH_MAX_EVENTS
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
        for fh in self._handles.values():
            fh.close()
        self._handles.clear()
        # Final flush on shutdown — with the spool, a failure here is queued
        # on disk for the next start rather than lost.
        self._flush()
