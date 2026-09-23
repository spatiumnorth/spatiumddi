"""Kea lease snapshot — the pull backstop behind the lease-event push (#1077).

The control plane learns about Kea leases only through
``POST /api/v1/dhcp/agents/lease-events``: ``KeaDriver.get_leases()`` is a
stub and the control-plane lease pull skips agent-based drivers. The durable
spool closes most of the gap a control-plane outage used to open, but not all
of it — the spool can trim at its byte cap, and the CSV tailer only ever reads
``kea-leases4.csv``, which Kea's lease-file cleanup (LFC, hourly) rotates into
``kea-leases4.csv.2``. A lease that has not changed since the last LFC is in no
file the tailer reads.

So after a start, and after every recovery from an outage, the agent walks
Kea's whole in-memory lease table over the control socket
(``lease4-get-page``, served by ``libdhcp_lease_cmds.so``, which
``render_kea`` always loads) and posts it to the SAME endpoint in the SAME
event shape the tailer produces. The ingest is an upsert, so a lease the
control plane already has costs one no-op update; one it missed appears.

Why not spooled: a snapshot is regenerable. If the control plane goes away
mid-walk the run is abandoned and repeated later — queueing a stale picture
of the lease table behind live events would be worse than not sending it.

Why stepwise: :meth:`LeaseSnapshot.step` walks at most a bounded time slice
of pages and returns, so the lease tailer that drives it keeps tailing between
slices. Driving it from the tailer's own thread is deliberate — it is what
orders the two writers correctly. A page is fetched and posted before the
tailer reads its next CSV rows, so any lease change newer than that page
reaches the control plane AFTER it and wins the upsert; a separate thread
could post a page read before a change after the event for that change,
rolling the lease back. The tailer additionally holds a step off while it has
unsent or spooled events, which are all older than any page read now.

DHCPv4 only: the agent has never tailed ``kea-leases6.csv`` either, and the
control plane's lease ingest is keyed on a MAC that most DHCPv6 leases (DUID-
identified) do not carry. Adding v6 here alone would make v6 leases appear
only at snapshot time — a half-feature that reads as a working one.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import structlog

from .kea_ctrl import KeaCtrlError, send_command
from .spool import RETRY, SENT, classify_status

log = structlog.get_logger(__name__)

PAGE_COMMAND = "lease4-get-page"
# Matches the tailer's batch size and the control plane's per-POST ingest
# expectation (``LeaseEventBatch`` is sized for ~100 events a POST).
DEFAULT_PAGE_SIZE = 100
# A snapshot is a full walk of the lease table; more than one every five
# minutes is load for no information.
DEFAULT_MIN_INTERVAL = 300.0
# How long one step may walk before handing the thread back to the tailer.
DEFAULT_STEP_BUDGET = 2.0
# Kea not answering yet (cold start, restart): back off, bounded.
_KEA_BACKOFF_START = 5.0
_KEA_BACKOFF_MAX = 60.0
_KEA_MAX_ATTEMPTS = 20  # ~15 min of waiting before giving up until the next trigger

# Kea lease states. 3 ("released") is Kea 3.0's lease-affinity state — a
# released lease the server is holding for the same client, not a live one.
_KEA_STATES = {0: "active", 1: "declined", 2: "expired", 3: "released"}
# Kea result code for "command succeeded, nothing to return".
_KEA_RESULT_EMPTY = 3


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).isoformat()


def kea_lease_to_event(lease: dict[str, Any]) -> dict[str, Any] | None:
    """One ``lease4-get-page`` entry → the tailer's ``_parse_row`` event shape.

    Same field names, same MAC-less skip (#428 — ``mac_address`` is required
    server-side), same timestamp semantics: Kea's ``cltt`` is the time the
    lease was last granted and ``cltt + valid-lft`` is the absolute expiry,
    which is exactly the CSV's ``expire - valid_lifetime`` / ``expire`` pair.
    """
    if not isinstance(lease, dict):
        return None
    ip = str(lease.get("ip-address") or "").strip()
    mac = str(lease.get("hw-address") or "").strip()
    if not ip or not mac:
        return None
    try:
        cltt = int(lease.get("cltt") or 0)
        valid_lft = int(lease.get("valid-lft") or 0)
        state_code = int(lease.get("state") or 0)
    except (TypeError, ValueError):
        return None
    hostname = str(lease.get("hostname") or "").strip() or None
    ends_at = _iso(cltt + valid_lft) if cltt else None
    return {
        "ip_address": ip,
        "mac_address": mac,
        "hostname": hostname,
        # Unknown codes read as active, matching the CSV path.
        "state": _KEA_STATES.get(state_code, "active"),
        "starts_at": _iso(cltt) if cltt and valid_lft else None,
        "ends_at": ends_at,
        "expires_at": ends_at,
    }


class LeaseSnapshot:
    """Stepwise, throttled walk of Kea's v4 lease table.

    ``post(payload) -> int`` delivers one ``{"leases": [...]}`` batch and
    returns the HTTP status (a raised :class:`httpx.HTTPError` means
    unreachable). ``fetch`` defaults to the Kea control socket and exists so
    tests can serve pages without one.
    """

    def __init__(
        self,
        socket_path: Path,
        post: Callable[[dict[str, Any]], int],
        *,
        page_size: int = DEFAULT_PAGE_SIZE,
        min_interval: float = DEFAULT_MIN_INTERVAL,
        clock: Callable[[], float] = time.monotonic,
        fetch: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> None:
        self.socket_path = socket_path
        self._post = post
        self.page_size = max(1, int(page_size))
        self.min_interval = min_interval
        self._clock = clock
        self._fetch = fetch or self._fetch_from_kea
        self._due = False
        self._reason = ""
        self._cursor: str | None = None
        self._last_started: float | None = None
        self._not_before = 0.0
        self._kea_failures = 0
        self._run_sent = 0
        self._run_skipped = 0
        self.runs_completed = 0

    # ── public ───────────────────────────────────────────────────────

    @property
    def running(self) -> bool:
        return self._cursor is not None

    @property
    def due(self) -> bool:
        return self._due

    def request(self, reason: str) -> None:
        """Ask for a snapshot. Throttled in :meth:`step`, not here.

        Ignored while a walk is in progress: that walk is already reading the
        current table, and if the control plane dropped out under it the walk
        fails and re-arms itself.
        """
        if self.running:
            return
        if not self._due:
            log.info("lease_snapshot_requested", reason=reason)
        self._due = True
        self._reason = reason
        self._kea_failures = 0
        self._not_before = 0.0

    def step(self, budget_seconds: float = DEFAULT_STEP_BUDGET) -> bool:
        """Walk pages for up to ``budget_seconds``. True while a walk is open."""
        deadline = self._clock() + budget_seconds
        while True:
            if not self._step_page():
                return self.running
            if self._clock() >= deadline:
                return self.running

    # ── internals ────────────────────────────────────────────────────

    def _fetch_from_kea(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return send_command(
            self.socket_path,
            PAGE_COMMAND,
            arguments,
            accept_results=(0, _KEA_RESULT_EMPTY),
        )

    def _can_start(self, now: float) -> bool:
        if not self._due or now < self._not_before:
            return False
        return self._last_started is None or now - self._last_started >= self.min_interval

    def _step_page(self) -> bool:
        """Fetch + post one page. True when there is more to walk right now."""
        now = self._clock()
        starting = self._cursor is None
        if starting:
            if not self._can_start(now):
                return False
            self._cursor = "start"
            self._run_sent = 0
            self._run_skipped = 0
        cursor = self._cursor
        if cursor is None:  # unreachable; keeps the type narrow without an assert
            return False
        try:
            resp = self._fetch({"from": cursor, "limit": self.page_size})
        except (KeaCtrlError, OSError) as exc:
            self._on_kea_failure(now, first_page=cursor == "start", error=str(exc))
            return False
        if cursor == "start":
            # Kea answered: the walk is under way. The throttle counts from
            # here, so a Kea that is not up yet does not burn the interval.
            self._last_started = now
            self._due = False
            self._kea_failures = 0
            log.info("lease_snapshot_started", reason=self._reason)

        args = resp.get("arguments") if isinstance(resp, dict) else None
        raw = args.get("leases") if isinstance(args, dict) else None
        leases = raw if isinstance(raw, list) else []
        empty = isinstance(resp, dict) and resp.get("result") == _KEA_RESULT_EMPTY

        events = [e for e in (kea_lease_to_event(le) for le in leases) if e is not None]
        self._run_skipped += len(leases) - len(events)
        if events and not self._post_page(events):
            return False

        last_ip = None
        if leases and isinstance(leases[-1], dict):
            last_ip = str(leases[-1].get("ip-address") or "") or None
        if empty or len(leases) < self.page_size or last_ip is None:
            self._finish()
            return False
        self._cursor = last_ip
        return True

    def _post_page(self, events: list[dict[str, Any]]) -> bool:
        payload = {"leases": events, "batch_id": uuid.uuid4().hex}
        try:
            outcome = classify_status(self._post(payload))
        except httpx.HTTPError as exc:
            log.warning("lease_snapshot_post_http_error", error=str(exc))
            outcome = RETRY
        if outcome == RETRY:
            # The control plane went away mid-walk. Abandon the walk and
            # re-arm it; the throttle spaces the retry, and the tailer's
            # recovery trigger asks again once events flow.
            log.warning("lease_snapshot_aborted", sent=self._run_sent)
            self._cursor = None
            self._due = True
            return False
        if outcome == SENT:
            self._run_sent += len(events)
        else:
            # A verdict on these rows. Retrying cannot change it, and
            # stopping would hide every lease after them.
            log.warning("lease_snapshot_page_rejected", count=len(events))
        return True

    def _on_kea_failure(self, now: float, *, first_page: bool, error: str) -> None:
        self._cursor = None
        self._due = True
        self._kea_failures += 1
        if first_page and self._kea_failures > _KEA_MAX_ATTEMPTS:
            # Kea has not answered for ~15 min. Stop polling it; the next
            # trigger (recovery, restart) starts the count again.
            log.warning("lease_snapshot_kea_unavailable", attempts=self._kea_failures, error=error)
            self._due = False
            return
        backoff = min(_KEA_BACKOFF_MAX, _KEA_BACKOFF_START * (2 ** max(0, self._kea_failures - 1)))
        self._not_before = now + backoff
        log.debug("lease_snapshot_kea_not_ready", error=error, retry_in=backoff)

    def _finish(self) -> None:
        self._cursor = None
        self.runs_completed += 1
        log.info(
            "lease_snapshot_completed",
            reason=self._reason,
            leases=self._run_sent,
            skipped=self._run_skipped,
        )


__all__ = ["PAGE_COMMAND", "LeaseSnapshot", "kea_lease_to_event"]
