"""Tails Kea's ``kea-dhcp4.log`` file and ships batches to the control plane.

The agent's ``render_kea`` adds a file ``output_options`` entry to
the Kea logger config (``/var/log/kea/kea-dhcp4.log`` by default;
overridable via ``DHCP_LOG_PATH``). Kea handles rotation in-process
via its ``maxsize`` / ``maxver`` settings — we just follow the
file like ``tail -F`` and re-open on inode change.

Same shape as the DNS agent's ``QueryLogShipper`` — see that module
for the tailing notes (file may not exist yet on first boot, rotation,
etc).

A batch the control plane does not accept is kept in the ``dhcp_log``
stream of the durable spool (#1077) and replayed, oldest first, once it
answers again — so a maintenance window no longer loses the window's DHCP
activity. Kea's lines carry their own timestamps (``kea_parser`` reads the
time from the line), so a late batch lands on the minute it happened. The
spool's age limit drops lines the control plane's 24 h log retention would
prune on arrival anyway. ``AGENT_SPOOL_ENABLED=false`` restores the old
drop-on-failure behaviour.

The daemon is never blocked: after a failed POST the shipper backs off for
``BATCH_INTERVAL`` and appends straight to the spool, so a black-holed
control plane costs a local disk write per batch rather than a connect
timeout. The in-memory buffer only holds lines read but not yet flushed;
every full batch is flushed each tick, and the ``MAX_BUFFER_LINES`` trim is
a last-resort OOM guard.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import TextIO

import httpx
import structlog

from .config import AgentConfig
from .push import CPPoster, disabled_spool, drain_for
from .spool import RETRY, Shipper, Spool

log = structlog.get_logger(__name__)

DEFAULT_DHCP_LOG_PATH = "/var/log/kea/kea-dhcp4.log"

MAX_BATCH = 200
BATCH_INTERVAL = 5.0
MAX_BUFFER_LINES = 5_000
TAIL_POLL_INTERVAL = 0.5
FILE_WAIT_INTERVAL = 5.0
# Upper bound on batches flushed in one tick, so a large burst can't starve
# rotation checks / stop() for long.
MAX_FLUSHES_PER_TICK = MAX_BUFFER_LINES // MAX_BATCH
# #1077 — how often an idle shipper retries its backlog, and how long one
# retry may spend replaying before it goes back to tailing.
DRAIN_INTERVAL = 10.0
DRAIN_BUDGET = 5.0
LOG_ENTRIES_PATH = "/api/v1/dhcp/agents/log-entries"


class LogShipper:
    """Tail thread + batching POST loop."""

    def __init__(
        self,
        cfg: AgentConfig,
        token_ref: list[str],
        path: str | None = None,
        spool: Spool | None = None,
    ) -> None:
        self.cfg = cfg
        self.token_ref = token_ref
        self.path = Path(path or os.environ.get("DHCP_LOG_PATH") or DEFAULT_DHCP_LOG_PATH)
        self._stop = threading.Event()
        self._buffer: list[str] = []
        self._last_flush = time.monotonic()
        self._last_drain = 0.0
        self._fh: TextIO | None = None
        self._inode: int | None = None
        self._shipper = Shipper(
            spool if spool is not None else disabled_spool("dhcp_log"),
            CPPoster(cfg, token_ref, LOG_ENTRIES_PATH, lambda: self._cp_client()),
            event_prefix="dhcp_log_ship",
            retry_backoff_seconds=BATCH_INTERVAL,
        )

    def stop(self) -> None:
        self._stop.set()

    def _cp_client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.cfg.control_plane_url,
            verify=self.cfg.httpx_verify(),
            timeout=15.0,
        )

    def _open(self) -> bool:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return False
        try:
            self._fh = self.path.open("r", encoding="utf-8", errors="replace")
        except OSError as exc:
            log.debug("dhcp_log_open_failed", path=str(self.path), error=str(exc))
            return False
        self._fh.seek(0, os.SEEK_END)
        self._inode = st.st_ino
        log.info("dhcp_log_attached", path=str(self.path), inode=self._inode)
        return True

    def _close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
        self._fh = None
        self._inode = None

    def _check_rotation(self) -> None:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            self._close()
            return
        if self._inode is not None and st.st_ino != self._inode:
            log.info("dhcp_log_rotated", path=str(self.path))
            self._close()
            self._open()

    def _read_available(self) -> None:
        if self._fh is None:
            return
        while True:
            try:
                line = self._fh.readline()
            except OSError as exc:
                log.warning("dhcp_log_read_failed", error=str(exc))
                self._close()
                return
            if not line:
                break
            if len(self._buffer) >= MAX_BUFFER_LINES:
                drop = MAX_BUFFER_LINES // 2
                self._buffer = self._buffer[drop:]
                log.warning("dhcp_log_buffer_trimmed", dropped=drop)
            self._buffer.append(line.rstrip("\n"))

    def _should_flush(self) -> bool:
        if not self._buffer:
            return False
        if len(self._buffer) >= MAX_BATCH:
            return True
        return (time.monotonic() - self._last_flush) >= BATCH_INTERVAL

    def _flush(self) -> str:
        batch = self._buffer[:MAX_BATCH]
        self._buffer = self._buffer[MAX_BATCH:]
        try:
            # Sent now, or queued behind the backlog (spooled on failure).
            return self._shipper.ship({"lines": batch})
        finally:
            self._last_flush = time.monotonic()

    def _maybe_drain(self) -> None:
        """Replay the backlog on an idle tick, throttled.

        ``ship`` already drains ahead of every live batch; this covers a
        server whose Kea has gone quiet, which would otherwise hold its
        backlog until the next log line. The shipper's retry backoff keeps a
        still-absent control plane from costing a timeout per attempt.
        """
        if not len(self._shipper.spool):
            return
        now = time.monotonic()
        if now - self._last_drain < DRAIN_INTERVAL:
            return
        self._last_drain = now
        drain_for(self._shipper, DRAIN_BUDGET)

    def tick(self) -> float:
        """One loop iteration. Returns how long to wait before the next."""
        if self._fh is None and not self._open():
            self._maybe_drain()
            return FILE_WAIT_INTERVAL
        self._read_available()
        self._check_rotation()
        if self._should_flush():
            flushes = 0
            while self._should_flush() and flushes < MAX_FLUSHES_PER_TICK:
                self._flush()
                flushes += 1
        else:
            self._maybe_drain()
        return TAIL_POLL_INTERVAL

    def run(self) -> None:
        log.info("dhcp_log_shipper_starting", path=str(self.path))
        while not self._stop.is_set():
            self._stop.wait(timeout=self.tick())
        # Final flush on shutdown so buffered lines reach the control plane
        # or the spool rather than dying with the process. Without a spool a
        # failed POST drops the batch, so stop at the first one rather than
        # paying a connect timeout per remaining batch during shutdown.
        while self._buffer:
            if self._flush() == RETRY and not self._shipper.spool.enabled:
                break
        self._close()
        log.info("dhcp_log_shipper_stopped")


__all__ = ["LogShipper", "DEFAULT_DHCP_LOG_PATH"]
