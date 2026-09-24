"""Tails BIND9's query log file and ships batches to the control plane.

BIND9 writes to the file we configure in ``options.query_log_file``
when ``query_log_enabled`` is on (rendered into ``named.conf`` by
the control-plane template, default ``/var/log/named/queries.log``).
This thread follows the file like ``tail -F``, batches up to
``MAX_BATCH`` lines or ``BATCH_INTERVAL`` seconds (whichever comes
first), and POSTs to ``/api/v1/dns/agents/query-log-entries``.

Resilience:

* If the file doesn't exist yet (operator hasn't enabled query
  logging) we sleep and re-check; no error spam.
* On rotation (BIND's ``versions 5 size 50m`` rotates the file when
  it grows past 50 MB) we detect the inode change and re-open.
* A batch the control plane does not accept is spooled to disk
  (``<state_dir>/spool/query_log/``, see :mod:`.spool`) instead of
  dropped, and replayed oldest-first once it answers again — including
  across an agent restart (#1077). Each batch carries a ``batch_id`` the
  control plane dedupes on, so re-sending the batch that was in flight
  when the outage began is safe. Spooled batches older than the control
  plane's log retention (``AGENT_SPOOL_LOG_MAX_AGE_HOURS``, default 24)
  are dropped at drain time and counted, since they would be pruned on
  arrival. ``AGENT_SPOOL_ENABLED=false`` restores the old drop-on-failure
  behaviour.
* We never block the daemon: after a failed POST the shipper backs off
  for ``BATCH_INTERVAL`` and appends straight to the spool, so a
  black-holed control plane costs a local disk write per batch rather
  than a connect timeout.
* Memory cap: the in-memory buffer only holds lines read but not yet
  flushed (to the control plane or the spool). It still trims to the
  most-recent half at ``MAX_BUFFER_LINES`` as a last-resort OOM guard,
  and every full batch is flushed on each tick so it should not fill.
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
from .spool import RETRY, Shipper, Spool

log = structlog.get_logger(__name__)

# Default file path — must match the BIND9 template's
# ``query_log_file`` default. Operators can override at the
# DNSServerOptions level, but the agent doesn't read DB state, so
# we rely on the default + an env override for dev / non-standard
# deployments.
DEFAULT_QUERY_LOG_PATH = "/var/log/named/queries.log"

# Tuning. Conservative — busy resolvers will batch up more often,
# quiet ones flush every 5 s with ~empty batches.
MAX_BATCH = 200
BATCH_INTERVAL = 5.0
MAX_BUFFER_LINES = 5_000
TAIL_POLL_INTERVAL = 0.5
FILE_WAIT_INTERVAL = 5.0
# Upper bound on batches flushed in one loop tick, so a large burst can't
# starve rotation checks / stop() for long.
MAX_FLUSHES_PER_TICK = MAX_BUFFER_LINES // MAX_BATCH


class QueryLogShipper:
    """Tail thread + batching POST loop, single-threaded.

    Spun up as a daemon thread by the agent supervisor; ``stop()``
    sets a thread-safe event the loop checks between iterations.
    """

    def __init__(
        self,
        cfg: AgentConfig,
        token_ref: list[str],
        path: str | None = None,
        *,
        spool: Spool | None = None,
    ) -> None:
        self.cfg = cfg
        self.token_ref = token_ref
        self.path = Path(path or os.environ.get("DNS_QUERY_LOG_PATH") or DEFAULT_QUERY_LOG_PATH)
        self._stop = threading.Event()
        # #1077 — no spool given (tests, ad-hoc callers) means a disabled one:
        # a failed batch is dropped, exactly the pre-spool behaviour.
        if spool is None:
            spool = Spool(cfg.state_dir, "query_log", 0, enabled=False)
        self.shipper = Shipper(
            spool,
            self._post,
            event_prefix="dns_query_log_ship",
            retry_backoff_seconds=BATCH_INTERVAL,
        )
        self._buffer: list[str] = []
        self._last_flush = time.monotonic()
        self._fh: TextIO | None = None
        self._inode: int | None = None

    def stop(self) -> None:
        self._stop.set()

    def _cp_client(self) -> httpx.Client:
        verify: bool | str = True
        if self.cfg.insecure_skip_tls_verify:
            verify = False
        elif self.cfg.tls_ca_path:
            verify = self.cfg.tls_ca_path
        return httpx.Client(base_url=self.cfg.control_plane_url, verify=verify, timeout=15.0)

    def _open(self) -> bool:
        """Open the log file. Return True on success."""
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return False
        try:
            self._fh = self.path.open("r", encoding="utf-8", errors="replace")
        except OSError as exc:
            log.debug("dns_query_log_open_failed", path=str(self.path), error=str(exc))
            return False
        # Start at end so we don't ship the entire historical file
        # on first attach (e.g. after agent restart). Operators get
        # whatever happens *after* the agent comes up, which matches
        # how `tail -f` behaves.
        self._fh.seek(0, os.SEEK_END)
        self._inode = st.st_ino
        log.info("dns_query_log_attached", path=str(self.path), inode=self._inode)
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
        """Detect file rotation (inode change) and re-open."""
        try:
            st = self.path.stat()
        except FileNotFoundError:
            self._close()
            return
        if self._inode is not None and st.st_ino != self._inode:
            log.info("dns_query_log_rotated", path=str(self.path))
            self._close()
            self._open()

    def _read_available(self) -> None:
        if self._fh is None:
            return
        while True:
            try:
                line = self._fh.readline()
            except OSError as exc:
                log.warning("dns_query_log_read_failed", error=str(exc))
                self._close()
                return
            if not line:
                break
            # Trim runaway buffers (control plane unreachable).
            if len(self._buffer) >= MAX_BUFFER_LINES:
                # Keep the most recent half — old lines are less
                # actionable than new ones.
                drop = MAX_BUFFER_LINES // 2
                self._buffer = self._buffer[drop:]
                log.warning("dns_query_log_buffer_trimmed", dropped=drop)
            self._buffer.append(line.rstrip("\n"))

    def _should_flush(self) -> bool:
        if not self._buffer:
            return False
        if len(self._buffer) >= MAX_BATCH:
            return True
        return (time.monotonic() - self._last_flush) >= BATCH_INTERVAL

    def _post(self, payload: dict) -> int:
        with self._cp_client() as c:
            resp = c.post(
                "/api/v1/dns/agents/query-log-entries",
                json=payload,
                headers={"Authorization": f"Bearer {self.token_ref[0]}"},
            )
        return resp.status_code

    def _flush(self) -> str:
        batch = self._buffer[:MAX_BATCH]
        self._buffer = self._buffer[MAX_BATCH:]
        try:
            return self.shipper.ship({"lines": batch})
        finally:
            self._last_flush = time.monotonic()

    def run(self) -> None:
        log.info("dns_query_log_shipper_starting", path=str(self.path))
        while not self._stop.is_set():
            if self._fh is None:
                if not self._open():
                    # No log file (query logging turned off, or not created
                    # yet) must not strand a backlog spooled before it went
                    # away — the DHCP LogShipper drains here too.
                    if len(self.shipper.spool):
                        self.shipper.drain()
                    self._stop.wait(timeout=FILE_WAIT_INTERVAL)
                    continue
            self._read_available()
            self._check_rotation()
            if self._should_flush():
                flushes = 0
                while self._should_flush() and flushes < MAX_FLUSHES_PER_TICK:
                    self._flush()
                    flushes += 1
            elif len(self.shipper.spool):
                # Idle tick with a backlog: drain it even when there is no
                # live traffic to carry it. Throttled by the shipper's
                # retry backoff while the control plane is still away.
                self.shipper.drain()
            self._stop.wait(timeout=TAIL_POLL_INTERVAL)
        # Final flush on shutdown so buffered lines reach the control plane
        # or the spool rather than dying with the process. Without a spool a
        # failed POST drops the batch, so stop at the first one rather than
        # paying a connect timeout per remaining batch during shutdown.
        while self._buffer:
            if self._flush() == RETRY and not self.shipper.spool.enabled:
                break
        self._close()
        log.info("dns_query_log_shipper_stopped")


__all__ = ["QueryLogShipper", "DEFAULT_QUERY_LOG_PATH"]
