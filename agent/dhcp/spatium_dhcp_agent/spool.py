"""Durable on-disk spool for agent → control-plane pushes (#1077).

Non-negotiable #5 covers the *serving* half of a control-plane outage: the
agent keeps answering from its cached config. This module covers the
*reporting* half. Before it existed every shipper dropped a batch the control
plane did not accept, and every buffer lived in process memory, so a
maintenance window measured in hours lost that window's query logs, DHCP
activity, per-minute metrics — and Kea lease events, which the control plane
has no other way to learn about.

Shape
-----

One :class:`Spool` per stream (``query_log``, ``metrics``, ``lease_events``,
…), each a directory of one-file-per-batch entries under
``<state_dir>/spool/<stream>/``. One file per batch because it makes every
operation that matters atomic without a database: append is write-tmp +
fsync + rename, acknowledge is unlink, trim-oldest is unlink, and a crash at
any point leaves either the whole entry or none of it. File names sort in
append order (a monotonic nanosecond sequence), so a restart drains in the
order the batches were produced.

:class:`Shipper` is the only thing a stream's code talks to. ``ship(payload)``
sends live when the spool is empty and appends when it is not, so ordering is
preserved: a live batch never overtakes the backlog. Each payload is stamped
with a ``batch_id`` the control plane records in the same transaction as the
rows it inserts, which is what makes the batch in flight at the moment of an
outage safe to replay — a POST whose response was lost is indistinguishable
from one that never arrived, and the server, not the agent, has to be the one
to say "already have it".

Bounds
------

* **Bytes, not lines.** Each stream gets a share of ``AGENT_SPOOL_MAX_BYTES``
  (default 256 MiB). At the cap the OLDEST entries are trimmed — the existing
  in-memory rule, now durable — and counted, so the heartbeat can say so and
  the ``agent_spool_trimmed`` alert can fire. An agent can never fill its own
  disk during a month-long outage.
* **Age, for streams the control plane would prune anyway.** Query and DHCP
  logs are kept 24 h on the control plane. Replaying a 3-day backlog would
  insert rows the nightly prune deletes immediately, so a stream may declare a
  ``max_age_seconds`` and entries older than that are dropped at drain time and
  counted as *expired*, not trimmed. Metrics and lease events declare none.
* **Poison.** A 4xx that is not about auth or rate is a verdict about the body,
  and retrying it forever would jam every batch queued behind it. Those entries
  are dropped and logged, never retried. A head entry that keeps drawing a
  plain 500 is quarantined to ``poison/`` too, but only once the control plane
  has been seen ACCEPTING the batch behind it — see :data:`POISON_ATTEMPTS`.

Nothing here blocks the daemon: every call is bounded, draining is capped per
call, and a full disk degrades to the pre-#1077 behaviour (log + drop) rather
than raising into a shipper thread.

The DNS and DHCP agents are separate Python packages with no shared import
path, so this module exists twice. Keep them byte-identical — a test in each
package compares the two.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import structlog

log = structlog.get_logger(__name__)

DEFAULT_TOTAL_BYTES = 256 * 1024 * 1024
DRAIN_BATCHES_PER_CALL = 50
# A batch the control plane answers with a plain 500 every time is a server
# bug meeting this particular body, and ``drain`` is strictly ordered — so
# without a limit that one batch holds every batch behind it until the byte
# cap trims them. After this many CONSECUTIVE 500s spanning at least this long
# (monotonic — an NTP step must not satisfy it), the batch queued behind it is
# sent as a probe, and only if the control plane takes THAT one is the head
# moved to ``poison/`` (kept for inspection, counted as rejected) and the
# stream moves on. The probe is what separates "500 for this body" from "500
# for every body" — schema skew mid-upgrade, an unhandled dependency error —
# which is an outage in all but status code and must cost nothing. 502 / 503 /
# 504 and transport errors never count, and reset the run: that is the control
# plane or its proxy being down, which is exactly what the spool rides out.
POISON_ATTEMPTS = 5
POISON_MIN_SECONDS = 600.0
POISON_KEEP = 20
_STATE_FILE = "_state.json"
_ENTRY_SUFFIX = ".json"

# Outcome of one POST, as the spool needs to see it.
SENT = "sent"
"""The control plane accepted it (or already had it). Done."""

RETRY = "retry"
"""Unreachable, 5xx, auth pending re-bootstrap, or rate-limited. Keep it.

(A head entry drawing a persistent, body-specific 500 is the one exception —
see :data:`POISON_ATTEMPTS`.)"""

REJECTED = "rejected"
"""The control plane refused the BODY. Retrying cannot help; drop it."""


def classify_status(status: int) -> str:
    """Map an HTTP status to :data:`SENT` / :data:`RETRY` / :data:`REJECTED`.

    401 and 404 are RETRY, not rejections: both are what an agent sees between
    a token going stale and the heartbeat re-bootstrapping it (the 404 case is
    a server row recreated after a control-plane reset), and the batch is
    perfectly good once it has a valid token. 408 / 425 / 429 are transient by
    definition. Every other 4xx is a verdict on the payload.
    """
    if 200 <= status < 300:
        return SENT
    if status in (401, 404, 408, 425, 429) or status >= 500:
        return RETRY
    return REJECTED


def spool_enabled() -> bool:
    """``AGENT_SPOOL_ENABLED=false`` restores the pre-#1077 drop behaviour.

    Exists for the negative control: a test of "nothing was lost" has to be
    able to fail, and the only honest baseline is the code path that loses.
    """
    return os.environ.get("AGENT_SPOOL_ENABLED", "true").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=UTC).isoformat()


@dataclass
class _Counters:
    trimmed_entries: int = 0
    trimmed_bytes: int = 0
    # Last time ANY batch was discarded undelivered: cap trim, a 4xx
    # rejection, or a poison quarantine. Named for the common case; it is what
    # the ``agent_spool_trimmed`` alert keys on.
    last_trim_at: float | None = None
    expired_entries: int = 0
    rejected_entries: int = 0
    write_failures: int = 0


class Spool:
    """One stream's on-disk queue. Thread-safe; normally one writer."""

    def __init__(
        self,
        root: Path,
        stream: str,
        cap_bytes: int,
        *,
        max_age_seconds: float | None = None,
        enabled: bool | None = None,
    ) -> None:
        self.stream = stream
        self.dir = Path(root) / "spool" / stream
        self.cap_bytes = max(0, int(cap_bytes))
        self.max_age_seconds = max_age_seconds
        self.enabled = spool_enabled() if enabled is None else enabled
        self._lock = threading.Lock()
        self._last_seq = 0
        # Counters persist across restarts — an agent that trimmed lease events
        # and then restarted must not report a clean spool, or the one restart
        # an operator does to "fix" it hides the loss.
        self._counters = _Counters()
        # Cached (name, size) of entries on disk, oldest first. Rebuilt from
        # the directory on start; maintained in step with every mutation so
        # status() and the cap check never rescan a large backlog.
        self._entries: list[tuple[str, int]] = []
        # (entry name, consecutive 500s, first failure monotonic, first
        # failure wall-clock) for the head entry.
        self._head_failures: tuple[str, int, float, float] | None = None
        if self.enabled:
            try:
                self.dir.mkdir(parents=True, exist_ok=True)
                self._load()
            except OSError as exc:
                log.warning("agent_spool_init_failed", stream=stream, error=str(exc))
                self.enabled = False

    # ── persistence ──────────────────────────────────────────────────

    def _load(self) -> None:
        entries: list[tuple[str, int]] = []
        for p in self.dir.iterdir():
            name = p.name
            if name.endswith(".tmp"):
                # A crash between write and rename. The entry never existed.
                try:
                    p.unlink()
                except OSError:
                    pass  # best effort; a stray .tmp is never read
                continue
            if not name.endswith(_ENTRY_SUFFIX) or name == _STATE_FILE:
                continue
            try:
                entries.append((name, p.stat().st_size))
            except OSError:
                continue
        entries.sort()
        self._entries = entries
        if entries:
            try:
                self._last_seq = int(entries[-1][0].split(".", 1)[0])
            except ValueError:
                self._last_seq = 0
        state = self.dir / _STATE_FILE
        try:
            data = json.loads(state.read_text())
            self._counters = _Counters(
                trimmed_entries=int(data.get("trimmed_entries", 0)),
                trimmed_bytes=int(data.get("trimmed_bytes", 0)),
                last_trim_at=data.get("last_trim_at"),
                expired_entries=int(data.get("expired_entries", 0)),
                rejected_entries=int(data.get("rejected_entries", 0)),
                write_failures=int(data.get("write_failures", 0)),
            )
        except FileNotFoundError:
            pass  # first start: no counters persisted yet
        except (OSError, ValueError, TypeError) as exc:
            log.warning("agent_spool_state_unreadable", stream=self.stream, error=str(exc))
        if entries:
            log.info(
                "agent_spool_loaded",
                stream=self.stream,
                entries=len(entries),
                bytes=sum(s for _, s in entries),
            )

    def _save_state(self) -> None:
        state = self.dir / _STATE_FILE
        tmp = state.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(self._counters.__dict__))
            os.replace(tmp, state)
        except OSError as exc:
            log.debug("agent_spool_state_write_failed", stream=self.stream, error=str(exc))

    def _next_seq(self) -> int:
        seq = time.time_ns()
        if seq <= self._last_seq:
            seq = self._last_seq + 1
        self._last_seq = seq
        return seq

    # ── queue operations ─────────────────────────────────────────────

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def append(self, payload: dict[str, Any]) -> bool:
        """Durably queue one batch. Returns False if it could not be kept."""
        if not self.enabled:
            return False
        body = json.dumps(
            {"v": 1, "spooled_at": time.time(), "payload": payload},
            separators=(",", ":"),
            default=str,
        ).encode()
        with self._lock:
            if self.cap_bytes and len(body) > self.cap_bytes:
                # A single batch bigger than the whole share can never fit.
                self._counters.trimmed_entries += 1
                self._counters.trimmed_bytes += len(body)
                self._counters.last_trim_at = time.time()
                self._save_state()
                log.warning("agent_spool_entry_oversize", stream=self.stream, bytes=len(body))
                return False
            name = f"{self._next_seq():020d}{_ENTRY_SUFFIX}"
            path = self.dir / name
            tmp = path.with_suffix(".tmp")
            try:
                with open(tmp, "wb") as fh:
                    fh.write(body)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, path)
            except OSError as exc:
                # Disk full / read-only volume. Degrade to the pre-#1077
                # behaviour (drop + log) — never raise into a shipper thread.
                self._counters.write_failures += 1
                try:
                    tmp.unlink()
                except OSError:
                    pass  # nothing was written, or it is already gone
                # Best effort — the disk that refused the entry may refuse
                # this too — but a counter that only lives in memory resets
                # on the restart an operator does to "fix" it.
                self._save_state()
                log.warning("agent_spool_write_failed", stream=self.stream, error=str(exc))
                return False
            self._entries.append((name, len(body)))
            self._enforce_cap_locked()
        return True

    def _enforce_cap_locked(self) -> None:
        if not self.cap_bytes:
            return
        total = sum(s for _, s in self._entries)
        if total <= self.cap_bytes:
            return
        dropped = 0
        dropped_bytes = 0
        # Never trim the entry just appended: at least the newest survives.
        while total > self.cap_bytes and len(self._entries) > 1:
            name, size = self._entries.pop(0)
            try:
                (self.dir / name).unlink()
            except FileNotFoundError:
                pass  # already gone — the accounting is what matters
            except OSError as exc:
                log.warning("agent_spool_trim_unlink_failed", stream=self.stream, error=str(exc))
            total -= size
            dropped += 1
            dropped_bytes += size
        if dropped:
            self._counters.trimmed_entries += dropped
            self._counters.trimmed_bytes += dropped_bytes
            self._counters.last_trim_at = time.time()
            self._save_state()
            log.warning(
                "agent_spool_trimmed",
                stream=self.stream,
                dropped_entries=dropped,
                dropped_bytes=dropped_bytes,
                cap_bytes=self.cap_bytes,
            )

    def _oldest(self) -> tuple[str, dict[str, Any] | None] | None:
        with self._lock:
            if not self._entries:
                return None
            name = self._entries[0][0]
        return name, self._read_entry(name)

    def _read_entry(self, name: str) -> dict[str, Any] | None:
        try:
            raw = (self.dir / name).read_bytes()
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("entry is not an object")
            return data
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            log.warning("agent_spool_entry_corrupt", stream=self.stream, entry=name, error=str(exc))
            return None

    def _usable(self, name: str, data: dict[str, Any] | None) -> tuple[dict[str, Any] | None, bool]:
        """``(payload, expired)`` for one read entry, removing it when unusable."""
        if data is None:
            self._remove(name)
            return None, False
        spooled_at = data.get("spooled_at")
        if (
            self.max_age_seconds is not None
            and isinstance(spooled_at, (int, float))
            and time.time() - spooled_at > self.max_age_seconds
        ):
            self._remove(name)
            return None, True
        payload = data.get("payload")
        if not isinstance(payload, dict):
            self._remove(name)
            return None, False
        return payload, False

    def _count_rejected(self, name: str) -> None:
        with self._lock:
            self._counters.rejected_entries += 1
            # A rejected batch is lost exactly as a trimmed one is, so it moves
            # the same clock the ``agent_spool_trimmed`` alert reads — or a
            # lease_events batch the control plane refused would vanish with no
            # alert at all.
            self._counters.last_trim_at = time.time()
            self._save_state()
        log.warning("agent_spool_entry_rejected", stream=self.stream, entry=name)

    def _remove(self, name: str) -> None:
        with self._lock:
            self._entries = [e for e in self._entries if e[0] != name]
        try:
            (self.dir / name).unlink()
        except FileNotFoundError:
            pass  # already acknowledged or trimmed
        except OSError as exc:
            log.warning("agent_spool_unlink_failed", stream=self.stream, error=str(exc))

    def drain(
        self,
        send: Callable[[dict[str, Any]], str],
        max_batches: int = DRAIN_BATCHES_PER_CALL,
        *,
        server_error: Callable[[], bool] | None = None,
    ) -> bool:
        """Send queued batches oldest-first. True when the spool is now empty.

        Stops at the first :data:`RETRY` — the control plane is still not
        taking them, and trying the rest would only reorder the backlog. The
        one exception is a head entry that keeps drawing a plain 500
        (``server_error()`` true after the RETRY): see :data:`POISON_ATTEMPTS`.
        """
        if not self.enabled:
            return True
        sent = 0
        expired = 0
        for _ in range(max_batches):
            item = self._oldest()
            if item is None:
                break
            name, data = item
            payload, was_expired = self._usable(name, data)
            if payload is None:
                expired += was_expired
                continue
            outcome = send(payload)
            if outcome == RETRY:
                if server_error is None or not server_error():
                    # An outage (or auth / rate). Whatever 500s the head drew
                    # before it are no longer consecutive: a 500 on either
                    # side of a two-hour 503 window is not a verdict.
                    self._head_failures = None
                    break
                if not self._poison_due(name):
                    break
                probe, probe_expired = self._probe_behind(name, send)
                expired += probe_expired
                if probe == SENT:
                    sent += 1
                if probe not in (SENT, REJECTED):
                    # Nothing behind it, or the control plane refuses that
                    # one too: "500 for every body" is not poison. Keep it.
                    break
                self._quarantine(name)
                continue
            self._head_failures = None
            if outcome == REJECTED:
                self._count_rejected(name)
            else:
                sent += 1
            self._remove(name)
        if expired:
            with self._lock:
                self._counters.expired_entries += expired
                self._save_state()
            # Said in the agent's own log because it is the one place it can
            # be: these rows would have been pruned on arrival anyway.
            log.info(
                "agent_spool_entries_expired",
                stream=self.stream,
                expired=expired,
                max_age_seconds=self.max_age_seconds,
            )
        if sent:
            log.info("agent_spool_drained", stream=self.stream, sent=sent, remaining=len(self))
        return len(self) == 0

    def _poison_due(self, name: str) -> bool:
        """Count a 500 against the head entry. True once it has drawn
        :data:`POISON_ATTEMPTS` consecutive 500s over :data:`POISON_MIN_SECONDS`."""
        now = time.monotonic()
        hf = self._head_failures
        if hf is None or hf[0] != name:
            hf = (name, 0, now, time.time())
        hf = (name, hf[1] + 1, hf[2], hf[3])
        self._head_failures = hf
        return hf[1] >= POISON_ATTEMPTS and now - hf[2] >= POISON_MIN_SECONDS

    def _probe_behind(
        self, head: str, send: Callable[[dict[str, Any]], str]
    ) -> tuple[str | None, int]:
        """Send the first usable entry queued behind ``head``.

        Returns ``(outcome, expired)``; outcome is None when there is nothing
        behind it. A SENT or REJECTED probe is removed — either way the control
        plane processed a body, which is what makes the head's 500 a verdict
        on the head. A RETRY probe stays where it is.
        """
        expired = 0
        while True:
            with self._lock:
                names = [n for n, _ in self._entries]
            try:
                idx = names.index(head)
            except ValueError:
                return None, expired
            if idx + 1 >= len(names):
                return None, expired
            name = names[idx + 1]
            # Unusable entries are removed by _usable, so this terminates.
            payload, was_expired = self._usable(name, self._read_entry(name))
            if payload is None:
                expired += was_expired
                continue
            outcome = send(payload)
            if outcome == REJECTED:
                self._count_rejected(name)
            if outcome != RETRY:
                self._remove(name)
            return outcome, expired

    def _quarantine(self, name: str) -> None:
        """Move a poisoned head entry to ``poison/`` and count it rejected."""
        hf = self._head_failures
        self._head_failures = None
        poison = self.dir / "poison"
        kept_for_inspection = True
        try:
            poison.mkdir(exist_ok=True)
            os.replace(self.dir / name, poison / name)
        except OSError as exc:
            kept_for_inspection = False
            log.warning(
                "agent_spool_poison_move_failed",
                stream=self.stream,
                entry=name,
                error=str(exc),
            )
        else:
            try:
                kept = sorted(p for p in poison.iterdir() if p.name.endswith(_ENTRY_SUFFIX))
                for old in kept[:-POISON_KEEP]:
                    old.unlink()
            except OSError as exc:
                log.warning("agent_spool_poison_prune_failed", stream=self.stream, error=str(exc))
        # Removed whether or not the move worked: left at the head it would
        # jam the stream it was quarantined to unblock.
        self._remove(name)
        with self._lock:
            self._counters.rejected_entries += 1
            self._counters.last_trim_at = time.time()  # see _count_rejected
            self._save_state()
        log.error(
            "agent_spool_entry_poisoned",
            stream=self.stream,
            entry=name,
            attempts=hf[1] if hf else None,
            first_failure_at=_iso(hf[3]) if hf else None,
            kept_for_inspection=kept_for_inspection,
        )

    def status(self) -> dict[str, Any]:
        with self._lock:
            entries = list(self._entries)
            c = self._counters
            oldest_at: float | None = None
            if entries:
                try:
                    oldest_at = int(entries[0][0].split(".", 1)[0]) / 1e9
                except ValueError:
                    oldest_at = None
            return {
                "enabled": self.enabled,
                "entries": len(entries),
                "bytes": sum(s for _, s in entries),
                "cap_bytes": self.cap_bytes,
                "oldest_at": _iso(oldest_at),
                "trimmed_entries_total": c.trimmed_entries,
                "trimmed_bytes_total": c.trimmed_bytes,
                "last_trim_at": _iso(c.last_trim_at),
                "expired_entries_total": c.expired_entries,
                "rejected_entries_total": c.rejected_entries,
                "write_failures_total": c.write_failures,
            }


class SpoolManager:
    """Owns every stream's spool for one agent and splits the byte budget.

    ``shares`` are relative weights, so adding a stream re-divides the budget
    rather than silently growing it past ``AGENT_SPOOL_MAX_BYTES``.
    """

    def __init__(self, state_dir: Path, total_bytes: int | None = None) -> None:
        self.state_dir = Path(state_dir)
        if total_bytes is None:
            try:
                total_bytes = int(os.environ.get("AGENT_SPOOL_MAX_BYTES", DEFAULT_TOTAL_BYTES))
            except ValueError:
                total_bytes = DEFAULT_TOTAL_BYTES
        self.total_bytes = max(0, total_bytes)
        self._specs: dict[str, tuple[float, float | None]] = {}
        self._spools: dict[str, Spool] = {}
        self._lock = threading.Lock()

    def declare(self, stream: str, share: float, *, max_age_seconds: float | None = None) -> None:
        """Register a stream before any :meth:`get`. Order-independent."""
        with self._lock:
            if self._spools:
                raise RuntimeError("declare every stream before the first get()")
            self._specs[stream] = (share, max_age_seconds)

    def get(self, stream: str) -> Spool:
        with self._lock:
            sp = self._spools.get(stream)
            if sp is not None:
                return sp
            if not self._spools:
                # First materialisation freezes the stream set.
                total_share = sum(s for s, _ in self._specs.values()) or 1.0
                for name, (share, age) in self._specs.items():
                    cap = int(self.total_bytes * share / total_share)
                    self._spools[name] = Spool(self.state_dir, name, cap, max_age_seconds=age)
            sp = self._spools.get(stream)
            if sp is None:
                raise KeyError(f"spool stream {stream!r} was not declared")
            return sp

    def status(self) -> dict[str, Any]:
        """The heartbeat's ``spool`` field."""
        streams = {name: sp.status() for name, sp in list(self._spools.items())}
        oldest = [s["oldest_at"] for s in streams.values() if s["oldest_at"]]
        trims = [s["last_trim_at"] for s in streams.values() if s["last_trim_at"]]
        return {
            # A spool that failed to initialise (read-only or missing state
            # dir) disables itself; the env flag alone would report "enabled"
            # while nothing is actually being kept.
            "enabled": (
                all(s["enabled"] for s in streams.values()) if streams else spool_enabled()
            ),
            "cap_bytes": self.total_bytes,
            "bytes": sum(s["bytes"] for s in streams.values()),
            "entries": sum(s["entries"] for s in streams.values()),
            "oldest_at": min(oldest) if oldest else None,
            "trimmed_entries_total": sum(s["trimmed_entries_total"] for s in streams.values()),
            "trimmed_bytes_total": sum(s["trimmed_bytes_total"] for s in streams.values()),
            "last_trim_at": max(trims) if trims else None,
            "expired_entries_total": sum(s["expired_entries_total"] for s in streams.values()),
            "streams": streams,
        }


class Shipper:
    """Send-or-spool for one stream. The only API a shipper thread uses.

    ``post(payload) -> int`` performs the HTTP POST and returns its status;
    a raised :class:`httpx.HTTPError` is treated as unreachable. Kept as a
    callable rather than a URL so each stream keeps its own client, auth and
    TLS handling exactly as before.

    ``retry_backoff_seconds``: after a :data:`RETRY`, stop attempting POSTs
    for this long and append straight to the spool. Without it a stream that
    ships every few seconds pays one full connect timeout per batch while the
    control plane is black-holed (15 s against a 5 s batch interval), and a
    busy producer's in-memory buffer overflows behind the stalled thread —
    losing exactly the lines the spool exists to keep. Only applies while the
    spool can actually hold the batch; a disabled spool still attempts every
    send, as before #1077. Default 0 (no backoff).
    """

    def __init__(
        self,
        spool: Spool,
        post: Callable[[dict[str, Any]], int],
        *,
        event_prefix: str,
        retry_backoff_seconds: float = 0.0,
    ) -> None:
        self.spool = spool
        self._post = post
        self._event = event_prefix
        self._backoff = max(0.0, retry_backoff_seconds)
        self._retry_after = 0.0
        # Outcome of the most recent POST actually attempted (None before the
        # first). Distinct from ship()'s return value, which is RETRY whenever
        # the live payload was queued — including when the control plane is
        # healthy and the backlog was merely longer than one drain slice.
        self.last_send_outcome: str | None = None
        # HTTP status of that POST (None for a transport error) — lets the
        # spool tell a server bug (500) from an outage (502/503/504).
        self.last_status: int | None = None

    def _server_error(self) -> bool:
        return self.last_status == 500

    def _backing_off(self) -> bool:
        return self._backoff > 0 and self.spool.enabled and time.monotonic() < self._retry_after

    def _send(self, payload: dict[str, Any]) -> str:
        self.last_status = None
        try:
            status = self._post(payload)
            self.last_status = status
        except httpx.HTTPError as exc:
            log.warning(f"{self._event}_http_error", error=str(exc))
            outcome = RETRY
        else:
            outcome = classify_status(status)
            if outcome != SENT:
                log.warning(f"{self._event}_failed", status=status, outcome=outcome)
        if outcome == RETRY and self._backoff:
            self._retry_after = time.monotonic() + self._backoff
        self.last_send_outcome = outcome
        return outcome

    def ship(self, payload: dict[str, Any]) -> str:
        """Deliver ``payload`` now, or queue it behind the backlog.

        Returns the outcome for the LIVE payload: :data:`SENT`, :data:`REJECTED`,
        or :data:`RETRY` (meaning it is now spooled, or dropped when spooling is
        disabled / impossible).
        """
        payload.setdefault("batch_id", uuid.uuid4().hex)
        if self._backing_off() and self.spool.append(payload):
            return RETRY
        drained = not len(self.spool) or self.spool.drain(
            self._send, server_error=self._server_error
        )
        if not drained:
            # Backlog still pending: queue behind it so order is preserved.
            self.spool.append(payload)
            return RETRY
        outcome = self._send(payload)
        if outcome == RETRY:
            self.spool.append(payload)
        return outcome

    def drain(self) -> bool:
        """Flush the backlog without a live payload (idle / reconnect ticks)."""
        if not len(self.spool):
            return True
        if self._backing_off():
            return False
        return self.spool.drain(self._send, server_error=self._server_error)


__all__ = [
    "REJECTED",
    "RETRY",
    "SENT",
    "Shipper",
    "Spool",
    "SpoolManager",
    "classify_status",
    "spool_enabled",
]
