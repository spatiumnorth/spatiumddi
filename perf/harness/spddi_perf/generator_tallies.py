"""Fold the orchestrator's shard counters into the numbers a report can print.

Pure and dependency-free so the orchestrator (perf/generators/orchestrator/
accounting.py), the report generator (collect.py) and any consumer of a
``orchestrator.shard*.summary.ndjson`` line compute the SAME handshake and DNS
figures from the same counters (#1057).

Two accounting holes made the shard summaries unreliable evidence before this
module existed:

* ``_dns_query`` counted ``dns_ok`` only for NOERROR/NXDOMAIN and
  ``dns_timeout`` only on an exception, so an answer with any other rcode was
  counted as nothing. A run whose 606k queries BIND answered REFUSED read
  "ok 0, timeouts 46" beside a 606k-sample latency histogram.
* ``_on_ack`` counted ``dora_ack`` only while the device was still
  DISCOVERING; an ACK arriving after the device had given up was counted as a
  timeout AND discarded, so the generator's handshake figure could not be
  reconciled with kea's own ACK count.

The counters are cumulative per shard; ``sum_counters`` adds shards, never
windows (a per-window row carries the cumulative value at that window's end,
so summing windows multiplies the truth — see ``dns_timeouts_from_windows``).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

#: rcodes that count as an answered query for ``dns_ok`` — unchanged meaning:
#: NOERROR is the positive path, NXDOMAIN the deliberate-miss slice (§1.7).
DNS_OK_RCODES = ("NOERROR", "NXDOMAIN")
RCODE_PREFIX = "dns_rcode_"


def _int(v: Any) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def sum_counters(summaries: Iterable[dict[str, Any]]) -> dict[str, int]:
    """Add every integer ``counters`` field across shard summaries.

    Dynamic ``dns_rcode_<NAME>`` keys are summed like any other counter, so a
    rcode seen by one shard only still appears in the fold.
    """
    out: dict[str, int] = {}
    for s in summaries:
        c = s.get("counters") if isinstance(s, dict) else None
        if not isinstance(c, dict):
            continue
        for k, v in c.items():
            if isinstance(v, bool) or not isinstance(v, (int, float, str)):
                continue
            out[k] = out.get(k, 0) + _int(v)
    return out


def dns_rcodes(counters: dict[str, Any]) -> dict[str, int]:
    """``{"REFUSED": n, "NOERROR": m, ...}`` from the flattened counter keys."""
    return {k[len(RCODE_PREFIX):]: _int(v) for k, v in counters.items()
            if k.startswith(RCODE_PREFIX)}


def _pct(num: int, den: int) -> float | None:
    return round(100.0 * num / den, 3) if den > 0 else None


def _opt_int(counters: dict[str, Any], key: str) -> int | None:
    """A counter that older generators did not write: None when absent, so a
    summary that predates it reads as unknown rather than as zero."""
    return _int(counters[key]) if key in counters else None


def handshake_summary(counters: dict[str, Any]) -> dict[str, Any]:
    """The DORA handshake figure at three strictnesses, from one counter set.

    A device resends like an RFC 2131 client (device_fleet.dora_retransmit_wait):
    it waits ≈4 s after its first send, doubling after each resend, and gives
    up after its fourth send's wait, ≈60 s into the round. Before that the wait
    was a fixed 4 s and a round gave up at 16 s.

    ``attempts``             = dora_ack + timeout + nak — every DORA the generator
                               closed itself, one way or the other (unchanged
                               denominator; a device that never got a verdict is
                               in none of the three — see ``in_flight``).
    ``acked``                = dora_ack: ACKed before the device gave up, retries
                               included — the pre-#1057 meaning, kept so existing
                               consumers read the same figure.
    ``acked_after_resend``   = dora_ack_resent: of ``acked``, the round had to
                               resend at least once first (no reply inside its
                               first ≈4 s wait). These are the slow successes a
                               longer round no longer counts as timeouts. None
                               when the summary predates the counter.
    ``acked_without_resend`` = acked minus ``acked_after_resend``: the lease came
                               back inside the round's first wait.
    ``acked_within_budget``  = acked minus ``dora_ack_over_budget``: the ACK
                               answered the exchange within that exchange's own
                               wait (no retransmit had fired for it). A device
                               that resent its DISCOVER and was then answered
                               promptly still counts here, so this is not the
                               same as ``acked_without_resend``.
    ``acked_late``           = dora_ack_late: the ACK arrived after the device had
                               given up and been counted as a timeout. Each one is
                               a timeout that turned out to be a slow ACK, so
                               ``acked_late <= timeouts`` and ``with_late_pct``
                               never exceeds 100.
    ``in_flight``            = dora_in_flight: devices still mid-round when their
                               shard stopped, with no verdict yet. None when the
                               summary predates the counter.
    """
    acked = _int(counters.get("dora_ack"))
    over = _int(counters.get("dora_ack_over_budget"))
    late = _int(counters.get("dora_ack_late"))
    resent = _opt_int(counters, "dora_ack_resent")
    timeouts = _int(counters.get("timeout"))
    naks = _int(counters.get("nak"))
    attempts = acked + timeouts + naks
    first = None if resent is None else max(0, acked - resent)
    return {
        "attempts": attempts,
        "acked": acked,
        "acked_without_resend": first,
        "acked_after_resend": resent,
        "acked_within_budget": max(0, acked - over),
        "acked_late": late,
        "timeouts": timeouts,
        "naks": naks,
        "in_flight": _opt_int(counters, "dora_in_flight"),
        "without_resend_pct": None if first is None else _pct(first, attempts),
        "within_budget_pct": _pct(max(0, acked - over), attempts),
        "strict_pct": _pct(acked, attempts),
        "with_late_pct": _pct(min(attempts, acked + late), attempts),
    }


def dns_summary(counters: dict[str, Any]) -> dict[str, Any]:
    """The DNS query stream's outcome ledger from one counter set.

    ``sent`` = ``answered + timeouts + errors`` when every query was accounted
    for; ``unaccounted`` shows any gap (queries still in flight at shutdown, or
    a generator that predates per-rcode accounting, where it equals the
    answers that were counted as nothing).
    """
    sent = _int(counters.get("dns_sent"))
    ok = _int(counters.get("dns_ok"))
    answered = _int(counters.get("dns_answered"))
    timeouts = _int(counters.get("dns_timeout"))
    errors = _int(counters.get("dns_error"))
    rcodes = dns_rcodes(counters)
    if not answered and rcodes:
        answered = sum(rcodes.values())
    not_ok = max(0, answered - ok)
    return {
        "sent": sent,
        "answered": answered,
        "ok": ok,
        "not_ok": not_ok,
        "timeouts": timeouts,
        "errors": errors,
        "unaccounted": max(0, sent - answered - timeouts - errors),
        "rcodes": dict(sorted(rcodes.items())),
        "ok_pct_of_sent": _pct(ok, sent),
        "ok_pct_of_answered": _pct(ok, answered),
        "timeout_pct_of_sent": _pct(timeouts, sent),
    }


def dns_timeouts_from_windows(stats_rows: Iterable[dict[str, Any]]) -> int:
    """Cumulative ``dns_timeout`` across shards from the PERIODIC stat rows.

    Each row carries the shard's cumulative value at the end of that window,
    so the run's total is the last (largest) value per shard, summed over
    shards — never the sum over rows, which counts every earlier window's
    timeouts again on every later row (collect.py b7 did exactly that).
    """
    per_shard: dict[Any, int] = {}
    for r in stats_rows:
        if not isinstance(r, dict):
            continue
        shard = r.get("shard", 0)
        v = _int(r.get("dns_timeout"))
        if v > per_shard.get(shard, 0):
            per_shard[shard] = v
    return sum(per_shard.values())


def orchestrator_accounting(summaries: Iterable[dict[str, Any]]) -> dict[str, Any] | None:
    """The report's generator block: folded counters + both ledgers, or None
    when no shard summary exists (absence is recorded, never fabricated)."""
    summaries = [s for s in summaries if isinstance(s, dict)]
    if not summaries:
        return None
    counters = sum_counters(summaries)
    return {
        "shards": len(summaries),
        "counters": dict(sorted(counters.items())),
        "handshake": handshake_summary(counters),
        "dns": dns_summary(counters),
    }
