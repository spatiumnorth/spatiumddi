"""generator_tallies: the shard counters folded the way the report prints them (#1057)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from spddi_perf.generator_tallies import (  # noqa: E402
    dns_rcodes,
    dns_summary,
    dns_timeouts_from_windows,
    handshake_summary,
    orchestrator_accounting,
    sum_counters,
)


def test_sum_counters_adds_shards_including_dynamic_rcode_keys() -> None:
    a = {"counters": {"dora_ack": 10, "dns_rcode_REFUSED": 5, "dns_rcode_NOERROR": 1}}
    b = {"counters": {"dora_ack": 7, "dns_rcode_REFUSED": 2, "dns_rcode_SERVFAIL": 3}}
    c = sum_counters([a, b, {"no": "counters"}, "junk"])
    assert c == {"dora_ack": 17, "dns_rcode_REFUSED": 7, "dns_rcode_NOERROR": 1,
                 "dns_rcode_SERVFAIL": 3}
    assert dns_rcodes(c) == {"REFUSED": 7, "NOERROR": 1, "SERVFAIL": 3}


def test_handshake_three_strictnesses_from_todays_numbers() -> None:
    """nightly-20260910 PostQA gate_load: acks 9997 / timeouts 637 → 94.01 %.
    The pre-fix figure is `strict_pct` unchanged; a late ACK per timed-out
    device would lift `with_late_pct` and never past 100."""
    h = handshake_summary({"dora_ack": 9997, "timeout": 637, "nak": 0})
    assert h["attempts"] == 10634 and h["strict_pct"] == 94.01
    assert h["with_late_pct"] == 94.01 and h["acked_late"] == 0
    h2 = handshake_summary({"dora_ack": 9997, "timeout": 637, "nak": 0,
                            "dora_ack_late": 600, "dora_ack_over_budget": 40})
    assert h2["acked_within_budget"] == 9957 and h2["within_budget_pct"] == 93.634
    assert h2["with_late_pct"] == round(100 * 10597 / 10634, 3)
    h3 = handshake_summary({"dora_ack": 10, "timeout": 2, "dora_ack_late": 5})
    assert h3["with_late_pct"] == 100.0            # capped: late ≤ timeouts by construction
    assert handshake_summary({})["strict_pct"] is None


def test_handshake_keeps_resent_leases_and_open_rounds_visible() -> None:
    """With the RFC 2131 backoff a round times out only ≈60 s in, so a lease
    that took a resend is a success: `acked_after_resend` says how many, and
    `in_flight` the rounds a stopped shard left without a verdict. 44 resent
    of 10,000 is the size of a 2026-10 narrow miss (8-44 timeouts)."""
    h = handshake_summary({"dora_ack": 10000, "timeout": 0, "nak": 0,
                           "dora_ack_resent": 44, "dora_ack_over_budget": 3,
                           "dora_in_flight": 2})
    assert h["strict_pct"] == 100.0 and h["acked_after_resend"] == 44
    assert h["acked_without_resend"] == 9956 and h["without_resend_pct"] == 99.56
    assert h["acked_within_budget"] == 9997 and h["in_flight"] == 2
    # a summary written before the counters existed reads as unknown, not 0
    old = handshake_summary({"dora_ack": 9997, "timeout": 637, "nak": 0})
    assert old["acked_after_resend"] is None and old["acked_without_resend"] is None
    assert old["without_resend_pct"] is None and old["in_flight"] is None
    # and a shard that wrote zero is a measured zero
    zero = handshake_summary({"dora_ack": 5, "dora_ack_resent": 0, "dora_in_flight": 0})
    assert zero["acked_without_resend"] == 5 and zero["in_flight"] == 0
    # folded across shards like every other counter
    blk = orchestrator_accounting([{"counters": {"dora_ack": 3, "dora_ack_resent": 1}},
                                   {"counters": {"dora_ack": 2, "dora_ack_resent": 2}}])
    assert blk["handshake"]["acked_after_resend"] == 3
    assert blk["handshake"]["acked_without_resend"] == 2


def test_dns_summary_shows_the_pre_fix_hole_and_the_fixed_ledger() -> None:
    """nightly-20260909 PostQA: dns_sent 606,185 / ok 0 / timeouts 46 beside a
    606,139-sample histogram — the answers counted as nothing show up as
    `unaccounted`. With per-rcode counters they are REFUSED."""
    old = dns_summary({"dns_sent": 606185, "dns_ok": 0, "dns_timeout": 46})
    assert old["answered"] == 0 and old["unaccounted"] == 606139
    assert old["ok_pct_of_sent"] == 0.0 and old["ok_pct_of_answered"] is None
    new = dns_summary({"dns_sent": 606185, "dns_ok": 0, "dns_timeout": 46,
                       "dns_answered": 606139, "dns_rcode_REFUSED": 606138,
                       "dns_rcode_NOERROR": 1})
    assert new["unaccounted"] == 0 and new["not_ok"] == 606139
    assert new["rcodes"] == {"NOERROR": 1, "REFUSED": 606138}
    # a summary written before dns_answered existed still gets a total from the rcodes
    partial = dns_summary({"dns_sent": 10, "dns_ok": 4, "dns_rcode_NOERROR": 4,
                           "dns_rcode_REFUSED": 6})
    assert partial["answered"] == 10 and partial["ok_pct_of_answered"] == 40.0


def test_dns_timeouts_from_windows_takes_the_last_value_per_shard_not_the_sum() -> None:
    rows = [{"shard": 0, "dns_timeout": 1}, {"shard": 0, "dns_timeout": 3},
            {"shard": 0, "dns_timeout": 46}, {"shard": 1, "dns_timeout": 2},
            {"shard": 1, "dns_timeout": 2}, "junk"]
    assert dns_timeouts_from_windows(rows) == 48      # not 1+3+46+2+2 = 54


def test_orchestrator_accounting_block_and_absence() -> None:
    assert orchestrator_accounting([]) is None
    blk = orchestrator_accounting([
        {"counters": {"dora_ack": 3, "timeout": 1, "dns_sent": 5, "dns_ok": 5,
                      "dns_answered": 5, "dns_rcode_NOERROR": 5}},
        {"counters": {"dora_ack": 2, "dora_ack_late": 1, "dns_sent": 1,
                      "dns_timeout": 1}},
    ])
    assert blk["shards"] == 2
    assert blk["handshake"]["acked"] == 5 and blk["handshake"]["acked_late"] == 1
    assert blk["handshake"]["with_late_pct"] == 100.0
    assert blk["dns"]["sent"] == 6 and blk["dns"]["timeouts"] == 1
    assert blk["dns"]["rcodes"] == {"NOERROR": 5} and blk["dns"]["unaccounted"] == 0
