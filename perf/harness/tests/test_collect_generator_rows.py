"""collect.py reads the orchestrator's per-rcode and late-ACK ledgers (#1057).

Needs PyYAML (the manifest loader), installed by the perf CI job; in a bare
environment the file import-skips.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import spddi_perf.manifest as manifest_mod  # noqa: E402
from spddi_perf import collect  # noqa: E402
from spddi_perf.runpaths import RunPaths  # noqa: E402

SMOKE = Path(__file__).resolve().parents[2] / "manifests" / "smoke.yaml"


def rundata(tmp_path, summaries, stats=(), dnsperf=()):
    m = manifest_mod.from_dict(yaml.safe_load(SMOKE.read_text()))
    rp = RunPaths.for_run("t-run", tmp_path)
    rp.ensure_dirs()
    rd = collect.RunData(rp=rp, m=m, profile="p")
    rd.orchestrator_summary = list(summaries)
    rd.orchestrator_stats = list(stats)
    rd.dnsperf = list(dnsperf)
    if summaries or stats:
        rd.present.add("orchestrator")
    return rd


def rows_by_id(rows):
    return {r["id"]: r for r in rows}


# The 2026-09-10 PostQA cluster load tier, as the fixed generator would have written it.
REFUSED_RUN = {"shard": 0, "counters": {
    "dora_sent": 19520, "dora_ack": 8599, "timeout": 695, "nak": 0, "dora_ack_late": 300,
    "dns_sent": 606185, "dns_ok": 0, "dns_timeout": 46, "dns_error": 0, "dns_answered": 606139,
    "dns_rcode_REFUSED": 606138, "dns_rcode_NOERROR": 1}}


def test_b6a_fails_structurally_on_the_orchestrators_refused_answers(tmp_path):
    rd = rundata(tmp_path, [REFUSED_RUN])
    b = rows_by_id(collect.criterion_b(rd))
    assert b["b6a"]["verdict"] == collect.FAIL
    assert b["b6a"]["measured"] == "606138 (dnsperf 0, orchestrator 606138)"
    assert b["b6"]["verdict"] == collect.PASS          # 0 SERVFAIL of 606,139 answered
    assert b["b6"]["measured"].startswith("0")            # _fmt renders 0.0 as "0%"
    slo = collect.build_slo_results(rd)
    assert slo["overall"]["verdict"] == collect.FAIL
    assert "b6a" in slo["overall"]["note"]
    assert slo["generator"]["dns"]["rcodes"] == {"NOERROR": 1, "REFUSED": 606138}
    assert slo["generator"]["handshake"]["acked_late"] == 300
    assert slo["generator"]["handshake"]["strict_pct"] == round(100 * 8599 / 9294, 3)
    assert slo["generator"]["handshake"]["with_late_pct"] == round(100 * 8899 / 9294, 3)


def test_b6_rates_servfail_over_queries_sent_not_answered(tmp_path):
    """8 SERVFAILs in 10,000 sent of which 8,000 were answered: 0.08 % per
    attempt (PASS), which is what BIND's SERVFAIL / QUERY ratio would show;
    over the answers it would read 0.10 % and FAIL the < 0.1 % row."""
    run = {"shard": 0, "counters": {"dns_sent": 10000, "dns_answered": 8000, "dns_ok": 7992,
                                    "dns_timeout": 2000, "dns_rcode_NOERROR": 7992,
                                    "dns_rcode_SERVFAIL": 8, "dora_ack": 1}}
    b6 = rows_by_id(collect.criterion_b(rundata(tmp_path, [run])))["b6"]
    assert b6["measured"] == "0.08%" and b6["verdict"] == collect.PASS
    assert b6["source"].endswith("dns_rcode_SERVFAIL / dns_sent")


def test_b6a_is_no_data_without_any_dns_source_and_passes_on_zero_refused(tmp_path):
    rd = rundata(tmp_path, [])
    assert rows_by_id(collect.criterion_b(rd))["b6a"]["verdict"] == collect.NO_DATA
    clean = {"shard": 0, "counters": {"dns_sent": 10, "dns_ok": 10, "dns_answered": 10,
                                      "dns_rcode_NOERROR": 10, "dora_ack": 1}}
    b = rows_by_id(collect.criterion_b(rundata(tmp_path, [clean])))
    assert b["b6a"]["verdict"] == collect.PASS and b["b7"]["verdict"] == collect.PASS


def test_b7_reads_the_cumulative_timeouts_once_not_summed_over_windows(tmp_path):
    windows = [{"shard": 0, "dns_timeout": v} for v in (1, 5, 46)]
    # summaries present: their counters are the truth
    rd = rundata(tmp_path, [REFUSED_RUN], stats=windows)
    b7 = rows_by_id(collect.criterion_b(rd))["b7"]
    assert "+46 orch timeouts" in b7["measured"] and b7["verdict"] == collect.FAIL
    # no summary (a run that died before _finalize): the last window per shard
    rd2 = rundata(tmp_path, [], stats=windows)
    b7 = rows_by_id(collect.criterion_b(rd2))["b7"]
    assert "+46 orch timeouts" in b7["measured"]     # pre-fix this printed 52
    # errors that are not timeouts still fail the drop-rate row
    err = {"shard": 0, "counters": {"dns_sent": 5, "dns_ok": 4, "dns_answered": 4,
                                    "dns_rcode_NOERROR": 4, "dns_error": 1}}
    b7 = rows_by_id(collect.criterion_b(rundata(tmp_path, [err])))["b7"]
    assert "+1 errors" in b7["measured"] and b7["verdict"] == collect.FAIL


def test_report_renders_the_generator_block_in_both_renderers(tmp_path):
    import logging
    log = logging.getLogger("t")
    rd = rundata(tmp_path, [REFUSED_RUN])
    slo = collect.build_slo_results(rd)
    deltas = collect.build_deltas(rd)
    bottleneck = collect.build_bottleneck(rd, slo)
    md = collect.render_markdown(rd, slo, deltas, bottleneck, None, log)
    assert "## Generator accounting (orchestrator)" in md
    assert "late 300" in md and "REFUSED 606,138" in md and "unaccounted 0" in md
    ctx = {"run_id": "r", "profile": "p", "generated_at": "t", "slo_thresholds_version": "v",
           "incomplete": False, "criteria": slo["criteria"], "overall": slo["overall"],
           "deltas": deltas, "bottleneck": bottleneck, "comparison": None,
           "manifest": collect._manifest_human(rd.m), "present_surfaces": [],
           "profile_key": {}, "generator": slo["generator"]}
    builtin = collect._render_markdown_builtin(ctx)
    assert "late 300" in builtin and "REFUSED 606,138" in builtin
    # a summary from before the resend counters: unknown, never a fabricated 0
    assert "after a resend —" in builtin and "in flight at stop —" in builtin
    ctx["generator"] = None
    assert "_No orchestrator shard summary" in collect._render_markdown_builtin(ctx)


def test_report_shows_how_many_leases_needed_a_resend(tmp_path):
    """A round now runs ≈60 s before it is a timeout, so the report says how
    many handshakes got their lease only after a resend, and how many rounds
    were still open when the shard stopped."""
    run = {"shard": 0, "counters": {"dora_sent": 10050, "dora_ack": 10000, "timeout": 0,
                                    "nak": 0, "dora_ack_resent": 44, "dora_in_flight": 3}}
    slo = collect.build_slo_results(rundata(tmp_path, [run]))
    h = slo["generator"]["handshake"]
    assert h["acked_after_resend"] == 44 and h["acked_without_resend"] == 9956
    md = "\n".join(collect._generator_lines(slo["generator"]))
    assert "without a resend 9,956 (99.56%)" in md
    assert "after a resend 44" in md and "in flight at stop 3" in md
