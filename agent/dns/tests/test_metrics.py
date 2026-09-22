"""Tests for the BIND9 metrics poller.

Covers XML parsing + delta / counter-reset behavior. The HTTP path
is excluded (same pattern as the DHCP metrics tests).
"""

from __future__ import annotations

from pathlib import Path

from spatium_dns_agent.config import AgentConfig
from spatium_dns_agent.metrics import MetricsPoller, _parse_snapshot

SAMPLE_XML = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<statistics version="3.12.1">
 <server>
  <counters type="opcode">
   <counter name="QUERY">1000</counter>
   <counter name="IQUERY">0</counter>
  </counters>
  <counters type="nsstat">
   <counter name="QrySuccess">900</counter>
   <counter name="QryAuthAns">700</counter>
   <counter name="QryNoauthAns">250</counter>
   <counter name="QryNxrrset">50</counter>
   <counter name="QryNXDOMAIN">30</counter>
   <counter name="QrySERVFAIL">5</counter>
   <counter name="QryRecursion">120</counter>
  </counters>
 </server>
</statistics>
"""


def test_parse_snapshot_extracts_expected_counters():
    out = _parse_snapshot(SAMPLE_XML)
    assert out["queries_total"] == 1000
    # No rcode table in this sample: the NOERROR responses are the nsstat
    # classes that carry that rcode, answers with data (QrySuccess 900)
    # and without (QryNxrrset 50) — never QryAuthAns + QryNoauthAns, which
    # count every response whatever its rcode (#1116).
    assert out["noerror"] == 950  # 900 + 50
    assert out["nxdomain"] == 30
    assert out["servfail"] == 5
    assert out["recursion"] == 120


def test_parse_snapshot_handles_malformed_xml():
    assert _parse_snapshot(b"<not-xml") == {}


# What BIND 9.20 actually publishes (the appliance's 9.20.27, statistics
# channel /xml/v3/server): the opcode table's QUERY AND the nsstat family's
# Requestv4/Requestv6 for the same requests, QrySuccess beside the
# QryAuthAns/QryNoauthAns split. Before #1064 the poller summed the
# spellings and reported 2000 queries for 1000, 1900 NOERROR for 950.
SAMPLE_XML_BOTH_SPELLINGS = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<statistics version="3.14">
 <server>
  <counters type="opcode">
   <counter name="QUERY">1000</counter>
   <counter name="IQUERY">0</counter>
   <counter name="NOTIFY">3</counter>
   <counter name="UPDATE">2</counter>
  </counters>
  <counters type="rcode">
   <counter name="NOERROR">950</counter>
   <counter name="NXDOMAIN">30</counter>
   <counter name="REFUSED">15</counter>
  </counters>
  <counters type="nsstat">
   <counter name="Requestv4">1004</counter>
   <counter name="Requestv6">1</counter>
   <counter name="QrySuccess">900</counter>
   <counter name="QryAuthAns">700</counter>
   <counter name="QryNoauthAns">250</counter>
   <counter name="QryNxrrset">50</counter>
   <counter name="QryNXDOMAIN">30</counter>
   <counter name="QrySERVFAIL">5</counter>
   <counter name="QryRecursion">120</counter>
   <counter name="RateDropped">4</counter>
   <counter name="RateSlipped">1</counter>
  </counters>
 </server>
</statistics>
"""


def test_parse_snapshot_counts_a_query_once_when_bind_publishes_both_spellings():
    out = _parse_snapshot(SAMPLE_XML_BOTH_SPELLINGS)
    # The opcode table is the documented source; Requestv4/Requestv6 are
    # the same requests spelled by address family, not more of them.
    assert out["queries_total"] == 1000
    # noerror is the auth/noauth split; QrySuccess is the older single name
    # for the same answers, not an extra 900 of them.
    assert out["noerror"] == 950
    assert out["nxdomain"] == 30
    assert out["servfail"] == 5
    assert out["recursion"] == 120
    assert out["rate_dropped"] == 4
    assert out["rate_slipped"] == 1


def test_parse_snapshot_falls_back_to_the_nsstat_spelling_without_an_opcode_table():
    xml = SAMPLE_XML_BOTH_SPELLINGS.replace(b'<counter name="QUERY">1000</counter>', b"")
    out = _parse_snapshot(xml)
    assert out["queries_total"] == 1004 + 1
    # noerror: the rcode table is the value while it is there (#1116); without
    # it, the nsstat classes that carry the rcode — QrySuccess + QryNxrrset.
    xml = xml.replace(b'<counters type="rcode">', b'<counters type="rcode-x">')
    assert _parse_snapshot(xml)["noerror"] == 900 + 50


def test_parse_snapshot_prefers_the_documented_spelling_even_when_it_reads_zero():
    # A zero is a value, not an absence: an idle server with the opcode table
    # present reports 0 queries, not the request family's count of
    # NOTIFY/UPDATE traffic.
    xml = SAMPLE_XML_BOTH_SPELLINGS.replace(b'<counter name="QUERY">1000</counter>',
                                            b'<counter name="QUERY">0</counter>')
    assert _parse_snapshot(xml)["queries_total"] == 0


def _poller(tmp_path: Path) -> MetricsPoller:
    cfg = AgentConfig(
        control_plane_url="http://api.invalid",
        dns_agent_key="unused",
        server_name="dns-test",
        driver="bind9",
        roles=["authoritative"],
        group_name=None,
        tls_ca_path=None,
        insecure_skip_tls_verify=True,
        state_dir=tmp_path,
    )
    return MetricsPoller(cfg, token_ref=["unused"])


def test_first_tick_no_delta(tmp_path):
    p = _poller(tmp_path)
    assert p._compute_delta(_parse_snapshot(SAMPLE_XML)) is None


def test_second_tick_emits_delta(tmp_path):
    p = _poller(tmp_path)
    p._compute_delta(_parse_snapshot(SAMPLE_XML))
    # Second XML with +50 queries total, +40 noerror, +10 recursion.
    second = (
        SAMPLE_XML.replace(b"1000", b"1050")
        .replace(b'QrySuccess">900', b'QrySuccess">940')
        .replace(b'QryRecursion">120', b'QryRecursion">130')
    )
    delta = p._compute_delta(_parse_snapshot(second))
    assert delta is not None
    assert delta["queries_total"] == 50
    assert delta["noerror"] == 40
    assert delta["recursion"] == 10


def test_counter_reset_returns_none(tmp_path):
    p = _poller(tmp_path)
    p._compute_delta(_parse_snapshot(SAMPLE_XML))
    # named restart — everything back to 0.
    reset_xml = (
        SAMPLE_XML.replace(b">1000<", b">0<")
        .replace(b">900<", b">0<")
        .replace(b">700<", b">0<")
        .replace(b">50<", b">0<")
        .replace(b">250<", b">0<")
        .replace(b">30<", b">0<")
        .replace(b">5<", b">0<")
        .replace(b">120<", b">0<")
    )
    assert p._compute_delta(_parse_snapshot(reset_xml)) is None


# What BIND 9.20 publishes (the appliance's 9.20.27, /xml/v3/server, read on
# the QA fleet 2026-09-21): the server-level rcode table beside the nsstat
# answer classes, and each view's resstats repeating NXDOMAIN / SERVFAIL /
# REFUSED as that view's RESOLVER counters. The numbers are the base rig's
# idle channel — 26 authoritative answers, 9 of them NXDOMAIN, so 17 NOERROR
# responses — with a SERVFAIL and non-zero resolver counters added so that a
# name-wide sum would show.
SAMPLE_XML_920 = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<statistics version="3.14">
 <server>
  <boot-time>2026-09-21T18:05:00.298Z</boot-time>
  <counters type="opcode">
   <counter name="QUERY">1280</counter>
   <counter name="IQUERY">0</counter>
  </counters>
  <counters type="rcode">
   <counter name="NOERROR">17</counter>
   <counter name="FORMERR">0</counter>
   <counter name="SERVFAIL">1</counter>
   <counter name="NXDOMAIN">9</counter>
   <counter name="REFUSED">1254</counter>
  </counters>
  <counters type="nsstat">
   <counter name="Requestv4">1280</counter>
   <counter name="Requestv6">0</counter>
   <counter name="QrySuccess">12</counter>
   <counter name="QryAuthAns">26</counter>
   <counter name="QryNoauthAns">0</counter>
   <counter name="QryReferral">0</counter>
   <counter name="QryNxrrset">5</counter>
   <counter name="QrySERVFAIL">1</counter>
   <counter name="QryNXDOMAIN">9</counter>
   <counter name="QryRecursion">0</counter>
  </counters>
 </server>
 <views>
  <view name="internal">
   <counters type="resstats">
    <counter name="NXDOMAIN">4</counter>
    <counter name="SERVFAIL">2</counter>
    <counter name="REFUSED">3</counter>
   </counters>
  </view>
 </views>
</statistics>
"""


def test_noerror_is_the_rcode_tables_noerror_not_every_authoritative_answer():
    out = _parse_snapshot(SAMPLE_XML_920)
    # 26 authoritative answers, 9 of them NXDOMAIN: the daemon sent 17
    # NOERROR responses, and 17 is the number — not QryAuthAns' 26 (#1116).
    assert out["noerror"] == 17
    assert out["nxdomain"] == 9
    assert out["servfail"] == 1


def test_the_rcode_breakdown_is_the_server_table_not_the_views_resolver_counters():
    out = _parse_snapshot(SAMPLE_XML_920)
    # The view's resstats repeat NXDOMAIN (4) and SERVFAIL (2) as resolver
    # counters; a name-wide sum would report 13 and 3.
    assert out["nxdomain"] == 9
    assert out["servfail"] == 1


def test_an_nxdomain_answer_moves_nxdomain_and_leaves_noerror_alone(tmp_path):
    # The base rig's experiment (#1116): 50 authoritative NXDOMAIN answers
    # moved QryAuthAns +50, QryNXDOMAIN +50 and rcode NXDOMAIN +50, and left
    # QrySuccess, QryNxrrset and rcode NOERROR where they were.
    p = _poller(tmp_path)
    p._compute_delta(_parse_snapshot(SAMPLE_XML_920))
    after = (
        SAMPLE_XML_920.replace(b'QUERY">1280', b'QUERY">1330')
        .replace(b'Requestv4">1280', b'Requestv4">1330')
        .replace(b'QryAuthAns">26', b'QryAuthAns">76')
        .replace(b'QryNXDOMAIN">9', b'QryNXDOMAIN">59')
        .replace(b'"NXDOMAIN">9', b'"NXDOMAIN">59')
    )
    delta = p._compute_delta(_parse_snapshot(after))
    assert delta is not None
    assert delta["nxdomain"] == 50
    assert delta["noerror"] == 0
    assert delta["servfail"] == 0


def test_without_an_rcode_table_noerror_is_the_nsstat_classes_that_carry_the_rcode():
    xml = SAMPLE_XML_920.replace(b'<counters type="rcode">', b'<counters type="rcode-x">')
    out = _parse_snapshot(xml)
    # QrySuccess (answers with data) + QryNxrrset (NODATA): 12 + 5 — and
    # never QryAuthAns, which carries the 9 NXDOMAIN answers too.
    assert out["noerror"] == 17
    assert out["nxdomain"] == 9
    assert out["servfail"] == 1
