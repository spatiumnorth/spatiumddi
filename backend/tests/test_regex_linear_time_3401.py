"""Hostile-input timing guards for the regexes CodeQL flags as ReDoS (#3401).

Each pattern was measured linear (about 25 ns per character, no
super-linear growth from 1 KB to 180 KB), so CodeQL's ``py/polynomial-redos``
/ ``py/redos`` findings were not reachable.  These tests pin that property:
a rewrite that introduces nested or overlapping quantifiers turns a
hostile 60 KB input from milliseconds into seconds.  The bounds are
deliberately generous (a quadratic pattern needs minutes at this size).
"""

from __future__ import annotations

import time

from app.services.dns.name_targets import record_target
from app.services.logs.bind9_parser import (
    parse_query_line,
    parse_response_line,
    parse_rpz_line,
)
from app.services.support_bundle.scrub import _pem_body_like

_N = 20_000
_BUDGET_S = 1.0


def _timed(fn, *args, **kwargs) -> float:
    start = time.perf_counter()
    fn(*args, **kwargs)
    return time.perf_counter() - start


def _hostile_heads() -> list[str]:
    return [
        "client\t" + "!\x7f!" * _N,
        "client\t@" + "!\x7f!" * _N,
        "client" + "\t!" * _N,
        "client 1.2.3.4#53 (view\t" + "\x7f\x7f" * _N,
        "client 1.2.3.4#53 (view" + "\t" * _N,
        "client 1.2.3.4#53 " + "view " * _N,
        "client 1.2.3.4#53 " + "(view a" * _N,
    ]


def test_query_parser_hostile_lines_stay_fast() -> None:
    for head in _hostile_heads():
        for line in (
            head,
            head + ": query: a IN A +",
            "03-Nov-2026 10:00:00.000 queries: info: " + head + ": query: " + "\t" * _N,
        ):
            assert _timed(parse_query_line, line) < _BUDGET_S


def test_response_and_rpz_parsers_hostile_lines_stay_fast() -> None:
    for head in _hostile_heads():
        resp = head + ": response: " + "!\t" * _N
        assert _timed(parse_response_line, resp) < _BUDGET_S
        assert _timed(parse_rpz_line, head + " rpz " + "\x7f\x7f" * _N) < _BUDGET_S


def test_svcb_target_hostile_values_stay_fast() -> None:
    for value in (
        "0\t" + "\x7f\x7f" * _N,
        "0 " + "a" * _N + "=",
        "1" * _N,
        "\t" * _N,
    ):
        assert _timed(record_target, "HTTPS", value) < _BUDGET_S


def test_pem_line_classifier_hostile_lines_stay_fast() -> None:
    for line in (
        "A" * _N + "!",
        "=" + "A" * _N + "====",
        "+" * _N + "!",
        "a" + " " * _N + "x",
        "V " * _N,
        "Version" * (_N // 7),
    ):
        assert _timed(_pem_body_like, line) < _BUDGET_S
        assert _timed(_pem_body_like, line, last=True) < _BUDGET_S
