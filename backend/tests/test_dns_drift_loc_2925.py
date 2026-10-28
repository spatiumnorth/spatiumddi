"""LOC values compare in dnspython's canonical form (#2925)."""

from __future__ import annotations

import pytest

from app.services.dns.pull_from_server import _normalize_value


def _n(t: str, v: str) -> str:
    return _normalize_value(t, v, "z.example.", relative_targets=True)


def test_loc_example_matches_axfr_form() -> None:
    typed = "37 23 30.900 N 121 59 19.000 W 7m"
    wire = "37 23 30.900 N 121 59 19.000 W 7.00m"
    assert _n("LOC", typed) == _n("LOC", wire)


def test_loc_short_form_and_explicit_defaults_match() -> None:
    assert _n("LOC", "37 23 N 121 59 W 7m") == _n(
        "LOC", "37 23 0.000 N 121 59 0.000 W 7.00m 1.00m 10000.00m 10.00m"
    )


def test_loc_different_values_stay_different() -> None:
    assert _n("LOC", "37 23 N 121 59 W 7m") != _n("LOC", "37 23 N 121 59 W 8m")


def test_loc_unparseable_does_not_raise() -> None:
    assert _n("LOC", " Garbage ") == "garbage"


@pytest.mark.parametrize(
    "rtype,a,b",
    [
        ("CAA", "0 issue letsencrypt.org", '0 issue "letsencrypt.org"'),
        ("SSHFP", "1 1 ABCDEF12", "1 1 abcdef12"),
        ("TLSA", "3 1 1 ABCD", "3 1 1 abcd"),
    ],
)
def test_probe_other_free_form(rtype: str, a: str, b: str) -> None:
    assert _n(rtype, a) == _n(rtype, b)


def test_caa_different_values_stay_different() -> None:
    assert _n("CAA", "0 issue a.org") != _n("CAA", "0 issue b.org")
