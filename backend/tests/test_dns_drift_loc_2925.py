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


# ── Adversarial review: each case is a spelling a server reads back
#    differently, or two records that must not collapse into one key. ──


def test_loc_size_keys_as_the_value_the_server_serves() -> None:
    # Size and precisions are one digit times a power of ten on the wire:
    # a typed 15m is served, and read back by AXFR, as 10.00m.
    typed = "37 23 N 121 59 W 7m 15m 3000m 7m"
    wire = "37 23 0.000 N 121 59 0.000 W 7.00m 10.00m 3000.00m 7.00m"
    assert _n("LOC", typed) == _n("LOC", wire)


def test_loc_lower_case_direction_letters_match() -> None:
    assert _n("LOC", "37 23 30.900 n 121 59 19.000 w 7m") == _n(
        "LOC", "37 23 30.900 N 121 59 19.000 W 7.00m"
    )


def test_loc_other_hemisphere_stays_different() -> None:
    assert _n("LOC", "37 23 N 121 59 W 7m") != _n("LOC", "37 23 S 121 59 W 7m")
    assert _n("LOC", "37 23 N 121 59 W 7m") != _n("LOC", "37 23 N 121 59 E 7m")


def test_caa_tag_case_folds_value_case_does_not() -> None:
    assert _n("CAA", '0 ISSUE "ca.org"') == _n("CAA", '0 issue "ca.org"')
    assert _n("CAA", '0 iodef "https://x.org/Report"') != _n(
        "CAA", '0 iodef "https://x.org/report"'
    )


def test_caa_flags_compare_as_a_number() -> None:
    assert _n("CAA", "00 issue ca.org") == _n("CAA", '0 issue "ca.org"')
    assert _n("CAA", '128 issue "ca.org"') != _n("CAA", '0 issue "ca.org"')


def test_caa_unquoted_semicolon_is_not_a_comment() -> None:
    # A zone-file parse reads ``; account=1`` as a comment, which would key
    # these two records (and the bare ``ca.org``) as one.
    a = _n("CAA", "0 issue ca.org; account=1")
    b = _n("CAA", "0 issue ca.org; account=2")
    assert a != b
    assert a != _n("CAA", '0 issue "ca.org"')
    assert a == _n("CAA", '0 issue "ca.org; account=1"')


def test_caa_escaped_quote_round_trips() -> None:
    assert _n("CAA", r'0 issue "a\"b"') == _n("CAA", r'0 issue "a\034b"')


def test_caa_unparseable_keeps_case() -> None:
    assert _n("CAA", "0 iodef-x Foo") != _n("CAA", "0 iodef-x foo")


@pytest.mark.parametrize(
    "rtype,typed,wire",
    [
        ("TLSA", "3 1 1 ABCD EF01", "3 1 1 abcdef01"),
        ("TLSA", "03  01 1 abcdef01", "3 1 1 abcdef01"),
        ("SSHFP", "1 1 AB CD", "1 1 abcd"),
    ],
)
def test_hex_types_fold_spacing_and_padding(rtype: str, typed: str, wire: str) -> None:
    assert _n(rtype, typed) == _n(rtype, wire)


def test_tlsa_long_data_matches_the_chunked_wire_form() -> None:
    data = "ab" * 100
    wire = f"3 1 0 {data[:128]} {data[128:]}"
    assert _n("TLSA", f"3 1 0 {data}") == _n("TLSA", wire)


def test_other_types_are_not_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    import app.services.dns.pull_from_server as pfs

    def boom(*_a: object, **_k: object) -> str:
        raise AssertionError("parsed a type that has no rdata rule")

    monkeypatch.setattr(pfs, "_wire_canonical", boom)
    for rtype, value in [("A", "192.0.2.1"), ("MX", "mail"), ("TXT", "x"), ("CNAME", "a")]:
        _n(rtype, value)
