"""Backend TXT quoting chunk-safety tests (issue #1514, finding 2).

The backend BIND9 and PowerDNS copies of ``_quote_txt`` escaped the
value first and then cut at 255 *characters*: a cut between a ``\\``
and the character it escapes left a chunk ending in a lone backslash
(malformed), and a chunk of multi-byte UTF-8 could exceed the
255-octet character-string limit. Both copies must chunk the
unescaped value by escaped UTF-8 octet length instead.
"""

from __future__ import annotations

import dns.rdata

from app.drivers.dns.bind9 import _quote_txt as bind9_quote_txt
from app.drivers.dns.powerdns import _quote_txt as powerdns_quote_txt

HELPERS = (bind9_quote_txt, powerdns_quote_txt)


def _strings(wire: str) -> list[bytes]:
    return list(dns.rdata.from_text("IN", "TXT", wire).strings)


def test_spf_dmarc_quoted_and_unquoted_forms_agree() -> None:
    for quote in HELPERS:
        for value in ("v=spf1 mx -all", "v=DMARC1; p=quarantine"):
            assert quote(value) == f'"{value}"'
            assert quote(f'"{value}"') == f'"{value}"'
            assert _strings(quote(value)) == [value.encode()]


def test_escape_sequence_never_split_across_chunks() -> None:
    value = "a" * 254 + '"' + "b" * 100
    for quote in HELPERS:
        strings = _strings(quote(value))
        assert all(len(s) <= 255 for s in strings)
        assert b"".join(strings) == value.encode()


def test_non_ascii_chunks_stay_within_255_octets() -> None:
    value = "é" * 200
    for quote in HELPERS:
        strings = _strings(quote(value))
        assert len(strings) > 1
        assert all(len(s) <= 255 for s in strings)
        assert b"".join(strings) == value.encode("utf-8")


def test_backend_copies_agree() -> None:
    for value in ("", "plain", "é" * 200, "a" * 300, '"already quoted"'):
        assert bind9_quote_txt(value) == powerdns_quote_txt(value)


# ── Already-quoted values round-trip exactly (#1609 QA regression) ────


def test_multi_string_quoted_value_keeps_its_boundaries() -> None:
    for quote in HELPERS:
        assert _strings(quote('"txtvers=1" "path=/printer" "note=2nd floor"')) == [
            b"txtvers=1",
            b"path=/printer",
            b"note=2nd floor",
        ]
        assert _strings(quote('"part one" "part two"')) == [b"part one", b"part two"]


def test_decimal_escape_is_one_octet() -> None:
    for quote in HELPERS:
        assert _strings(quote('"caf\\195\\169 \\226\\156\\147"')) == ["café ✓".encode()]
        assert _strings(quote('"a\\255b\\000c"')) == [b"a\xffb\x00c"]


def test_quoted_string_over_255_octets_still_splits() -> None:
    for quote in HELPERS:
        value = '"' + "x" * 300 + '" "tail"'
        assert [len(s) for s in _strings(quote(value))] == [255, 45, 4]


def test_unquoted_non_ascii_splits_on_character_boundary() -> None:
    for quote in HELPERS:
        assert [len(s) for s in _strings(quote("é" * 200))] == [254, 146]
