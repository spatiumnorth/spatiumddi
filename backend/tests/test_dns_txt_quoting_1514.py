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
