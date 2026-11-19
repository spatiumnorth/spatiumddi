"""BIND9 agent TXT quoting tests (issue #1514).

The Email zone template and API clients store TXT values unquoted.
The BIND9 agent used to drop them into zone files and RFC 2136
updates verbatim, so BIND parsed them as zone-file syntax: a ``;``
in a DMARC value started a comment, and spaces in an SPF value split
it into character-strings resolvers concatenate without the spaces.

The chunking half of #1514: the old ``_quote_txt`` copies escaped
first and cut at 255 *characters*, which could split an escape
sequence across chunks and exceed 255 *octets* for non-ASCII text.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import dns.rdata
import dns.rdatatype
import dns.zone
import pytest

from spatium_dns_agent.drivers.bind9 import Bind9Driver, _quote_txt, _wire_value
from spatium_dns_agent.drivers.powerdns import _quote_txt as _pdns_quote_txt

SPF = "v=spf1 mx include:_spf.example.com -all"
DMARC = "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"


def _served_strings(wire: str) -> list[bytes]:
    rdata = dns.rdata.from_text("IN", "TXT", wire)
    return list(rdata.strings)


def test_quote_txt_unquoted_spf_and_dmarc_round_trip() -> None:
    for value in (SPF, DMARC):
        wire = _quote_txt(value)
        assert wire == f'"{value}"'
        assert _served_strings(wire) == [value.encode()]


def test_quote_txt_already_quoted_is_unchanged() -> None:
    for value in (SPF, DMARC):
        assert _quote_txt(f'"{value}"') == f'"{value}"'


def test_quote_txt_strips_control_characters() -> None:
    assert _quote_txt("bad\x01value\x7f") == '"badvalue"'


def test_quote_txt_empty_value() -> None:
    assert _quote_txt("") == '""'


def test_quote_txt_chunk_never_splits_an_escape_sequence() -> None:
    # The quote sits exactly where a naive 255-char cut of the escaped
    # string would leave a lone backslash at the end of chunk one.
    value = "a" * 254 + '"' + "b" * 100
    wire = _quote_txt(value)
    strings = _served_strings(wire)
    assert all(len(s) <= 255 for s in strings)
    assert b"".join(strings) == value.encode()


def test_quote_txt_chunk_counts_utf8_octets_not_characters() -> None:
    value = "é" * 200  # 400 UTF-8 octets
    wire = _quote_txt(value)
    strings = _served_strings(wire)
    assert len(strings) > 1
    assert all(len(s) <= 255 for s in strings)
    assert b"".join(strings) == value.encode("utf-8")


def test_quote_txt_long_ascii_value_chunks_at_255() -> None:
    value = "x" * 600
    strings = _served_strings(_quote_txt(value))
    assert [len(s) for s in strings] == [255, 255, 90]


def test_quote_txt_copies_agree() -> None:
    """The agent PowerDNS copy must render identically (shared helper)."""
    for value in (SPF, DMARC, "é" * 200, "a" * 254 + '"' + "b" * 100, ""):
        assert _pdns_quote_txt(value) == _quote_txt(value)


def test_wire_value_quotes_txt_only() -> None:
    assert _wire_value("TXT", SPF, {}) == f'"{SPF}"'
    assert _wire_value("TXT", f'"{SPF}"', {}) == f'"{SPF}"'
    assert _wire_value("A", "192.0.2.1", {}) == "192.0.2.1"
    assert _wire_value("MX", "mail.example.com", {"priority": 10}) == (
        "10 mail.example.com"
    )


def _rec(name: str, rtype: str, value: str) -> dict[str, Any]:
    return {
        "name": name,
        "type": rtype,
        "ttl": 3600,
        "value": value,
        "priority": None,
        "weight": None,
        "port": None,
    }


def _zone_file_text(tmp_path: Path, records: list[dict[str, Any]]) -> str:
    zone = {
        "id": "example.test",
        "name": "example.test",
        "type": "primary",
        "ttl": 3600,
        "serial": 2026100401,
        "records": records,
    }
    path = tmp_path / "example.test.db"
    Bind9Driver(state_dir=tmp_path)._write_zone_file(path, zone)
    return path.read_text()


def test_write_zone_file_serves_spf_and_dmarc_intact(tmp_path: Path) -> None:
    for stored_spf, stored_dmarc in ((SPF, DMARC), (f'"{SPF}"', f'"{DMARC}"')):
        text = _zone_file_text(
            tmp_path,
            [_rec("@", "TXT", stored_spf), _rec("_dmarc", "TXT", stored_dmarc)],
        )
        served = dns.zone.from_text(text, origin="example.test", relativize=False)
        apex = served.find_rdataset(served.origin, dns.rdatatype.TXT)
        dmarc = served.find_rdataset("_dmarc.example.test.", dns.rdatatype.TXT)
        assert list(apex[0].strings) == [SPF.encode()]
        assert list(dmarc[0].strings) == [DMARC.encode()]


# ── Already-quoted values round-trip exactly (#1609 QA regression) ────
#
# The first #1609 cut joined the character-strings of an already-quoted
# value into one and read ``\DDD`` as a code point. Both changed what
# BIND9 and PowerDNS served for a value that ``main`` served as entered.

AGENT_HELPERS = pytest.mark.parametrize(
    "quote", [_quote_txt, _pdns_quote_txt], ids=["bind9", "powerdns"]
)

DNS_SD = '"txtvers=1" "path=/printer" "note=2nd floor"'


@AGENT_HELPERS
def test_multi_string_quoted_value_keeps_its_boundaries(quote: Any) -> None:
    assert _served_strings(quote(DNS_SD)) == [
        b"txtvers=1",
        b"path=/printer",
        b"note=2nd floor",
    ]
    assert _served_strings(quote('"part one" "part two"')) == [
        b"part one",
        b"part two",
    ]


@AGENT_HELPERS
def test_decimal_escape_is_one_octet(quote: Any) -> None:
    value = '"caf\\195\\169 \\226\\156\\147"'
    assert _served_strings(quote(value)) == ["café ✓".encode()]
    # A non-UTF-8 octet survives too.
    assert _served_strings(quote('"a\\255b\\000c"')) == [b"a\xffb\x00c"]


@AGENT_HELPERS
def test_quoted_string_over_255_octets_still_splits(quote: Any) -> None:
    value = '"' + "x" * 300 + '" "tail"'
    assert [len(s) for s in _served_strings(quote(value))] == [255, 45, 4]


@AGENT_HELPERS
def test_unquoted_non_ascii_splits_on_character_boundary(quote: Any) -> None:
    strings = _served_strings(quote("é" * 200))
    assert [len(s) for s in strings] == [254, 146]


def test_write_zone_file_serves_multi_string_txt_intact(tmp_path: Path) -> None:
    text = _zone_file_text(tmp_path, [_rec("_ipp._tcp", "TXT", DNS_SD)])
    served = dns.zone.from_text(text, origin="example.test", relativize=False)
    rdset = served.find_rdataset("_ipp._tcp.example.test.", dns.rdatatype.TXT)
    assert list(rdset[0].strings) == [b"txtvers=1", b"path=/printer", b"note=2nd floor"]
