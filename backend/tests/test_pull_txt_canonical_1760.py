"""#1760: a quoted TXT in the DB and the wire form compare equal, case kept.

Applies to every driver that pulls via AXFR (BIND9 included): dnspython
renders TXT in quoted presentation form, the DB may hold either shape.
"""

from __future__ import annotations

from app.drivers.dns.base import RecordData
from app.services.dns.pull_from_server import _key, _normalize_value


def test_bare_and_quoted_txt_key_the_same() -> None:
    assert _normalize_value("TXT", "v=spf1 -all", "example.com.") == _normalize_value(
        "TXT", '"v=spf1 -all"', "example.com."
    )


def test_txt_case_is_significant() -> None:
    a = _key(RecordData(name="@", record_type="TXT", value='"AbC"'), "example.com.")
    b = _key(RecordData(name="@", record_type="TXT", value='"abc"'), "example.com.")
    assert a != b


def test_split_strings_are_not_merged() -> None:
    assert _normalize_value("TXT", '"a" "b"', "z.") != _normalize_value("TXT", '"ab"', "z.")
