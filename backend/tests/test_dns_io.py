"""Unit tests for the DNS zone-file parse / diff / write service."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from app.services.dns_io import (
    ZoneParseError,
    diff_records,
    parse_zone_file,
    write_zone_file,
)

REALISTIC_ZONE = """\
$ORIGIN example.com.
$TTL 3600
@\tIN\tSOA\tns1.example.com. hostmaster.example.com. (
    2024010101  ; serial
    86400       ; refresh
    7200        ; retry
    3600000     ; expire
    3600        ; minimum
)
@       IN  NS      ns1.example.com.
@       IN  NS      ns2.example.com.
@       IN  A       192.0.2.1
@       IN  AAAA    2001:db8::1
@       IN  MX  10  mail.example.com.
www     IN  A       192.0.2.10
www     IN  AAAA    2001:db8::10
ftp     IN  CNAME   www.example.com.
_sip._tcp IN SRV    10 60 5060 sipserver.example.com.
txt     IN  TXT     "v=spf1 -all"
"""


def test_parse_realistic_zone() -> None:
    parsed = parse_zone_file(REALISTIC_ZONE, "example.com")
    assert parsed.soa is not None
    assert parsed.soa.serial == 2024010101
    assert parsed.soa.refresh == 86400

    kinds = {r.record_type for r in parsed.records}
    assert {"A", "AAAA", "NS", "MX", "CNAME", "SRV", "TXT"}.issubset(kinds)

    # MX has priority split out
    mx = next(r for r in parsed.records if r.record_type == "MX")
    assert mx.priority == 10
    assert mx.value.startswith("mail.example.com")

    # SRV has priority/weight/port
    srv = next(r for r in parsed.records if r.record_type == "SRV")
    assert (srv.priority, srv.weight, srv.port) == (10, 60, 5060)
    assert "sipserver" in srv.value


def test_parse_malformed_zone_raises_readable_error() -> None:
    with pytest.raises(ZoneParseError) as exc_info:
        parse_zone_file("this is not a zone file {{{", "example.com")
    assert "parse" in str(exc_info.value).lower() or "fail" in str(exc_info.value).lower()


@dataclass
class FakeRecord:
    """Shim mimicking the subset of DNSRecord fields used by diff/write."""

    id: str
    name: str
    record_type: str
    value: str
    ttl: int | None = None
    priority: int | None = None
    weight: int | None = None
    port: int | None = None
    # Scope + ownership, read by the diff since #2167.
    view_id: object = None
    pool_member_id: object = None
    tailscale_tenant_id: object = None
    netbird_instance_id: object = None
    kubernetes_cluster_id: object = None
    ip_address_id: object = None
    auto_generated: bool = False
    ip_alias: bool = False
    tags: dict | None = None
    import_source: str | None = None


def test_diff_detects_create_update_delete() -> None:
    parsed = parse_zone_file(REALISTIC_ZONE, "example.com")

    existing = [
        # Matches -> unchanged
        FakeRecord(id="1", name="www", record_type="A", value="192.0.2.10", ttl=3600),
        # Same name/type/value but different TTL -> update
        FakeRecord(id="2", name="@", record_type="A", value="192.0.2.1", ttl=60),
        # Not in parsed -> delete
        FakeRecord(id="3", name="obsolete", record_type="A", value="10.0.0.1", ttl=3600),
    ]

    diff = diff_records(parsed.records, existing)

    create_keys = {(c.name, c.record_type, c.value) for c in diff.to_create}
    # At minimum AAAA records and TXT should be creates
    assert any(c.record_type == "AAAA" for c in diff.to_create)
    assert ("www", "A", "192.0.2.10") not in create_keys

    updated_pairs = {(c.existing_id, c.record_type) for c in diff.to_update}
    assert ("2", "A") in updated_pairs

    deleted_ids = {c.existing_id for c in diff.to_delete}
    assert "3" in deleted_ids


def test_write_zone_file_round_trip() -> None:
    # Zone stub with fields the writer needs.
    @dataclass
    class FakeZone:
        name: str = "example.com."
        primary_ns: str = "ns1.example.com."
        admin_email: str = "hostmaster.example.com."
        ttl: int = 3600
        refresh: int = 86400
        retry: int = 7200
        expire: int = 3600000
        minimum: int = 3600
        last_serial: int = 2024010101

    zone = FakeZone()
    records = [
        FakeRecord(id="1", name="@", record_type="NS", value="ns1.example.com.", ttl=3600),
        FakeRecord(id="2", name="@", record_type="A", value="192.0.2.1", ttl=3600),
        FakeRecord(id="3", name="www", record_type="A", value="192.0.2.10", ttl=3600),
        FakeRecord(
            id="4", name="@", record_type="MX", value="mail.example.com.", ttl=3600, priority=10
        ),
        FakeRecord(
            id="5",
            name="_sip._tcp",
            record_type="SRV",
            value="sipserver.example.com.",
            ttl=3600,
            priority=10,
            weight=60,
            port=5060,
        ),
        FakeRecord(id="6", name="txt", record_type="TXT", value="v=spf1 -all", ttl=3600),
    ]

    text = write_zone_file(zone, records)  # type: ignore[arg-type]
    assert "$ORIGIN example.com." in text
    assert "SOA" in text
    assert "192.0.2.1" in text
    assert "10 60 5060" in text  # SRV
    assert '"v=spf1 -all"' in text  # TXT quoted

    # Re-parse the output and confirm we get back the same records.
    reparsed = parse_zone_file(text, "example.com")
    values = {(r.name, r.record_type, r.value) for r in reparsed.records}
    assert ("@", "A", "192.0.2.1") in values
    assert ("www", "A", "192.0.2.10") in values
    assert any(r.record_type == "SRV" and r.priority == 10 for r in reparsed.records)
    assert any(r.record_type == "MX" and r.priority == 10 for r in reparsed.records)


_TTL_ZONE = """\
$ORIGIN example.com.
$TTL 3600
@\tIN\tSOA\tns1.example.com. hostmaster.example.com. ( 1 2 3 4 5 )
"""


def test_diff_meta_only_update_keeps_inherited_ttl() -> None:
    """#1727: an SRV/MX change alone does not pin the TTL a row inherits."""
    parsed = parse_zone_file(
        _TTL_ZONE
        + "_sip._tcp\tIN\tSRV\t20 70 5061 sip.example.com.\n"
        + "@\tIN\tMX\t5 mail.example.com.\n",
        "example.com",
    )
    existing = [
        FakeRecord(
            id="1",
            name="_sip._tcp",
            record_type="SRV",
            value="sip.example.com.",
            ttl=None,
            priority=10,
            weight=60,
            port=5060,
        ),
        FakeRecord(
            id="2", name="@", record_type="MX", value="mail.example.com.", ttl=None, priority=10
        ),
    ]

    diff = diff_records(parsed.records, existing, zone_default_ttl=3600)  # type: ignore[arg-type]

    by_id = {c.existing_id: c for c in diff.to_update}
    assert set(by_id) == {"1", "2"}
    assert (by_id["1"].priority, by_id["1"].weight, by_id["1"].port) == (20, 70, 5061)
    assert by_id["1"].ttl is None
    assert by_id["2"].priority == 5
    assert by_id["2"].ttl is None


def test_diff_inherited_row_with_a_different_file_ttl_updates() -> None:
    parsed = parse_zone_file(_TTL_ZONE + "www\t120\tIN\tA\t192.0.2.1\n", "example.com")
    existing = [FakeRecord(id="1", name="www", record_type="A", value="192.0.2.1", ttl=None)]

    diff = diff_records(parsed.records, existing, zone_default_ttl=3600)  # type: ignore[arg-type]

    assert [(c.existing_id, c.ttl) for c in diff.to_update] == [("1", 120)]


def test_diff_mixed_ttl_rrset_round_trips_unchanged() -> None:
    """#1727: an RRset whose members carry different TTLs parses back at the
    lowest of them. Neither the inherited member nor the explicit higher one
    may be rewritten to that minimum by a round trip of the zone's own export.
    """

    @dataclass
    class FakeZone:
        name: str = "example.com."
        primary_ns: str = "ns1.example.com."
        admin_email: str = "hostmaster.example.com."
        ttl: int = 3600
        refresh: int = 86400
        retry: int = 7200
        expire: int = 3600000
        minimum: int = 3600
        last_serial: int = 1

    existing = [
        FakeRecord(id="1", name="www", record_type="A", value="192.0.2.1", ttl=None),
        FakeRecord(id="2", name="www", record_type="A", value="192.0.2.2", ttl=300),
        FakeRecord(id="3", name="big", record_type="A", value="192.0.2.3", ttl=7200),
        FakeRecord(id="4", name="big", record_type="A", value="192.0.2.4", ttl=None),
    ]
    text = write_zone_file(FakeZone(), existing)  # type: ignore[arg-type]
    parsed = parse_zone_file(text, "example.com")
    # The premise: the parser collapses each RRset to its lowest TTL.
    assert {r.ttl for r in parsed.records if r.name == "www"} == {300}
    assert {r.ttl for r in parsed.records if r.name == "big"} == {3600}

    diff = diff_records(parsed.records, existing, zone_default_ttl=3600)  # type: ignore[arg-type]

    assert diff.to_update == []
    assert diff.to_create == []
    assert diff.to_delete == []
    assert len(diff.unchanged) == 4


def test_diff_mixed_ttl_rrset_explicit_change_still_updates() -> None:
    # The file lowers the whole RRset below its existing minimum: every member
    # that does not already carry that TTL is an update.
    parsed = parse_zone_file(
        _TTL_ZONE + "www\t60\tIN\tA\t192.0.2.1\nwww\t60\tIN\tA\t192.0.2.2\n", "example.com"
    )
    existing = [
        FakeRecord(id="1", name="www", record_type="A", value="192.0.2.1", ttl=None),
        FakeRecord(id="2", name="www", record_type="A", value="192.0.2.2", ttl=300),
    ]

    diff = diff_records(parsed.records, existing, zone_default_ttl=3600)  # type: ignore[arg-type]

    assert sorted((c.existing_id, c.ttl) for c in diff.to_update) == [("1", 60), ("2", 60)]
