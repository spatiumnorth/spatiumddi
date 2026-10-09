"""Technitium live-pull importer (issue #744).

The interesting surface is ``_rdata_to_value``: Technitium's record GET
returns a structured ``rData`` object whose field names do NOT match its
own write API, and which renders numeric rdata as enum NAMES. This is the
inverse of the agent driver's ``_normalize_rdata``. Every expectation
below was captured from a live technitium/dns-server:15.4.0.
"""

from __future__ import annotations

import pytest

from app.services.dns_import.technitium import (
    TechnitiumImportError,
    _build_imported_zone,
    _classify_zone,
    _rdata_to_value,
    _rel_name,
    _unwrap,
)


def test_rel_name_relativises_against_the_zone() -> None:
    assert _rel_name("www.example.com", "example.com.") == "www"
    assert _rel_name("example.com", "example.com.") == "@"
    assert _rel_name("_sip._tcp.example.com", "example.com.") == "_sip._tcp"


def test_classify_zone_detects_reverse() -> None:
    assert _classify_zone("10.in-addr.arpa.") == "reverse"
    assert _classify_zone("8.b.d.0.1.0.0.2.ip6.arpa.") == "reverse"
    assert _classify_zone("example.com.") == "forward"


@pytest.mark.parametrize(
    ("rtype", "rdata", "expected"),
    [
        ("A", {"ipAddress": "10.0.0.1"}, "10.0.0.1"),
        ("AAAA", {"ipAddress": "2001:db8::1"}, "2001:db8::1"),
        ("CNAME", {"cname": "www.example.net"}, "www.example.net"),
        ("DNAME", {"dname": "other.example.net"}, "other.example.net"),
        ("NS", {"nameServer": "ns1.example.net"}, "ns1.example.net"),
        ("PTR", {"ptrName": "host.example.net"}, "host.example.net"),
        ("TXT", {"text": "v=spf1 -all"}, "v=spf1 -all"),
        (
            "CAA",
            {"flags": 0, "tag": "issue", "value": "letsencrypt.org"},
            '0 issue "letsencrypt.org"',
        ),
        (
            "URI",
            {"priority": 1, "weight": 1, "uri": "https://example.test/"},
            # #1513: the bare-authority slash Technitium appends is
            # canonicalised away on read, matching the write side.
            "1 1 https://example.test",
        ),
        (
            "URI",
            {"priority": 1, "weight": 1, "uri": "https://example.test/path/"},
            # …but a path's trailing slash is significant and stays.
            "1 1 https://example.test/path/",
        ),
        (
            "AAAA",
            {"ipAddress": "2001:DB8:0:0::1"},
            # #1513: canonicalised through ipaddress on read.
            "2001:db8::1",
        ),
    ],
)
def test_rdata_to_value_simple_types(rtype: str, rdata: dict, expected: str) -> None:
    value, extra = _rdata_to_value(rtype, rdata)
    assert value == expected
    assert extra == {}


def test_rdata_to_value_hoists_structured_fields() -> None:
    """MX/SRV carry priority (and weight/port) as columns, not in the
    value string."""
    value, extra = _rdata_to_value("MX", {"exchange": "mail.example.net", "preference": 20})
    assert (value, extra) == ("mail.example.net", {"priority": 20})

    value, extra = _rdata_to_value(
        "SRV", {"target": "sip.example.net", "priority": 10, "weight": 20, "port": 5060}
    )
    assert value == "sip.example.net"
    assert extra == {"priority": 10, "weight": 20, "port": 5060}


def test_rdata_to_value_reverses_enum_names() -> None:
    """The crux: Technitium reads TLSA/SSHFP numeric fields back as enum
    NAMES. Importing them verbatim would produce records no other driver
    could serve."""
    value, _ = _rdata_to_value(
        "TLSA",
        {
            "certificateUsage": "DANE-EE",
            "selector": "SPKI",
            "matchingType": "SHA2-256",
            "certificateAssociationData": "ABCD",
        },
    )
    assert value == "3 1 1 abcd"

    value, _ = _rdata_to_value(
        "SSHFP",
        {"algorithm": "Ed25519", "fingerprintType": "SHA256", "fingerprint": "AB12"},
    )
    assert value == "4 2 ab12"


def test_rdata_to_value_unknown_enum_passes_through() -> None:
    """A Technitium version that adds an enum member must degrade to one
    odd-looking record, not an exception mid-import."""
    value, _ = _rdata_to_value(
        "SSHFP", {"algorithm": "5", "fingerprintType": "SHA1", "fingerprint": "aa"}
    )
    assert value == "5 1 aa"


def test_rdata_to_value_svcb_params_dict_to_presentation() -> None:
    """svcParams comes back as a dict; a multi-value param keeps its
    commas (issue #745 confirmed Technitium accepts and stores them)."""
    value, _ = _rdata_to_value(
        "HTTPS", {"svcPriority": 1, "svcTargetName": ".", "svcParams": {"alpn": "h2,h3"}}
    )
    assert value == '1 . alpn="h2,h3"'


def test_build_imported_zone_hoists_soa_and_skips_dnssec() -> None:
    zone = _build_imported_zone(
        "example.com",
        [
            {
                "name": "example.com",
                "type": "SOA",
                "ttl": 900,
                "rData": {
                    "primaryNameServer": "ns1.example.com",
                    "responsiblePerson": "admin.example.com",
                    "serial": 42,
                    "refresh": 900,
                    "retry": 300,
                    "expire": 604800,
                    "minimum": 60,
                },
            },
            {
                "name": "www.example.com",
                "type": "A",
                "ttl": 300,
                "rData": {"ipAddress": "10.0.0.1"},
            },
            {"name": "example.com", "type": "DNSKEY", "ttl": 3600, "rData": {}},
            {"name": "example.com", "type": "RRSIG", "ttl": 3600, "rData": {}},
        ],
    )
    assert zone.name == "example.com."
    assert zone.soa is not None and zone.soa.serial == 42
    assert zone.soa.primary_ns == "ns1.example.com."
    assert [r.record_type for r in zone.records] == ["A"]
    assert any("DNSSEC" in w for w in zone.parse_warnings)


def test_build_imported_zone_skips_disabled_records() -> None:
    """Technitium marks a disabled record rather than omitting it —
    importing one would silently resurrect something the operator turned
    off on the source server."""
    zone = _build_imported_zone(
        "example.com",
        [
            {
                "name": "off.example.com",
                "type": "A",
                "ttl": 300,
                "disabled": True,
                "rData": {"ipAddress": "10.0.0.9"},
            }
        ],
    )
    assert zone.records == []
    assert any("disabled" in w for w in zone.parse_warnings)


def test_unwrap_surfaces_body_level_failure() -> None:
    """Technitium answers HTTP 200 even on failure — an expired token
    included — so the body's status is the only place it shows."""
    with pytest.raises(TechnitiumImportError, match="invalid-token"):
        _unwrap({"status": "invalid-token", "errorMessage": "token expired"}, "zone list")
    assert _unwrap({"status": "ok", "response": {"zones": []}}, "zone list") == {"zones": []}


def test_int_or_preserves_legitimate_zero() -> None:
    """``int(x or default)`` silently rewrites 0 to the default. That
    matters: SVCB/HTTPS priority 0 is AliasMode (not ServiceMode), MX
    preference 0 is the highest priority, and URI priority/weight 0 are
    valid."""
    from app.services.dns_import.technitium import _int_or

    assert _int_or(0, 10) == 0
    assert _int_or(None, 10) == 10
    assert _int_or("", 10) == 10
    assert _int_or("garbage", 10) == 10

    value, extra = _rdata_to_value("MX", {"exchange": "mail.example.net", "preference": 0})
    assert extra["priority"] == 0

    value, _ = _rdata_to_value(
        "HTTPS", {"svcPriority": 0, "svcTargetName": "svc.example.net", "svcParams": {}}
    )
    assert value.startswith("0 "), value


def test_build_imported_zone_preserves_zero_ttl() -> None:
    zone = _build_imported_zone(
        "example.com",
        [{"name": "www.example.com", "type": "A", "ttl": 0, "rData": {"ipAddress": "10.0.0.1"}}],
    )
    assert zone.records[0].ttl == 0


# ── #1513: rdata round-trip canonicalisation (write direction) ─────────


def test_svcb_params_sorted_by_key_and_valueless_keys_kept() -> None:
    """The read direction rebuilds svcParams sorted by key, so the write
    direction must sort too — and a valueless param (no-default-alpn)
    must be emitted as ``key|``, not dropped."""
    from app.services.technitium.rdata import svcb_params

    _, _, params = svcb_params('1 . port=443 alpn="h2"')
    assert params == "alpn|h2,port|443"
    _, _, params = svcb_params('1 . no-default-alpn alpn="h2"')
    assert params == "alpn|h2,no-default-alpn|"


def test_record_params_uri_and_aaaa_canonicalisation() -> None:
    from app.services.technitium.rdata import record_params

    # A path's trailing slash survives; a bare authority's does not.
    assert record_params("URI", "1 1 https://example.com/path/")["uri"] == (
        "https://example.com/path/"
    )
    assert record_params("URI", "1 1 https://example.com/")["uri"] == "https://example.com"
    # Non-canonical AAAA is canonicalised on write.
    assert record_params("AAAA", "2001:DB8:0:0::1") == {"ipAddress": "2001:db8::1"}


def test_pull_normalize_value_uri_and_aaaa() -> None:
    """The drift key folds the same canonicalisations (#1513)."""
    from app.services.dns.pull_from_server import _normalize_value

    assert _normalize_value("URI", "1 1 https://example.test/", "example.test.") == (
        "1 1 https://example.test"
    )
    assert _normalize_value("URI", "1 1 https://example.test/path/", "example.test.") == (
        "1 1 https://example.test/path/"
    )
    assert _normalize_value("AAAA", "2001:DB8:0:0::1", "example.test.") == "2001:db8::1"
