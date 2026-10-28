"""CAA values round-trip through every driver's write and pull (#2943).

store -> the driver's write payload -> the pull path -> the same key. The
key is :func:`app.drivers.dns._caa.caa_key`, which reads a value the way
``caa_canonical`` (#2925) does, and a test below pins the two together once
both are on the branch.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.drivers.dns._caa import (
    caa_key,
    caa_presentation,
    caa_unquoted_value,
    parse_caa,
)
from app.drivers.dns._cloud_base import compose_structured_rdata
from app.drivers.dns.azuredns import AzureDNSDriver
from app.drivers.dns.base import RecordData
from app.drivers.dns.cloudflare import _content_key
from app.drivers.dns.powerdns import _record_content
from app.services.technitium.rdata import rdata_to_value, record_params

# (stored value, the value Azure / Technitium receive unquoted)
CASES = [
    ('0 issue "letsencrypt.org"', "letsencrypt.org"),
    ("0 issue letsencrypt.org", "letsencrypt.org"),
    ('0 issue "ca.org; account=1"', "ca.org; account=1"),
    ("0 issue ca.org; account=1", "ca.org; account=1"),
    ('0 issue "say \\"hi\\" \\\\ there"', 'say "hi" \\ there'),
    ('128 iodef "mailto:sec@example.com"', "mailto:sec@example.com"),
    ('0 ISSUE "ca.org"', "ca.org"),
    ('0 issue ""', ""),
]


def _rec(value: str) -> RecordData:
    return RecordData(name="@", record_type="CAA", value=value, ttl=300)


@pytest.mark.parametrize(("stored", "plain"), CASES)
def test_parse_and_unquote(stored: str, plain: str) -> None:
    assert caa_unquoted_value(stored) == plain


def test_bare_and_quoted_are_one_key() -> None:
    assert caa_key("0 issue ca.org") == caa_key('0 issue "ca.org"')
    # An unquoted ';' is part of the value, not a comment.
    assert caa_key("0 issue ca.org; account=1") != caa_key("0 issue ca.org")
    assert caa_key("0 ISSUE ca.org") == caa_key("0 issue ca.org")
    # value case is kept
    assert caa_key("0 issue CA.org") != caa_key("0 issue ca.org")


def test_unparseable_is_left_alone() -> None:
    assert parse_caa("garbage") is None
    assert caa_presentation("garbage") == "garbage"
    assert parse_caa('0 issue "unterminated') is None


def test_matches_caa_canonical_when_present() -> None:
    pull = pytest.importorskip("app.services.dns.pull_from_server")
    canonical = getattr(pull, "caa_canonical", None)
    if canonical is None:
        pytest.skip("caa_canonical (#2925) is not on this branch")
    for stored, _ in CASES:
        assert caa_key(stored) == canonical(stored), stored


# ── Azure ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(("stored", "plain"), CASES)
def test_azure_writes_the_unquoted_value(stored: str, plain: str) -> None:
    drv = AzureDNSDriver()
    params = drv._build_record_set_params(_rec(stored))
    (entry,) = params["caa_records"]
    assert entry["value"] == plain
    assert entry["flags"] == int(stored.split()[0])


@pytest.mark.parametrize(("stored", "plain"), CASES)
def test_azure_round_trip_dedupes_and_pulls_same_key(stored: str, plain: str) -> None:
    drv = AzureDNSDriver()
    entry = drv._build_record_entry(_rec(stored))
    live = SimpleNamespace(
        caa_records=[SimpleNamespace(flags=entry["flags"], tag=entry["tag"], value=entry["value"])]
    )
    # the live set, read back, is the entry just written: no duplicate on re-apply
    (read_back,) = drv._existing_entries(live, "CAA")
    assert drv._entry_key("CAA", read_back) == drv._entry_key("CAA", entry)
    # and the pull's text form keys as the stored value does
    if plain:  # an empty value has no bare text form to read back
        pulled = f"{read_back['flags']} {read_back['tag']} {read_back['value']}"
        assert caa_key(pulled) == caa_key(stored)


def test_azure_quoted_and_bare_are_one_entry() -> None:
    drv = AzureDNSDriver()
    a = drv._build_record_entry(_rec('0 issue "ca.org"'))
    b = drv._build_record_entry(_rec("0 issue ca.org"))
    assert drv._entry_key("CAA", a) == drv._entry_key("CAA", b)


# ── Route 53 / Google Cloud DNS (single-string rdata) ────────────────────


@pytest.mark.parametrize(("stored", "plain"), CASES)
def test_cloud_rdata_is_quoted_and_pulls_same_key(stored: str, plain: str) -> None:
    sent = compose_structured_rdata(_rec(stored))
    assert sent.split(" ", 2)[2].startswith('"') and sent.endswith('"')
    # the provider stores it as written and hands it back; the pull path
    # (split_structured_rdata) leaves a CAA value verbatim
    assert caa_key(sent) == caa_key(stored)
    assert caa_unquoted_value(sent) == plain
    # writing the pulled form again is stable
    assert compose_structured_rdata(_rec(sent)) == sent


# ── Cloudflare ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(("stored", "plain"), CASES)
def test_cloudflare_content_key_matches_pulled_content(stored: str, plain: str) -> None:
    # Cloudflare reports CAA content in the quoted form
    pulled = caa_presentation(stored)
    assert _content_key("CAA", pulled) == _content_key("CAA", stored)


# ── PowerDNS (API content) ───────────────────────────────────────────────


@pytest.mark.parametrize(("stored", "plain"), CASES)
def test_powerdns_content_is_quoted_and_round_trips(stored: str, plain: str) -> None:
    content = _record_content(_rec(stored))
    assert content.split(" ", 2)[2].startswith('"')
    assert caa_key(content) == caa_key(stored)


# ── Technitium (API driver + importer share services/technitium/rdata) ───


@pytest.mark.parametrize(("stored", "plain"), CASES)
def test_technitium_write_params_are_unquoted(stored: str, plain: str) -> None:
    params = record_params("CAA", stored)
    assert params["value"] == plain
    assert params["flags"] == int(stored.split()[0])


@pytest.mark.parametrize(("stored", "plain"), CASES)
def test_technitium_pull_keys_like_the_stored_value(stored: str, plain: str) -> None:
    params = record_params("CAA", stored)
    value, _extra = rdata_to_value(
        "CAA", {"flags": params["flags"], "tag": params["tag"], "value": params["value"]}
    )
    assert caa_key(value) == caa_key(stored)
    # a second trip is a fixed point
    again = record_params("CAA", value)
    assert again["value"] == plain


def test_technitium_pull_escapes_an_embedded_quote() -> None:
    value, _ = rdata_to_value("CAA", {"flags": 0, "tag": "issue", "value": 'a"b'})
    assert value == '0 issue "a\\"b"'
