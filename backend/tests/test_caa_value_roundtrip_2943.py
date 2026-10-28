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


# ── Edge cases found in validation ───────────────────────────────────────


@pytest.mark.parametrize(
    ("stored", "octets", "presentation"),
    [
        # \DDD decimal escapes are undone, and non-ASCII prints as \DDD
        ('0 issue "\\195\\169t\\195\\169"', "été".encode(), '0 issue "\\195\\169t\\195\\169"'),
        ('0 issue "été"', "été".encode(), '0 issue "\\195\\169t\\195\\169"'),
        ('0 issue "x\\059y"', b"x;y", '0 issue "x;y"'),
        # spaces inside the quotes are the value's own
        ('0 issue "  pad  "', b"  pad  ", '0 issue "  pad  "'),
        ('0 issue ""', b"", '0 issue ""'),
        # the critical flag and tags the RFC registry added later
        (
            "128 contactemail ops@example.com",
            b"ops@example.com",
            '128 contactemail "ops@example.com"',
        ),
        ("0 issuemail ca.example", b"ca.example", '0 issuemail "ca.example"'),
        # the documented "no CA may issue" form: bare, a zone file reads the
        # ';' as a comment and refuses the whole zone
        ("0 issue ;", b";", '0 issue ";"'),
        # tag case is kept on the wire
        ('0 IssueWild "ca.org"', b"ca.org", '0 IssueWild "ca.org"'),
    ],
)
def test_edge_values(stored: str, octets: bytes, presentation: str) -> None:
    parsed = parse_caa(stored)
    assert parsed is not None and parsed[2] == octets
    assert caa_presentation(stored) == presentation
    assert caa_presentation(presentation) == presentation


def test_a_short_decimal_escape_is_malformed() -> None:
    # A zone-file reader (and ``caa_canonical``) refuses ``\1a``.
    assert parse_caa('0 issue "\\1a"') is None
    assert caa_presentation('0 issue "\\1a"') == '0 issue "\\1a"'


def test_edge_values_reach_azure_and_technitium_unescaped() -> None:
    drv = AzureDNSDriver()
    for stored, plain in [
        ('0 issue "  pad  "', "  pad  "),
        ('0 issue "\\195\\169t\\195\\169"', "été"),
        ("128 contactemail ops@example.com", "ops@example.com"),
    ]:
        (entry,) = drv._build_record_set_params(_rec(stored))["caa_records"]
        assert entry["value"] == plain
        assert record_params("CAA", stored)["value"] == plain


# ── Upgrade: Azure entries written with literal quotes before #2943 ──────


class _FakeRecordSets:
    def __init__(self, entries: list[tuple[int, str, str]]) -> None:
        self.live = SimpleNamespace(
            ttl=300,
            caa_records=[SimpleNamespace(flags=f, tag=t, value=v) for f, t, v in entries],
        )
        self.puts: list[dict] = []
        self.deleted = False

    def get(self, *_a: object) -> SimpleNamespace:
        return self.live

    def create_or_update(self, _rg: str, _z: str, _n: str, _t: str, params: dict) -> None:
        self.puts.append(params)

    def delete(self, *_a: object) -> None:
        self.deleted = True


async def test_azure_deletes_a_legacy_literally_quoted_entry() -> None:
    drv = AzureDNSDriver()
    rs = _FakeRecordSets([(0, "issue", '"ca.org"'), (0, "issue", "other.org")])
    client = SimpleNamespace(record_sets=rs)
    await drv._apply_delete(client, "rg", "z", "@", "CAA", _rec('0 issue "ca.org"'))
    (put,) = rs.puts
    assert [e["value"] for e in put["caa_records"]] == ["other.org"]


async def test_azure_create_replaces_a_legacy_literally_quoted_entry() -> None:
    drv = AzureDNSDriver()
    rs = _FakeRecordSets([(0, "issue", '"ca.org"'), (0, "issue", "other.org")])
    client = SimpleNamespace(record_sets=rs)
    await drv._apply_create(client, "rg", "z", "@", "CAA", _rec('0 issue "ca.org"'))
    (put,) = rs.puts
    assert sorted(e["value"] for e in put["caa_records"]) == ["ca.org", "other.org"]


# ── Route 53 / Google zone-delete emptying recognises what was written ───


def test_cloud_managed_candidates_include_the_quoted_form() -> None:
    from app.drivers.dns._cloud_base import provider_value_candidates

    cands = provider_value_candidates(_rec("0 issue ca.org; account=1"))
    assert '0 issue "ca.org; account=1"' in cands


# ── Cloudflare sends and looks up the quoted form ────────────────────────


def test_cloudflare_payload_and_lookup_content_are_quoted() -> None:
    from app.drivers.dns.base import RecordChange
    from app.drivers.dns.cloudflare import CloudflareDNSDriver, _wire_content

    assert _wire_content("CAA", "0 issue ca.org") == '0 issue "ca.org"'
    assert _wire_content("TXT", "v=spf1 -all") == "v=spf1 -all"
    drv = CloudflareDNSDriver()
    change = RecordChange(
        op="create", zone_name="example.com.", record=_rec("0 issue ca.org"), target_serial=1
    )
    assert drv._record_payload(change, "example.com.")["content"] == '0 issue "ca.org"'
