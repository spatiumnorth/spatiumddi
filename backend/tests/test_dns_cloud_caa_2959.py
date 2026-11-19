"""CAA on DigitalOcean / Linode / Vultr / Hetzner (#2959).

Each provider's record API is built around its own CAA shape. A stored value
(``0 issue "ca.org"`` or the bare ``0 issue ca.org``) must be split on write
the way the provider documents, and rebuilt to one canonical value on pull, so
store -> payload -> pull keys back to the record that went in.
"""

from __future__ import annotations

import pytest

from app.drivers.dns._caa import caa_key
from app.drivers.dns._cloud_base import CloudDNSError
from app.drivers.dns.base import RecordChange, RecordData
from app.drivers.dns.digitalocean import DigitalOceanDNSDriver
from app.drivers.dns.hetzner import HetznerDNSDriver
from app.drivers.dns.linode import LinodeDNSDriver
from app.drivers.dns.vultr import VultrDNSDriver
from tests import test_dns_digitalocean as do
from tests import test_dns_hetzner as hz
from tests import test_dns_linode as ln
from tests import test_dns_vultr as vu

STORED = ['0 issue "ca.org"', "0 issue ca.org", '128 issuewild "ca.org; account=1"']


def _rec(value: str) -> RecordData:
    return RecordData(name="@", record_type="CAA", value=value, ttl=300)


def _change(value: str, op: str = "create") -> RecordChange:
    return RecordChange(op=op, zone_name="example.com.", record=_rec(value), target_serial=1)


# ── DigitalOcean: flags / tag / data ────────────────────────────────────
@pytest.mark.parametrize("stored", STORED)
async def test_digitalocean_split_and_round_trip(
    monkeypatch: pytest.MonkeyPatch, stored: str
) -> None:
    payload = DigitalOceanDNSDriver()._record_payload(_change(stored))
    assert set(payload) >= {"flags", "tag", "data"}
    assert '"' not in payload["data"]
    flags, tag, data = stored.split(" ", 2)
    assert (payload["flags"], payload["tag"]) == (int(flags), tag)
    assert payload["data"] == data.strip('"')

    row = {"id": 1, "name": "@", "type": "CAA", "ttl": 300, **payload}
    fake = do._FakeClient({"get": [do._FakeResponse(200, do._records([row]))]})
    driver = do._patch_client(monkeypatch, fake)
    pulled = await driver._list_zone_records(do._Server(), do._CREDS, "example.com.")
    assert caa_key(pulled[0].value) == caa_key(stored)


async def test_digitalocean_update_finds_row_by_parts(monkeypatch: pytest.MonkeyPatch) -> None:
    row = {
        "id": 7,
        "name": "@",
        "type": "CAA",
        "ttl": 300,
        "flags": 0,
        "tag": "issue",
        "data": "ca.org",
    }
    fake = do._FakeClient(
        {
            "get": [do._FakeResponse(200, do._records([row]))],
            "delete": [do._FakeResponse(204, {})],
        }
    )
    driver = do._patch_client(monkeypatch, fake)
    await driver._apply_record(do._Server(), do._CREDS, _change('0 issue "ca.org"', "delete"))
    assert any(c["method"] == "delete" and c["path"].endswith("/records/7") for c in fake.calls)


def test_digitalocean_rejects_unparseable_caa() -> None:
    with pytest.raises(CloudDNSError):
        DigitalOceanDNSDriver()._record_payload(_change("garbage"))


# ── Linode: tag + target, no flags ──────────────────────────────────────
@pytest.mark.parametrize("stored", ['0 issue "ca.org"', "0 issue ca.org"])
async def test_linode_split_and_round_trip(monkeypatch: pytest.MonkeyPatch, stored: str) -> None:
    payload = LinodeDNSDriver()._record_payload(_change(stored), "example.com.")
    assert payload["tag"] == "issue"
    assert payload["target"] == "ca.org"

    row = {"id": 1, "name": "", "type": "CAA", "ttl_sec": 300, **payload}
    fake = ln._FakeClient(
        {
            "get": [
                ln._FakeResponse(200, ln._env([{"id": 42, "domain": "example.com"}])),
                ln._FakeResponse(200, ln._env([row])),
            ]
        }
    )
    driver = ln._patch_client(monkeypatch, fake)
    pulled = await driver._list_zone_records(ln._Server(), ln._CREDS, "example.com.")
    assert caa_key(pulled[0].value) == caa_key(stored)


def test_linode_refuses_nonzero_flags() -> None:
    with pytest.raises(CloudDNSError, match="flags"):
        LinodeDNSDriver()._record_payload(_change('128 issue "ca.org"'), "example.com.")


async def test_linode_delete_matches_by_tag_and_target(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [
        {"id": 1, "name": "", "type": "CAA", "tag": "issuewild", "target": "ca.org"},
        {"id": 2, "name": "", "type": "CAA", "tag": "issue", "target": "ca.org"},
    ]
    fake = ln._FakeClient({"get": [ln._FakeResponse(200, ln._env(rows))]})
    driver = ln._patch_client(monkeypatch, fake)
    async with driver._client("t") as client:
        rid = await driver._find_record_id(client, 42, "", "CAA", target='0 issue "ca.org"')
    assert rid == 2


# ── Vultr / Hetzner: one zone-file value field ──────────────────────────
@pytest.mark.parametrize("stored", STORED)
async def test_vultr_quotes_on_write_and_round_trips(
    monkeypatch: pytest.MonkeyPatch, stored: str
) -> None:
    payload = VultrDNSDriver()._record_payload(_change(stored))
    assert payload["data"].split(" ", 2)[2].startswith('"')
    row = {"id": "r1", "name": "", "type": "CAA", "ttl": 300, "data": payload["data"]}
    fake = vu._FakeClient({"get": [vu._FakeResponse(200, vu._records_env([row]))]})
    driver = vu._patch_client(monkeypatch, fake)
    pulled = await driver._list_zone_records(vu._Server(), vu._CREDS, "example.com.")
    assert caa_key(pulled[0].value) == caa_key(stored)


@pytest.mark.parametrize("stored", STORED)
async def test_hetzner_quotes_on_write_and_round_trips(
    monkeypatch: pytest.MonkeyPatch, stored: str
) -> None:
    wire = HetznerDNSDriver._wire_value(_rec(stored))
    assert wire.split(" ", 2)[2].startswith('"')
    body = hz._page(
        "rrsets",
        [{"name": "@", "type": "CAA", "ttl": 300, "records": [{"value": wire}]}],
    )
    fake = hz._FakeClient({"get": [hz._FakeResponse(200, body)]})
    driver = hz._patch_client(monkeypatch, fake)
    pulled = await driver._list_zone_records(hz._Server(), hz._CREDS, "example.com.")
    assert caa_key(pulled[0].value) == caa_key(stored)


# ── Upgrade: records a release before #2959 wrote ───────────────────────
# Before #2959 every one of the four drivers sent the stored value as typed
# into its one value field. A record that reached the provider that way must
# still be found by update / delete (not orphaned, not duplicated), and pull
# must key it the same as the stored value.
async def test_digitalocean_finds_and_pulls_a_pre_2959_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The whole value in ``data``, no ``tag``, as main sent it.
    row = {"id": 9, "name": "@", "type": "CAA", "ttl": 300, "data": '0 issue "ca.org"'}
    fake = do._FakeClient(
        {
            "get": [
                do._FakeResponse(200, do._records([row])),
                do._FakeResponse(200, do._records([row])),
            ],
            "delete": [do._FakeResponse(204, {})],
        }
    )
    driver = do._patch_client(monkeypatch, fake)
    pulled = await driver._list_zone_records(do._Server(), do._CREDS, "example.com.")
    assert caa_key(pulled[0].value) == caa_key('0 issue "ca.org"')
    await driver._apply_record(do._Server(), do._CREDS, _change("0 issue ca.org", "delete"))
    assert any(c["method"] == "delete" and c["path"].endswith("/records/9") for c in fake.calls)


async def test_digitalocean_quoted_data_keys_the_same(monkeypatch: pytest.MonkeyPatch) -> None:
    # A ``data`` that comes back quoted is the same record, not one whose
    # value contains quote characters.
    row = {"id": 1, "name": "@", "type": "CAA", "flags": 0, "tag": "issue", "data": '"ca.org"'}
    fake = do._FakeClient({"get": [do._FakeResponse(200, do._records([row]))]})
    driver = do._patch_client(monkeypatch, fake)
    pulled = await driver._list_zone_records(do._Server(), do._CREDS, "example.com.")
    assert caa_key(pulled[0].value) == caa_key("0 issue ca.org")


async def test_linode_finds_a_pre_2959_row(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [{"id": 5, "name": "", "type": "CAA", "tag": None, "target": "0 issue ca.org"}]
    fake = ln._FakeClient({"get": [ln._FakeResponse(200, ln._env(rows))]})
    driver = ln._patch_client(monkeypatch, fake)
    async with driver._client("t") as client:
        rid = await driver._find_record_id(client, 42, "", "CAA", target='0 issue "ca.org"')
    assert rid == 5
    assert caa_key(LinodeDNSDriver._read_value(rows[0])) == caa_key('0 issue "ca.org"')


@pytest.mark.parametrize("held", ["0 issue ca.org", '0 issue "ca.org"', '0 ISSUE "ca.org"'])
async def test_vultr_finds_a_pre_2959_row(monkeypatch: pytest.MonkeyPatch, held: str) -> None:
    row = {"id": "r9", "name": "", "type": "CAA", "ttl": 300, "data": held}
    fake = vu._FakeClient(
        {
            "get": [
                vu._FakeResponse(200, vu._records_env([row])),
                vu._FakeResponse(200, vu._records_env([row])),
            ]
        }
    )
    driver = vu._patch_client(monkeypatch, fake)
    pulled = await driver._list_zone_records(vu._Server(), vu._CREDS, "example.com.")
    assert caa_key(pulled[0].value) == caa_key('0 issue "ca.org"')
    async with driver._client("t") as client:
        rid = await driver._find_record_id(client, "example.com", "", "CAA", '0 issue "ca.org"')
    assert rid == "r9"


async def test_hetzner_per_value_delete_removes_the_held_spelling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Main sent the bare stored value; the provider holds it bare. A delete
    # without a resolved set must remove THAT value, not return as if absent.
    fake = hz._FakeClient(
        {
            "get": [hz._rrset("@", "CAA", ["0 issue ca.org", '0 issuewild "other.org"'])],
            "post": [hz._FakeResponse(201, hz._action("remove_rrset_records"))],
        }
    )
    driver = hz._patch_client(monkeypatch, fake)
    await driver._apply_record(hz._Server(), hz._CREDS, _change('0 issue "ca.org"', "delete"))
    (write,) = fake.writes()
    assert write["path"].endswith("/actions/remove_records")
    assert write["json"] == {"records": [{"value": "0 issue ca.org"}]}


async def test_hetzner_per_value_delete_of_last_value_deletes_rrset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = hz._FakeClient(
        {
            "get": [hz._rrset("@", "CAA", ["0 issue ca.org"])],
            "delete": [hz._FakeResponse(201, hz._action("delete_rrset"))],
        }
    )
    driver = hz._patch_client(monkeypatch, fake)
    await driver._apply_record(hz._Server(), hz._CREDS, _change('0 issue "ca.org"', "delete"))
    (write,) = fake.writes()
    assert write["method"] == "delete"


async def test_hetzner_per_value_create_does_not_duplicate_a_held_spelling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = hz._FakeClient({"get": [hz._rrset("@", "CAA", ["0 issue ca.org"], ttl=300)]})
    driver = hz._patch_client(monkeypatch, fake)
    await driver._apply_record(hz._Server(), hz._CREDS, _change('0 issue "ca.org"', "create"))
    assert fake.writes() == []


# ── Value refusals, checked by the record API before storing ────────────
@pytest.mark.parametrize(
    ("value", "match"),
    [('128 issue "ca.org"', "flags"), ('0 issuemail "ca.org"', "tag"), ("garbage", "not")],
)
def test_linode_value_refusal(value: str, match: str) -> None:
    refusal = LinodeDNSDriver.record_value_refusal("CAA", value)
    assert refusal is not None and match in refusal
    with pytest.raises(CloudDNSError, match=match):
        LinodeDNSDriver()._record_payload(_change(value), "example.com.")


def test_linode_value_refusal_accepts_flags_zero_and_other_types() -> None:
    assert LinodeDNSDriver.record_value_refusal("CAA", '0 ISSUE "ca.org"') is None
    assert LinodeDNSDriver.record_value_refusal("TXT", "128 anything") is None


@pytest.mark.parametrize(
    "value",
    ['0 issue "ca.org; account=1"', '0 issue ""', '0 iodef "a\\"b"', '0 issue "c\\195\\169"'],
)
def test_vultr_value_refusal(value: str) -> None:
    assert VultrDNSDriver.record_value_refusal("CAA", value) is not None


def test_vultr_value_refusal_accepts_plain_values() -> None:
    assert VultrDNSDriver.record_value_refusal("CAA", "0 issue ca.org") is None
    assert VultrDNSDriver.record_value_refusal("CAA", '128 iodef "mailto:a@b.org"') is None


def test_digitalocean_value_refusal() -> None:
    assert DigitalOceanDNSDriver.record_value_refusal("CAA", "garbage") is not None
    assert DigitalOceanDNSDriver.record_value_refusal("CAA", '128 issue "ca.org"') is None


@pytest.mark.parametrize("stored", STORED)
def test_drift_keys_caa_with_the_drivers_key(stored: str) -> None:
    """Drift / Sync (#2925) and these drivers share one CAA key."""
    from app.services.dns.pull_from_server import caa_canonical

    assert caa_canonical(stored) == caa_key(stored)
