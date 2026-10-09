"""Unit tests for the Azure DNS cloud driver (issue #37, Part B).

These are tier-3 provider tests — no Azure account is available, so the
``azure-mgmt-dns`` SDK is never imported and never hit. Every test
monkeypatches :meth:`AzureDNSDriver._client` to return a ``Mock`` whose
``zones`` / ``record_sets`` namespaces yield ``SimpleNamespace`` objects
shaped exactly like the ``azure-mgmt-dns`` models. Fully offline +
deterministic.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from app.drivers.dns._cloud_base import CloudDNSError, CloudDNSZone
from app.drivers.dns.azuredns import AzureDNSDriver
from app.drivers.dns.base import RecordChange, RecordData

# ── Fixtures ───────────────────────────────────────────────────────────────

_CREDS = {
    "tenant_id": "t",
    "client_id": "c",
    "client_secret": "s",
    "subscription_id": "sub",
    "resource_group": "rg",
}


class _FakeHttpResponseError(Exception):
    """Stand-in for ``azure.core.exceptions.HttpResponseError``.

    The driver's ``_wrap_errors`` lazy-imports the real exception types;
    when those imports fail in the test env it falls back to wrapping any
    exception as a ``CloudDNSError`` anyway, so a plain subclass is enough
    to exercise the error path deterministically.
    """


@pytest.fixture
def server() -> SimpleNamespace:
    return SimpleNamespace(id="srv-1", name="azure-1", credentials_encrypted=b"blob")


@pytest.fixture
def driver(monkeypatch: pytest.MonkeyPatch) -> AzureDNSDriver:
    """Driver with credential decrypt stubbed (no Fernet key in tests)."""
    drv = AzureDNSDriver()
    monkeypatch.setattr(drv, "_load_credentials", lambda srv: dict(_CREDS))
    return drv


def _patch_client(monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, client: Any) -> None:
    monkeypatch.setattr(driver, "_client", lambda creds: client)


# ── Registry / capabilities ────────────────────────────────────────────────


def test_name_and_credential_fields() -> None:
    drv = AzureDNSDriver()
    assert drv.name == "azure_dns"
    assert drv.credential_fields == (
        "tenant_id",
        "client_id",
        "client_secret",
        "subscription_id",
        "resource_group",
    )


def test_capabilities_shape() -> None:
    caps = AzureDNSDriver().capabilities()
    assert caps["name"] == "azure_dns"
    assert caps["agentless"] is True
    assert caps["manages_zones"] is True
    assert caps["alias_records"] is False  # #29 — alias authoring deferred
    assert caps["dnssec_online"] is False
    assert "SOA" in caps["record_types"]
    assert "online DNSSEC" in caps["notes"]


# ── Zone listing ────────────────────────────────────────────────────────────


async def test_list_zones_by_resource_group(
    monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, server: SimpleNamespace
) -> None:
    client = Mock()
    client.zones.list_by_resource_group.return_value = [
        SimpleNamespace(name="example.com", number_of_record_sets=12),
        SimpleNamespace(name="0.0.10.in-addr.arpa", number_of_record_sets=3),
    ]
    _patch_client(monkeypatch, driver, client)

    zones = await driver._list_zones(server, dict(_CREDS))

    client.zones.list_by_resource_group.assert_called_once_with("rg")
    assert zones == [
        CloudDNSZone(name="example.com.", zone_id="example.com", is_reverse=False, record_count=12),
        CloudDNSZone(
            name="0.0.10.in-addr.arpa.",
            zone_id="0.0.10.in-addr.arpa",
            is_reverse=True,
            record_count=3,
        ),
    ]


async def test_list_zones_empty_resource_group_is_named_error(
    monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, server: SimpleNamespace
) -> None:
    """#1534 — an empty resource_group must not fall back to a
    subscription-wide list that makes the probe pass while record ops fail."""
    client = Mock()
    _patch_client(monkeypatch, driver, client)

    creds = dict(_CREDS, resource_group="")
    with pytest.raises(CloudDNSError, match="resource_group"):
        await driver._list_zones(server, creds)

    client.zones.list.assert_not_called()
    client.zones.list_by_resource_group.assert_not_called()


def test_client_missing_fields_raise_named_error_not_keyerror() -> None:
    """#1534 — missing fields surface as CloudDNSError naming them."""
    drv = AzureDNSDriver()
    with pytest.raises(CloudDNSError) as excinfo:
        drv._client({"tenant_id": "t"})
    message = str(excinfo.value)
    assert "client_id" in message
    assert "resource_group" in message
    assert "KeyError" not in message


def test_client_empty_resource_group_raises_named_error() -> None:
    drv = AzureDNSDriver()
    with pytest.raises(CloudDNSError, match="resource_group"):
        drv._client(dict(_CREDS, resource_group=""))


async def test_probe_fails_when_resource_group_empty(
    monkeypatch: pytest.MonkeyPatch, server: SimpleNamespace
) -> None:
    """#1534 — probe exercises the resource-group scope record paths use,
    so a server with no resource group reports failure, not success."""
    drv = AzureDNSDriver()
    monkeypatch.setattr(drv, "_load_credentials", lambda srv: dict(_CREDS, resource_group=""))
    client = Mock()
    _patch_client(monkeypatch, drv, client)

    probe = await drv.probe(server)
    assert probe.ok is False
    assert "resource_group" in probe.message


async def test_save_time_validation_rejects_missing_azure_fields() -> None:
    """#1534 — _validate_driver_credentials refuses an azure_dns save
    missing any of the five fields, with a 422 naming them."""
    from fastapi import HTTPException

    from app.api.v1.dns.router import _validate_driver_credentials

    with pytest.raises(HTTPException) as excinfo:
        await _validate_driver_credentials("azure_dns", {"tenant_id": "t"})
    assert excinfo.value.status_code == 422
    assert "resource_group" in str(excinfo.value.detail)
    # A complete set passes.
    await _validate_driver_credentials("azure_dns", dict(_CREDS))


async def test_pull_zones_from_server_returns_neutral_dicts(
    monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, server: SimpleNamespace
) -> None:
    client = Mock()
    client.zones.list_by_resource_group.return_value = [
        SimpleNamespace(name="example.com", number_of_record_sets=7)
    ]
    _patch_client(monkeypatch, driver, client)

    rows = await driver.pull_zones_from_server(server)

    assert rows == [
        {
            "name": "example.com.",
            "zone_type": "Primary",
            "is_reverse_lookup": False,
            "dnssec_enabled": False,
            "zone_id": "example.com",
            "record_count": 7,
        }
    ]


# ── Record listing / multi-type expansion ───────────────────────────────────


async def test_list_zone_records_expands_multiple_types(
    monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, server: SimpleNamespace
) -> None:
    record_sets = [
        # A record set with two records.
        SimpleNamespace(
            name="www",
            type="Microsoft.Network/dnszones/A",
            ttl=300,
            a_records=[
                SimpleNamespace(ipv4_address="10.0.0.1"),
                SimpleNamespace(ipv4_address="10.0.0.2"),
            ],
        ),
        # MX record set.
        SimpleNamespace(
            name="@",
            type="Microsoft.Network/dnszones/MX",
            ttl=3600,
            mx_records=[SimpleNamespace(preference=10, exchange="mail.example.com")],
        ),
        # TXT record set (Azure splits long strings into a value list).
        SimpleNamespace(
            name="@",
            type="Microsoft.Network/dnszones/TXT",
            ttl=3600,
            txt_records=[SimpleNamespace(value=["v=spf1 ", "-all"])],
        ),
        # SOA is skipped entirely.
        SimpleNamespace(name="@", type="Microsoft.Network/dnszones/SOA", ttl=3600),
    ]
    client = Mock()
    client.record_sets.list_by_dns_zone.return_value = record_sets
    _patch_client(monkeypatch, driver, client)

    records = await driver._list_zone_records(server, dict(_CREDS), "example.com.")

    # Azure zone label is stripped of the trailing dot for the SDK call.
    client.record_sets.list_by_dns_zone.assert_called_once_with("rg", "example.com")

    assert records == [
        RecordData(name="www", record_type="A", value="10.0.0.1", ttl=300),
        RecordData(name="www", record_type="A", value="10.0.0.2", ttl=300),
        RecordData(name="@", record_type="MX", value="mail.example.com", ttl=3600, priority=10),
        RecordData(name="@", record_type="TXT", value="v=spf1 -all", ttl=3600),
    ]


async def test_list_zone_records_expands_srv_and_caa(
    monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, server: SimpleNamespace
) -> None:
    record_sets = [
        SimpleNamespace(
            name="_sip._tcp",
            type="Microsoft.Network/dnszones/SRV",
            ttl=3600,
            srv_records=[
                SimpleNamespace(priority=10, weight=20, port=5060, target="sip.example.com")
            ],
        ),
        SimpleNamespace(
            name="@",
            type="Microsoft.Network/dnszones/CAA",
            ttl=3600,
            caa_records=[SimpleNamespace(flags=0, tag="issue", value="letsencrypt.org")],
        ),
    ]
    client = Mock()
    client.record_sets.list_by_dns_zone.return_value = record_sets
    _patch_client(monkeypatch, driver, client)

    records = await driver._list_zone_records(server, dict(_CREDS), "example.com.")

    assert records[0] == RecordData(
        name="_sip._tcp",
        record_type="SRV",
        value="sip.example.com",
        ttl=3600,
        priority=10,
        weight=20,
        port=5060,
    )
    assert records[1] == RecordData(
        name="@", record_type="CAA", value="0 issue letsencrypt.org", ttl=3600
    )


# ── Record write (create_or_update param building) ──────────────────────────
#
# Cloud providers group every value under one RRset keyed by {name, type}.
# SpatiumDDI stores one row per value and emits one op per row, so the create
# / delete paths read-merge against the provider's live RRset rather than
# blindly writing a single-value set (which would silently drop the siblings
# of a round-robin A / multi-MX / multi-NS set). ``record_sets.get`` is mocked
# to return ``None`` for "no existing set" and a ``SimpleNamespace`` shaped
# like the SDK model for an existing one.


async def test_apply_record_create_into_empty_set_builds_a_params(
    monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, server: SimpleNamespace
) -> None:
    client = Mock()
    client.record_sets.get.return_value = None  # no existing RRset
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="10.0.0.5", ttl=120),
        target_serial=1,
    )
    await driver._apply_record(server, dict(_CREDS), change)

    client.record_sets.create_or_update.assert_called_once_with(
        "rg", "example.com", "www", "A", {"ttl": 120, "a_records": [{"ipv4_address": "10.0.0.5"}]}
    )


async def test_apply_record_create_merges_into_existing_rrset(
    monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, server: SimpleNamespace
) -> None:
    """Creating a 2nd A value writes BOTH values (no silent sibling drop)."""
    client = Mock()
    client.record_sets.get.return_value = SimpleNamespace(
        ttl=300, a_records=[SimpleNamespace(ipv4_address="10.0.0.1")]
    )
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="10.0.0.2", ttl=300),
        target_serial=1,
    )
    await driver._apply_record(server, dict(_CREDS), change)

    client.record_sets.get.assert_called_once_with("rg", "example.com", "www", "A")
    client.record_sets.create_or_update.assert_called_once_with(
        "rg",
        "example.com",
        "www",
        "A",
        {"ttl": 300, "a_records": [{"ipv4_address": "10.0.0.1"}, {"ipv4_address": "10.0.0.2"}]},
    )


async def test_apply_record_create_dedupes_existing_value(
    monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, server: SimpleNamespace
) -> None:
    """Creating a value already in the RRset is a merge no-op (no duplicate)."""
    client = Mock()
    client.record_sets.get.return_value = SimpleNamespace(
        ttl=300,
        a_records=[
            SimpleNamespace(ipv4_address="10.0.0.1"),
            SimpleNamespace(ipv4_address="10.0.0.2"),
        ],
    )
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="10.0.0.1", ttl=300),
        target_serial=1,
    )
    await driver._apply_record(server, dict(_CREDS), change)

    _, _, _, _, params = client.record_sets.create_or_update.call_args.args
    assert params["a_records"] == [{"ipv4_address": "10.0.0.1"}, {"ipv4_address": "10.0.0.2"}]


async def test_apply_record_create_falls_back_to_existing_ttl(
    monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, server: SimpleNamespace
) -> None:
    """When the change carries no TTL, the existing RRset's TTL is kept."""
    client = Mock()
    client.record_sets.get.return_value = SimpleNamespace(
        ttl=900, a_records=[SimpleNamespace(ipv4_address="10.0.0.1")]
    )
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="10.0.0.2", ttl=None),
        target_serial=1,
    )
    await driver._apply_record(server, dict(_CREDS), change)

    _, _, _, _, params = client.record_sets.create_or_update.call_args.args
    assert params["ttl"] == 900


async def test_apply_record_create_cname_uses_replace_no_get(
    monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, server: SimpleNamespace
) -> None:
    """CNAME is single-valued (``cname_record``) — replace, never read-merge."""
    client = Mock()
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="alias", record_type="CNAME", value="target.example.com", ttl=300),
        target_serial=1,
    )
    await driver._apply_record(server, dict(_CREDS), change)

    client.record_sets.get.assert_not_called()
    client.record_sets.create_or_update.assert_called_once_with(
        "rg",
        "example.com",
        "alias",
        "CNAME",
        {"ttl": 300, "cname_record": {"cname": "target.example.com"}},
    )


async def test_apply_record_update_replaces_rrset(
    monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, server: SimpleNamespace
) -> None:
    """update keeps single-value replace — it never read-merges (see #29)."""
    client = Mock()
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="update",
        zone_name="example.com.",
        record=RecordData(
            name="@", record_type="MX", value="mail2.example.com", ttl=3600, priority=20
        ),
        target_serial=2,
    )
    await driver._apply_record(server, dict(_CREDS), change)

    client.record_sets.get.assert_not_called()
    _, _, _, rtype, params = client.record_sets.create_or_update.call_args.args
    assert rtype == "MX"
    assert params == {
        "ttl": 3600,
        "mx_records": [{"preference": 20, "exchange": "mail2.example.com"}],
    }


async def test_apply_record_create_builds_srv_params(
    monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, server: SimpleNamespace
) -> None:
    client = Mock()
    client.record_sets.get.return_value = None
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(
            name="_sip._tcp",
            record_type="SRV",
            value="sip.example.com",
            ttl=3600,
            priority=10,
            weight=20,
            port=5060,
        ),
        target_serial=3,
    )
    await driver._apply_record(server, dict(_CREDS), change)

    _, _, _, _, params = client.record_sets.create_or_update.call_args.args
    assert params["srv_records"] == [
        {"priority": 10, "weight": 20, "port": 5060, "target": "sip.example.com"}
    ]


async def test_apply_record_delete_one_of_two_leaves_the_other(
    monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, server: SimpleNamespace
) -> None:
    """Deleting one value of a 2-value RRset writes the reduced set, not delete."""
    client = Mock()
    client.record_sets.get.return_value = SimpleNamespace(
        ttl=300,
        a_records=[
            SimpleNamespace(ipv4_address="10.0.0.1"),
            SimpleNamespace(ipv4_address="10.0.0.2"),
        ],
    )
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="10.0.0.1"),
        target_serial=4,
    )
    await driver._apply_record(server, dict(_CREDS), change)

    client.record_sets.delete.assert_not_called()
    client.record_sets.create_or_update.assert_called_once_with(
        "rg", "example.com", "www", "A", {"ttl": 300, "a_records": [{"ipv4_address": "10.0.0.2"}]}
    )


async def test_apply_record_delete_last_value_removes_rrset(
    monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, server: SimpleNamespace
) -> None:
    """Deleting the last remaining value removes the whole RRset."""
    client = Mock()
    client.record_sets.get.return_value = SimpleNamespace(
        ttl=300, a_records=[SimpleNamespace(ipv4_address="10.0.0.9")]
    )
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="old", record_type="A", value="10.0.0.9"),
        target_serial=4,
    )
    await driver._apply_record(server, dict(_CREDS), change)

    client.record_sets.delete.assert_called_once_with("rg", "example.com", "old", "A")
    client.record_sets.create_or_update.assert_not_called()


async def test_apply_record_delete_missing_value_is_noop(
    monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, server: SimpleNamespace
) -> None:
    """Deleting a value that isn't in the RRset is an idempotent no-op."""
    client = Mock()
    client.record_sets.get.return_value = SimpleNamespace(
        ttl=300, a_records=[SimpleNamespace(ipv4_address="10.0.0.1")]
    )
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="10.0.0.99"),
        target_serial=4,
    )
    await driver._apply_record(server, dict(_CREDS), change)

    client.record_sets.delete.assert_not_called()
    client.record_sets.create_or_update.assert_not_called()


async def test_apply_record_delete_missing_rrset_is_noop(
    monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, server: SimpleNamespace
) -> None:
    """Deleting from an absent RRset is an idempotent no-op."""
    client = Mock()
    client.record_sets.get.return_value = None
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="gone", record_type="A", value="10.0.0.9"),
        target_serial=4,
    )
    await driver._apply_record(server, dict(_CREDS), change)

    client.record_sets.delete.assert_not_called()
    client.record_sets.create_or_update.assert_not_called()


async def test_apply_record_delete_txt_dedupes_across_chunk_split(
    monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, server: SimpleNamespace
) -> None:
    """A TXT value Azure stored as multiple chunks still matches for removal."""
    client = Mock()
    client.record_sets.get.return_value = SimpleNamespace(
        ttl=3600,
        txt_records=[
            SimpleNamespace(value=["v=spf1 ", "-all"]),
            SimpleNamespace(value=["keep-me"]),
        ],
    )
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="@", record_type="TXT", value="v=spf1 -all"),
        target_serial=4,
    )
    await driver._apply_record(server, dict(_CREDS), change)

    client.record_sets.delete.assert_not_called()
    _, _, _, _, params = client.record_sets.create_or_update.call_args.args
    assert params["txt_records"] == [{"value": ["keep-me"]}]


# ── Zone write ───────────────────────────────────────────────────────────────


async def test_apply_zone_create(
    monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, server: SimpleNamespace
) -> None:
    client = Mock()
    _patch_client(monkeypatch, driver, client)

    zone = SimpleNamespace(name="new.example.com.")
    await driver._apply_zone(server, dict(_CREDS), zone, "create")

    client.zones.create_or_update.assert_called_once_with(
        "rg", "new.example.com", {"location": "global"}
    )


async def test_apply_zone_delete_uses_lro_poller(
    monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, server: SimpleNamespace
) -> None:
    poller = Mock()
    client = Mock()
    client.zones.begin_delete.return_value = poller
    _patch_client(monkeypatch, driver, client)

    zone = SimpleNamespace(name="gone.example.com.")
    await driver._apply_zone(server, dict(_CREDS), zone, "delete")

    client.zones.begin_delete.assert_called_once_with("rg", "gone.example.com")
    poller.result.assert_called_once_with()


# ── Error wrapping ───────────────────────────────────────────────────────────


async def test_list_zones_wraps_http_error_as_cloud_dns_error(
    monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, server: SimpleNamespace
) -> None:
    client = Mock()
    client.zones.list_by_resource_group.side_effect = _FakeHttpResponseError("403 Forbidden")
    _patch_client(monkeypatch, driver, client)

    with pytest.raises(CloudDNSError) as excinfo:
        await driver._list_zones(server, dict(_CREDS))
    assert "403 Forbidden" in str(excinfo.value)


async def test_apply_record_wraps_error_as_cloud_dns_error(
    monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, server: SimpleNamespace
) -> None:
    client = Mock()
    client.record_sets.get.return_value = None  # no existing set → reach create_or_update
    client.record_sets.create_or_update.side_effect = _FakeHttpResponseError("boom")
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="10.0.0.1", ttl=300),
        target_serial=5,
    )
    with pytest.raises(CloudDNSError):
        await driver._apply_record(server, dict(_CREDS), change)


# ── Probe (inherited from base, exercised end-to-end with mocked client) ─────


async def test_probe_ok_reports_zone_count(
    monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, server: SimpleNamespace
) -> None:
    client = Mock()
    client.zones.list_by_resource_group.return_value = [
        SimpleNamespace(name="example.com", number_of_record_sets=1)
    ]
    _patch_client(monkeypatch, driver, client)

    probe = await driver.probe(server)
    assert probe.ok is True
    assert probe.zone_count == 1


# ── MX / SRV split-form contract (#1526) ────────────────────────────────────


async def test_apply_record_create_mx_bare_target_does_not_raise(
    monkeypatch: pytest.MonkeyPatch, driver: AzureDNSDriver, server: SimpleNamespace
) -> None:
    """Regression: an API-shaped MX (bare target + priority column) used to
    raise ValueError when the driver tried int() on the split value."""
    client = Mock()
    client.record_sets.get.return_value = None
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(
            name="@", record_type="MX", value="mail.example.com", ttl=3600, priority=15
        ),
        target_serial=1,
    )
    await driver._apply_record(server, dict(_CREDS), change)

    _, _, _, _, params = client.record_sets.create_or_update.call_args.args
    assert params["mx_records"] == [{"preference": 15, "exchange": "mail.example.com"}]
