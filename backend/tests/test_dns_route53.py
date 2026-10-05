"""Unit tests for the Amazon Route 53 cloud DNS driver (issue #37).

All tests are offline: the boto3 client factory (``_client``) is
monkeypatched to a ``Mock`` returning canned Route 53 API dicts, so
nothing ever touches AWS.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.drivers.dns._cloud_base import CloudDNSConflictError, CloudDNSError
from app.drivers.dns.base import RecordChange, RecordData
from app.drivers.dns.route53 import Route53DNSDriver


def _server() -> SimpleNamespace:
    """A stand-in DNS server row (the driver only touches a few attrs)."""
    return SimpleNamespace(id="srv-1", name="aws", credentials_encrypted=None)


CREDS = {"access_key_id": "AKIAEXAMPLE", "secret_access_key": "secret"}


def _patch_client(monkeypatch: pytest.MonkeyPatch, driver: Route53DNSDriver, client: Any) -> None:
    """Wire ``driver._client`` to return ``client`` regardless of creds."""
    monkeypatch.setattr(driver, "_client", lambda creds: client)


class _ClientError(Exception):
    """Stand-in for botocore.exceptions.ClientError (offline)."""

    def __init__(self, code: str, message: str = "boom") -> None:
        super().__init__(f"{code}: {message}")
        self.response = {"Error": {"Code": code, "Message": message}}


# ── Zone listing ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_zones_paginated_and_reverse(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones.side_effect = [
        {
            "HostedZones": [
                {"Id": "/hostedzone/Z1", "Name": "example.com.", "ResourceRecordSetCount": 5},
            ],
            "IsTruncated": True,
            "NextMarker": "m2",
        },
        {
            "HostedZones": [
                {
                    "Id": "/hostedzone/Z2",
                    "Name": "10.in-addr.arpa.",
                    "ResourceRecordSetCount": 2,
                },
            ],
            "IsTruncated": False,
        },
    ]
    _patch_client(monkeypatch, driver, client)

    zones = await driver._list_zones(_server(), CREDS)

    assert [z.name for z in zones] == ["example.com.", "10.in-addr.arpa."]
    assert [z.zone_id for z in zones] == ["Z1", "Z2"]
    assert [z.is_reverse for z in zones] == [False, True]
    assert [z.record_count for z in zones] == [5, 2]
    # Second page must be requested with the marker from the first page.
    assert client.list_hosted_zones.call_count == 2
    assert client.list_hosted_zones.call_args_list[1].kwargs["Marker"] == "m2"


@pytest.mark.asyncio
async def test_pull_zones_from_server_neutral_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones.return_value = {
        "HostedZones": [
            {"Id": "/hostedzone/Z1", "Name": "Example.COM.", "ResourceRecordSetCount": 3},
        ],
        "IsTruncated": False,
    }
    monkeypatch.setattr(_server(), "credentials_encrypted", b"x", raising=False)
    _patch_client(monkeypatch, driver, client)
    # Bypass credential decrypt — the base loads from credentials_encrypted.
    monkeypatch.setattr(driver, "_load_credentials", lambda server: CREDS)

    out = await driver.pull_zones_from_server(_server())

    assert out == [
        {
            "name": "example.com.",
            "zone_type": "Primary",
            "is_reverse_lookup": False,
            "dnssec_enabled": False,
            "zone_id": "Z1",
            "record_count": 3,
        }
    ]


# ── Record listing / relativization / multi-value expansion ───────────────


@pytest.mark.asyncio
async def test_list_zone_records_relativize_and_expand(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [{"Id": "/hostedzone/Z1", "Name": "example.com."}]
    }
    client.list_resource_record_sets.side_effect = [
        {
            "ResourceRecordSets": [
                {
                    "Name": "example.com.",
                    "Type": "NS",
                    "TTL": 172800,
                    "ResourceRecords": [
                        {"Value": "ns-1.awsdns.com."},
                        {"Value": "ns-2.awsdns.net."},
                    ],
                },
                {
                    "Name": "www.example.com.",
                    "Type": "A",
                    "TTL": 300,
                    "ResourceRecords": [{"Value": "10.0.0.1"}],
                },
            ],
            "IsTruncated": True,
            "NextRecordName": "www.example.com.",
            "NextRecordType": "MX",
        },
        {
            "ResourceRecordSets": [
                {
                    "Name": "example.com.",
                    "Type": "MX",
                    "TTL": 3600,
                    "ResourceRecords": [{"Value": "10 mail.example.com."}],
                },
                {
                    "Name": "app.example.com.",
                    "Type": "A",
                    "AliasTarget": {"DNSName": "elb-123.us-east-1.elb.amazonaws.com."},
                },
            ],
            "IsTruncated": False,
        },
    ]
    _patch_client(monkeypatch, driver, client)

    records = await driver._list_zone_records(_server(), CREDS, "example.com.")

    # NS apex rrset expands into two RecordData rows (one per value),
    # relativized to "@".
    ns = [r for r in records if r.record_type == "NS"]
    assert len(ns) == 2
    assert {r.value for r in ns} == {"ns-1.awsdns.com.", "ns-2.awsdns.net."}
    assert all(r.name == "@" for r in ns)

    www = next(r for r in records if r.record_type == "A" and r.value == "10.0.0.1")
    assert www.name == "www"
    assert www.ttl == 300

    # MX keeps the priority baked into the value; priority stays None.
    mx = next(r for r in records if r.record_type == "MX")
    assert mx.value == "10 mail.example.com."
    assert mx.priority is None
    assert mx.name == "@"

    # ALIAS rrset → value is the target DNS name, ttl is None.
    alias = next(r for r in records if r.name == "app")
    assert alias.value == "elb-123.us-east-1.elb.amazonaws.com."
    assert alias.ttl is None

    # Pagination: the second call carries the start markers.
    assert client.list_resource_record_sets.call_count == 2
    second = client.list_resource_record_sets.call_args_list[1].kwargs
    assert second["StartRecordName"] == "www.example.com."
    assert second["StartRecordType"] == "MX"


@pytest.mark.asyncio
async def test_list_zone_records_zone_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = Route53DNSDriver()
    client = MagicMock()
    # API returns a neighbouring zone, not the one we asked for, and the
    # result set is exhausted (not truncated) — so the zone really is absent.
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [{"Id": "/hostedzone/Z9", "Name": "other.com."}],
        "IsTruncated": False,
    }
    _patch_client(monkeypatch, driver, client)

    with pytest.raises(CloudDNSError, match="not found"):
        await driver._list_zone_records(_server(), CREDS, "example.com.")


# ── Hosted-zone id resolution (issue #334) ────────────────────────────────


@pytest.mark.asyncio
async def test_resolve_zone_id_skips_lexical_neighbour_same_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lexical neighbour ahead of the target on the same page is skipped.

    ``list_hosted_zones_by_name`` returns zones at-or-after ``DNSName`` in
    Route 53's sort order, so the target need not be the first row. The
    resolver must scan the whole (non-truncated) page rather than trusting
    the first entry — the old ``MaxItems='1'`` path would have raised
    'not found' here.
    """
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [
            # Sorts at-or-after the queried name but isn't the match.
            {"Id": "/hostedzone/Zneighbour", "Name": "example-staging.com."},
            {"Id": "/hostedzone/Ztarget", "Name": "example.com."},
        ],
        "IsTruncated": False,
    }
    _patch_client(monkeypatch, driver, client)

    zone_id = await driver._resolve_zone_id(client, "example.com.")

    assert zone_id == "Ztarget"
    # Single round-trip: page wasn't truncated, no continuation needed.
    assert client.list_hosted_zones_by_name.call_count == 1
    first = client.list_hosted_zones_by_name.call_args_list[0].kwargs
    assert first["DNSName"] == "example.com."
    # No longer capped at one row.
    assert first["MaxItems"] != "1"


@pytest.mark.asyncio
async def test_resolve_zone_id_paginates_to_find_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the first page is a truncated run of neighbours, follow the
    continuation tokens until the exact apex match is found."""
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.side_effect = [
        {
            "HostedZones": [{"Id": "/hostedzone/Zn1", "Name": "alpha.com."}],
            "IsTruncated": True,
            "NextDNSName": "example.com.",
            "NextHostedZoneId": "Zmarker",
        },
        {
            "HostedZones": [
                {"Id": "/hostedzone/Zn2", "Name": "example-staging.com."},
                {"Id": "/hostedzone/Ztarget", "Name": "example.com."},
            ],
            "IsTruncated": False,
        },
    ]
    _patch_client(monkeypatch, driver, client)

    zone_id = await driver._resolve_zone_id(client, "example.com.")

    assert zone_id == "Ztarget"
    assert client.list_hosted_zones_by_name.call_count == 2
    # The second page must carry the continuation tokens from the first.
    second = client.list_hosted_zones_by_name.call_args_list[1].kwargs
    assert second["DNSName"] == "example.com."
    assert second["HostedZoneId"] == "Zmarker"


@pytest.mark.asyncio
async def test_resolve_zone_id_truncated_no_tokens_stops(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A truncated page with no continuation tokens stops (no infinite loop)
    and reports the zone as not found."""
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [{"Id": "/hostedzone/Zn1", "Name": "other.com."}],
        "IsTruncated": True,
        # NextDNSName / NextHostedZoneId intentionally omitted.
    }
    _patch_client(monkeypatch, driver, client)

    with pytest.raises(CloudDNSError, match="not found"):
        await driver._resolve_zone_id(client, "example.com.")
    assert client.list_hosted_zones_by_name.call_count == 1


# ── Record write: UPSERT vs DELETE change batches ─────────────────────────


@pytest.mark.asyncio
async def test_apply_record_create_new_rrset(monkeypatch: pytest.MonkeyPatch) -> None:
    """Creating a value when no rrset exists yet writes just that value."""
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [{"Id": "/hostedzone/Z1", "Name": "example.com."}]
    }
    # Read-merge: Route 53 returns the lexically-next rrset (a non-match),
    # so the driver treats {www, A} as absent.
    client.list_resource_record_sets.return_value = {
        "ResourceRecordSets": [{"Name": "zzz.example.com.", "Type": "A"}]
    }
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="10.0.0.1", ttl=120),
        target_serial=1,
    )
    await driver._apply_record(_server(), CREDS, change)

    kwargs = client.change_resource_record_sets.call_args.kwargs
    assert kwargs["HostedZoneId"] == "Z1"
    batch_change = kwargs["ChangeBatch"]["Changes"][0]
    assert batch_change["Action"] == "UPSERT"
    rrset = batch_change["ResourceRecordSet"]
    assert rrset == {
        "Name": "www.example.com.",
        "Type": "A",
        "TTL": 120,
        "ResourceRecords": [{"Value": "10.0.0.1"}],
    }


@pytest.mark.asyncio
async def test_apply_record_create_merges_into_existing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Creating a 2nd value for an existing {name,type} writes BOTH values."""
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [{"Id": "/hostedzone/Z1", "Name": "example.com."}]
    }
    # Live rrset already carries one A value at the round-robin host.
    client.list_resource_record_sets.return_value = {
        "ResourceRecordSets": [
            {
                "Name": "rr.example.com.",
                "Type": "A",
                "TTL": 300,
                "ResourceRecords": [{"Value": "10.0.0.1"}],
            }
        ]
    }
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="rr", record_type="A", value="10.0.0.2", ttl=None),
        target_serial=1,
    )
    await driver._apply_record(_server(), CREDS, change)

    # The read used the absolute name + type as the start key.
    read_kwargs = client.list_resource_record_sets.call_args.kwargs
    assert read_kwargs["StartRecordName"] == "rr.example.com."
    assert read_kwargs["StartRecordType"] == "A"
    assert read_kwargs["MaxItems"] == "1"

    batch_change = client.change_resource_record_sets.call_args.kwargs["ChangeBatch"]["Changes"][0]
    assert batch_change["Action"] == "UPSERT"
    rrset = batch_change["ResourceRecordSet"]
    assert rrset["Name"] == "rr.example.com."
    assert rrset["Type"] == "A"
    # TTL falls back to the live rrset's TTL when the change carries none.
    assert rrset["TTL"] == 300
    # BOTH values present — the sibling was NOT clobbered.
    assert {v["Value"] for v in rrset["ResourceRecords"]} == {"10.0.0.1", "10.0.0.2"}


@pytest.mark.asyncio
async def test_apply_record_create_duplicate_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    """Creating a value already in the rrset writes nothing (idempotent)."""
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [{"Id": "/hostedzone/Z1", "Name": "example.com."}]
    }
    client.list_resource_record_sets.return_value = {
        "ResourceRecordSets": [
            {
                "Name": "rr.example.com.",
                "Type": "A",
                "TTL": 300,
                "ResourceRecords": [{"Value": "10.0.0.1"}],
            }
        ]
    }
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="rr", record_type="A", value="10.0.0.1", ttl=300),
        target_serial=1,
    )
    await driver._apply_record(_server(), CREDS, change)

    # Value already present — no write submitted.
    client.change_resource_record_sets.assert_not_called()


@pytest.mark.asyncio
async def test_apply_record_create_skips_alias_merge(monkeypatch: pytest.MonkeyPatch) -> None:
    """An ALIAS rrset is single-valued — create replaces, never merges."""
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [{"Id": "/hostedzone/Z1", "Name": "example.com."}]
    }
    client.list_resource_record_sets.return_value = {
        "ResourceRecordSets": [
            {
                "Name": "app.example.com.",
                "Type": "A",
                "AliasTarget": {"DNSName": "elb-123.elb.amazonaws.com."},
            }
        ]
    }
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="app", record_type="A", value="10.0.0.5", ttl=120),
        target_serial=1,
    )
    await driver._apply_record(_server(), CREDS, change)

    rrset = client.change_resource_record_sets.call_args.kwargs["ChangeBatch"]["Changes"][0][
        "ResourceRecordSet"
    ]
    # Replaced with the value-bearing rrset; no alias merge attempted.
    assert "AliasTarget" not in rrset
    assert rrset["ResourceRecords"] == [{"Value": "10.0.0.5"}]


@pytest.mark.asyncio
async def test_apply_record_apex_and_default_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [{"Id": "/hostedzone/Z1", "Name": "example.com."}]
    }
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="update",
        zone_name="example.com.",
        record=RecordData(name="@", record_type="TXT", value="v=spf1 -all", ttl=None),
        target_serial=1,
    )
    await driver._apply_record(_server(), CREDS, change)

    rrset = client.change_resource_record_sets.call_args.kwargs["ChangeBatch"]["Changes"][0][
        "ResourceRecordSet"
    ]
    assert rrset["Name"] == "example.com."  # apex absolutized
    assert rrset["TTL"] == 300  # default when ttl is None


@pytest.mark.asyncio
async def test_apply_record_delete_last_value_removes_rrset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deleting the only value submits a DELETE of the EXACT live rrset."""
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [{"Id": "/hostedzone/Z1", "Name": "example.com."}]
    }
    client.list_resource_record_sets.return_value = {
        "ResourceRecordSets": [
            {
                "Name": "old.example.com.",
                "Type": "A",
                "TTL": 300,
                "ResourceRecords": [{"Value": "10.0.0.9"}],
            }
        ]
    }
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="old", record_type="A", value="10.0.0.9", ttl=300),
        target_serial=1,
    )
    await driver._apply_record(_server(), CREDS, change)

    batch_change = client.change_resource_record_sets.call_args.kwargs["ChangeBatch"]["Changes"][0]
    assert batch_change["Action"] == "DELETE"
    # DELETE must carry the EXACT existing rrset (TTL + value) verbatim.
    assert batch_change["ResourceRecordSet"] == {
        "Name": "old.example.com.",
        "Type": "A",
        "TTL": 300,
        "ResourceRecords": [{"Value": "10.0.0.9"}],
    }


@pytest.mark.asyncio
async def test_apply_record_delete_one_of_many_leaves_others(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deleting one value of a multi-value rrset UPSERTs the reduced set."""
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [{"Id": "/hostedzone/Z1", "Name": "example.com."}]
    }
    client.list_resource_record_sets.return_value = {
        "ResourceRecordSets": [
            {
                "Name": "rr.example.com.",
                "Type": "A",
                "TTL": 300,
                "ResourceRecords": [{"Value": "10.0.0.1"}, {"Value": "10.0.0.2"}],
            }
        ]
    }
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="rr", record_type="A", value="10.0.0.1", ttl=300),
        target_serial=1,
    )
    await driver._apply_record(_server(), CREDS, change)

    batch_change = client.change_resource_record_sets.call_args.kwargs["ChangeBatch"]["Changes"][0]
    # Reduced set is UPSERTed, NOT deleted — the surviving sibling stays.
    assert batch_change["Action"] == "UPSERT"
    rrset = batch_change["ResourceRecordSet"]
    assert rrset["TTL"] == 300
    assert rrset["ResourceRecords"] == [{"Value": "10.0.0.2"}]


@pytest.mark.asyncio
async def test_apply_record_delete_value_not_present_is_noop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deleting a value absent from the live rrset writes nothing."""
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [{"Id": "/hostedzone/Z1", "Name": "example.com."}]
    }
    client.list_resource_record_sets.return_value = {
        "ResourceRecordSets": [
            {
                "Name": "rr.example.com.",
                "Type": "A",
                "TTL": 300,
                "ResourceRecords": [{"Value": "10.0.0.1"}],
            }
        ]
    }
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="rr", record_type="A", value="10.0.0.9", ttl=300),
        target_serial=1,
    )
    await driver._apply_record(_server(), CREDS, change)

    client.change_resource_record_sets.assert_not_called()


@pytest.mark.asyncio
async def test_apply_record_delete_missing_rrset_is_noop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No rrset at all for {name,type} → idempotent no-op (no write)."""
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [{"Id": "/hostedzone/Z1", "Name": "example.com."}]
    }
    # Route 53 returns a neighbouring rrset, not the one we asked for.
    client.list_resource_record_sets.return_value = {
        "ResourceRecordSets": [{"Name": "zzz.example.com.", "Type": "A"}]
    }
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="ghost", record_type="A", value="10.0.0.9", ttl=300),
        target_serial=1,
    )
    await driver._apply_record(_server(), CREDS, change)

    client.change_resource_record_sets.assert_not_called()


@pytest.mark.asyncio
async def test_apply_record_delete_invalid_batch_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    """A racing InvalidChangeBatch on the DELETE write is still a no-op."""
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [{"Id": "/hostedzone/Z1", "Name": "example.com."}]
    }
    client.list_resource_record_sets.return_value = {
        "ResourceRecordSets": [
            {
                "Name": "old.example.com.",
                "Type": "A",
                "TTL": 300,
                "ResourceRecords": [{"Value": "10.0.0.9"}],
            }
        ]
    }
    client.change_resource_record_sets.side_effect = _ClientError(
        "InvalidChangeBatch", "tried to delete a record that doesn't exist"
    )
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="old", record_type="A", value="10.0.0.9", ttl=300),
        target_serial=1,
    )
    # No raise — InvalidChangeBatch on the write is treated as idempotent.
    await driver._apply_record(_server(), CREDS, change)


@pytest.mark.asyncio
async def test_apply_record_wraps_client_error(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [{"Id": "/hostedzone/Z1", "Name": "example.com."}]
    }
    # Read-merge finds no existing rrset; the write then fails on auth.
    client.list_resource_record_sets.return_value = {"ResourceRecordSets": []}
    client.change_resource_record_sets.side_effect = _ClientError("AccessDenied", "not authorized")
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="10.0.0.1", ttl=300),
        target_serial=1,
    )
    with pytest.raises(CloudDNSError, match="change_resource_record_sets"):
        await driver._apply_record(_server(), CREDS, change)


@pytest.mark.asyncio
async def test_apply_record_wraps_read_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A failure on the read-merge call surfaces as a CloudDNSError."""
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [{"Id": "/hostedzone/Z1", "Name": "example.com."}]
    }
    client.list_resource_record_sets.side_effect = _ClientError("AccessDenied", "not authorized")
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="10.0.0.1", ttl=300),
        target_serial=1,
    )
    with pytest.raises(CloudDNSError, match="read-merge"):
        await driver._apply_record(_server(), CREDS, change)


@pytest.mark.asyncio
async def test_apply_record_update_replaces_without_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """Update keeps single-value replace — it never reads the live rrset."""
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [{"Id": "/hostedzone/Z1", "Name": "example.com."}]
    }
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="update",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="10.0.0.7", ttl=120),
        target_serial=1,
    )
    await driver._apply_record(_server(), CREDS, change)

    # No read-merge for update (the op carries only the new value).
    client.list_resource_record_sets.assert_not_called()
    batch_change = client.change_resource_record_sets.call_args.kwargs["ChangeBatch"]["Changes"][0]
    assert batch_change["Action"] == "UPSERT"
    assert batch_change["ResourceRecordSet"]["ResourceRecords"] == [{"Value": "10.0.0.7"}]


# ── Zone write ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_apply_zone_create(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = Route53DNSDriver()
    client = MagicMock()
    # No existing zone of this name — the create proceeds.
    client.list_hosted_zones_by_name.return_value = {"HostedZones": [], "IsTruncated": False}
    _patch_client(monkeypatch, driver, client)

    zone = SimpleNamespace(name="new.example.")
    await driver._apply_zone(_server(), CREDS, zone, "create")

    kwargs = client.create_hosted_zone.call_args.kwargs
    assert kwargs["Name"] == "new.example."
    # CallerReference must be a non-empty token, stable for the logical
    # create (#1527) so a retry is deduplicated by AWS.
    assert kwargs["CallerReference"]
    import hashlib

    assert kwargs["CallerReference"] == hashlib.sha256(b":new.example.").hexdigest()


@pytest.mark.asyncio
async def test_apply_zone_create_refuses_existing_zone(monkeypatch: pytest.MonkeyPatch) -> None:
    """A same-name hosted zone SpatiumDDI did not create is NEVER adopted:
    the create is refused with a conflict naming the existing zone id and
    pointing at Import existing zones — the explicit adoption path."""
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [
            {
                "Id": "/hostedzone/Zexisting",
                "Name": "new.example.",
                "CallerReference": "minted-by-someone-else",
            }
        ],
        "IsTruncated": False,
    }
    _patch_client(monkeypatch, driver, client)

    zone = SimpleNamespace(name="new.example.")
    with pytest.raises(CloudDNSConflictError) as excinfo:
        await driver._apply_zone(_server(), CREDS, zone, "create")

    message = str(excinfo.value)
    assert "Zexisting" in message
    assert "Import existing zones" in message
    assert "/api/v1/dns/import/cloud/preview" in message
    client.create_hosted_zone.assert_not_called()


@pytest.mark.asyncio
async def test_apply_zone_create_retry_of_same_row_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retried create of the SAME zone row finds the hosted zone its
    first attempt minted (same deterministic CallerReference) and
    succeeds without minting a second zone or refusing."""
    import hashlib

    driver = Route53DNSDriver()
    client = MagicMock()
    caller_reference = hashlib.sha256(b"zone-uuid-1:new.example.").hexdigest()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [
            {
                "Id": "/hostedzone/Zours",
                "Name": "new.example.",
                "CallerReference": caller_reference,
            }
        ],
        "IsTruncated": False,
    }
    _patch_client(monkeypatch, driver, client)

    zone = SimpleNamespace(id="zone-uuid-1", name="new.example.")
    # No raise, no second create.
    await driver._apply_zone(_server(), CREDS, zone, "create")
    client.create_hosted_zone.assert_not_called()


@pytest.mark.asyncio
async def test_resolve_zone_id_prefers_public_over_private_same_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same-name public + private zones: the pick is deterministic —
    the PUBLIC zone wins even when the API lists the private one first."""
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [
            {
                "Id": "/hostedzone/Zpriv",
                "Name": "example.com.",
                "Config": {"PrivateZone": True},
            },
            {
                "Id": "/hostedzone/Zpub",
                "Name": "example.com.",
                "Config": {"PrivateZone": False},
            },
        ],
        "IsTruncated": False,
    }
    _patch_client(monkeypatch, driver, client)

    assert await driver._resolve_zone_id(client, "example.com.") == "Zpub"


@pytest.mark.asyncio
async def test_apply_zone_create_caller_reference_stable_across_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1527 — two attempts at the same logical create share a reference."""
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {"HostedZones": [], "IsTruncated": False}
    _patch_client(monkeypatch, driver, client)

    zone = SimpleNamespace(id="zone-uuid-1", name="new.example.")
    await driver._apply_zone(_server(), CREDS, zone, "create")
    first = client.create_hosted_zone.call_args.kwargs["CallerReference"]
    await driver._apply_zone(_server(), CREDS, zone, "create")
    second = client.create_hosted_zone.call_args.kwargs["CallerReference"]
    assert first == second


@pytest.mark.asyncio
async def test_apply_zone_delete_resolves_id(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [{"Id": "/hostedzone/Z42", "Name": "doomed.example."}]
    }
    # Zone carries only SOA + apex NS — nothing to empty before delete.
    client.list_resource_record_sets.return_value = {
        "ResourceRecordSets": [
            {
                "Name": "doomed.example.",
                "Type": "SOA",
                "TTL": 900,
                "ResourceRecords": [{"Value": "ns-1.awsdns.com. hostmaster.awsdns.com. 1 2 3 4 5"}],
            },
            {
                "Name": "doomed.example.",
                "Type": "NS",
                "TTL": 172800,
                "ResourceRecords": [{"Value": "ns-1.awsdns.com."}],
            },
        ],
        "IsTruncated": False,
    }
    _patch_client(monkeypatch, driver, client)

    zone = SimpleNamespace(name="doomed.example.")
    await driver._apply_zone(_server(), CREDS, zone, "delete")

    client.change_resource_record_sets.assert_not_called()
    assert client.delete_hosted_zone.call_args.kwargs["Id"] == "Z42"


@pytest.mark.asyncio
async def test_apply_zone_delete_empties_only_managed_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1528 — zone emptying is scoped to records SpatiumDDI manages.

    The managed www A + delegated sub-zone NS rrsets are deleted; the
    foreign TXT rrset (in the provider zone but NOT in our DB) must
    NOT be touched; SOA / apex NS are always skipped.
    """
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [{"Id": "/hostedzone/Z42", "Name": "doomed.example."}]
    }
    www = {
        "Name": "www.doomed.example.",
        "Type": "A",
        "TTL": 300,
        "ResourceRecords": [{"Value": "10.0.0.1"}],
    }
    sub_ns = {
        "Name": "sub.doomed.example.",
        "Type": "NS",
        "TTL": 300,
        "ResourceRecords": [{"Value": "ns.other.example."}],
    }
    foreign_txt = {
        "Name": "doomed.example.",
        "Type": "TXT",
        "TTL": 300,
        "ResourceRecords": [{"Value": '"v=spf1 -all"'}],
    }
    client.list_resource_record_sets.return_value = {
        "ResourceRecordSets": [
            {
                "Name": "doomed.example.",
                "Type": "SOA",
                "TTL": 900,
                "ResourceRecords": [{"Value": "ns hostmaster 1 2 3 4 5"}],
            },
            {
                "Name": "doomed.example.",
                "Type": "NS",
                "TTL": 172800,
                "ResourceRecords": [{"Value": "ns-1.awsdns.com."}],
            },
            www,
            sub_ns,
            foreign_txt,
        ],
        "IsTruncated": False,
    }
    _patch_client(monkeypatch, driver, client)

    zone = SimpleNamespace(name="doomed.example.")
    managed = [
        RecordData(name="www", record_type="A", value="10.0.0.1", ttl=300),
        RecordData(name="sub", record_type="NS", value="ns.other.example.", ttl=300),
    ]
    await driver._apply_zone(_server(), CREDS, zone, "delete", managed_records=managed)

    # One batched change carrying exactly the two managed rrsets — the
    # foreign TXT rrset is absent, so it survives the emptying.
    batch = client.change_resource_record_sets.call_args.kwargs["ChangeBatch"]
    assert batch["Changes"] == [
        {"Action": "DELETE", "ResourceRecordSet": www},
        {"Action": "DELETE", "ResourceRecordSet": sub_ns},
    ]
    assert client.delete_hosted_zone.call_args.kwargs["Id"] == "Z42"


@pytest.mark.asyncio
async def test_apply_zone_delete_mixed_rrset_keeps_foreign_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A managed value sharing an rrset with a foreign value: the rrset
    is UPSERTed down to just the foreign value, never deleted wholesale."""
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [{"Id": "/hostedzone/Z42", "Name": "doomed.example."}]
    }
    client.list_resource_record_sets.return_value = {
        "ResourceRecordSets": [
            {
                "Name": "rr.doomed.example.",
                "Type": "A",
                "TTL": 300,
                "ResourceRecords": [{"Value": "10.0.0.1"}, {"Value": "10.0.0.2"}],
            },
        ],
        "IsTruncated": False,
    }
    _patch_client(monkeypatch, driver, client)

    zone = SimpleNamespace(name="doomed.example.")
    managed = [RecordData(name="rr", record_type="A", value="10.0.0.1", ttl=300)]
    await driver._apply_zone(_server(), CREDS, zone, "delete", managed_records=managed)

    batch = client.change_resource_record_sets.call_args.kwargs["ChangeBatch"]
    assert batch["Changes"] == [
        {
            "Action": "UPSERT",
            "ResourceRecordSet": {
                "Name": "rr.doomed.example.",
                "Type": "A",
                "TTL": 300,
                "ResourceRecords": [{"Value": "10.0.0.2"}],
            },
        }
    ]
    assert client.delete_hosted_zone.call_args.kwargs["Id"] == "Z42"


@pytest.mark.asyncio
async def test_apply_zone_delete_foreign_records_block_delete_honestly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Foreign records are never deleted; when they keep the zone
    non-empty, Route 53's refusal surfaces as a clear error instead of
    the records being silently wiped."""
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [{"Id": "/hostedzone/Z42", "Name": "doomed.example."}]
    }
    client.list_resource_record_sets.return_value = {
        "ResourceRecordSets": [
            {
                "Name": "www.doomed.example.",
                "Type": "A",
                "TTL": 300,
                "ResourceRecords": [{"Value": "10.0.0.1"}],
            },
        ],
        "IsTruncated": False,
    }
    client.delete_hosted_zone.side_effect = _ClientError(
        "HostedZoneNotEmpty", "The specified hosted zone contains non-DNSSEC resource records"
    )
    _patch_client(monkeypatch, driver, client)

    zone = SimpleNamespace(name="doomed.example.")
    # We manage NOTHING in this zone — emptying must submit no changes.
    with pytest.raises(CloudDNSError, match="does not manage"):
        await driver._apply_zone(_server(), CREDS, zone, "delete", managed_records=[])

    client.change_resource_record_sets.assert_not_called()


@pytest.mark.asyncio
async def test_apply_zone_delete_without_scoping_deletes_no_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """managed_records=None (caller supplied no scoping): no record is
    deleted on the way out — only the zone delete itself is attempted."""
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [{"Id": "/hostedzone/Z42", "Name": "doomed.example."}]
    }
    _patch_client(monkeypatch, driver, client)

    zone = SimpleNamespace(name="doomed.example.")
    await driver._apply_zone(_server(), CREDS, zone, "delete")

    client.list_resource_record_sets.assert_not_called()
    client.change_resource_record_sets.assert_not_called()
    assert client.delete_hosted_zone.call_args.kwargs["Id"] == "Z42"


@pytest.mark.asyncio
async def test_apply_zone_delete_absent_zone_is_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1528 — deleting a zone that is already gone is a no-op success."""
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {"HostedZones": [], "IsTruncated": False}
    _patch_client(monkeypatch, driver, client)

    zone = SimpleNamespace(name="gone.example.")
    await driver._apply_zone(_server(), CREDS, zone, "delete")

    client.delete_hosted_zone.assert_not_called()


@pytest.mark.asyncio
async def test_apply_zone_bad_op(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = Route53DNSDriver()
    _patch_client(monkeypatch, driver, MagicMock())
    with pytest.raises(CloudDNSError, match="unsupported op"):
        await driver._apply_zone(_server(), CREDS, SimpleNamespace(name="x.test."), "rename")


# ── Capabilities ───────────────────────────────────────────────────────────


def test_capabilities_shape() -> None:
    caps = Route53DNSDriver().capabilities()
    assert caps["name"] == "route53"
    assert caps["agentless"] is True
    assert caps["manages_zones"] is True
    assert caps["dnssec_online"] is False  # #29 — cloud DNSSEC deferred
    assert caps["alias_records"] is False  # #29 — R53 alias authoring deferred
    assert "ALIAS" not in caps["record_types"]  # #29 — authoring deferred
    assert caps["views"] is False
    assert caps["rpz"] is False


def test_credential_fields() -> None:
    driver = Route53DNSDriver()
    assert driver.name == "route53"
    assert driver.credential_fields == ("access_key_id", "secret_access_key")
