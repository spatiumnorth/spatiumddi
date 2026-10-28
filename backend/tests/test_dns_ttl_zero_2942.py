"""#2942 — a stored TTL of 0 is published as 0, never as a default.

The record API accepts ``ttl: 0`` and the zone-file import stores it, so the
database can hold 0. ``ttl or default`` reads that as missing; only ``None``
may fall back. One test per driver path, each with a positive control
(``None`` still takes the default).

Cloudflare is deliberately not here: it has no way to represent 0 (see the
driver module docstring) and sends the stored value through unchanged so the
provider's own validation refuses it, instead of publishing something else.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.drivers.dns.base import (
    RecordChange,
    RecordData,
    RRsetData,
    RRsetMember,
    ZoneData,
    first_ttl,
)


def _change(
    ttl: int | None,
    *,
    op: str = "create",
    rrset_ttl: int | None = None,
    rrset: bool = False,
) -> RecordChange:
    return RecordChange(
        op=op,
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="10.0.0.1", ttl=ttl),
        target_serial=1,
        rrset=(
            RRsetData(ttl=rrset_ttl, members=(RRsetMember(value="10.0.0.1"),)) if rrset else None
        ),
    )


def test_first_ttl_only_none_falls_through() -> None:
    assert first_ttl(0, 5, default=9) == 0
    assert first_ttl(None, 0, default=9) == 0
    assert first_ttl(None, None, default=9) == 9


# ── PowerDNS (control-plane renderer) ────────────────────────────────


@pytest.mark.parametrize(("ttl", "expected"), [(0, 0), (None, 3600), (60, 60)])
def test_powerdns_rrset_ttl(ttl: int | None, expected: int) -> None:
    from app.drivers.dns.powerdns import PowerDNSDriver

    zone = ZoneData(
        name="example.com.",
        zone_type="primary",
        kind="forward",
        ttl=3600,
        refresh=1,
        retry=1,
        expire=1,
        minimum=1,
        primary_ns="ns1.example.com.",
        admin_email="h.example.com.",
        serial=1,
        records=(),
    )
    out = json.loads(
        PowerDNSDriver().render_zone_file(
            zone, [RecordData(name="www", record_type="A", value="10.0.0.1", ttl=ttl)]
        )
    )
    (rr,) = [r for r in out["rrsets"] if r["type"] == "A"]
    assert rr["ttl"] == expected


# ── Windows: RFC 2136 (Path A) ───────────────────────────────────────


async def _rfc2136(monkeypatch: pytest.MonkeyPatch, change: RecordChange) -> Any:
    import dns.query

    from app.drivers.dns import windows

    sent: list[Any] = []
    monkeypatch.setattr(windows, "resolve_server_address", lambda *a, **k: ["192.0.2.53"])
    monkeypatch.setattr(dns.query, "tcp", lambda msg, *a, **k: sent.append(msg))
    server = SimpleNamespace(id="s1", host="dc1.example.com", api_port=53)
    await windows.WindowsDNSDriver().apply_record_change(server, change)
    (msg,) = sent
    return [rs for rs in msg.update if rs.rdtype.name == "A" and len(rs)][0]


@pytest.mark.parametrize(("ttl", "expected"), [(0, 0), (None, 3600), (120, 120)])
async def test_windows_rfc2136_single_value(monkeypatch, ttl, expected) -> None:
    assert (await _rfc2136(monkeypatch, _change(ttl))).ttl == expected


@pytest.mark.parametrize(
    ("rrset_ttl", "rec_ttl", "expected"),
    [(0, 300, 0), (None, 0, 0), (None, None, 3600), (30, 0, 30)],
)
async def test_windows_rfc2136_rrset(monkeypatch, rrset_ttl, rec_ttl, expected) -> None:
    ch = _change(rec_ttl, op="update", rrset_ttl=rrset_ttl, rrset=True)
    assert (await _rfc2136(monkeypatch, ch)).ttl == expected


# ── Windows: WinRM / PowerShell (Path B) ─────────────────────────────


@pytest.mark.parametrize(("ttl", "expected"), [(0, 0), (None, 3600), (120, 120)])
def test_windows_winrm_singular_and_batch(ttl: int | None, expected: int) -> None:
    from app.drivers.dns.windows import _ps_apply_record, _ps_apply_record_batch
    from tests.test_dns_agentless_rrset import _batch_payload

    assert f"FromSeconds({expected})" in _ps_apply_record(_change(ttl))
    (op,) = _batch_payload(_ps_apply_record_batch([_change(ttl)]))
    assert op["ttl"] == expected


def test_windows_winrm_rrset_ttl_zero_beats_record_ttl() -> None:
    from app.drivers.dns.windows import _ps_apply_record

    ch = _change(300, op="update", rrset_ttl=0, rrset=True)
    assert "FromSeconds(0)" in _ps_apply_record(ch)


# ── Route 53 ─────────────────────────────────────────────────────────


def _r53_client() -> MagicMock:
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [{"Id": "/hostedzone/Z1", "Name": "example.com."}]
    }
    client.list_resource_record_sets.return_value = {"ResourceRecordSets": []}
    return client


async def _r53_ttl(monkeypatch: pytest.MonkeyPatch, change: RecordChange) -> int:
    from app.drivers.dns.route53 import Route53DNSDriver

    driver = Route53DNSDriver()
    client = _r53_client()
    monkeypatch.setattr(driver, "_client", lambda creds: client)
    await driver._apply_record(SimpleNamespace(id="s"), {"access_key_id": "a"}, change)
    rrset = client.change_resource_record_sets.call_args.kwargs["ChangeBatch"]["Changes"][0][
        "ResourceRecordSet"
    ]
    return int(rrset["TTL"])


@pytest.mark.parametrize(("ttl", "expected"), [(0, 0), (None, 300), (60, 60)])
async def test_route53_create_and_update(monkeypatch, ttl, expected) -> None:
    assert await _r53_ttl(monkeypatch, _change(ttl)) == expected
    assert await _r53_ttl(monkeypatch, _change(ttl, op="update")) == expected


@pytest.mark.parametrize(
    ("rrset_ttl", "rec_ttl", "expected"), [(0, 300, 0), (None, 0, 0), (None, None, 300)]
)
async def test_route53_rrset_update(monkeypatch, rrset_ttl, rec_ttl, expected) -> None:
    ch = _change(rec_ttl, op="update", rrset_ttl=rrset_ttl, rrset=True)
    assert await _r53_ttl(monkeypatch, ch) == expected


def test_route53_merge_ttl_zero() -> None:
    from app.drivers.dns.route53 import Route53DNSDriver

    m = Route53DNSDriver._merge_ttl
    assert m(0, {"TTL": 60}, 300) == 0
    assert m(None, {"TTL": 0}, 300) == 0
    assert m(None, None, 300) == 300


async def test_route53_delete_keeps_live_zero_ttl(monkeypatch) -> None:
    from app.drivers.dns.route53 import Route53DNSDriver

    driver = Route53DNSDriver()
    client = _r53_client()
    client.list_resource_record_sets.return_value = {
        "ResourceRecordSets": [
            {
                "Name": "www.example.com.",
                "Type": "A",
                "TTL": 0,
                "ResourceRecords": [{"Value": "10.0.0.1"}, {"Value": "10.0.0.2"}],
            }
        ]
    }
    monkeypatch.setattr(driver, "_client", lambda creds: client)
    await driver._apply_record(
        SimpleNamespace(id="s"), {"access_key_id": "a"}, _change(300, op="delete")
    )
    rrset = client.change_resource_record_sets.call_args.kwargs["ChangeBatch"]["Changes"][0][
        "ResourceRecordSet"
    ]
    assert rrset["TTL"] == 0


# ── Google Cloud DNS ─────────────────────────────────────────────────


@pytest.mark.parametrize(("ttl", "expected"), [(0, 0), (None, 300), (600, 600)])
async def test_google_update(monkeypatch, ttl, expected) -> None:
    from app.drivers.dns.googledns import GoogleCloudDNSDriver
    from tests.test_dns_google_dns import (
        CREDS,
        _client_with_zones,
        _patch_client,
        _server,
        _StubZone,
    )

    for ch in (
        _change(ttl, op="update"),
        _change(ttl, op="update", rrset_ttl=None, rrset=True),
    ):
        driver = GoogleCloudDNSDriver()
        zone = _StubZone("example-com", "example.com.", rrsets=[])
        _patch_client(monkeypatch, driver, _client_with_zones(zone))
        await driver._apply_record(_server(), CREDS, ch)
        assert zone.built_rrsets[0][2] == expected


async def test_google_rrset_zero_beats_record(monkeypatch) -> None:
    from app.drivers.dns.googledns import GoogleCloudDNSDriver
    from tests.test_dns_google_dns import (
        CREDS,
        _client_with_zones,
        _patch_client,
        _server,
        _StubZone,
    )

    driver = GoogleCloudDNSDriver()
    zone = _StubZone("example-com", "example.com.", rrsets=[])
    _patch_client(monkeypatch, driver, _client_with_zones(zone))
    await driver._apply_record(_server(), CREDS, _change(300, op="update", rrset_ttl=0, rrset=True))
    assert zone.built_rrsets[0][2] == 0


@pytest.mark.parametrize(("change_ttl", "expected"), [(0, 0), (None, 60)])
def test_google_merge_create_ttl(change_ttl: int | None, expected: int) -> None:
    from app.drivers.dns.googledns import GoogleCloudDNSDriver

    existing = SimpleNamespace(ttl=60, rrdatas=["10.0.0.9"])
    _merged, ttl = GoogleCloudDNSDriver()._merge_create(existing, "10.0.0.1", change_ttl)
    assert ttl == expected


# ── Azure DNS ────────────────────────────────────────────────────────


async def test_azure_delete_keeps_live_zero_ttl(monkeypatch) -> None:
    from app.drivers.dns.azuredns import AzureDNSDriver

    driver = AzureDNSDriver()
    existing = SimpleNamespace(
        ttl=0,
        a_records=[
            SimpleNamespace(ipv4_address="10.0.0.1"),
            SimpleNamespace(ipv4_address="10.0.0.2"),
        ],
    )
    monkeypatch.setattr(driver, "_get_record_set", lambda *a, **k: existing)
    client = MagicMock()
    await driver._apply_delete(
        client,
        "rg",
        "example.com",
        "www",
        "A",
        RecordData(name="www", record_type="A", value="10.0.0.1", ttl=300),
    )
    assert client.record_sets.create_or_update.call_args.args[-1]["ttl"] == 0


@pytest.mark.parametrize(("ttl", "expected"), [(0, 0), (None, 3600)])
def test_azure_record_set_params_ttl(ttl: int | None, expected: int) -> None:
    from app.drivers.dns.azuredns import AzureDNSDriver

    rec = RecordData(name="w", record_type="A", value="10.0.0.1", ttl=ttl)
    assert AzureDNSDriver()._build_record_set_params(rec)["ttl"] == expected


# ── AXFR read-back (drift) ───────────────────────────────────────────


async def test_axfr_reads_ttl_zero_as_zero(monkeypatch) -> None:
    import dns.query
    import dns.zone

    from app.drivers.dns._axfr import axfr_zone_records

    z = dns.zone.from_text(
        "$ORIGIN example.com.\n@ 3600 IN SOA ns1 h 1 1 1 1 1\n@ 3600 IN NS ns1\n"
        "www 0 IN A 10.0.0.1\nmail 300 IN A 10.0.0.2\n",
        origin="example.com.",
        relativize=True,
    )
    monkeypatch.setattr(dns.query, "xfr", lambda *a, **k: object())
    monkeypatch.setattr(dns.zone, "from_xfr", lambda _gen: z)
    recs = await axfr_zone_records(host="192.0.2.10", port=53, zone_name="example.com.")
    ttls = {r.name: r.ttl for r in recs}
    assert ttls == {"www": 0, "mail": 300}


# ── PowerDNS importer ────────────────────────────────────────────────


def test_powerdns_import_keeps_ttl_zero() -> None:
    from app.services.dns_import.powerdns import _build_imported_zone

    full = {
        "rrsets": [
            {
                "name": "www.example.com.",
                "type": "A",
                "ttl": 0,
                "records": [{"content": "10.0.0.1", "disabled": False}],
            },
            {
                "name": "x.example.com.",
                "type": "A",
                "ttl": None,
                "records": [{"content": "10.0.0.2", "disabled": False}],
            },
        ]
    }
    z = _build_imported_zone({"name": "example.com.", "kind": "Native"}, full)
    by_name = {r.name: r.ttl for r in z.records}
    assert by_name == {"www": 0, "x": 3600}


# ── Cloudflare: cannot represent 0, must not substitute ──────────────


@pytest.mark.parametrize(("ttl", "expected"), [(0, 0), (None, 1), (300, 300)])
def test_cloudflare_payload_never_rewrites_zero(ttl: int | None, expected: int) -> None:
    from app.drivers.dns.cloudflare import CloudflareDNSDriver

    payload = CloudflareDNSDriver()._record_payload(_change(ttl), "example.com.")
    assert payload["ttl"] == expected
