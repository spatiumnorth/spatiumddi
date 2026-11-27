"""Tests for the PowerDNS catalog-zone renderer (issue #127, Phase 3d)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import httpx
import pytest

from spatium_dns_agent.drivers.powerdns import (
    PowerDNSDriver,
    _render_catalog_zone_payload,
)
from tests.test_powerdns_serial_owner import FakePdns, _install


def _sha1_label(zone: str) -> str:
    """Reproduce the RFC 9432 §4.1 SHA-1 wire-format zone-name hash."""
    text = zone.lower().rstrip(".")
    wire = (
        b"".join(
            bytes([len(label)]) + label.encode("ascii")
            for label in text.split(".")
            if label
        )
        + b"\x00"
    )
    return hashlib.sha1(wire).hexdigest()


def test_catalog_zone_payload_apex_records() -> None:
    payload = _render_catalog_zone_payload(
        {
            "zone_name": "catalog.spatium.invalid.",
            "members": [],
        }
    )
    assert payload["name"] == "catalog.spatium.invalid."
    assert payload["kind"] == "Master"  # Native never sends NOTIFY (#4574)

    rrsets = {(r["name"], r["type"]): r for r in payload["rrsets"]}

    # Apex SOA — invalid placeholder owner per RFC 9432 (catalog
    # zones are administrative, not authoritative for real names).
    soa = rrsets[("catalog.spatium.invalid.", "SOA")]
    assert "invalid. invalid." in soa["records"][0]["content"]

    # Apex NS — also invalid placeholder.
    ns = rrsets[("catalog.spatium.invalid.", "NS")]
    assert ns["records"][0]["content"] == "invalid."

    # version.<catalog>. IN TXT "2" — pinned schema version.
    version = rrsets[("version.catalog.spatium.invalid.", "TXT")]
    assert version["records"][0]["content"] == '"2"'


def test_catalog_zone_payload_member_ptr_uses_rfc_9432_hash() -> None:
    members = [
        {"zone_name": "example.com."},
        {"zone_name": "example.org."},
    ]
    payload = _render_catalog_zone_payload(
        {
            "zone_name": "catalog.spatium.invalid.",
            "members": members,
        }
    )

    # Every member produces exactly one PTR rrset under
    # ``<sha1>.zones.<catalog>.``. Hashes must be deterministic and
    # match a hand-computed reference.
    ptrs = {
        r["records"][0]["content"]: r
        for r in payload["rrsets"]
        if r["type"] == "PTR"
    }
    assert "example.com." in ptrs
    assert "example.org." in ptrs

    expected_label = (
        f"{_sha1_label('example.com')}.zones.catalog.spatium.invalid."
    )
    assert ptrs["example.com."]["name"] == expected_label


def test_catalog_zone_payload_skips_empty_member_names() -> None:
    payload = _render_catalog_zone_payload(
        {
            "zone_name": "catalog.spatium.invalid.",
            "members": [
                {"zone_name": ""},
                {"zone_name": None},
                {"zone_name": "real.example."},
            ],
        }
    )
    ptr_targets = [
        r["records"][0]["content"]
        for r in payload["rrsets"]
        if r["type"] == "PTR"
    ]
    assert ptr_targets == ["real.example."]


def test_catalog_zone_payload_normalises_zone_name_trailing_dot() -> None:
    # Operators sometimes type the catalog zone name without a
    # trailing dot. The renderer must still emit FQDNs with the dot
    # so PowerDNS accepts the records on POST.
    payload = _render_catalog_zone_payload(
        {
            "zone_name": "catalog.spatium.invalid",
            "members": [],
        }
    )
    assert payload["name"] == "catalog.spatium.invalid."
    rrsets = {(r["name"], r["type"]) for r in payload["rrsets"]}
    assert ("catalog.spatium.invalid.", "SOA") in rrsets
    assert ("version.catalog.spatium.invalid.", "TXT") in rrsets


def test_catalog_zone_payload_serial_is_unix_timestamp() -> None:
    # Each render bumps the serial via int(time.time()) so consumers
    # always pull on membership change. Just validate the field is
    # present and a sane unix timestamp (>= 2026-01-01).
    payload = _render_catalog_zone_payload(
        {
            "zone_name": "catalog.spatium.invalid.",
            "members": [],
        }
    )
    assert payload["serial"] >= 1_767_225_600  # 2026-01-01 UTC


# ── #4574: the catalog must NOTIFY its consumers ─────────────────────────────


def test_catalog_zone_is_master_with_also_notify_and_short_refresh() -> None:
    payload = _render_catalog_zone_payload(
        {"zone_name": "catalog.pdns.example.", "members": []},
        {"also_notify": ["192.0.2.53"], "notify_enabled": "yes"},
    )
    assert payload["kind"] == "Master"
    assert payload["also_notify"] == ["192.0.2.53"]
    soa = next(r for r in payload["rrsets"] if r["type"] == "SOA")
    assert int(soa["records"][0]["content"].split()[3]) <= 600


def test_catalog_zone_stays_native_when_notify_is_off() -> None:
    payload = _render_catalog_zone_payload(
        {"zone_name": "catalog.pdns.example.", "members": []},
        {"notify_enabled": "no"},
    )
    assert payload["kind"] == "Native"


def _catalog_payload(members: list[str]) -> dict:
    payload = _render_catalog_zone_payload(
        {
            "zone_name": "catalog.pdns.example.",
            "members": [{"zone_name": m} for m in members],
        },
        {"also_notify": ["192.0.2.53"]},
    )
    payload.update({"update_acl": [], "update_tsig_keys": []})
    return payload


def _fake(monkeypatch: pytest.MonkeyPatch) -> FakePdns:
    class Fake(FakePdns):
        def handle(self, request: httpx.Request) -> httpx.Response:
            resp = super().handle(request)
            if request.method == "GET" and resp.status_code == 200:
                doc = json.loads(resp.content)
                if isinstance(doc, dict):
                    for rs in doc.get("rrsets", []):
                        rs["ttl"] = 86400
                    return httpx.Response(200, json=doc)
            return resp

    fake = Fake()
    _install(monkeypatch, fake)
    return fake


def test_an_existing_native_catalog_is_migrated_to_master(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _fake(monkeypatch)
    fake.seed("catalog.pdns.example.", 1, kind="Native")
    PowerDNSDriver(state_dir=tmp_path)._reconcile_zones(
        "k", [_catalog_payload(["a.example."])]
    )
    assert fake.zones["catalog.pdns.example."]["kind"] == "Master"
    assert (
        "PUT",
        "/zones/catalog.pdns.example./metadata/ALSO-NOTIFY",
        {"kind": "ALSO-NOTIFY", "metadata": ["192.0.2.53"]},
    ) in fake.calls


def test_an_unchanged_catalog_is_not_repatched_and_a_change_notifies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _fake(monkeypatch)
    drv = PowerDNSDriver(state_dir=tmp_path)
    drv._reconcile_zones("k", [_catalog_payload(["a.example."])])
    fake.calls.clear()
    # Same membership, fresh timestamp serial: nothing is published.
    drv._reconcile_zones("k", [_catalog_payload(["a.example."])])
    assert not [c for c in fake.calls if c[0] == "PATCH"]
    assert not [c for c in fake.calls if c[1].endswith("/notify")]
    # A new member is published and consumers are told.
    drv._reconcile_zones("k", [_catalog_payload(["a.example.", "b.example."])])
    assert [c for c in fake.calls if c[0] == "PATCH"]
    assert [c for c in fake.calls if c[1].endswith("/notify")]


def test_a_membership_change_moves_the_serial_past_a_date_form_serial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PowerDNS's DEFAULT serial is YYYYMMDDnn, always above a clock serial;
    the catalog must still advance on every change, or a consumer comparing
    serials ignores the NOTIFY (#4574)."""
    fake = _fake(monkeypatch)
    drv = PowerDNSDriver(state_dir=tmp_path)
    # Created by a pre-fix agent: SOA-EDIT-API DEFAULT, date-form serial.
    fake.seed("catalog.pdns.example.", 2_026_112_001, kind="Native")
    drv._reconcile_zones("k", [_catalog_payload(["a.example."])])
    first = fake.serial("catalog.pdns.example.")
    assert fake.zones["catalog.pdns.example."]["soa_edit_api"] == ""
    drv._reconcile_zones("k", [_catalog_payload(["a.example."])])
    assert fake.serial("catalog.pdns.example.") == first  # unchanged: no creep
    drv._reconcile_zones("k", [_catalog_payload(["a.example.", "b.example."])])
    second = fake.serial("catalog.pdns.example.")
    assert second > first
    drv._reconcile_zones("k", [_catalog_payload(["b.example."])])
    assert fake.serial("catalog.pdns.example.") > second
