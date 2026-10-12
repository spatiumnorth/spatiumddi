"""#1533 — sync with servers never pulled or pushed CAA records.

Both halves of ``sync_zone_with_server`` filtered record types through a
hardcoded set (``A, AAAA, CNAME, MX, TXT, SRV, PTR, NS, TLSA``), so CAA
drift between SpatiumDDI and a provider could never be repaired through
sync — even though every cloud driver advertises CAA and the one-shot
cloud importer imports it. The push set was a deliberate copy of the
Windows driver's supported types, so adding CAA to the shared set
naively would have broken Windows pushes.

The filter is now derived per server: the driver's advertised
``capabilities()["record_types"]`` intersected with the types the DB
models. These tests pin that derivation — CAA flows for a driver that
advertises it, never reaches a driver that doesn't (Windows), and a
driver publishing no ``record_types`` falls back to the legacy set
instead of syncing nothing.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

from app.drivers.dns import get_driver
from app.drivers.dns.base import RecordChangeResult, RecordData
from app.models.dns import DNSRecord, DNSZone
from app.services.dns.pull_from_server import (
    _IMPORTABLE_TYPES,
    _PUSHABLE_TYPES,
    _additive_import,
    _additive_push,
    _syncable_types,
)

_CAA_VALUE = '0 issue "letsencrypt.org"'


class _NoCapsDriver:
    """A driver whose capabilities publish no record_types list."""

    def capabilities(self) -> dict[str, Any]:
        return {"name": "no-caps"}


class _RecordingDriver:
    """Minimal driver double for the push phase: records what it was
    asked to apply and reports success for every change."""

    def __init__(self, record_types: list[str]) -> None:
        self._record_types = record_types
        self.applied: list[Any] = []

    def capabilities(self) -> dict[str, Any]:
        return {"record_types": list(self._record_types)}

    async def apply_record_changes(self, server: Any, changes: list[Any]) -> list[Any]:
        self.applied.extend(changes)
        return [RecordChangeResult(ok=True, change=c) for c in changes]


def _zone() -> DNSZone:
    return DNSZone(id=uuid.uuid4(), name="example.com", group_id=uuid.uuid4())


def _caa_row(zone: DNSZone) -> DNSRecord:
    return DNSRecord(
        zone_id=zone.id,
        name="@",
        fqdn="example.com",
        record_type="CAA",
        value=_CAA_VALUE,
        ttl=3600,
    )


# ── The derivation itself ────────────────────────────────────────────────


def test_cloud_driver_syncable_types_include_caa_and_exclude_soa() -> None:
    """Route 53 advertises CAA (syncable) and SOA (zone metadata the DB
    does not model as a record — must stay out of both phases)."""
    types = _syncable_types(get_driver("route53"), _IMPORTABLE_TYPES)
    assert "CAA" in types
    assert "SOA" not in types


def test_windows_driver_syncable_types_have_no_caa() -> None:
    """The old push set existed to mirror Windows. Deriving from the
    Windows driver's own capabilities must reproduce it exactly, so the
    CAA fix cannot leak a type Windows cannot serve."""
    types = _syncable_types(get_driver("windows_dns"), _PUSHABLE_TYPES)
    assert types == _PUSHABLE_TYPES
    assert "CAA" not in types


def test_driver_without_record_types_falls_back_to_legacy_set() -> None:
    assert _syncable_types(_NoCapsDriver(), _PUSHABLE_TYPES) == _PUSHABLE_TYPES
    assert _syncable_types(_NoCapsDriver(), _IMPORTABLE_TYPES) == frozenset(_IMPORTABLE_TYPES)


# ── Pull phase ───────────────────────────────────────────────────────────


def test_pull_imports_caa_when_the_driver_advertises_it() -> None:
    zone = _zone()
    on_wire = [RecordData(name="@", record_type="CAA", value=_CAA_VALUE, ttl=3600)]
    result = _additive_import(
        None,  # apply=False never touches the session
        zone,
        on_wire,
        set(),
        apply=False,
        importable_types=_syncable_types(get_driver("route53"), _IMPORTABLE_TYPES),
    )
    assert result.imported == 1
    assert result.skipped_unsupported == 0
    assert result.imported_records[0]["record_type"] == "CAA"


def test_pull_still_skips_caa_for_a_driver_that_lacks_it() -> None:
    zone = _zone()
    on_wire = [RecordData(name="@", record_type="CAA", value=_CAA_VALUE, ttl=3600)]
    result = _additive_import(
        None,
        zone,
        on_wire,
        set(),
        apply=False,
        importable_types=_syncable_types(get_driver("windows_dns"), _IMPORTABLE_TYPES),
    )
    assert result.imported == 0
    assert result.skipped_unsupported == 1


# ── Push phase ───────────────────────────────────────────────────────────


async def test_push_sends_caa_to_a_driver_that_advertises_it() -> None:
    zone = _zone()
    row = _caa_row(zone)
    driver = _RecordingDriver(["A", "CAA", "SOA"])
    primary = SimpleNamespace(id=uuid.uuid4(), driver="route53")
    result = await _additive_push(None, primary, driver, zone, [], [row], apply=True)
    assert result.candidates == 1
    assert result.pushed == 1
    assert [c.record.record_type for c in driver.applied] == ["CAA"]


async def test_push_never_sends_caa_to_windows() -> None:
    zone = _zone()
    row = _caa_row(zone)
    driver = _RecordingDriver(list(_PUSHABLE_TYPES))
    primary = SimpleNamespace(id=uuid.uuid4(), driver="windows_dns")
    result = await _additive_push(None, primary, driver, zone, [], [row], apply=True)
    assert result.candidates == 0
    assert result.pushed == 0
    assert driver.applied == []
