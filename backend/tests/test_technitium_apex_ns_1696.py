"""Technitium + Sync with Servers / drift (#1696, #1809).

* #1696 / #1809: Technitium's own apex NS is not imported by Sync and is not
  listed as extra by drift; an apex NS the DB holds is still compared.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns.base import RecordData
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.services.dns import drift as drift_mod
from app.services.dns.pull_from_server import (
    _additive_import,
    _key,
    without_server_apex_ns,
)

_ZONE = "example.com."


def _zone() -> DNSZone:
    return DNSZone(id=uuid.uuid4(), name=_ZONE, group_id=uuid.uuid4())


def _row(zone: DNSZone, name: str, rtype: str, value: str, **kw: Any) -> DNSRecord:
    fqdn = zone.name.rstrip(".") if name == "@" else f"{name}.{zone.name.rstrip('.')}"
    return DNSRecord(
        zone_id=zone.id, name=name, fqdn=fqdn, record_type=rtype, value=value, ttl=300, **kw
    )


# ── #1696 / #1809 ───────────────────────────────────────────────────────


def _apex_ns(value: str = "ddipg-seed.") -> RecordData:
    return RecordData(name="@", record_type="NS", value=value, ttl=14400)


def test_apex_ns_is_not_imported_on_technitium_api() -> None:
    zone = _zone()
    server = SimpleNamespace(driver="technitium_api")
    delegation = RecordData(name="kid", record_type="NS", value="ns.kid.example.com.", ttl=300)
    wire = without_server_apex_ns([_apex_ns(), delegation], server, zone.name, set())
    assert wire == [delegation]

    result = _additive_import(
        None,
        zone,
        wire,
        set(),
        apply=False,
        relative_targets=True,
    )
    assert [r["name"] for r in result.imported_records] == ["kid"]


def test_an_apex_ns_the_db_holds_is_still_compared() -> None:
    zone = _zone()
    server = SimpleNamespace(driver="technitium_api")
    held = _row(zone, "@", "NS", "ns1.example.com.")
    keys = {_key(held, zone.name, relative_targets=True)}
    ours = _apex_ns("ns1.example.com.")
    wire = without_server_apex_ns([ours, _apex_ns()], server, zone.name, keys)
    # The default is dropped; the one the DB holds stays, and compares in sync.
    assert wire == [ours]


@pytest.mark.parametrize("driver", ["bind9", "technitium", "windows_dns", "route53"])
def test_other_drivers_are_untouched(driver: str) -> None:
    wire = [_apex_ns()]
    assert without_server_apex_ns(wire, SimpleNamespace(driver=driver), _ZONE, set()) is wire


class _WireDriver:
    def __init__(self, records: list[RecordData]) -> None:
        self._records = records

    async def pull_zone_records(self, server: Any, zone_name: str, *, tsig: Any = None) -> Any:
        return list(self._records)


async def test_drift_on_a_fresh_technitium_api_zone_reads_in_sync(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1809: the zone's first drift read, before any record exists, listed
    Technitium's own apex NS as extra on the server."""
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    server = DNSServer(
        group_id=group.id,
        name="t1",
        driver="technitium_api",
        host="10.0.0.1",
        port=53,
        is_enabled=True,
        is_primary=True,
    )
    zone = DNSZone(
        group_id=group.id, name="fresh.example.com.", zone_type="primary", kind="forward"
    )
    db_session.add_all([server, zone])
    await db_session.commit()

    delegation = RecordData(
        name="kid", record_type="NS", value="ns.kid.fresh.example.com.", ttl=300
    )
    monkeypatch.setattr(
        drift_mod, "get_driver", lambda _d: _WireDriver([_apex_ns("ddipg-seed."), delegation])
    )
    report = await drift_mod.compute_zone_drift(db_session, group_id=group.id, zone=zone)
    (s,) = report.servers
    assert s.status == "drift"  # transferred; the delegation is extra on the server (#3198)
    # Only the delegation, which the operator may well have made on the server.
    assert [(r.name, r.record_type) for r in s.extra_on_server] == [("kid", "NS")]
