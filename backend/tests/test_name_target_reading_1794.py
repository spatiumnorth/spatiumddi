"""#1794 — the drift / sync key reads a dot-less name target the way the
driver does.

A zone-file driver (BIND9, PowerDNS, both Technitium drivers, Windows Path A)
stores and serves ``a.b`` as ``a.b.<zone>.``; only a trailing dot makes a name
absolute. The shared key used to read any dot-less name holding a dot as
absolute, so a relative multi-label target drifted forever against the
absolute name an AXFR returns, and Sync with Servers imported it a second
time. The cloud drivers (and Windows Path B) take the name as given, so there
``a.b`` IS absolute and must keep keying as ``a.b.``.
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
    targets_are_relative,
)

ZONE = "example.com."

# (type, stored value with a dot-less multi-label target,
#  the same record as a zone-file server's AXFR returns it,
#  the same record as a cloud pull returns it)
_CASES = [
    ("CNAME", "a.b", "a.b.example.com.", "a.b"),
    ("DNAME", "a.b", "a.b.example.com.", "a.b"),
    ("NS", "ns.sub", "ns.sub.example.com.", "ns.sub"),
    ("PTR", "h.sub", "h.sub.example.com.", "h.sub"),
    ("MX", "mx.sub", "mx.sub.example.com.", "mx.sub"),
    ("SRV", "sip.sub", "sip.sub.example.com.", "sip.sub"),
    (
        "NAPTR",
        '100 10 "S" "SIP+D2U" "" _sip._udp',
        '100 10 "S" "SIP+D2U" "" _sip._udp.example.com.',
        '100 10 "S" "SIP+D2U" "" _sip._udp',
    ),
    ("SVCB", '1 svc.sub alpn="h2"', '1 svc.sub.example.com. alpn="h2"', '1 svc.sub alpn="h2"'),
    ("HTTPS", "1 svc.sub alpn=h2", "1 svc.sub.example.com. alpn=h2", "1 svc.sub alpn=h2"),
]
_STRUCT = {"MX": {"priority": 10}, "SRV": {"priority": 1, "weight": 1, "port": 80}}

_RELATIVE = ["bind9", "powerdns", "technitium", "technitium_api"]
_ABSOLUTE = ["route53", "azure_dns", "google_dns", "cloudflare"]


def _srv(driver: str, **kw: Any) -> Any:
    return SimpleNamespace(driver=driver, **kw)


def _rec(rtype: str, value: str) -> RecordData:
    return RecordData(name="www", record_type=rtype, value=value, **_STRUCT.get(rtype, {}))


def test_reading_per_driver() -> None:
    for d in _RELATIVE:
        assert targets_are_relative(_srv(d)), d
    for d in _ABSOLUTE:
        assert not targets_are_relative(_srv(d)), d
    # Windows: Path A (no WinRM credentials) is RFC 2136 against the zone
    # origin; Path B hands the name to PowerShell as written.
    assert targets_are_relative(_srv("windows_dns", credentials_encrypted=None))
    assert not targets_are_relative(_srv("windows_dns", credentials_encrypted=b"x"))


def test_cloud_driver_names_match_the_registry() -> None:
    from app.drivers.dns import CLOUD_DNS_DRIVERS

    assert set(_ABSOLUTE) <= CLOUD_DNS_DRIVERS


def test_zone_file_drivers_read_dotless_as_relative() -> None:
    for driver in _RELATIVE:
        rel = targets_are_relative(_srv(driver))
        for rtype, stored, axfr, _cloud in _CASES:
            assert _key(_rec(rtype, stored), ZONE, relative_targets=rel) == _key(
                _rec(rtype, axfr), ZONE, relative_targets=rel
            ), (driver, rtype)


def test_cloud_drivers_keep_dotless_multilabel_absolute() -> None:
    for driver in _ABSOLUTE:
        rel = targets_are_relative(_srv(driver))
        for rtype, stored, _axfr, cloud in _CASES:
            # The cloud pull of the stored name is the same name...
            assert _key(_rec(rtype, stored), ZONE, relative_targets=rel) == _key(
                _rec(rtype, cloud), ZONE, relative_targets=rel
            ), (driver, rtype)
            # ...and is NOT the in-zone name a zone-file server would build.
            assert _key(_rec(rtype, stored), ZONE, relative_targets=rel) != _key(
                _rec(rtype, stored), ZONE, relative_targets=True
            ), (driver, rtype)


def test_single_label_and_trailing_dot_read_the_same_on_both() -> None:
    one = {
        "CNAME": "web",
        "NS": "ns",
        "PTR": "h",
        "DNAME": "d",
        "MX": "mx",
        "SRV": "sip",
        "NAPTR": '1 2 "" "" "" t',
        "SVCB": "1 svc",
        "HTTPS": "1 svc",
    }
    for rel in (True, False):
        for rtype, base in one.items():
            head, _, last = base.rpartition(" ")
            absolute = f"{head} {last}.example.com.".strip()
            assert _key(_rec(rtype, base), ZONE, relative_targets=rel) == _key(
                _rec(rtype, absolute), ZONE, relative_targets=rel
            ), (rel, rtype)
            # A trailing dot is absolute whatever the driver: never qualified.
            other = f"{head} other.net.".strip()
            assert "example.com" not in _key(_rec(rtype, other), ZONE, relative_targets=rel)[2]


def test_sync_imports_no_duplicate_on_a_zone_file_driver() -> None:
    for driver in _RELATIVE:
        _sync_no_dup(driver, 2)


def test_sync_imports_no_duplicate_on_a_cloud_driver() -> None:
    for driver in _ABSOLUTE:
        _sync_no_dup(driver, 3)


def _sync_no_dup(driver: str, idx: int) -> None:
    zone = DNSZone(id=uuid.uuid4(), name="example.com", group_id=uuid.uuid4())
    server = _srv(driver)
    rel = targets_are_relative(server)
    rows = [
        DNSRecord(zone_id=zone.id, name="www", record_type=t, value=v, **_STRUCT.get(t, {}))
        for t, v, _a, _c in _CASES
    ]
    on_wire = [_rec(c[0], c[idx]) for c in _CASES]
    result = _additive_import(
        None,  # apply=False never touches the session
        zone,
        on_wire,
        {_key(r, zone.name, relative_targets=rel) for r in rows},
        apply=False,
        relative_targets=rel,
        importable_types=frozenset(c[0] for c in _CASES),
    )
    assert result.imported == 0, driver
    assert result.existing_in_db == len(_CASES)


class _Driver:
    def __init__(self, records: list[RecordData]) -> None:
        self._records = records

    async def pull_zone_records(
        self, server: Any, zone_name: str, *, tsig: Any = None
    ) -> list[RecordData]:
        return list(self._records)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("driver", "wire_idx"),
    [("bind9", 2), ("technitium_api", 2), ("route53", 3), ("cloudflare", 3)],
)
async def test_drift_converges_per_driver(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, driver: str, wire_idx: int
) -> None:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    db_session.add(
        DNSServer(
            group_id=group.id,
            name="ns1",
            driver=driver,
            host="10.0.0.53",
            port=53,
            is_enabled=True,
        )
    )
    zone = DNSZone(group_id=group.id, name=ZONE, zone_type="primary", kind="forward")
    db_session.add(zone)
    await db_session.flush()
    for t, v, _a, _c in _CASES:
        db_session.add(
            DNSRecord(zone_id=zone.id, name="www", record_type=t, value=v, **_STRUCT.get(t, {}))
        )
    await db_session.commit()

    live = [_rec(c[0], c[wire_idx]) for c in _CASES]
    monkeypatch.setattr(drift_mod, "get_driver", lambda _d: _Driver(live))
    report = await drift_mod.compute_zone_drift(db_session, group_id=group.id, zone=zone)
    s = report.servers[0]
    assert s.status == "ok", s.error
    assert s.drift_count == 0, (s.extra_on_server, s.missing_on_server)
    assert s.in_sync == len(_CASES)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("managed_driver", "stored", "wire"),
    [
        # A BIND9 managed group serves a dot-less ``a.b`` as ``a.b.<zone>.``.
        ("bind9", "a.b", "a.b.corp.example."),
        # A cloud managed group serves it as the absolute ``a.b.``: the DB side
        # is read the way the managed group reads it, not always zone-file.
        ("route53", "a.b", "a.b."),
    ],
)
async def test_cutover_parity_reads_the_db_side_by_the_managed_group(
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    managed_driver: str,
    stored: str,
    wire: str,
) -> None:
    from app.services.cutover import parity as parity_mod

    group = DNSServerGroup(name=f"m-{uuid.uuid4().hex[:6]}")
    source_group = DNSServerGroup(name=f"w-{uuid.uuid4().hex[:6]}")
    db_session.add_all([group, source_group])
    await db_session.flush()
    source = DNSServer(
        group_id=source_group.id,
        name="win-dns",
        driver="windows_dns",
        host="10.0.0.10",
        port=53,
        is_enabled=True,
    )
    db_session.add_all(
        [
            DNSServer(
                group_id=group.id,
                name="ns-managed",
                driver=managed_driver,
                host="10.0.0.53",
                port=53,
                is_enabled=True,
                is_primary=True,
            ),
            source,
        ]
    )
    zone = DNSZone(group_id=group.id, name="corp.example.", zone_type="primary", kind="forward")
    db_session.add(zone)
    await db_session.flush()
    db_session.add(DNSRecord(zone_id=zone.id, name="www", record_type="CNAME", value=stored))
    await db_session.commit()

    live = [RecordData(name="www", record_type="CNAME", value=wire)]
    monkeypatch.setattr(parity_mod, "get_dns_driver", lambda _d: _Driver(live))
    report = await parity_mod.compute_dns_parity(
        db_session, source_server=source, zone=zone, source_zone_name="corp.example"
    )
    assert report.status == "ok", report.error
    assert report.in_sync == 1, report.differences
    assert not report.differences
