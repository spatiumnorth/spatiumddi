"""#1774 / #1779 — technitium_api writes the zone's SOA, apex NS and serial.

Fake-client tests over the driver's real request sequence (what is SENT to
Technitium), the route that drives it, and the serial the sync pill judges.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns._cloud_base import CloudDNSError
from app.drivers.dns.technitium_api import TechnitiumAPIDriver
from app.models.dns import DNSRecord, DNSServerZoneState, DNSZone
from app.services.dns.drift import zone_state_in_sync
from app.services.technitium.apex import zone_apex
from tests.test_dns_driver_technitium_api import _driver, _ok, _Server
from tests.test_technitium_api_scope_1784 import _group, _h, _token, _zone

_SRV = _Server({"api_url": "https://x.test", "api_token": "t"})
_ZONE = "example.com"


def _soa(serial: int, *, mname: str = "dns-host", rname: str = "hostadmin@example.com") -> Any:
    return {
        "name": _ZONE,
        "type": "SOA",
        "ttl": 900,
        "rData": {
            "primaryNameServer": mname,
            "responsiblePerson": rname,
            "serial": serial,
            "refresh": 900,
            "retry": 300,
            "expire": 604800,
            "minimum": 900,
        },
    }


def _ns(target: str, ttl: int = 3600) -> Any:
    return {"name": _ZONE, "type": "NS", "ttl": ttl, "rData": {"nameServer": target}}


def _read(*records: Any) -> Any:
    return _ok({"zone": {"name": _ZONE}, "records": list(records)})


def _apex(**kw: Any) -> dict[str, Any]:
    zone = {
        "primary_ns": "ns1.example.com.",
        "admin_email": "hostmaster.example.com.",
        "ttl": 3600,
        "refresh": 7200,
        "retry": 900,
        "expire": 1209600,
        "minimum": 300,
        "records": [],
    }
    zone.update(kw)
    apex = zone_apex(_ZONE, zone)
    assert apex is not None
    return apex


def _paths(fake: Any) -> list[str]:
    return [c["path"].removeprefix("/api/") for c in fake.calls]


def _sent(fake: Any, path: str) -> list[dict[str, Any]]:
    return [c["params"] for c in fake.calls if c["path"] == f"/api/{path}"]


@pytest.mark.asyncio
async def test_soa_and_apex_ns_are_written_from_the_zone(monkeypatch: pytest.MonkeyPatch) -> None:
    drv, fake = _driver(
        monkeypatch,
        [
            _read(_soa(1), _ns("dns-host")),
            _ok({}),  # SOA update
            _ok({}),  # NS add
            _ok({}),  # NS delete of the daemon's own
            _read(_soa(2)),
        ],
    )
    await drv.apply_zone_apex(_SRV, "example.com.", _apex())
    soa = _sent(fake, "zones/records/update")[0]
    assert soa["type"] == "SOA"
    assert soa["primaryNameServer"] == "ns1.example.com"
    assert soa["responsiblePerson"] == "hostmaster@example.com"
    assert (soa["refresh"], soa["retry"], soa["expire"], soa["minimum"]) == (
        7200,
        900,
        1209600,
        300,
    )
    assert soa["ttl"] == 3600
    assert _sent(fake, "zones/records/add")[0]["nameServer"] == "ns1.example.com"
    assert _sent(fake, "zones/records/delete")[0]["nameServer"] == "dns-host"
    # The new name server is in before the old one goes.
    assert _paths(fake).index("zones/records/add") < _paths(fake).index("zones/records/delete")


@pytest.mark.asyncio
async def test_a_zone_behind_ours_is_raised_to_our_serial(monkeypatch: pytest.MonkeyPatch) -> None:
    """Technitium adopts a SOA serial that is higher than its own."""
    apex = _apex()
    current = _soa(
        1,
        mname="ns1.example.com",
        rname="hostmaster@example.com",
    )
    current["rData"].update(refresh=7200, retry=900, expire=1209600, minimum=300)
    current["ttl"] = 3600
    drv, fake = _driver(
        monkeypatch, [_read(current, _ns("ns1.example.com")), _ok({}), _read(_soa(50))]
    )
    served = await drv.apply_zone_apex(_SRV, "example.com.", apex, serial=50)
    assert [p["serial"] for p in _sent(fake, "zones/records/update")] == [50]
    assert served == 50


@pytest.mark.asyncio
async def test_a_zone_ahead_of_ours_is_not_rewritten(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every SOA write bumps the serial, so a converged apex is left alone."""
    current = _soa(143, mname="ns1.example.com", rname="hostmaster@example.com")
    current["rData"].update(refresh=7200, retry=900, expire=1209600, minimum=300)
    current["ttl"] = 3600
    drv, fake = _driver(monkeypatch, [_read(current, _ns("ns1.example.com")), _read(current)])
    served = await drv.apply_zone_apex(_SRV, "example.com.", _apex(), serial=50)
    assert _paths(fake) == ["zones/records/get", "zones/records/get"]
    assert served == 143


@pytest.mark.asyncio
async def test_the_returned_serial_is_read_back_not_the_one_asked_for(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    drv, _ = _driver(
        monkeypatch,
        [_read(_soa(1), _ns("dns-host")), _ok({}), _ok({}), _ok({}), _read(_soa(7))],
    )
    assert await drv.apply_zone_apex(_SRV, "example.com.", _apex(), serial=500) == 7


@pytest.mark.asyncio
async def test_an_unreadable_serial_is_none_not_a_guess(monkeypatch: pytest.MonkeyPatch) -> None:
    drv, _ = _driver(
        monkeypatch,
        [
            _read(_soa(1), _ns("dns-host")),
            _ok({}),
            _ok({}),
            _ok({}),
            _FakeError(),
        ],
    )
    assert await drv.apply_zone_apex(_SRV, "example.com.", _apex(), serial=500) is None


class _FakeError:
    """A response that is not a Technitium envelope."""

    status_code = 502

    def json(self) -> Any:
        return {}


@pytest.mark.asyncio
async def test_a_missing_zone_is_refused_before_any_write(monkeypatch: pytest.MonkeyPatch) -> None:
    """``zone=`` resolves to the enclosing zone when the zone is absent."""
    drv, fake = _driver(monkeypatch, [_ok({"zone": {"name": "com"}, "records": []})])
    with pytest.raises(CloudDNSError, match="not found on the server"):
        await drv.apply_zone_apex(_SRV, "example.com.", _apex(), serial=5)
    assert _paths(fake) == ["zones/records/get"]


def test_a_zone_that_sets_nothing_leaves_the_apex_alone() -> None:
    assert zone_apex(_ZONE, {"records": [], "ttl": 3600, "refresh": 7200}) is None


# ── the routes ──────────────────────────────────────────────────────────


@pytest.fixture()
def driver_mocks(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    m = SimpleNamespace(
        zone=AsyncMock(return_value=True),
        apex=AsyncMock(return_value=41),
    )
    monkeypatch.setattr(TechnitiumAPIDriver, "apply_zone_change", m.zone)
    monkeypatch.setattr(TechnitiumAPIDriver, "apply_zone_apex", m.apex)
    return m


@pytest.mark.asyncio
async def test_create_writes_the_apex_and_records_the_served_serial(
    client: AsyncClient, db_session: AsyncSession, driver_mocks: SimpleNamespace
) -> None:
    t = await _token(db_session)
    g = await _group(db_session, "technitium_api")
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{g.id}/zones",
        headers=_h(t),
        json={
            "name": "apex.example.com.",
            "primary_ns": "ns1.apex.example.com.",
            "admin_email": "hostmaster.apex.example.com.",
            "refresh": 7200,
        },
    )
    assert r.status_code == 201, r.text
    assert driver_mocks.apex.await_count == 1
    args = driver_mocks.apex.await_args
    apex = args.args[2]
    assert apex["soa"]["primaryNameServer"] == "ns1.apex.example.com"
    assert apex["soa"]["refresh"] == 7200
    assert apex["ns"] == ["ns1.apex.example.com"]
    # The serial the server answered with is what the sync state holds.
    state = (await db_session.execute(select(DNSServerZoneState))).scalar_one()
    assert state.current_serial == 41


@pytest.mark.asyncio
async def test_a_refused_apex_fails_the_create_and_removes_the_zone(
    client: AsyncClient, db_session: AsyncSession, driver_mocks: SimpleNamespace
) -> None:
    driver_mocks.apex.side_effect = CloudDNSError("Technitium rejected the SOA update")
    t = await _token(db_session)
    g = await _group(db_session, "technitium_api")
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{g.id}/zones",
        headers=_h(t),
        json={"name": "refused.example.com.", "primary_ns": "ns1.example.com."},
    )
    assert r.status_code == 502, r.text
    assert "rejected the SOA update" in r.text
    ops = [c.args[2] for c in driver_mocks.zone.await_args_list]
    assert ops == ["create", "delete"]


@pytest.mark.asyncio
async def test_update_writes_a_changed_soa_and_refuses_when_the_server_does(
    client: AsyncClient, db_session: AsyncSession, driver_mocks: SimpleNamespace
) -> None:
    t = await _token(db_session)
    g = await _group(db_session, "technitium_api")
    z = await _zone(db_session, g)
    db_session.add(
        DNSRecord(
            zone_id=z.id,
            name="@",
            fqdn=z.name.rstrip("."),
            record_type="NS",
            value="ns2.example.com.",
            ttl=600,
        )
    )
    await db_session.commit()
    url = f"/api/v1/dns/groups/{g.id}/zones/{z.id}"
    r = await client.put(
        url, headers=_h(t), json={"admin_email": "ops.example.com.", "refresh": 5000}
    )
    assert r.status_code == 200, r.text
    apex = driver_mocks.apex.await_args.args[2]
    assert apex["soa"]["responsiblePerson"] == "ops@example.com"
    assert apex["soa"]["refresh"] == 5000
    assert apex["ns"] == ["ns2.example.com"]
    # An edit that does not touch the SOA sends nothing.
    driver_mocks.apex.reset_mock()
    assert (await client.put(url, headers=_h(t), json={"color": "red"})).status_code == 200
    assert driver_mocks.apex.await_count == 0
    # A server that refuses the change leaves the row as it was.
    driver_mocks.apex.side_effect = CloudDNSError("boom")
    bad = await client.put(url, headers=_h(t), json={"refresh": 4000})
    assert bad.status_code == 502, bad.text
    assert "not saved" in bad.text


# ── what the sync pill calls converged ──────────────────────────────────


@pytest.mark.parametrize("driver", ["technitium", "technitium_api"])
def test_technitium_is_in_sync_at_or_past_our_serial_never_below(driver: str) -> None:
    zone = DNSZone(id=uuid.uuid4(), name="z.", group_id=uuid.uuid4(), zone_type="primary")
    assert zone_state_in_sync(zone, 143, 50, driver)
    assert zone_state_in_sync(zone, 50, 50, driver)
    assert not zone_state_in_sync(zone, 1, 50, driver)
    # Every other driver still has to serve exactly ours.
    assert not zone_state_in_sync(zone, 143, 50, "bind9")
