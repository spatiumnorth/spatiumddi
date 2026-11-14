"""The drift report flags a locked DNS record whose live value differs (#3361)."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns.base import RecordData
from app.models.dns import DNSRecord
from app.services.dns import drift as drift_mod
from tests.test_dns_drift import _FakeDriver, _group_server_zone, _settle


@pytest.mark.asyncio
async def test_drift_flags_a_locked_record_whose_live_value_differs(
    db_session: AsyncSession, monkeypatch: Any
) -> None:
    from datetime import UTC, datetime

    group, _server, zone = await _group_server_zone(
        db_session, server_name="ns1", zone_name="locked.example.com."
    )
    locked = DNSRecord(zone_id=zone.id, name="www", record_type="A", value="10.0.0.1", ttl=300)
    locked.lock_level = "edit"
    locked.locked_by = "alice"
    locked.lock_reason = "audit hold"
    locked.locked_at = datetime.now(UTC)
    plain = DNSRecord(zone_id=zone.id, name="mail", record_type="A", value="10.0.0.2", ttl=300)
    db_session.add_all([locked, plain])
    _settle(zone)
    await db_session.commit()

    # Someone changed both on the host; only the locked one is flagged as such.
    live = [
        RecordData(name="www", record_type="A", value="10.9.9.9", ttl=300),
        RecordData(name="mail", record_type="A", value="10.9.9.8", ttl=300),
    ]
    monkeypatch.setattr(drift_mod, "get_driver", lambda _d: _FakeDriver(live))
    report = await drift_mod.compute_zone_drift(db_session, group_id=group.id, zone=zone)
    (s,) = report.servers
    assert len(s.locked_differs) == 1
    d = s.locked_differs[0]
    assert (d.name, d.value, d.live_values) == ("www", "10.0.0.1", ["10.9.9.9"])
    assert (d.lock_level, d.locked_by, d.lock_reason) == ("edit", "alice", "audit hold")

    # A locked record that matches the server is not flagged.
    live = [
        RecordData(name="www", record_type="A", value="10.0.0.1", ttl=300),
        RecordData(name="mail", record_type="A", value="10.0.0.2", ttl=300),
    ]
    monkeypatch.setattr(drift_mod, "get_driver", lambda _d: _FakeDriver(live))
    report = await drift_mod.compute_zone_drift(db_session, group_id=group.id, zone=zone)
    assert report.servers[0].locked_differs == []
