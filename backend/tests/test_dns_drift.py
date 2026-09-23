"""DNS config-drift report (#61)."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns.base import RecordData
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSView, DNSZone
from app.services.dns import drift as drift_mod


class _FakeDriver:
    def __init__(self, records: list[RecordData]) -> None:
        self._records = records

    async def pull_zone_records(
        self, server: Any, zone_name: str, *, tsig: Any = None
    ) -> list[RecordData]:
        return list(self._records)


async def _group_server_zone(
    db: AsyncSession, *, server_name: str, zone_name: str
) -> tuple[DNSServerGroup, DNSServer, DNSZone]:
    # Agent-managed and keyed — the flagship BIND9 shape. Since #734 a
    # keyless agent-managed group is reported as ``unsupported`` before any
    # pull is attempted, because the transfer could only be REFUSED. These
    # tests are about categorising a diff, so give them a server that can
    # actually be transferred from; the keyless and operator-run paths are
    # covered by ``test_dns_transfer_tsig.py``.
    group = DNSServerGroup(
        name=f"g-{uuid.uuid4().hex[:6]}",
        tsig_key_name="spatium-test",
        tsig_key_secret="c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MDE=",
    )
    db.add(group)
    await db.flush()
    server = DNSServer(
        group_id=group.id,
        name=server_name,
        driver="bind9",
        host="10.0.0.53",
        port=53,
        is_enabled=True,
        agent_id=uuid.uuid4(),
    )
    db.add(server)
    zone = DNSZone(group_id=group.id, name=zone_name, zone_type="primary", kind="forward")
    db.add(zone)
    await db.flush()
    return group, server, zone


async def test_zone_drift_categorises(db_session: AsyncSession, monkeypatch: Any) -> None:
    group, _server, zone = await _group_server_zone(
        db_session, server_name="ns1", zone_name="drift.example.com."
    )
    db_session.add_all(
        [
            DNSRecord(zone_id=zone.id, name="www", record_type="A", value="10.0.0.1", ttl=300),
            DNSRecord(zone_id=zone.id, name="mail", record_type="A", value="10.0.0.2", ttl=300),
        ]
    )
    await db_session.commit()

    # Live server: www in sync, a rogue record added directly on the host,
    # mail not being served.
    live = [
        RecordData(name="www", record_type="A", value="10.0.0.1", ttl=300),
        RecordData(name="rogue", record_type="A", value="10.0.0.9", ttl=300),
    ]
    monkeypatch.setattr(drift_mod, "get_driver", lambda _d: _FakeDriver(live))

    report = await drift_mod.compute_zone_drift(db_session, group_id=group.id, zone=zone)
    assert report.db_record_count == 2
    assert len(report.servers) == 1
    s = report.servers[0]
    assert s.status == "ok"
    assert s.in_sync == 1  # www matches
    assert {(r.name, r.value) for r in s.extra_on_server} == {("rogue", "10.0.0.9")}
    assert {(r.name, r.value) for r in s.missing_on_server} == {("mail", "10.0.0.2")}
    assert s.drift_count == 2


async def test_zone_drift_pull_failure_is_surfaced(
    db_session: AsyncSession, monkeypatch: Any
) -> None:
    group, _server, zone = await _group_server_zone(
        db_session, server_name="ns-down", zone_name="down.example.com."
    )
    await db_session.commit()

    class _BoomDriver:
        async def pull_zone_records(
            self, server: Any, zone_name: str, *, tsig: Any = None
        ) -> list[RecordData]:
            raise RuntimeError("AXFR refused")

    monkeypatch.setattr(drift_mod, "get_driver", lambda _d: _BoomDriver())

    report = await drift_mod.compute_zone_drift(db_session, group_id=group.id, zone=zone)
    assert len(report.servers) == 1
    s = report.servers[0]
    assert s.status == "error"
    assert "AXFR refused" in (s.error or "")
    assert s.drift_count == 0


async def test_no_warning_for_a_plain_zone(db_session: AsyncSession, monkeypatch: Any) -> None:
    """A zone with no views must not carry the split-horizon caveat."""
    group, _server, zone = await _group_server_zone(
        db_session, server_name="ns1", zone_name="plain.example.com."
    )
    db_session.add(DNSRecord(zone_id=zone.id, name="www", record_type="A", value="10.0.0.1"))
    await db_session.commit()
    monkeypatch.setattr(drift_mod, "get_driver", lambda _d: _FakeDriver([]))

    report = await drift_mod.compute_zone_drift(db_session, group_id=group.id, zone=zone)
    assert report.warnings == []


async def test_view_scoped_zone_is_flagged(db_session: AsyncSession, monkeypatch: Any) -> None:
    """A view-scoped zone read WITHOUT addressing its view carries the caveat.

    An AXFR is addressed by zone *name*, and under split-horizon several zone
    rows share one name — so a transfer the server matches to a view by the
    control plane's address can compare this row against a different view's
    content. Report that rather than let an operator "fix" it. Since #920 an
    agent-managed server is read through the zone's own view, so the caveat
    stays only where that cannot happen — here an operator-run BIND9, which
    SpatiumDDI reaches unsigned and which authorises by address.
    """
    group, server, zone = await _group_server_zone(
        db_session, server_name="ns1", zone_name="split.example.com."
    )
    server.agent_id = None
    view = DNSView(group_id=group.id, name="internal", match_clients=["10.0.0.0/8"])
    db_session.add(view)
    await db_session.flush()
    zone.view_id = view.id
    await db_session.commit()
    monkeypatch.setattr(drift_mod, "get_driver", lambda _d: _FakeDriver([]))

    report = await drift_mod.compute_zone_drift(db_session, group_id=group.id, zone=zone)
    assert len(report.warnings) == 1
    assert "view" in report.warnings[0].lower()
    assert "ns1" in report.warnings[0]


async def test_view_addressed_transfer_carries_no_view_caveat(
    db_session: AsyncSession, monkeypatch: Any
) -> None:
    """#920: an agent-managed server's transfer is signed with the zone's own
    view key, so the server answers from that view — the caveat would be
    telling the operator to distrust a comparison that is exactly right."""
    group, _server, zone = await _group_server_zone(
        db_session, server_name="ns1", zone_name="split.example.com."
    )
    view = DNSView(group_id=group.id, name="internal", match_clients=["10.0.0.0/8"])
    db_session.add(view)
    await db_session.flush()
    zone.view_id = view.id
    await db_session.commit()
    monkeypatch.setattr(drift_mod, "get_driver", lambda _d: _FakeDriver([]))

    report = await drift_mod.compute_zone_drift(db_session, group_id=group.id, zone=zone)
    assert [s.status for s in report.servers] == ["ok"]
    assert report.warnings == []


async def test_view_scoped_records_are_flagged(db_session: AsyncSession, monkeypatch: Any) -> None:
    """Records pinned to a view aren't served to every client — say so."""
    group, _server, zone = await _group_server_zone(
        db_session, server_name="ns1", zone_name="partial.example.com."
    )
    view = DNSView(group_id=group.id, name="internal", match_clients=["10.0.0.0/8"])
    db_session.add(view)
    await db_session.flush()
    db_session.add(
        DNSRecord(
            zone_id=zone.id, view_id=view.id, name="secret", record_type="A", value="10.0.0.7"
        )
    )
    await db_session.commit()
    monkeypatch.setattr(drift_mod, "get_driver", lambda _d: _FakeDriver([]))

    report = await drift_mod.compute_zone_drift(db_session, group_id=group.id, zone=zone)
    assert len(report.warnings) == 1
    assert "scoped to a specific DNS view" in report.warnings[0]
