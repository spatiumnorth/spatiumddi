"""DNS config-drift report (#61)."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
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
        tsig_key_secret_encrypted=encrypt_str("c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MDE="),
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
    assert (
        s.status == "behind"
    )  # a record missing + one extra: not serving the zone as saved (#3198)
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


# ── The agent's own NS glue is not drift (found fixing #920) ────────────────
#
# The BIND9 agent writes ``ns1 IN A 127.0.0.1`` into every primary zone file,
# beside the apex ``NS ns1.<zone>`` it also writes, so BIND will load a zone
# whose NS names an in-zone host. Nobody created that record. Before the
# transfer worked on the QA seed (#920) nobody saw a real comparison; once it
# did, every agent-managed zone reported ``ns1 A 127.0.0.1`` as extra on the
# server, so no zone could ever read in sync.

_AGENT_GLUE = RecordData(name="ns1", record_type="A", value="127.0.0.1", ttl=3600)
_WWW = RecordData(name="www", record_type="A", value="10.0.0.1", ttl=3600)


async def test_the_agents_own_ns_glue_is_not_drift(
    db_session: AsyncSession, monkeypatch: Any
) -> None:
    group, _server, zone = await _group_server_zone(
        db_session, server_name="ns1", zone_name="glue.example.com."
    )
    db_session.add(DNSRecord(zone_id=zone.id, name="www", record_type="A", value="10.0.0.1"))
    await db_session.commit()
    monkeypatch.setattr(drift_mod, "get_driver", lambda _d: _FakeDriver([_WWW, _AGENT_GLUE]))

    report = await drift_mod.compute_zone_drift(db_session, group_id=group.id, zone=zone)

    (s,) = report.servers
    assert s.status == "ok"
    assert (s.drift_count, s.in_sync) == (0, 1)


async def test_ns_glue_on_an_operator_run_bind9_is_still_reported(
    db_session: AsyncSession, monkeypatch: Any
) -> None:
    """Only the agent adds that record. On a server SpatiumDDI never
    configured, the same record is whatever the operator put there."""
    group, server, zone = await _group_server_zone(
        db_session, server_name="ns1", zone_name="glue-op.example.com."
    )
    server.agent_id = None
    await db_session.commit()
    monkeypatch.setattr(drift_mod, "get_driver", lambda _d: _FakeDriver([_AGENT_GLUE]))

    report = await drift_mod.compute_zone_drift(db_session, group_id=group.id, zone=zone)

    (s,) = report.servers
    assert [(r.name, r.record_type, r.value) for r in s.extra_on_server] == [
        ("ns1", "A", "127.0.0.1")
    ]


async def test_ns_glue_the_db_really_holds_is_compared_like_any_record(
    db_session: AsyncSession, monkeypatch: Any
) -> None:
    """If somebody did create ``ns1 A 127.0.0.1``, it is a record like any
    other: served, and counted in sync — not hidden into 'missing'."""
    group, _server, zone = await _group_server_zone(
        db_session, server_name="ns1", zone_name="glue-db.example.com."
    )
    db_session.add(DNSRecord(zone_id=zone.id, name="ns1", record_type="A", value="127.0.0.1"))
    await db_session.commit()
    monkeypatch.setattr(drift_mod, "get_driver", lambda _d: _FakeDriver([_AGENT_GLUE]))

    report = await drift_mod.compute_zone_drift(db_session, group_id=group.id, zone=zone)

    (s,) = report.servers
    assert (s.drift_count, s.in_sync) == (0, 1)


# ── MX / SRV structured fields are part of the identity (#1525) ─────────────
#
# MX priority and SRV priority/weight/port live in their own columns, not
# in the value, so a (name, type, value) key treated an out-of-band
# priority edit on the server as "in sync" — drift never reported it and
# sync never corrected it.


async def test_zone_drift_reports_mx_priority_only_difference(
    db_session: AsyncSession, monkeypatch: Any
) -> None:
    group, _server, zone = await _group_server_zone(
        db_session, server_name="ns1", zone_name="mxdrift.example.com."
    )
    db_session.add(
        DNSRecord(
            zone_id=zone.id,
            name="@",
            record_type="MX",
            value="mail.example.com.",
            ttl=300,
            priority=10,
        )
    )
    await db_session.commit()

    # Same name, type and target on the wire — only the preference changed.
    live = [RecordData(name="@", record_type="MX", value="mail.example.com.", ttl=300, priority=20)]
    monkeypatch.setattr(drift_mod, "get_driver", lambda _d: _FakeDriver(live))

    report = await drift_mod.compute_zone_drift(db_session, group_id=group.id, zone=zone)
    (s,) = report.servers
    assert s.status == "behind"  # transferred; a different-priority MX is missing + extra (#3198)
    assert s.in_sync == 0
    assert [(r.record_type, r.priority) for r in s.extra_on_server] == [("MX", 20)]
    assert [(r.record_type, r.priority) for r in s.missing_on_server] == [("MX", 10)]
    assert s.drift_count == 2


async def test_zone_drift_reports_srv_port_only_difference(
    db_session: AsyncSession, monkeypatch: Any
) -> None:
    group, _server, zone = await _group_server_zone(
        db_session, server_name="ns1", zone_name="srvdrift.example.com."
    )
    db_session.add(
        DNSRecord(
            zone_id=zone.id,
            name="_sip._tcp",
            record_type="SRV",
            value="sip.example.com.",
            ttl=300,
            priority=10,
            weight=20,
            port=5060,
        )
    )
    await db_session.commit()

    live = [
        RecordData(
            name="_sip._tcp",
            record_type="SRV",
            value="sip.example.com.",
            ttl=300,
            priority=10,
            weight=20,
            port=5061,
        )
    ]
    monkeypatch.setattr(drift_mod, "get_driver", lambda _d: _FakeDriver(live))

    report = await drift_mod.compute_zone_drift(db_session, group_id=group.id, zone=zone)
    (s,) = report.servers
    assert s.in_sync == 0
    assert [(r.record_type, r.port) for r in s.extra_on_server] == [("SRV", 5061)]
    assert [(r.record_type, r.port) for r in s.missing_on_server] == [("SRV", 5060)]


def test_key_ignores_struct_fields_for_other_types() -> None:
    from app.services.dns.pull_from_server import _key

    a = RecordData(name="www", record_type="A", value="10.0.0.1")
    assert _key(a, "example.com.", relative_targets=True) == (
        "www",
        "A",
        "10.0.0.1",
        None,
        None,
        None,
    )
    mx = RecordData(name="@", record_type="MX", value="mail.example.com.", priority=10)
    assert _key(mx, "example.com.", relative_targets=True) == (
        "@",
        "MX",
        "mail.example.com.",
        10,
        None,
        None,
    )


class _ApexNsDriver(_FakeDriver):
    """An AXFR driver that, like BIND9 and the agent Technitium driver, keeps
    the apex NS only when asked (#1857); records whether it was asked."""

    pull_can_include_apex_ns = True

    def __init__(self, records: list[RecordData]) -> None:
        super().__init__(records)
        self.asked: list[bool] = []

    async def pull_zone_records(
        self, server: Any, zone_name: str, *, tsig: Any = None, include_apex_ns: bool = False
    ) -> list[RecordData]:
        self.asked.append(include_apex_ns)
        return [
            r
            for r in self._records
            if include_apex_ns or not (r.record_type == "NS" and r.name == "@")
        ]


async def _imported_zone(db: AsyncSession, apex_ns: list[str]) -> tuple[Any, Any, DNSZone]:
    group, server, zone = await _group_server_zone(
        db, server_name="ns1", zone_name="imp.example.com."
    )
    db.add_all(
        [DNSRecord(zone_id=zone.id, name="@", record_type="NS", value=v, ttl=3600) for v in apex_ns]
        + [
            DNSRecord(zone_id=zone.id, name="www", record_type="A", value="10.0.0.1", ttl=300),
            # A delegation below the apex is an ordinary record, always compared.
            DNSRecord(zone_id=zone.id, name="sub", record_type="NS", value="ns.sub.", ttl=300),
        ]
    )
    await db.commit()
    return group, server, zone


_WWW = RecordData(name="www", record_type="A", value="10.0.0.1", ttl=300)
_SUB = RecordData(name="sub", record_type="NS", value="ns.sub.", ttl=300)


async def test_agent_served_apex_ns_matching_the_zone_is_in_sync(
    db_session: AsyncSession, monkeypatch: Any
) -> None:
    """#1857 — the agent serves a zone's apex NS rows as its NS set, so an
    imported ``@ NS`` it serves is in sync, not "missing on server"."""
    group, _server, zone = await _imported_zone(db_session, ["tech.lan."])
    live = [RecordData(name="@", record_type="NS", value="tech.lan.", ttl=3600), _WWW, _SUB]
    driver = _ApexNsDriver(live)
    monkeypatch.setattr(drift_mod, "get_driver", lambda _d: driver)

    report = await drift_mod.compute_zone_drift(db_session, group_id=group.id, zone=zone)
    s = report.servers[0]
    assert driver.asked == [True]
    assert s.missing_on_server == []
    assert s.extra_on_server == []
    assert s.in_sync == 3


async def test_agent_served_apex_ns_changed_on_the_server_is_drift(
    db_session: AsyncSession, monkeypatch: Any
) -> None:
    """An NS set changed on the server (or an NS change the agent never
    applied) is real drift and must show, on both sides."""
    group, _server, zone = await _imported_zone(db_session, ["ns-a.example.net."])
    live = [
        RecordData(name="@", record_type="NS", value="ns-b.example.net.", ttl=3600),
        _WWW,
        _SUB,
    ]
    monkeypatch.setattr(drift_mod, "get_driver", lambda _d: _ApexNsDriver(live))

    report = await drift_mod.compute_zone_drift(db_session, group_id=group.id, zone=zone)
    s = report.servers[0]
    assert [(r.name, r.value) for r in s.missing_on_server] == [("@", "ns-a.example.net.")]
    assert [(r.name, r.value) for r in s.extra_on_server] == [("@", "ns-b.example.net.")]


async def test_server_own_apex_ns_is_not_drift_when_the_zone_declares_none(
    db_session: AsyncSession, monkeypatch: Any
) -> None:
    """A zone with no apex NS rows is served the agent's ``primary_ns`` or
    placeholder NS: that is the server's own, not a difference."""
    group, _server, zone = await _imported_zone(db_session, [])
    live = [
        RecordData(name="@", record_type="NS", value="ns1.imp.example.com.", ttl=3600),
        RecordData(name="ns1", record_type="A", value="127.0.0.1", ttl=3600),
        _WWW,
        _SUB,
    ]
    monkeypatch.setattr(drift_mod, "get_driver", lambda _d: _ApexNsDriver(live))

    report = await drift_mod.compute_zone_drift(db_session, group_id=group.id, zone=zone)
    s = report.servers[0]
    assert s.extra_on_server == []
    assert s.missing_on_server == []


async def test_stored_apex_ns_is_not_reported_missing(
    db_session: AsyncSession, monkeypatch: Any
) -> None:
    """#1857 — a read that cannot carry the apex NS (an AXFR of a server that
    does not render the zone's NS rows) must not report the stored apex NS
    row missing forever. A delegation below the apex still counts."""
    group, server, zone = await _imported_zone(db_session, ["tech.lan."])
    server.agent_id = None  # an operator's own BIND9: the NS set is not ours
    await db_session.commit()
    driver = _ApexNsDriver(
        [RecordData(name="@", record_type="NS", value="other.lan.", ttl=3600), _WWW]
    )
    monkeypatch.setattr(drift_mod, "get_driver", lambda _d: driver)

    report = await drift_mod.compute_zone_drift(db_session, group_id=group.id, zone=zone)
    s = report.servers[0]
    assert driver.asked == [False]
    assert [(r.name, r.record_type) for r in s.missing_on_server] == [("sub", "NS")]
    assert s.extra_on_server == []
    assert s.in_sync == 1


# ── #3198 — "ok" means transferred AND serving the zone as saved ──────────────


async def _with_state(
    db: AsyncSession,
    server: DNSServer,
    zone: DNSZone,
    *,
    current: int,
    target: int,
    age_s: int = 600,
) -> None:
    from datetime import UTC, datetime, timedelta

    from app.models.dns import DNSServerZoneState

    zone.last_serial = target
    zone.modified_at = datetime.now(UTC) - timedelta(seconds=age_s)
    db.add(DNSServerZoneState(server_id=server.id, zone_id=zone.id, current_serial=current))
    await db.commit()


async def _one(db: AsyncSession, group: DNSServerGroup, zone: DNSZone, live: list[RecordData], mp):
    mp.setattr(drift_mod, "get_driver", lambda _d: _FakeDriver(live))
    report = await drift_mod.compute_zone_drift(db, group_id=group.id, zone=zone)
    return report.servers[0]


async def test_transfer_ok_but_records_missing_is_behind(
    db_session: AsyncSession, monkeypatch: Any
) -> None:
    group, server, zone = await _group_server_zone(
        db_session, server_name="ns1", zone_name="behind.example.com."
    )
    db_session.add(DNSRecord(zone_id=zone.id, name="www", record_type="A", value="10.0.0.1"))
    await _with_state(db_session, server, zone, current=5, target=5)
    s = await _one(db_session, group, zone, [], monkeypatch)
    assert s.status == "behind"
    assert "1 saved record not being served" in (s.reason or "")


async def test_serial_below_target_is_behind_even_with_every_record_present(
    db_session: AsyncSession, monkeypatch: Any
) -> None:
    group, server, zone = await _group_server_zone(
        db_session, server_name="ns1", zone_name="serial.example.com."
    )
    db_session.add(DNSRecord(zone_id=zone.id, name="www", record_type="A", value="10.0.0.1"))
    await _with_state(db_session, server, zone, current=4, target=5)
    live = [RecordData(name="www", record_type="A", value="10.0.0.1", ttl=300)]
    s = await _one(db_session, group, zone, live, monkeypatch)
    assert s.status == "behind"
    assert (s.current_serial, s.target_serial) == (4, 5)
    assert "below the zone's 5" in (s.reason or "")


async def test_serial_below_target_within_the_grace_window_is_not_flagged(
    db_session: AsyncSession, monkeypatch: Any
) -> None:
    group, server, zone = await _group_server_zone(
        db_session, server_name="ns1", zone_name="fresh.example.com."
    )
    db_session.add(DNSRecord(zone_id=zone.id, name="www", record_type="A", value="10.0.0.1"))
    await _with_state(db_session, server, zone, current=4, target=5, age_s=5)
    live = [RecordData(name="www", record_type="A", value="10.0.0.1", ttl=300)]
    s = await _one(db_session, group, zone, live, monkeypatch)
    assert s.status == "ok"


async def test_complete_and_at_target_is_ok(db_session: AsyncSession, monkeypatch: Any) -> None:
    group, server, zone = await _group_server_zone(
        db_session, server_name="ns1", zone_name="ok.example.com."
    )
    db_session.add(DNSRecord(zone_id=zone.id, name="www", record_type="A", value="10.0.0.1"))
    await _with_state(db_session, server, zone, current=5, target=5)
    live = [RecordData(name="www", record_type="A", value="10.0.0.1", ttl=300)]
    s = await _one(db_session, group, zone, live, monkeypatch)
    assert s.status == "ok"
    assert s.reason is None


async def test_extra_records_only_is_drift_not_ok(
    db_session: AsyncSession, monkeypatch: Any
) -> None:
    group, server, zone = await _group_server_zone(
        db_session, server_name="ns1", zone_name="extra.example.com."
    )
    db_session.add(DNSRecord(zone_id=zone.id, name="www", record_type="A", value="10.0.0.1"))
    await _with_state(db_session, server, zone, current=5, target=5)
    live = [
        RecordData(name="www", record_type="A", value="10.0.0.1", ttl=300),
        RecordData(name="rogue", record_type="A", value="10.0.0.9", ttl=300),
    ]
    s = await _one(db_session, group, zone, live, monkeypatch)
    assert s.status == "drift"


async def test_transfer_failure_stays_error_not_behind(
    db_session: AsyncSession, monkeypatch: Any
) -> None:
    group, server, zone = await _group_server_zone(
        db_session, server_name="ns1", zone_name="err.example.com."
    )
    await _with_state(db_session, server, zone, current=1, target=5)

    class _Boom:
        async def pull_zone_records(self, *a: Any, **k: Any) -> list[RecordData]:
            raise RuntimeError("AXFR refused")

    monkeypatch.setattr(drift_mod, "get_driver", lambda _d: _Boom())
    report = await drift_mod.compute_zone_drift(db_session, group_id=group.id, zone=zone)
    assert report.servers[0].status == "error"
