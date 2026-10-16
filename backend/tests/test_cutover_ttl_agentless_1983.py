"""#1983 — the cutover TTL pre-flight must not collapse a multi-value RRset on
an agentless driver.

``_ttl_ops`` sends the first record of a ``(name, type)`` group as a plain
``update`` and its siblings as ``update`` + ``rrset_action="add"``, and the
``add`` ones opt out of #773 stamping. ``RecordChange`` has no
``rrset_action``, so an agentless driver saw each unstamped sibling as a
single-value replace and the last value written won: a 3-address round-robin
name kept one address.

These tests run the REAL path — ``_ttl_ops`` -> ``enqueue_record_ops_batch``
-> the ``RecordChange`` the dispatcher builds — and then hand each change to
the real request builder of every agentless driver, asserting on what would
go on the wire. A 3-value A name must keep all 3 at the new TTL. They call
``enqueue_record_ops_batch`` directly: the pre-flight itself refuses an
agentless primary, so these pin the mechanism, and the last two tests pin
reachability (the pre-flight never reaches an agentless server) and the one
path that did reach one (a pool TTL change).
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns.base import RecordChange
from app.drivers.dns.cloudflare import CloudflareDNSDriver
from app.drivers.dns.route53 import Route53DNSDriver
from app.services.cutover.preflight import _ttl_ops
from app.services.dns.record_ops import enqueue_record_ops_batch
from tests.test_dns_agentless_rrset import _batch_payload
from tests.test_dns_cloudflare import _CREDS as CF_CREDS
from tests.test_dns_cloudflare import _env, _FakeClient, _FakeResponse, _Server
from tests.test_dns_route53 import CREDS as R53_CREDS
from tests.test_dns_route53 import _server as r53_server
from tests.test_dns_rrset_ops import _add_record, _group_and_zone, _RecordingDriver

VALUES = {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
NEW_TTL = 60


async def _preflight_changes(
    db: AsyncSession, monkeypatch: pytest.MonkeyPatch, driver: str
) -> list[RecordChange]:
    """The RecordChanges the dispatcher hands an agentless driver for a TTL
    rewrite of a 3-value round-robin name, built the way the pre-flight does."""
    _grp, _server, zone = await _group_and_zone(db, driver=driver)
    recs = [await _add_record(db, zone, name="rr", value=v, ttl=3600) for v in sorted(VALUES)]
    await db.commit()

    recorder = _RecordingDriver()
    monkeypatch.setattr("app.services.dns.record_ops.get_driver", lambda _name: recorder)

    for rec in recs:  # the pre-flight rewrites the rows, then queues the ops
        rec.ttl = NEW_TTL
    ops = _ttl_ops(recs, zone)
    await enqueue_record_ops_batch(db, zone, ops)
    await db.commit()
    assert len(recorder.full_changes) == 3
    return list(recorder.full_changes)


async def test_every_op_reaches_the_driver_with_the_whole_set(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    changes = await _preflight_changes(db_session, monkeypatch, "windows_dns")
    for c in changes:
        assert c.rrset is not None, "a sibling reached the driver as a single-value replace"
        assert {m.value for m in c.rrset.members} == VALUES
        assert c.rrset.ttl == NEW_TTL


async def test_windows_winrm_batch_keeps_all_three(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.drivers.dns.windows import _ps_apply_record, _ps_apply_record_batch

    changes = await _preflight_changes(db_session, monkeypatch, "windows_dns")
    for op in _batch_payload(_ps_apply_record_batch(changes)):
        assert {m["v"] for m in op["m"]} == VALUES
    for c in changes:
        script = _ps_apply_record(c)
        assert script.count("Add-DnsServerResourceRecordA") == 3
        assert (
            f"-TimeToLive ([TimeSpan]::FromSeconds({NEW_TTL}))" in script or str(NEW_TTL) in script
        )


async def test_windows_rfc2136_keeps_all_three(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    import dns.query

    from app.drivers.dns import windows

    changes = await _preflight_changes(db_session, monkeypatch, "windows_dns")
    sent: list[Any] = []
    monkeypatch.setattr(windows, "resolve_server_address", lambda *a, **k: ["192.0.2.53"])
    monkeypatch.setattr(dns.query, "tcp", lambda msg, *a, **k: sent.append(msg))
    server = SimpleNamespace(id="s1", host="dc1.example.com", api_port=53)
    for c in changes:
        await windows.WindowsDNSDriver().apply_record_change(server, c)
    assert len(sent) == 3
    for msg in sent:
        # ``replace`` is a delete-RRset (class ANY, empty) then the adds.
        adds = [r for r in msg.update if len(r)]
        assert {str(x) for r in adds for x in r} == VALUES
        assert all(r.ttl == NEW_TTL for r in adds)


async def test_route53_keeps_all_three(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from unittest.mock import MagicMock

    changes = await _preflight_changes(db_session, monkeypatch, "route53")
    driver = Route53DNSDriver()
    client = MagicMock()
    client.list_hosted_zones_by_name.return_value = {
        "HostedZones": [{"Id": "/hostedzone/Z1", "Name": changes[0].zone_name}]
    }
    monkeypatch.setattr(driver, "_client", lambda creds: client)
    for c in changes:
        await driver._apply_record(r53_server(), R53_CREDS, c)
    calls = client.change_resource_record_sets.call_args_list
    assert len(calls) == 3
    for call in calls:
        rrset = call.kwargs["ChangeBatch"]["Changes"][0]["ResourceRecordSet"]
        assert {v["Value"] for v in rrset["ResourceRecords"]} == VALUES
        assert rrset["TTL"] == NEW_TTL


async def test_google_keeps_all_three(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.test_dns_google_dns import (
        CREDS,
        GoogleCloudDNSDriver,
        _client_with_zones,
        _server,
        _StubZone,
    )

    changes = await _preflight_changes(db_session, monkeypatch, "google_dns")
    driver = GoogleCloudDNSDriver()
    zone = _StubZone("zone", changes[0].zone_name)
    monkeypatch.setattr(driver, "_client", lambda creds: _client_with_zones(zone))
    for c in changes:
        await driver._apply_record(_server(), CREDS, c)
    assert len(zone.built_rrsets) == 3
    for _name, rtype, ttl, values in zone.built_rrsets:
        assert rtype == "A" and ttl == NEW_TTL
        assert set(values) == VALUES


async def test_azure_keeps_all_three(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace
    from unittest.mock import Mock

    from tests.test_dns_azure_dns import _CREDS, AzureDNSDriver

    changes = await _preflight_changes(db_session, monkeypatch, "azure_dns")
    driver = AzureDNSDriver()
    client = Mock()
    monkeypatch.setattr(driver, "_client", lambda creds: client)
    server = SimpleNamespace(id="srv-1", name="azure-1", credentials_encrypted=b"blob")
    for c in changes:
        await driver._apply_record(server, dict(_CREDS), c)
    calls = client.record_sets.create_or_update.call_args_list
    assert len(calls) == 3
    for call in calls:
        params = call.args[4]
        assert params["ttl"] == NEW_TTL
        assert {r["ipv4_address"] for r in params["a_records"]} == VALUES


async def test_cloudflare_keeps_all_three(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    changes = await _preflight_changes(db_session, monkeypatch, "cloudflare")
    rows = [
        {"id": f"r{i}", "type": "A", "content": v, "ttl": 3600}
        for i, v in enumerate(sorted(VALUES))
    ]
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": "zid"}])),
                _FakeResponse(200, _env(rows)),
            ]
            * 3,
            "put": [_FakeResponse(200, _env({"id": "x"}))] * 9,
            "post": [],
            "delete": [],
        }
    )
    driver = CloudflareDNSDriver()
    monkeypatch.setattr(driver, "_client", lambda token: fake)
    for c in changes:
        await driver._apply_record(_Server(), CF_CREDS, c)
    methods = {c["method"] for c in fake.calls}
    assert "delete" not in methods and "post" not in methods
    puts = [c["json"] for c in fake.calls if c["method"] == "put"]
    assert {p["content"] for p in puts} == VALUES
    assert all(p["ttl"] == NEW_TTL for p in puts)


# ── Reachability + the paths the flag does and does not change ──────────────


async def test_preflight_never_dispatches_to_an_agentless_secondary(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A mixed group (agent primary, agentless secondary) is the only shape the
    pre-flight accepts that contains an agentless server, and record ops there
    fan out to the AGENT servers only. So the pre-flight cannot reach an
    agentless driver at all; and the agent ops keep the unstamped per-RR
    ``add`` siblings (the agent path is unchanged by #1983)."""
    import uuid

    from sqlalchemy import select

    from app.models.dns import DNSRecordOp, DNSServer

    grp, agent, zone = await _group_and_zone(db_session, driver="bind9")
    win = DNSServer(
        group_id=grp.id,
        driver="windows_dns",
        host="10.0.0.9",
        name=f"win-{uuid.uuid4().hex[:6]}",
        is_primary=False,
        is_enabled=True,
    )
    db_session.add(win)
    recs = [
        await _add_record(db_session, zone, name="rr", value=v, ttl=3600) for v in sorted(VALUES)
    ]
    await db_session.commit()
    recorder = _RecordingDriver()
    monkeypatch.setattr("app.services.dns.record_ops.get_driver", lambda _name: recorder)

    for rec in recs:
        rec.ttl = NEW_TTL
    await enqueue_record_ops_batch(db_session, zone, _ttl_ops(recs, zone))
    await db_session.commit()

    assert recorder.full_changes == []
    rows = (await db_session.execute(select(DNSRecordOp))).scalars().all()
    assert {r.server_id for r in rows} == {agent.id}
    siblings = [r for r in rows if r.record.get("rrset_action") == "add"]
    assert len(siblings) == 2
    assert all("rrset" not in r.record for r in siblings)


async def test_pool_ttl_change_keeps_every_member_on_an_agentless_server(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The REACHABLE ``update`` + ``rrset_action="add"`` producer on main: a
    pool TTL change emits one such op per member through ``enqueue_record_op``.
    Unstamped, each reached Windows DNS as a single-value replace and the pool
    kept only its last member. Stamped, the last op carries the whole set at
    the new TTL. (#1979 reshapes this into one plain stamped update; this pin
    holds either way.)"""
    from app.services.dns.pool_apply import apply_pool_state
    from tests.test_dns_pool_geo_steering import _pool_with_members

    grp, _server, zone = await _group_and_zone(db_session, driver="windows_dns")
    recorder = _RecordingDriver()
    monkeypatch.setattr("app.services.dns.record_ops.get_driver", lambda _name: recorder)
    pool = await _pool_with_members(db_session, grp, zone, [{"address": a} for a in sorted(VALUES)])
    await db_session.commit()
    recorder.full_changes.clear()

    await db_session.refresh(pool, ["members"])
    pool.ttl = NEW_TTL
    await apply_pool_state(db_session, pool)
    await db_session.commit()

    updates = [c for c in recorder.full_changes if c.op == "update"]
    assert updates, "the TTL change sent nothing"
    last = updates[-1]
    assert last.rrset is not None, "the pool TTL update reached Windows as a single-value replace"
    assert {m.value for m in last.rrset.members} == VALUES
    assert last.rrset.ttl == NEW_TTL
    for c in updates:
        assert c.rrset is not None and {m.value for m in c.rrset.members} == VALUES
