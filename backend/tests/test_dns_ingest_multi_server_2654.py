"""DDNS ingest-back and Sync imports in a group with several agent servers (#2654).

Each agent server is an independent primary. A record an RFC 2136 writer put
on one of them used to be mirrored with no record op, so the other servers
never served it, and their own ingest reports (which lacked it) deleted the
mirror again: the row flapped on every sweep. These tests drive the real
ingest endpoint as two agents.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.agents import _auth_agent
from app.drivers.dns.base import RecordChangeResult, RecordData
from app.main import app
from app.models.audit import AuditLog
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.services.dns import pull_from_server as pfs

ZONE = "ad.example.com"
DC01 = {"name": "dc01", "record_type": "A", "value": "10.0.0.5", "ttl": 1200}


async def _group(
    db: AsyncSession, *drivers: str, dynamic: bool = True
) -> tuple[DNSZone, list[DNSServer]]:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    servers = [
        DNSServer(
            group_id=group.id,
            name=f"ns{i + 1}",
            driver=drv,
            host=f"10.0.0.{53 + i}",
            port=53,
            is_enabled=True,
            is_primary=(i == 0),
        )
        for i, drv in enumerate(drivers)
    ]
    zone = DNSZone(
        group_id=group.id,
        name=ZONE + ".",
        zone_type="primary",
        kind="forward",
        dynamic_update_enabled=dynamic,
    )
    db.add_all([*servers, zone])
    await db.commit()
    return zone, servers


async def _post(client: AsyncClient, server: DNSServer, records: list[dict]) -> dict[str, Any]:
    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        r = await client.post(
            "/api/v1/dns/agents/ingested-records",
            json={"zone_name": ZONE, "records": records},
        )
    finally:
        app.dependency_overrides.pop(_auth_agent, None)
    assert r.status_code == 200, r.text
    return r.json()


async def _mirrors(db: AsyncSession, zone: DNSZone) -> list[tuple[str, str]]:
    rows = (
        (
            await db.execute(
                select(DNSRecord).where(
                    DNSRecord.zone_id == zone.id, DNSRecord.import_source == "ddns_external"
                )
            )
        )
        .scalars()
        .all()
    )
    return sorted((r.name, r.value) for r in rows)


async def _ops(db: AsyncSession, zone: DNSZone) -> list[DNSRecordOp]:
    return list(
        (
            await db.execute(
                select(DNSRecordOp)
                .where(DNSRecordOp.zone_id == zone.id)
                .order_by(DNSRecordOp.created_at, DNSRecordOp.seq)
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )


def _for(ops: list[DNSRecordOp], server: DNSServer) -> list[tuple[str, str]]:
    return [(o.op, o.record["name"]) for o in ops if o.server_id == server.id]


async def _apply_all(db: AsyncSession, zone: DNSZone) -> None:
    """Mark every queued op applied, as the agents would."""
    await db.execute(
        update(DNSRecordOp)
        .where(DNSRecordOp.zone_id == zone.id, DNSRecordOp.state.in_(("pending", "in_flight")))
        .values(state="applied", applied_at=datetime.now(UTC))
    )
    await db.commit()


# ── The reported flap ────────────────────────────────────────────────────────


async def test_record_learned_on_one_server_is_queued_to_the_other_and_does_not_flap(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    zone, (ns1, ns2) = await _group(db_session, "bind9", "bind9")

    for _ in range(2):  # the reviewer's repro ran two sweeps of each
        r1 = await _post(client, ns1, [DC01])
        r2 = await _post(client, ns2, [])
        # ns2 never had dc01: that is not the writer withdrawing it.
        assert r2["removed"] == 0
        assert await _mirrors(db_session, zone) == [("dc01", "10.0.0.5")]
    assert r1["added"] == 0  # second sweep: already mirrored

    ops = await _ops(db_session, zone)
    # One create to ns2, none to ns1 (it already holds the record), and the
    # second sweep did not queue a duplicate while the first is still pending.
    assert _for(ops, ns1) == []
    assert _for(ops, ns2) == [("create", "dc01")]
    # Per value: an add of exactly this RR, not a replace of the RRset.
    assert ops[0].record["rrset_action"] == "add" and "rrset" not in ops[0].record
    assert ops[0].record["value"] == "10.0.0.5"

    # ns2 applies it and reports it: nothing more happens.
    await _apply_all(db_session, zone)
    r = await _post(client, ns2, [DC01])
    assert (r["added"], r["removed"], r["peer_ops"], r["corrections"]) == (0, 0, 0, 0)

    audits = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "dns.record.external_ingest")
            )
        )
        .scalars()
        .all()
    )
    assert len(audits) == 1  # the one real add, no add/remove churn
    assert audits[0].new_value["peer_ops"] == 1
    assert audits[0].new_value["mode"] == "multi"


async def test_writer_delete_on_one_server_reaches_the_others(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    zone, (ns1, ns2) = await _group(db_session, "bind9", "bind9")
    await _post(client, ns1, [DC01])
    await _apply_all(db_session, zone)
    await _post(client, ns2, [DC01])

    # The writer withdraws dc01 on ns1.
    r = await _post(client, ns1, [])
    assert r["removed"] == 1 and r["peer_ops"] == 1
    assert await _mirrors(db_session, zone) == []
    ops = await _ops(db_session, zone)
    assert _for(ops, ns1) == []
    assert _for(ops, ns2)[-1] == ("delete", "dc01")
    assert ops[-1].record["rrset_action"] == "delete_value"
    assert ops[-1].record["value"] == "10.0.0.5"

    # ns2 reports before applying it: still holds dc01, a delete is queued.
    # No second delete, and no resurrection.
    r = await _post(client, ns2, [DC01])
    assert (r["added"], r["corrections"]) == (0, 0)
    assert len(await _ops(db_session, zone)) == len(ops)


async def test_our_own_op_landing_is_not_read_as_a_writer_delete(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The reverse cascade: an op WE queued removes a record from ns2 between
    its reports, while ns1's writer has already re-added it. ns2's report
    must not delete the mirror and push that delete back to ns1."""
    zone, (ns1, ns2) = await _group(db_session, "bind9", "bind9")
    await _post(client, ns1, [DC01])
    await _apply_all(db_session, zone)
    await _post(client, ns2, [DC01])  # ns2 snapshot: {dc01}

    await _post(client, ns1, [])  # writer delete on ns1 -> delete queued to ns2
    await _apply_all(db_session, zone)  # ns2 drops dc01
    await _post(client, ns1, [DC01])  # writer re-adds on ns1 -> create queued to ns2
    before = await _ops(db_session, zone)

    # ns2 reports with the delete applied and the create still pending.
    r = await _post(client, ns2, [])
    assert r["removed"] == 0 and r["deferred"] == 1
    assert await _mirrors(db_session, zone) == [("dc01", "10.0.0.5")]
    after = await _ops(db_session, zone)
    assert _for(after, ns1) == _for(before, ns1) == []

    # The create lands; the next report is consistent and does nothing.
    await _apply_all(db_session, zone)
    r = await _post(client, ns2, [DC01])
    assert (r["added"], r["removed"], r["peer_ops"], r["corrections"]) == (0, 0, 0, 0)


async def test_value_change_ships_both_values_per_value(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    zone, (ns1, ns2) = await _group(db_session, "bind9", "bind9")
    await _post(client, ns1, [DC01])
    await _apply_all(db_session, zone)
    r = await _post(client, ns1, [{**DC01, "value": "10.0.0.6"}])
    assert (r["added"], r["removed"]) == (1, 1)
    assert await _mirrors(db_session, zone) == [("dc01", "10.0.0.6")]
    pending = [o for o in await _ops(db_session, zone) if o.state == "pending"]
    assert {o.server_id for o in pending} == {ns2.id}
    # Per-value ops commute: whatever order ns2 drains them in, it ends on .6.
    assert sorted((o.op, o.record["rrset_action"], o.record["value"]) for o in pending) == [
        ("create", "add", "10.0.0.6"),
        ("delete", "delete_value", "10.0.0.5"),
    ]


async def test_record_arriving_on_both_servers_is_mirrored_once(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    zone, (ns1, ns2) = await _group(db_session, "bind9", "bind9")
    await _post(client, ns1, [DC01])
    r = await _post(client, ns2, [DC01])
    assert r["added"] == 0 and r["peer_ops"] == 0
    assert await _mirrors(db_session, zone) == [("dc01", "10.0.0.5")]
    assert len(await _ops(db_session, zone)) == 1  # ns1's add, to ns2


# ── Servers that are behind ─────────────────────────────────────────────────


async def test_server_missing_an_existing_mirror_is_corrected_once(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The state the bug left behind: a mirror ns2 never received. ns2's first
    report after the upgrade gets it an op, and only it."""
    zone, (ns1, ns2) = await _group(db_session, "bind9", "bind9")
    db_session.add(
        DNSRecord(
            zone_id=zone.id,
            name="dc01",
            fqdn=f"dc01.{ZONE}",
            record_type="A",
            value="10.0.0.5",
            import_source="ddns_external",
        )
    )
    await db_session.commit()

    r = await _post(client, ns2, [])
    assert r["removed"] == 0 and r["corrections"] == 1
    assert _for(await _ops(db_session, zone), ns2) == [("create", "dc01")]
    r = await _post(client, ns2, [])  # still pending: not queued again
    assert r["corrections"] == 0
    assert len(await _ops(db_session, zone)) == 1


async def test_server_still_holding_a_withdrawn_record_is_corrected(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """ns2 was disabled when the delete went out, so it never got it."""
    zone, (ns1, ns2) = await _group(db_session, "bind9", "bind9")
    await _post(client, ns1, [DC01])
    await _apply_all(db_session, zone)
    await _post(client, ns2, [DC01])
    await db_session.execute(
        update(DNSServer).where(DNSServer.id == ns2.id).values(is_enabled=False)
    )
    await db_session.commit()
    await _post(client, ns1, [])  # ns1 alone now: the plain reconcile drops it
    assert await _mirrors(db_session, zone) == []
    await db_session.execute(
        update(DNSServer).where(DNSServer.id == ns2.id).values(is_enabled=True)
    )
    await db_session.commit()
    await db_session.refresh(ns2)

    r = await _post(client, ns2, [DC01])
    assert r["added"] == 0 and r["corrections"] == 1
    op = (await _ops(db_session, zone))[-1]
    assert (op.server_id, op.op, op.record["rrset_action"], op.record["value"]) == (
        ns2.id,
        "delete",
        "delete_value",
        "10.0.0.5",
    )


async def test_disabled_reporter_does_not_drive_the_mirror(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    zone, (ns1, ns2) = await _group(db_session, "bind9", "bind9")
    await _post(client, ns1, [DC01])
    await db_session.execute(
        update(DNSServer).where(DNSServer.id == ns2.id).values(is_enabled=False)
    )
    await db_session.commit()
    await db_session.refresh(ns2)
    r = await _post(client, ns2, [{**DC01, "name": "rogue"}])
    assert r["skipped"] == "server_disabled"
    assert await _mirrors(db_session, zone) == [("dc01", "10.0.0.5")]


# ── Groups that must behave exactly as before ──────────────────────────────


async def test_single_agent_group_is_unchanged(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    zone, (ns1,) = await _group(db_session, "bind9")
    r = await _post(client, ns1, [DC01])
    assert r["added"] == 1 and r["peer_ops"] == 0
    r = await _post(client, ns1, [])
    assert r["removed"] == 1
    assert await _ops(db_session, zone) == []


async def test_agentless_member_is_not_a_peer(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    zone, (ns1, win) = await _group(db_session, "bind9", "windows_dns")
    r = await _post(client, ns1, [DC01])
    assert r["added"] == 1 and r["peer_ops"] == 0
    r = await _post(client, ns1, [])
    assert r["removed"] == 1  # the one-agent reconcile, as before
    assert all(o.server_id != win.id for o in await _ops(db_session, zone))


# ── Sync with server(s) ──────────────────────────────────────────────────────


class _FakeDriver:
    def capabilities(self) -> dict[str, Any]:
        return {"record_types": ["A"]}

    async def apply_record_changes(self, server: Any, changes: list[Any]) -> list[Any]:
        return [RecordChangeResult(ok=True, change=c) for c in changes]


@pytest.mark.parametrize("drivers", [("bind9", "bind9"), ("bind9",)])
async def test_sync_import_is_queued_to_the_other_agent_servers(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, drivers: tuple[str, ...]
) -> None:
    zone, servers = await _group(db_session, *drivers, dynamic=False)
    ns1 = servers[0]
    fake = _FakeDriver()

    async def _resolve(db: Any, z: Any, server: Any = None) -> Any:
        return server or ns1, fake, [None], None

    async def _pull(driver: Any, server: Any, zone_name: str, keys: Any, **kw: Any) -> Any:
        return [RecordData(name="printer", record_type="A", value="10.0.0.9", ttl=300)], None

    monkeypatch.setattr(pfs, "_resolve_primary_and_driver", _resolve)
    monkeypatch.setattr(pfs, "pull_zone_records_signed", _pull)

    result = await pfs.sync_zone_with_server(db_session, zone, apply=True, server=ns1)
    assert result.pull.imported == 1
    ops = await _ops(db_session, zone)
    assert _for(ops, ns1) == []
    if len(servers) == 2:
        assert result.pull.peer_ops == 1
        assert _for(ops, servers[1]) == [("create", "printer")]
    else:
        assert result.pull.peer_ops == 0 and ops == []


# ── Review of PR #2666 ───────────────────────────────────────────────────────


async def _set_enabled(db: AsyncSession, server: DNSServer, enabled: bool) -> None:
    await db.execute(update(DNSServer).where(DNSServer.id == server.id).values(is_enabled=enabled))
    await db.commit()
    await db.refresh(server)


async def test_writer_add_on_a_paused_server_survives_re_enable(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Finding 1. A writer registers W on ns2 while ns2 is paused. On re-enable
    W is a change since ns2's pre-pause report: mirrored and fanned out, not
    deleted from ns2 as drift."""
    zone, (ns1, ns2) = await _group(db_session, "bind9", "bind9")
    await _post(client, ns1, [])
    await _post(client, ns2, [])
    await _set_enabled(db_session, ns2, False)
    w = {**DC01, "name": "laptop7", "value": "10.0.0.77"}
    r = await _post(client, ns2, [w])  # paused: ignored
    assert r["skipped"] == "server_disabled"
    await _set_enabled(db_session, ns2, True)

    r = await _post(client, ns2, [w])
    assert r["added"] == 1 and r["corrections"] == 0
    assert await _mirrors(db_session, zone) == [("laptop7", "10.0.0.77")]
    ops = await _ops(db_session, zone)
    assert _for(ops, ns2) == []  # nothing deletes it from ns2
    assert _for(ops, ns1) == [("create", "laptop7")]


async def test_writer_delete_on_a_paused_server_reaches_the_others_on_re_enable(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Finding 1, the other direction: a mirrored record the writer deleted on
    ns2 during the pause is deleted everywhere, not re-created on ns2."""
    zone, (ns1, ns2) = await _group(db_session, "bind9", "bind9")
    await _post(client, ns1, [DC01])
    await _apply_all(db_session, zone)
    await _post(client, ns2, [DC01])
    await _set_enabled(db_session, ns2, False)
    await _post(client, ns2, [])  # writer deleted it on ns2 while paused
    await _set_enabled(db_session, ns2, True)
    # The pause lasted longer than the op-attribution slack: our .5 add to ns2
    # no longer explains a change on it.
    await db_session.execute(
        update(DNSRecordOp)
        .where(DNSRecordOp.zone_id == zone.id)
        .values(applied_at=datetime.now(UTC) - timedelta(hours=1))
    )
    await db_session.commit()

    r = await _post(client, ns2, [])
    assert r["removed"] == 1 and r["corrections"] == 0
    assert await _mirrors(db_session, zone) == []
    pending = [o for o in await _ops(db_session, zone) if o.state == "pending"]
    assert [(o.server_id, o.op) for o in pending] == [(ns1.id, "delete")]


async def test_peer_ops_never_wipe_values_the_peer_holds(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Finding 2. ns2 holds a writer value (.6) at a name we also push to.
    The op we send ns2 for ns1's new value (.7) must add .7, not replace the
    RRset with what the database holds; and .6 is mirrored, not deferred,
    because our op for .5 does not explain a change to .6."""
    zone, (ns1, ns2) = await _group(db_session, "bind9", "bind9")
    await _post(client, ns2, [])
    await _post(client, ns1, [DC01])  # .5 -> add to ns2
    await _apply_all(db_session, zone)
    v6 = {**DC01, "value": "10.0.0.6"}
    v7 = {**DC01, "value": "10.0.0.7"}
    r = await _post(client, ns2, [DC01, v6])  # right after our .5 landed
    assert r["deferred"] == 0 and r["added"] == 1
    await _post(client, ns1, [DC01, v7])

    pending = [o for o in await _ops(db_session, zone) if o.state == "pending"]
    assert all("rrset" not in o.record for o in pending)
    to_ns2 = sorted(
        (o.op, o.record["rrset_action"], o.record["value"])
        for o in pending
        if o.server_id == ns2.id
    )
    assert to_ns2 == [("create", "add", "10.0.0.7")]
    to_ns1 = sorted((o.op, o.record["value"]) for o in pending if o.server_id == ns1.id)
    assert to_ns1 == [("create", "10.0.0.6")]  # ns2's .6, once (no duplicate correction)

    await _apply_all(db_session, zone)
    r = await _post(client, ns2, [DC01, v6, v7])
    assert (r["added"], r["removed"]) == (0, 0)
    assert await _mirrors(db_session, zone) == [
        ("dc01", "10.0.0.5"),
        ("dc01", "10.0.0.6"),
        ("dc01", "10.0.0.7"),
    ]


async def test_managed_record_taking_over_a_name_sends_no_wire_delete(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Finding 3. Like the one-server path: the mirror row goes, nothing is
    deleted on any server (the managed row is often an import of the very
    record the servers serve)."""
    zone, (ns1, ns2) = await _group(db_session, "bind9", "bind9")
    await _post(client, ns1, [DC01])
    await _apply_all(db_session, zone)
    await _post(client, ns2, [DC01])
    db_session.add(
        DNSRecord(
            zone_id=zone.id, name="dc01", fqdn=f"dc01.{ZONE}", record_type="A", value="10.0.0.5"
        )
    )
    await db_session.commit()
    before = len(await _ops(db_session, zone))

    r = await _post(client, ns1, [DC01])
    assert r["removed"] == 1 and r["peer_ops"] == 0
    assert await _mirrors(db_session, zone) == []
    assert len(await _ops(db_session, zone)) == before


async def test_sync_does_not_import_a_record_whose_op_is_still_queued(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding 4. ns1 still serves `printer` because its delete op has not
    landed yet; the sync must not bring the row back and re-send it to ns2,
    which already applied the delete."""
    zone, (ns1, ns2) = await _group(db_session, "bind9", "bind9", dynamic=False)
    db_session.add(
        DNSRecordOp(
            server_id=ns1.id,
            zone_id=zone.id,
            zone_name=zone.name,
            op="delete",
            record={"name": "printer", "type": "A", "value": "10.0.0.9"},
            state="pending",
        )
    )
    await db_session.commit()
    fake = _FakeDriver()

    async def _resolve(db: Any, z: Any, server: Any = None) -> Any:
        return server or ns1, fake, [None], None

    async def _pull(driver: Any, server: Any, zone_name: str, keys: Any, **kw: Any) -> Any:
        return [RecordData(name="printer", record_type="A", value="10.0.0.9", ttl=300)], None

    monkeypatch.setattr(pfs, "_resolve_primary_and_driver", _resolve)
    monkeypatch.setattr(pfs, "pull_zone_records_signed", _pull)

    result = await pfs.sync_zone_with_server(db_session, zone, apply=True, server=ns1)
    assert (result.pull.imported, result.pull.skipped_in_flight, result.pull.peer_ops) == (0, 1, 0)
    assert _for(await _ops(db_session, zone), ns2) == []


async def test_a_correction_that_failed_is_not_requeued_every_report(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Finding 5. A correction ns2 cannot apply goes ``failed`` after
    MAX_OP_ATTEMPTS. It is retried after FAILED_OP_BACKOFF, not on every
    180 s report."""
    from app.services.dns.ingest import FAILED_OP_BACKOFF

    zone, (ns1, ns2) = await _group(db_session, "bind9", "bind9")
    db_session.add(
        DNSRecord(
            zone_id=zone.id,
            name="dc01",
            fqdn=f"dc01.{ZONE}",
            record_type="A",
            value="10.0.0.5",
            import_source="ddns_external",
        )
    )
    await db_session.commit()
    r = await _post(client, ns2, [])
    assert r["corrections"] == 1
    await db_session.execute(
        update(DNSRecordOp)
        .where(DNSRecordOp.zone_id == zone.id)
        .values(state="failed", attempts=8, updated_at=datetime.now(UTC))
    )
    await db_session.commit()

    r = await _post(client, ns2, [])
    assert r["corrections"] == 0
    assert len(await _ops(db_session, zone)) == 1

    await db_session.execute(
        update(DNSRecordOp)
        .where(DNSRecordOp.zone_id == zone.id)
        .values(updated_at=datetime.now(UTC) - FAILED_OP_BACKOFF - timedelta(minutes=1))
    )
    await db_session.commit()
    r = await _post(client, ns2, [])
    assert r["corrections"] == 1
