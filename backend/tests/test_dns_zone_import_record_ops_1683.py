"""#1683 — records put into a zone by its zone-file import reach the server.

``POST /dns/groups/{gid}/zones/{zid}/import/commit`` wrote the parsed adds,
updates and deletes as rows and woke the group's agents, but queued no record
op and left the zone's serial. In a group without views the agent bundle's
structural etag leaves records out, so a record-only change reaches the daemon
only as a ``DNSRecordOp`` (the reason #707 / #711 queue ops in the bulk
importer): an imported record was not served until some later write in the
zone. Seen on PowerDNS; by the code, every agent-served zone.

The contract: an import's changes are queued like the record API's, as record
ops in one batch on one serial bump, and an agentless provider takes them the
way it takes the record API's (#1538: a change that did not land is surfaced,
not reported as a clean success).
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone

ZONE = "import.example.edu."


async def _admin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _group(
    db: AsyncSession, *, driver: str = "bind9", servers: int = 1
) -> tuple[DNSServerGroup, DNSZone, list[DNSServer]]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    rows = [
        DNSServer(
            group_id=grp.id,
            driver=driver,
            host=f"ns{i}.example.edu",
            name=f"srv-{uuid.uuid4().hex[:6]}",
            is_primary=i == 0,
            is_enabled=True,
        )
        for i in range(servers)
    ]
    db.add_all(rows)
    zone = DNSZone(
        group_id=grp.id,
        name=ZONE,
        zone_type="primary",
        kind="forward",
        primary_ns=f"ns1.{ZONE}",
        admin_email=f"admin.{ZONE}",
    )
    db.add(zone)
    await db.flush()
    return grp, zone, rows


def _record(zone: DNSZone, name: str, rtype: str, value: str, ttl: int | None = None) -> DNSRecord:
    return DNSRecord(
        zone_id=zone.id,
        name=name,
        fqdn=f"{name}.{zone.name}",
        record_type=rtype,
        value=value,
        ttl=ttl,
    )


async def _import(
    client: AsyncClient,
    headers: dict[str, str],
    grp: DNSServerGroup,
    zone: DNSZone,
    lines: str,
    strategy: str = "merge",
) -> dict[str, Any]:
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/import/commit",
        headers=headers,
        json={
            "zone_file": f"$ORIGIN {ZONE}\n$TTL 300\n{lines}",
            "conflict_strategy": strategy,
        },
    )
    assert r.status_code == 200, r.text
    body: dict[str, Any] = r.json()
    return body


async def _ops(db: AsyncSession, server: DNSServer) -> list[DNSRecordOp]:
    """The server's ops in the order its agent drains them (agent_config)."""
    res = await db.execute(
        select(DNSRecordOp)
        .where(DNSRecordOp.server_id == server.id)
        .order_by(DNSRecordOp.created_at, DNSRecordOp.seq, DNSRecordOp.id)
    )
    return list(res.scalars().all())


def _shape(op: DNSRecordOp) -> tuple[str, str, str, str, str]:
    rec = op.record
    return (op.op, rec["name"], rec["type"], rec["value"], op.state)


async def test_an_imported_record_is_queued_for_every_agent_and_moves_the_serial(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin_headers(db_session)
    grp, zone, servers = await _group(db_session, servers=2)
    serial_before = zone.last_serial
    await db_session.commit()

    body = await _import(client, h, grp, zone, "imp1 IN A 192.0.2.21\n")
    assert body["created"] == 1

    await db_session.refresh(zone)
    assert zone.last_serial > serial_before, "the import must move the zone's serial"
    for server in servers:
        ops = await _ops(db_session, server)
        assert [_shape(o) for o in ops] == [("create", "imp1", "A", "192.0.2.21", "pending")]
        assert ops[0].target_serial == zone.last_serial
        # The whole RRset rides with the op (#773), as on the record API.
        assert ops[0].record["rrset"]["members"] == [{"value": "192.0.2.21"}]
    assert body["provider_warning"] is None


async def test_a_replace_that_turns_an_a_into_a_cname_ships_the_delete_first(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin_headers(db_session)
    grp, zone, (server,) = await _group(db_session)
    db_session.add(_record(zone, "alias", "A", "192.0.2.30"))
    await db_session.commit()
    serial_before = zone.last_serial

    body = await _import(client, h, grp, zone, f"alias IN CNAME target.{ZONE}\n", "replace")
    assert (body["created"], body["deleted"]) == (1, 1)

    await db_session.refresh(zone)
    ops = await _ops(db_session, server)
    # The A must be gone before the CNAME can land at its name: a server
    # refuses a CNAME beside other data, so the agent drains the delete first.
    assert [_shape(o) for o in ops] == [
        ("delete", "alias", "A", "192.0.2.30", "pending"),
        ("create", "alias", "CNAME", f"target.{ZONE}", "pending"),
    ]
    assert ops[0].record["rrset"]["members"] == [], "the A RRset must be retired"
    assert ops[1].record["rrset"]["members"] == [{"value": f"target.{ZONE}"}]
    # One batch, one serial bump.
    assert zone.last_serial > serial_before
    assert {o.target_serial for o in ops} == {zone.last_serial}


async def test_an_imported_ttl_change_ships_as_an_update(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin_headers(db_session)
    grp, zone, (server,) = await _group(db_session)
    db_session.add(_record(zone, "www", "A", "192.0.2.10", ttl=3600))
    await db_session.commit()

    body = await _import(client, h, grp, zone, "www 60 IN A 192.0.2.10\n")
    assert body["updated"] == 1

    ops = await _ops(db_session, server)
    assert [_shape(o) for o in ops] == [("update", "www", "A", "192.0.2.10", "pending")]
    assert ops[0].record["ttl"] == 60
    assert ops[0].record["rrset"]["ttl"] == 60


async def test_an_import_that_changes_nothing_queues_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin_headers(db_session)
    grp, zone, (server,) = await _group(db_session)
    db_session.add(_record(zone, "www", "A", "192.0.2.10", ttl=300))
    await db_session.commit()
    serial_before = zone.last_serial

    body = await _import(client, h, grp, zone, "www IN A 192.0.2.10\n")
    assert (body["created"], body["updated"], body["unchanged"]) == (0, 0, 1)

    await db_session.refresh(zone)
    assert zone.last_serial == serial_before
    assert await _ops(db_session, server) == []


class _AgentlessDriver:
    """An agentless provider: records every batch, fails while ``fail`` is set."""

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.batches: list[list[Any]] = []

    async def apply_record_changes(self, _server: Any, changes: Any) -> list[Any]:
        from app.drivers.dns.base import RecordChangeResult  # noqa: PLC0415

        self.batches.append(list(changes))
        if self.fail:
            raise RuntimeError("503 provider unavailable")
        return [RecordChangeResult(ok=True, change=c) for c in changes]


async def _last_import_audit(db: AsyncSession, zone: DNSZone) -> AuditLog:
    res = await db.execute(
        select(AuditLog)
        .where(AuditLog.resource_type == "dns_zone_import", AuditLog.resource_id == str(zone.id))
        .order_by(AuditLog.timestamp.desc())
    )
    return res.scalars().first()  # type: ignore[return-value]


async def test_an_agentless_zone_takes_the_import_in_one_batch(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = await _admin_headers(db_session)
    grp, zone, (server,) = await _group(db_session, driver="windows_dns")
    await db_session.commit()
    driver = _AgentlessDriver()
    monkeypatch.setattr("app.services.dns.record_ops.get_driver", lambda _name: driver)

    body = await _import(client, h, grp, zone, "a IN A 192.0.2.41\nb IN A 192.0.2.42\n")

    assert body["created"] == 2
    assert [[c.record.name for c in batch] for batch in driver.batches] == [["a", "b"]]
    ops = await _ops(db_session, server)
    assert sorted(o.record["name"] for o in ops) == ["a", "b"]
    assert {o.state for o in ops} == {"applied"}
    assert body["provider_warning"] is None
    assert (await _last_import_audit(db_session, zone)).result == "success"


async def test_an_agentless_failure_is_surfaced_not_reported_as_success(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = await _admin_headers(db_session)
    grp, zone, (server,) = await _group(db_session, driver="windows_dns")
    await db_session.commit()
    driver = _AgentlessDriver(fail=True)
    monkeypatch.setattr("app.services.dns.record_ops.get_driver", lambda _name: driver)

    body = await _import(client, h, grp, zone, "a IN A 192.0.2.41\n")

    assert body["created"] == 1
    # #1538: rescheduled with backoff, and the response says so.
    ops = await _ops(db_session, server)
    assert [(o.state, o.next_attempt_at is not None) for o in ops] == [("pending", True)]
    assert body["provider_warning"] and "503 provider unavailable" in body["provider_warning"]
    assert (await _last_import_audit(db_session, zone)).result == "error"
