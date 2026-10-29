"""Sync with Servers moves a zone's serial only when it sends something (#3004).

A sync that imported nothing and pushed nothing used to take the zone's next
serial anyway: the push phase bumped ``last_serial`` before it looked for
anything to send, and the group route commits whatever happened, once per
enabled server. No record op carried that serial to an agent-managed server
(and in a group without views the serial is not part of the structural
bundle), so the zone's server-state, which compares the served serial with
``last_serial``, read "not in sync" until the next record change.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.drivers.dns.base import RecordChangeResult, RecordData
from app.models.auth import User
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.models.settings import PlatformSettings
from app.services.dns import pull_from_server as pfs
from app.services.dns.pull_from_server import sync_zone_with_server
from app.services.dns.serial import compute_next_serial
from app.tasks import dns_pull

_SERIAL = 2026010105
_WWW = RecordData(name="www", record_type="A", value="192.0.2.5", ttl=300)


class _Driver:
    """Records every batch the push sends. The read is faked separately."""

    def __init__(self) -> None:
        self.sent: list[list[Any]] = []

    def capabilities(self) -> dict[str, Any]:
        return {"record_types": ["A"]}

    async def pull_zone_records(self, server: Any, zone_name: str, *, tsig: Any = None) -> Any:
        raise AssertionError("the read goes through pull_zone_records_signed, faked below")

    async def apply_record_changes(self, server: Any, changes: list[Any]) -> list[Any]:
        self.sent.append(list(changes))
        return [RecordChangeResult(ok=True, change=c) for c in changes]


async def _zone(db: AsyncSession, *drivers: str) -> tuple[DNSZone, list[DNSServer]]:
    """A zone at serial ``_SERIAL`` holding ``www A 192.0.2.5``, in a group of
    one enabled server per driver name (the first is the primary)."""
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
        name="example.com.",
        zone_type="primary",
        kind="forward",
        last_serial=_SERIAL,
    )
    db.add_all([*servers, zone])
    await db.flush()
    db.add(
        DNSRecord(
            zone_id=zone.id,
            name="www",
            fqdn="www.example.com.",
            record_type="A",
            value="192.0.2.5",
            ttl=300,
        )
    )
    await db.commit()
    return zone, servers


def _serve(monkeypatch: pytest.MonkeyPatch, driver: _Driver, on_wire: list[RecordData]) -> None:
    """Every server of the group answers the zone read with ``on_wire``."""

    async def _resolve(db: Any, zone: Any, server: Any = None) -> Any:
        if server is None:
            server = (
                await db.execute(
                    select(DNSServer).where(
                        DNSServer.group_id == zone.group_id, DNSServer.is_primary.is_(True)
                    )
                )
            ).scalar_one()
        return server, driver, [None], None

    async def _pull(drv: Any, server: Any, zone_name: str, keys: Any, **kw: Any) -> Any:
        return list(on_wire), None

    monkeypatch.setattr(pfs, "_resolve_primary_and_driver", _resolve)
    monkeypatch.setattr(pfs, "pull_zone_records_signed", _pull)


async def _ops(db: AsyncSession, zone_id: uuid.UUID) -> list[DNSRecordOp]:
    return list(
        (await db.execute(select(DNSRecordOp).where(DNSRecordOp.zone_id == zone_id)))
        .scalars()
        .all()
    )


async def _stored_serial(db: AsyncSession, zone_id: uuid.UUID) -> int:
    """The serial as committed, read past the session's identity map."""
    db.expire_all()
    return int(
        (await db.execute(select(DNSZone.last_serial).where(DNSZone.id == zone_id))).scalar_one()
    )


# ── Nothing to send: the serial stays ────────────────────────────────────────


@pytest.mark.parametrize("driver_name", ["bind9", "technitium"])
async def test_sync_with_nothing_to_send_keeps_the_serial_on_an_agent_server(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, driver_name: str
) -> None:
    """The issue's case: the server already serves every row, so the sync
    imports 0 and pushes 0, and no op is queued for the agent. A serial taken
    here would be one the server can never report."""
    zone, (ns1,) = await _zone(db_session, driver_name)
    _serve(monkeypatch, _Driver(), [_WWW])

    result = await sync_zone_with_server(db_session, zone, apply=True, server=ns1)

    assert (result.pull.imported, result.push.candidates, result.push.pushed) == (0, 0, 0)
    assert await _ops(db_session, zone.id) == []
    assert zone.last_serial == _SERIAL


async def test_sync_with_nothing_to_send_keeps_the_serial_on_an_agentless_server(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    zone, (ns1,) = await _zone(db_session, "technitium_api")
    driver = _Driver()
    _serve(monkeypatch, driver, [_WWW])

    result = await sync_zone_with_server(db_session, zone, apply=True, server=ns1)

    assert result.push.candidates == 0
    assert driver.sent == []
    assert zone.last_serial == _SERIAL


async def test_second_sync_before_the_agent_drains_keeps_the_queued_serial(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The row is still missing on the server because its op is still queued
    (upstream's #2667 test presses twice the same way). The second press
    queues nothing new, so it must not take a serial either: the queued op
    carries the zone's serial, and the agent reports what that op carries."""
    zone, (ns1,) = await _zone(db_session, "bind9")
    _serve(monkeypatch, _Driver(), [])

    await sync_zone_with_server(db_session, zone, apply=True, server=ns1)
    (op,) = await _ops(db_session, zone.id)
    assert op.target_serial == zone.last_serial

    again = await sync_zone_with_server(db_session, zone, apply=True, server=ns1)

    assert again.push.queued_for_agent is True
    assert again.push.push_errors == []
    assert [o.id for o in await _ops(db_session, zone.id)] == [op.id]
    assert zone.last_serial == op.target_serial


async def test_group_sync_with_nothing_to_send_keeps_the_serial(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Through the group's Sync with Servers, with two enabled agent servers:
    the press used to move the zone two serials, one per server."""
    zone, _servers = await _zone(db_session, "bind9", "bind9")
    zone_id, group_id = zone.id, zone.group_id
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(user)
    await db_session.commit()
    token = create_access_token(str(user.id))
    _serve(monkeypatch, _Driver(), [_WWW])

    resp = await client.post(
        f"/api/v1/dns/groups/{group_id}/sync-with-servers",
        params={"import_new_zones": "false"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert (body["servers_succeeded"], body["total_imported"], body["total_pushed"]) == (2, 0, 0)
    assert await _ops(db_session, zone_id) == []
    assert await _stored_serial(db_session, zone_id) == _SERIAL


async def test_scheduled_sync_with_nothing_to_send_keeps_the_serial(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The scheduled DNS server sync takes the same path for every pullable
    zone on each run once it is switched on."""
    zone, _servers = await _zone(db_session, "bind9")
    zone_id = zone.id
    db_session.add(
        PlatformSettings(
            id=1,
            dns_pull_from_server_enabled=True,
            dns_pull_from_server_interval_minutes=1,
            dns_pull_from_server_last_run_at=None,
        )
    )
    await db_session.commit()
    driver = _Driver()
    _serve(monkeypatch, driver, [_WWW])
    monkeypatch.setattr(dns_pull, "get_driver", lambda name: driver)

    out = await dns_pull._run_sync()

    assert out["status"] == "ran"
    assert (out["zones_scanned"], out["imported"], out["pushed"]) == (1, 0, 0)
    assert await _stored_serial(db_session, zone_id) == _SERIAL


# ── Something to send: one serial, carried by what is sent ───────────────────


async def test_agent_push_takes_one_serial_and_its_op_carries_it(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    zone, (ns1,) = await _zone(db_session, "bind9")
    _serve(monkeypatch, _Driver(), [])

    result = await sync_zone_with_server(db_session, zone, apply=True, server=ns1)

    assert result.push.queued_for_agent is True and result.push.pushed == 1
    (op,) = await _ops(db_session, zone.id)
    assert op.server_id == ns1.id and op.record["name"] == "www"
    assert zone.last_serial == compute_next_serial(_SERIAL)
    assert op.target_serial == zone.last_serial


async def test_agentless_push_takes_one_serial_and_every_change_carries_it(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    zone, (ns1,) = await _zone(db_session, "technitium_api")
    db_session.add(
        DNSRecord(
            zone_id=zone.id,
            name="mail",
            fqdn="mail.example.com.",
            record_type="A",
            value="192.0.2.6",
            ttl=300,
        )
    )
    await db_session.commit()
    driver = _Driver()
    _serve(monkeypatch, driver, [])

    result = await sync_zone_with_server(db_session, zone, apply=True, server=ns1)

    assert result.push.pushed == 2
    (batch,) = driver.sent
    assert zone.last_serial == compute_next_serial(_SERIAL)
    assert [c.target_serial for c in batch] == [zone.last_serial] * 2


async def test_preview_takes_no_serial(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    zone, (ns1,) = await _zone(db_session, "bind9")
    _serve(monkeypatch, _Driver(), [])

    result = await sync_zone_with_server(db_session, zone, apply=False, server=ns1)

    assert result.push.candidates == 1
    assert await _ops(db_session, zone.id) == []
    assert zone.last_serial == _SERIAL
