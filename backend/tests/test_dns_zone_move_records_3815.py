"""#3815 — a zone moved to a different agentless provider arrived with SOA +
NS only: the create made an empty zone and nothing pushed the saved records,
so every one answered NXDOMAIN while SpatiumDDI listed it as served."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns.base import RecordChangeResult, RecordData
from app.models.audit import AuditLog
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSZone
from tests.test_dns_zone_move_same_provider_3805 import (
    _A,
    _B,
    _FakeProvider,
    _move,
    _setup,
    _token,
)


class _RecordProvider(_FakeProvider):
    def __init__(self) -> None:
        super().__init__()
        self.records: dict[tuple[str | None, str], set[tuple[str, str, str]]] = {}
        self.writes: list[tuple[str, str, str, str]] = []
        self.fail = False
        self.deletes: list[tuple[str, str, str, str]] = []

    async def pull_zone_records(self, server: Any, zone_name: str, **_: Any) -> list[RecordData]:
        held = self.records.get((self.provider_identity(server), zone_name), set())
        return [RecordData(name=n, record_type=t, value=v) for n, t, v in held]

    async def apply_record_changes(self, server: Any, changes: list[Any]) -> list[Any]:
        out = []
        for c in changes:
            if self.fail:
                out.append(RecordChangeResult(ok=False, change=c, error="boom"))
                continue
            r = c.record
            key = (self.provider_identity(server), c.zone_name)
            if c.op == "delete":
                self.records.get(key, set()).discard((r.name, r.record_type, r.value))
                self.deletes.append((server.name, r.name, r.record_type, r.value))
                out.append(RecordChangeResult(ok=True, change=c))
                continue
            self.records.setdefault(key, set()).add((r.name, r.record_type, r.value))
            self.writes.append((server.name, r.name, r.record_type, r.value))
            out.append(RecordChangeResult(ok=True, change=c))
        return out


@pytest.fixture
def prov(monkeypatch: pytest.MonkeyPatch) -> _RecordProvider:
    fake = _RecordProvider()
    monkeypatch.setattr("app.drivers.dns.get_driver", lambda name: fake)
    return fake


def _rec(zone: DNSZone, name: str, value: str, **kw: Any) -> DNSRecord:
    return DNSRecord(
        zone_id=zone.id,
        name=name,
        fqdn=f"{name}.{zone.name}",
        record_type="A",
        value=value,
        ttl=300,
        **kw,
    )


async def _seed(db: AsyncSession, zone: DNSZone) -> None:
    src_srv = (
        await db.execute(select(DNSServer).where(DNSServer.group_id == zone.group_id))
    ).scalar_one()
    db.add_all(
        [
            _rec(zone, "www", "192.0.2.1"),
            _rec(zone, "pending", "192.0.2.2"),
            _rec(zone, "gone", "192.0.2.3", deleted_at=datetime.now(UTC)),
        ]
    )
    db.add(
        DNSRecordOp(
            server_id=src_srv.id,
            zone_name=zone.name,
            zone_id=zone.id,
            op="create",
            record={"name": "pending", "type": "A", "value": "192.0.2.2"},
            state="pending",
        )
    )
    db.add(
        DNSRecordOp(
            server_id=src_srv.id,
            zone_name=zone.name,
            zone_id=zone.id,
            op="delete",
            record={"name": "gone", "type": "A", "value": "192.0.2.3"},
            state="pending",
        )
    )
    await db.flush()


@pytest.mark.asyncio
async def test_move_to_another_provider_pushes_live_records_only(
    client: AsyncClient, db_session: AsyncSession, prov: _RecordProvider
) -> None:
    token = await _token(db_session)
    zone, dst = await _setup(db_session, _A, _B)
    await _seed(db_session, zone)

    resp = await _move(client, token, zone, dst)

    assert resp.status_code == 200, resp.text
    held = prov.records[("route53:key:AKIA-TWO", zone.name)]
    assert {n for n, _t, _v in held} == {"www", "pending"}  # the pending add arrived
    assert "gone" not in {w[1] for w in prov.writes}  # the pending delete did not resurrect
    audit = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "move", AuditLog.resource_id == str(zone.id))
        )
    ).scalar_one()
    assert audit.new_value["records_pushed"] == {"dst-ns": 2}


@pytest.mark.asyncio
async def test_adopted_copy_gets_only_the_record_still_queued_for_retry(
    client: AsyncClient, db_session: AsyncSession, prov: _RecordProvider
) -> None:
    """One provider behind both groups (#3805): the target adopts the source's
    copy, which holds every record but the one whose write was waiting for its
    retry. The move drops that op, so the push must deliver it — and nothing
    else, since the rest is already there."""
    token = await _token(db_session)
    zone, dst = await _setup(db_session, _A, _A)
    await _seed(db_session, zone)
    key = ("route53:key:AKIA-ONE", zone.name)
    prov.zones.add(key)
    prov.records[key] = {("www", "A", "192.0.2.1")}

    resp = await _move(client, token, zone, dst)

    assert resp.status_code == 200, resp.text
    assert prov.writes == [("dst-ns", "pending", "A", "192.0.2.2")]
    assert key in prov.zones  # the shared copy is still there


@pytest.mark.asyncio
async def test_adopted_copy_loses_the_record_whose_delete_was_queued(
    client: AsyncClient, db_session: AsyncSession, prov: _RecordProvider
) -> None:
    """The provider was unreachable when the record was deleted, so its delete
    is still queued when the zone moves to a group on the SAME provider. The
    move drops the op and the push is additive, so the adopted copy kept the
    record for good. A live record, and a queued update, are untouched."""
    token = await _token(db_session)
    zone, dst = await _setup(db_session, _A, _A)
    await _seed(db_session, zone)
    key = ("route53:key:AKIA-ONE", zone.name)
    prov.zones.add(key)
    prov.records[key] = {
        ("www", "A", "192.0.2.1"),
        ("gone", "A", "192.0.2.3"),  # the record whose delete is queued
        ("pending", "A", "192.0.2.9"),  # stale value; the queued update sets .2
    }

    resp = await _move(client, token, zone, dst)

    assert resp.status_code == 200, resp.text
    held = prov.records[key]
    assert ("gone", "A", "192.0.2.3") not in held
    assert ("www", "A", "192.0.2.1") in held
    assert [d[1:] for d in prov.deletes] == [("gone", "A", "192.0.2.3")]
    assert ("pending", "A", "192.0.2.2") in held


@pytest.mark.asyncio
async def test_queued_delete_is_skipped_when_the_record_is_live_again(
    client: AsyncClient, db_session: AsyncSession, prov: _RecordProvider
) -> None:
    token = await _token(db_session)
    zone, dst = await _setup(db_session, _A, _A)
    await _seed(db_session, zone)
    db_session.add(_rec(zone, "gone", "192.0.2.3"))  # re-created after the delete
    await db_session.flush()
    key = ("route53:key:AKIA-ONE", zone.name)
    prov.zones.add(key)
    prov.records[key] = {("www", "A", "192.0.2.1"), ("gone", "A", "192.0.2.3")}

    resp = await _move(client, token, zone, dst)

    assert resp.status_code == 200, resp.text
    assert prov.deletes == []
    assert ("gone", "A", "192.0.2.3") in prov.records[key]


@pytest.mark.asyncio
async def test_undeliverable_queued_delete_fails_the_move(
    client: AsyncClient, db_session: AsyncSession, prov: _RecordProvider
) -> None:
    token = await _token(db_session)
    zone, dst = await _setup(db_session, _A, _A)
    await _seed(db_session, zone)
    key = ("route53:key:AKIA-ONE", zone.name)
    prov.zones.add(key)
    prov.records[key] = {("www", "A", "192.0.2.1"), ("gone", "A", "192.0.2.3")}
    prov.fail = True

    resp = await _move(client, token, zone, dst)

    assert resp.status_code == 502, resp.text
    assert "delete of gone" in resp.text
    assert key in prov.zones  # the adopted copy is left as found


@pytest.mark.asyncio
async def test_failed_record_push_is_not_a_clean_move(
    client: AsyncClient, db_session: AsyncSession, prov: _RecordProvider
) -> None:
    token = await _token(db_session)
    zone, dst = await _setup(db_session, _A, _B)
    await _seed(db_session, zone)
    prov.fail = True

    resp = await _move(client, token, zone, dst)

    assert resp.status_code == 502, resp.text
    assert "records" in resp.json()["detail"]
    # The fresh copy the move created is removed again, so a retry does not
    # adopt a half-filled zone and skip filling it.
    assert ("route53:key:AKIA-TWO", zone.name) not in prov.zones
    assert ("dst-ns", "delete") in prov.calls
    assert "removed again" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_failed_record_push_never_deletes_an_adopted_copy(
    client: AsyncClient, db_session: AsyncSession, prov: _RecordProvider
) -> None:
    token = await _token(db_session)
    zone, dst = await _setup(db_session, _A, _A)
    await _seed(db_session, zone)
    key = ("route53:key:AKIA-ONE", zone.name)
    prov.zones.add(key)
    prov.fail = True

    resp = await _move(client, token, zone, dst)

    assert resp.status_code == 502, resp.text
    assert key in prov.zones
    assert ("dst-ns", "delete") not in prov.calls
    assert ("src-ns", "delete") not in prov.calls


@pytest.mark.asyncio
async def test_record_type_the_target_cannot_serve_is_reported(
    client: AsyncClient,
    db_session: AsyncSession,
    prov: _RecordProvider,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = await _token(db_session)
    zone, dst = await _setup(db_session, _A, _B)
    await _seed(db_session, zone)
    monkeypatch.setattr(prov, "capabilities", lambda: {"record_types": ["CNAME"]})

    resp = await _move(client, token, zone, dst)

    assert resp.status_code == 200, resp.text
    assert any("cannot serve record type(s) A" in w for w in resp.json()["warnings"])
