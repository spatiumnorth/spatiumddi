"""#1773 — renaming a DNS record via PUT must retract the old name.

An ``update`` op replaces the RRset AT the new name and never touches the old
one, so the old name stayed served (#492 fixed only the IPAM path). A rename is
now delete(old) then create(new) in one batch; a value-only edit stays a single
update.
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecordOp
from tests.test_dns_agentless_soft_delete_632 import (
    _add_record,
    _make_admin,
    _make_zone,
    _record_delete_url,
)


@pytest.mark.asyncio
async def test_rename_agentless_deletes_old_then_creates_new_in_one_call(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.drivers.dns.base import RecordChangeResult

    batches: list[list[tuple[str, str]]] = []

    class _Rec:
        async def apply_record_changes(self, _server: Any, changes: list[Any]) -> list[Any]:
            batches.append([(c.op, c.record.name) for c in changes])
            return [RecordChangeResult(ok=True) for _ in changes]

    monkeypatch.setattr("app.services.dns.record_ops.get_driver", lambda _n: _Rec())
    _server, zone = await _make_zone(db_session)
    rec = await _add_record(db_session, zone, "web01")
    headers = await _make_admin(db_session)
    await db_session.commit()

    r = await client.put(_record_delete_url(zone, rec), json={"name": "web02"}, headers=headers)
    assert r.status_code == 200, r.text
    assert batches == [[("delete", "web01"), ("create", "web02")]]


@pytest.mark.asyncio
async def test_rename_agent_queues_delete_old_before_create_new(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _server, zone = await _make_zone(db_session, driver="bind9")
    rec = await _add_record(db_session, zone, "web01")
    headers = await _make_admin(db_session)
    await db_session.commit()

    r = await client.put(_record_delete_url(zone, rec), json={"name": "web02"}, headers=headers)
    assert r.status_code == 200, r.text
    rows = (await db_session.execute(select(DNSRecordOp).order_by(DNSRecordOp.seq))).scalars().all()
    assert [(o.op, o.record["name"]) for o in rows] == [("delete", "web01"), ("create", "web02")]
    # The delete's RRset at the old name is empty: nothing else lives there.
    assert rows[0].record["rrset"]["members"] == []
    assert [m["value"] for m in rows[1].record["rrset"]["members"]] == ["203.0.113.40"]


@pytest.mark.asyncio
async def test_value_only_edit_stays_a_single_update(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _server, zone = await _make_zone(db_session, driver="bind9")
    rec = await _add_record(db_session, zone, "web01")
    headers = await _make_admin(db_session)
    await db_session.commit()

    r = await client.put(
        _record_delete_url(zone, rec), json={"value": "203.0.113.41"}, headers=headers
    )
    assert r.status_code == 200, r.text
    rows = (await db_session.execute(select(DNSRecordOp))).scalars().all()
    assert [(o.op, o.record["name"]) for o in rows] == [("update", "web01")]


@pytest.mark.asyncio
async def test_record_type_cannot_change_on_update(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A type change is not an edit: the type is immutable, so there is no
    type-change path that could leave the old RRset behind."""
    _server, zone = await _make_zone(db_session, driver="bind9")
    rec = await _add_record(db_session, zone, "web01")
    headers = await _make_admin(db_session)
    await db_session.commit()

    await client.put(_record_delete_url(zone, rec), json={"record_type": "AAAA"}, headers=headers)
    await db_session.refresh(rec)
    assert rec.record_type == "A"
