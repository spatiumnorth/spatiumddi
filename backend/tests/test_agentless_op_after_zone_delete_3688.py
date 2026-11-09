"""An agentless record dispatch that outlives a permanent zone delete is undone (#3688).

A record write claims its op row, then calls the provider with no lock. A
permanent zone delete that commits in between sweeps the claimed row and pushes
the zone's removal. The in-flight call then reaches the provider AFTER the
removal (re-creating the zone, or leaving its record), and its outcome is
dropped with the swept row, so nothing retried or cleaned up. The dropped
outcome now re-sends the removal when the zone no longer exists.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.services.dns import record_ops
from tests.conftest import _test_engine
from tests.test_dns_dynamic_update_acl import _superadmin


class _Provider:
    """A fake agentless provider holding zones and the records in them."""

    def __init__(self) -> None:
        self.zones: dict[str, list[str]] = {}
        self.zone_calls: list[tuple[str, str]] = []

    async def apply_zone_change(self, _server: Any, zone: Any, op: str) -> bool:
        self.zone_calls.append((zone.name, op))
        if op == "delete":
            return self.zones.pop(zone.name, None) is not None
        self.zones.setdefault(zone.name, [])
        return True

    async def apply_record_change(self, _server: Any, change: Any) -> None:
        # A real provider rejects a record for a missing zone, but Windows /
        # cloud writes can create the zone implicitly; model the leak.
        self.zones.setdefault(change.zone_name, []).append(change.record.name)


async def _seed(db: AsyncSession) -> tuple[dict[str, str], DNSServer, DNSZone, uuid.UUID]:
    _, headers = await _superadmin(db)
    group = DNSServerGroup(name=f"g3688-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    server = DNSServer(
        group_id=group.id,
        name="win1",
        driver="windows_dns",
        host="10.9.9.9",
        is_primary=True,
        is_enabled=True,
        credentials_encrypted=b"x",
    )
    zone = DNSZone(
        group_id=group.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
    )
    db.add_all([server, zone])
    await db.flush()
    op = DNSRecordOp(
        server_id=server.id,
        zone_id=zone.id,
        zone_name=zone.name,
        op="create",
        record={"name": "www", "type": "A", "value": "192.0.2.10"},
        state="pending",
    )
    db.add(op)
    await db.flush()
    op_id = op.id
    await db.commit()
    return headers, server, zone, op_id


@pytest.mark.asyncio
async def test_a_dispatch_claimed_before_a_permanent_zone_delete_is_retracted(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = _Provider()
    monkeypatch.setattr("app.drivers.dns.get_driver", lambda _name: provider)
    monkeypatch.setattr(record_ops, "get_driver", lambda _name: provider)
    headers, server, zone, op_id = await _seed(db_session)
    provider.zones[zone.name] = []

    # The record write's claim commits first.
    claimed_at = datetime.now(UTC)
    rows = await record_ops._claim(db_session, [op_id], now=claimed_at)
    await db_session.commit()
    assert len(rows) == 1

    # The permanent zone delete sweeps the claimed row and removes the zone.
    resp = await client.delete(
        f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}",
        headers=headers,
        params={"permanent": "true"},
    )
    assert resp.status_code == 204, resp.text
    assert provider.zones == {}
    assert (
        await db_session.execute(select(DNSRecordOp).where(DNSRecordOp.id == op_id))
    ).scalar_one_or_none() is None

    # Now the in-flight provider call goes out, after the removal.
    out = await record_ops._dispatch_claimed(
        _test_engine, server, rows, batched=False, claimed_at=claimed_at
    )
    assert out == {}  # the outcome was dropped with the swept row
    assert provider.zones == {}, provider.zones  # the repair re-sent the removal
    assert provider.zone_calls.count((zone.name, "delete")) == 2


@pytest.mark.asyncio
async def test_a_dropped_outcome_leaves_a_zone_that_still_exists_alone(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lease the sweep took back with the zone still there is not a removal."""
    provider = _Provider()
    monkeypatch.setattr(record_ops, "get_driver", lambda _name: provider)
    _headers, server, zone, op_id = await _seed(db_session)
    claimed_at = datetime.now(UTC)
    rows = await record_ops._claim(db_session, [op_id], now=claimed_at)
    await db_session.commit()
    row = (
        await db_session.execute(select(DNSRecordOp).where(DNSRecordOp.id == op_id))
    ).scalar_one()
    row.state = "pending"  # the sweep reclaimed the expired lease
    await db_session.commit()
    await record_ops._dispatch_claimed(
        _test_engine, server, rows, batched=False, claimed_at=claimed_at
    )
    assert provider.zone_calls == []
    assert zone.name in provider.zones
