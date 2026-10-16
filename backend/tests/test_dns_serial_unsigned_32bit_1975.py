"""#1975 — SOA serials are unsigned 32-bit (0..4294967295); storage must hold them."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.agents import _auth_agent
from app.main import app
from app.models.dns import DNSRecordOp, DNSServer, DNSServerGroup, DNSServerZoneState, DNSZone
from app.services.dns.serial import compute_next_serial

BIG = 3_000_000_000  # > 2^31 - 1


async def _setup(db: AsyncSession, serial: int = 1) -> tuple[DNSServer, DNSZone]:
    grp = DNSServerGroup(name=f"g1975-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    srv = DNSServer(
        group_id=grp.id,
        name=f"ns-{uuid.uuid4().hex[:6]}",
        driver="bind9",
        host="10.0.0.53",
        port=53,
    )
    zone = DNSZone(
        group_id=grp.id,
        name="big.example.test.",
        zone_type="primary",
        kind="forward",
        last_serial=serial,
    )
    db.add_all([srv, zone])
    await db.flush()
    return srv, zone


@pytest.mark.asyncio
async def test_zone_and_record_op_store_serial_above_int32(db_session: AsyncSession) -> None:
    srv, zone = await _setup(db_session, serial=BIG)
    db_session.add(
        DNSRecordOp(
            server_id=srv.id,
            zone_name=zone.name,
            op="create",
            record={},
            target_serial=4_294_967_295,
            state="pending",
        )
    )
    await db_session.commit()
    await db_session.refresh(zone)
    assert zone.last_serial == BIG


@pytest.mark.asyncio
async def test_agent_zone_state_stores_serial_above_int32(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv, zone = await _setup(db_session)
    srv_id, zone_id = srv.id, zone.id
    await db_session.commit()
    db_session.expunge_all()
    app.dependency_overrides[_auth_agent] = lambda: (srv, {})
    try:
        resp = await client.post(
            "/api/v1/dns/agents/zone-state",
            json={"zones": [{"zone_name": "big.example.test.", "serial": BIG}]},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json() == {"updated": 1, "skipped": 0}
        for bad in (-1, 4_294_967_296):
            r = await client.post(
                "/api/v1/dns/agents/zone-state",
                json={"zones": [{"zone_name": "big.example.test.", "serial": bad}]},
            )
            assert r.status_code == 422, bad
    finally:
        app.dependency_overrides.pop(_auth_agent, None)
    row = (
        await db_session.execute(
            select(DNSServerZoneState).where(
                DNSServerZoneState.server_id == srv_id, DNSServerZoneState.zone_id == zone_id
            )
        )
    ).scalar_one_or_none()
    assert row is not None and row.current_serial == BIG


def test_serial_increment_wraps_mod_2_32() -> None:
    now = datetime(2026, 10, 16, tzinfo=UTC)
    # Wraps past 2^32 - 1 to 1, skipping 0 (BIND's increment does the same;
    # 0 is the "never seeded" sentinel that renderers turn into 1).
    assert compute_next_serial(4_294_967_295, now=now) == 1
    assert compute_next_serial(4_294_967_294, now=now) == 4_294_967_295
    assert compute_next_serial(BIG, now=now) == BIG + 1
    # Every step from just below the top is later than its predecessor under
    # RFC 1982 serial arithmetic, including the wrap and the jump back to a
    # date-based serial afterwards.
    cur = 4_294_967_290
    for _ in range(10):
        nxt = compute_next_serial(cur, now=now)
        assert 0 < nxt < 2**32
        assert 0 < (nxt - cur) % 2**32 < 2**31, (cur, nxt)
        cur = nxt
