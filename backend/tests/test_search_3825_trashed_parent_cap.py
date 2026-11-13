"""Rows under a trashed parent must not eat the per-type fetch cap (#3825)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord
from app.services.search import engine, execute
from tests.test_search import _address, _space, _subnet, _user, _zone_with_record

pytestmark = pytest.mark.asyncio


async def _types(db: AsyncSession, user, q: str, rtype: str) -> list[str]:
    resp = await execute(db, user, q, types={rtype}, limit=25)
    return [r.display for r in resp.results if r.type == rtype]


async def test_trashed_subnet_addresses_do_not_hide_live_ones(db_session: AsyncSession) -> None:
    user, _ = await _user(db_session, superadmin=True)
    space = await _space(db_session, "s3825")
    dead = await _subnet(db_session, space, "10.20.2.0/24")
    live = await _subnet(db_session, space, "10.20.3.0/24")
    for i in range(1, engine.FETCH_CAP + 11):
        await _address(db_session, dead, f"10.20.2.{i}", hostname=f"zz3825-t{i}")
    for i in range(1, 4):
        await _address(db_session, live, f"10.20.3.{i}", hostname=f"zz3825-l{i}")
    dead.deleted_at = datetime.now(UTC)
    await db_session.flush()

    got = await _types(db_session, user, "zz3825", "ip_address")
    assert sorted(got) == ["10.20.3.1", "10.20.3.2", "10.20.3.3"]


async def test_trashed_zone_records_do_not_hide_live_ones(db_session: AsyncSession) -> None:
    user, _ = await _user(db_session, superadmin=True)
    _g, dead_zone, _r = await _zone_with_record(db_session, "dead3825.test.", "a0.dead3825.test.")
    for i in range(1, engine.FETCH_CAP + 11):
        db_session.add(
            DNSRecord(
                zone_id=dead_zone.id,
                name=f"a{i}",
                fqdn=f"a{i}.dead3825.test.",
                record_type="A",
                value="10.0.0.1",
                ttl=300,
            )
        )
    await _zone_with_record(db_session, "live3825.test.", "zz.live3825.test.")
    await db_session.flush()
    dead_zone.deleted_at = datetime.now(UTC)
    await db_session.flush()

    got = await _types(db_session, user, "3825.test", "dns_record")
    assert got == ["zz.live3825.test."]
