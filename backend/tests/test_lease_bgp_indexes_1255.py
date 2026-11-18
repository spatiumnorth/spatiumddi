"""spatiumddi#1255 — the lease-expiry sweep and BGP containment queries have indexes.

Planner choice is not asserted from cost: ``enable_seqscan = off`` makes an
unusable index the only way the assertion can fail.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, or_, select, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.bgp_looking_glass import BGPLGRoute
from app.models.dhcp import DHCPLease
from app.models.ipam import Subnet


async def _plan(db: AsyncSession, stmt) -> str:  # type: ignore[no-untyped-def]
    sql = str(stmt.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
    await db.execute(text("SET LOCAL enable_seqscan = off"))
    await db.execute(text("SET LOCAL enable_material = off"))
    return "\n".join(r[0] for r in (await db.execute(text("EXPLAIN " + sql))).all())


@pytest.mark.asyncio
async def test_lease_expiry_sweep_uses_partial_index(db_session: AsyncSession) -> None:
    stmt = select(DHCPLease.id).where(
        DHCPLease.state == "active", DHCPLease.expires_at < text("now()")
    )
    assert "ix_dhcp_lease_active_expires_at" in await _plan(db_session, stmt)


@pytest.mark.asyncio
async def test_bgp_route_containment_uses_gist(db_session: AsyncSession) -> None:
    net = "10.1.0.0/16"
    stmt = select(BGPLGRoute.id).where(
        or_(
            BGPLGRoute.prefix.op(">>=")(func.inet(net)), BGPLGRoute.prefix.op("<<=")(func.inet(net))
        )
    )
    assert "ix_bgp_lg_route_prefix_gist" in await _plan(db_session, stmt)
    stmt = select(BGPLGRoute.id).where(BGPLGRoute.prefix.op(">>=")(func.inet("10.1.2.3")))
    assert "ix_bgp_lg_route_prefix_gist" in await _plan(db_session, stmt)


@pytest.mark.asyncio
async def test_bgp_covering_exists_uses_gist(db_session: AsyncSession) -> None:
    covering = (
        select(BGPLGRoute.id)
        .where(BGPLGRoute.withdrawn_at.is_(None), BGPLGRoute.prefix.op(">>=")(Subnet.network))
        .correlate(Subnet)
        .exists()
    )
    plan = await _plan(db_session, select(Subnet.id).where(~covering))
    assert "ix_bgp_lg_route_prefix_gist" in plan, plan
