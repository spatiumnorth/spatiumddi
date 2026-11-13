"""#3578 — catalog zones on a BIND9 group with views are flagged, not silent.

named refuses a top-level zone next to views, so the agent publishes no
catalog for such a group; the group response carries the warning the UI shows.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSView
from tests.test_dns_server_group_move import _auth, _group, _server, _superadmin


@pytest.mark.asyncio
async def test_catalog_with_views_warns(client: AsyncClient, db_session: AsyncSession) -> None:
    token = await _superadmin(db_session, "root3578a")
    g = await _group(db_session, "cv", catalog_zones_enabled=True)
    await _server(db_session, g, "ns1", driver="bind9")
    db_session.add(DNSView(group_id=g.id, name="internal"))
    await db_session.commit()
    got = await client.get(f"/api/v1/dns/groups/{g.id}", headers=_auth(token))
    assert "views" in got.json()["catalog_views_warning"]
    listed = await client.get("/api/v1/dns/groups", headers=_auth(token))
    row = next(r for r in listed.json() if r["id"] == str(g.id))
    assert row["catalog_views_warning"]


@pytest.mark.asyncio
async def test_no_warning_without_views_or_without_catalog(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root3578b")
    flat = await _group(db_session, "flat", catalog_zones_enabled=True)
    await _server(db_session, flat, "ns1", driver="bind9")
    off = await _group(db_session, "off", catalog_zones_enabled=False)
    await _server(db_session, off, "ns2", driver="bind9")
    db_session.add(DNSView(group_id=off.id, name="internal"))
    await db_session.commit()
    for g in (flat, off):
        got = await client.get(f"/api/v1/dns/groups/{g.id}", headers=_auth(token))
        assert got.json()["catalog_views_warning"] is None
