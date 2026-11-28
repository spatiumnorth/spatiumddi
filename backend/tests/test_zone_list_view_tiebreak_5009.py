"""#5009 — zones sharing a name across views list in a stable, view-ordered order.

Zone lists sorted by name only, so the two ``example.test.`` zones (one per
view) tied and PostgreSQL returned them in heap order. The rows are inserted
here in the OPPOSITE of the expected order (descending view id), so an
unbroken ``ORDER BY name`` returns them reversed every time.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSView, DNSZone


async def _setup(
    db: AsyncSession, descending: bool = True
) -> tuple[dict[str, str], DNSServerGroup, DNSServer, list[str]]:
    u = User(
        username="zt5009",
        email="zt5009@example.com",
        display_name="zt5009",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    g = DNSServerGroup(name="g5009")
    db.add_all([u, g])
    await db.flush()
    srv = DNSServer(group_id=g.id, name="s5009", driver="bind9", host="10.50.9.1")
    views = [DNSView(group_id=g.id, name=f"v5009-{i}") for i in range(4)]
    db.add_all([srv, *views])
    await db.flush()
    expected = sorted(str(v.id) for v in views)
    # Insert in descending view-id order so heap order is the reverse of the
    # expected order; also a name sorting before the shared one.
    for vid in reversed(expected) if descending else expected:
        db.add(DNSZone(group_id=g.id, view_id=vid, name="example.test.", primary_ns="ns.test."))
    await db.flush()
    h = {"Authorization": f"Bearer {create_access_token(str(u.id))}"}
    return h, g, srv, expected


@pytest.mark.asyncio
@pytest.mark.parametrize("descending", [True, False])
async def test_zone_list_stable_view_order(
    client: AsyncClient, db_session: AsyncSession, descending: bool
) -> None:
    h, g, _srv, expected = await _setup(db_session, descending)
    for _ in range(5):
        r = await client.get(f"/api/v1/dns/groups/{g.id}/zones", headers=h)
        assert r.status_code == 200, r.text
        assert [z["view_id"] for z in r.json()] == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("descending", [True, False])
async def test_server_zone_state_stable_view_order(
    client: AsyncClient, db_session: AsyncSession, descending: bool
) -> None:
    h, g, srv, expected = await _setup(db_session, descending)
    from sqlalchemy import select

    by_id = {
        str(z.id): str(z.view_id)
        for z in (await db_session.execute(select(DNSZone).where(DNSZone.group_id == g.id)))
        .scalars()
        .all()
    }
    r = await client.get(f"/api/v1/dns/servers/{srv.id}/zone-state", headers=h)
    assert r.status_code == 200, r.text
    zones = r.json()["zones"]
    assert [by_id[z["zone_id"]] for z in zones] == expected
