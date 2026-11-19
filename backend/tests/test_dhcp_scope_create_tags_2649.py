"""#2649 — creating a DHCP scope keeps its tags."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_dhcp_scope_group_immutable_2479 import _make_token, _subnet_and_group


async def _create(client: AsyncClient, db: AsyncSession, **extra):
    token = await _make_token(db)
    subnet, grp = await _subnet_and_group(db)
    await db.commit()
    h = {"Authorization": f"Bearer {token}"}
    r = await client.post(
        f"/api/v1/dhcp/subnets/{subnet.id}/dhcp-scopes",
        headers=h,
        json={"group_id": str(grp.id), "name": "s", **extra},
    )
    assert r.status_code in (200, 201), r.text
    return h, r.json(), grp


async def test_create_scope_keeps_tags(client: AsyncClient, db_session: AsyncSession) -> None:
    h, scope, _ = await _create(client, db_session, tags={"env": "prod"})
    assert scope["tags"] == {"env": "prod"}
    got = (await client.get(f"/api/v1/dhcp/scopes/{scope['id']}", headers=h)).json()
    assert got["tags"] == {"env": "prod"}
