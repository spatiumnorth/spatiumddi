"""#4391 — the refusal of a pool row's edit / delete spells its verb."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSPool, DNSRecord, DNSServerGroup, DNSZone
from app.services.dns.pool_apply import apply_pool_state


async def _setup(db: AsyncSession) -> tuple[dict, uuid.UUID, uuid.UUID]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add_all([user, grp])
    await db.flush()
    zone = DNSZone(
        group_id=grp.id,
        name="p1.test.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.p1.test.",
        admin_email="admin.p1.test.",
    )
    db.add(zone)
    await db.commit()
    h = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    return h, grp.id, zone.id


async def _make_pool(client: AsyncClient, h: dict, gid, zid) -> None:
    r = await client.post(
        f"/api/v1/dns/groups/{gid}/zones/{zid}/pools",
        headers=h,
        json={
            "name": "p",
            "record_name": "www",
            "record_type": "A",
            "hc_type": "none",
            "members": [{"address": "192.0.2.46"}],
        },
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_pool_record_refusal_spells_its_verb(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#4391 — "deleted" / "edited", and no pointer to a door an editor lacks."""
    h, gid, zid = await _setup(db_session)
    await _make_pool(client, h, gid, zid)
    pool = (await db_session.execute(select(DNSPool))).scalar_one()
    await db_session.refresh(pool, ["members"])
    for m in pool.members:
        m.last_check_state = "healthy"
    await apply_pool_state(db_session, pool)
    await db_session.commit()
    rec = (await db_session.execute(select(DNSRecord))).scalar_one()
    r = await client.delete(f"/api/v1/dns/groups/{gid}/zones/{zid}/records/{rec.id}", headers=h)
    assert r.status_code == 422, r.text
    assert "cannot be deleted manually" in r.text
    r = await client.put(
        f"/api/v1/dns/groups/{gid}/zones/{zid}/records/{rec.id}", headers=h, json={"ttl": 60}
    )
    assert r.status_code == 422, r.text
    assert "cannot be edited manually" in r.text
