"""#1812 — GET .../dnssec/info 500'd once an agent had reported keys:
``DNSKey.algorithm`` is an integer column, the response model typed it str."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSKey, DNSServerGroup, DNSZone


async def _headers(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"ka-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="x",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    u.groups = []
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


@pytest.mark.asyncio
async def test_dnssec_info_with_reported_keys(client: AsyncClient, db_session: AsyncSession):
    h = await _headers(db_session)
    g = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(g)
    await db_session.flush()
    z = DNSZone(
        group_id=g.id,
        name="example.test.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.test.",
        admin_email="admin.example.test.",
        dnssec_enabled=True,
    )
    db_session.add(z)
    await db_session.flush()
    for tag, kt, alg in ((1111, "ksk", 13), (2222, "zsk", 99)):
        db_session.add(
            DNSKey(zone_id=z.id, key_tag=tag, key_type=kt, algorithm=alg, state="active")
        )
    await db_session.commit()

    r = await client.get(f"/api/v1/dns/groups/{g.id}/zones/{z.id}/dnssec/info", headers=h)
    assert r.status_code == 200, r.text
    keys = {k["key_tag"]: k for k in r.json()["keys"]}
    assert keys[1111]["algorithm"] == 13
    assert keys[1111]["algorithm_name"] == "ECDSAP256SHA256"
    assert keys[2222]["algorithm"] == 99
    assert keys[2222]["algorithm_name"] is None
