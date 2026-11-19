"""Technitium cannot apply an allow-notify list, nor a non-address also-notify
entry; the API refuses both rather than storing a value the daemon ignores
(#2267). What it can apply is accepted."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@t.io",
        display_name="sa",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    u.groups = []
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _group(db: AsyncSession, driver: str) -> DNSServerGroup:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    db.add(
        DNSServer(
            group_id=group.id,
            name=f"s-{uuid.uuid4().hex[:6]}",
            driver=driver,
            host=f"h-{uuid.uuid4().hex[:6]}",
            port=53,
        )
    )
    await db.flush()
    return group


@pytest.mark.asyncio
async def test_group_allow_notify_is_a_422_on_technitium(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group = await _group(db_session, "technitium")
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/options"
    r = await client.put(url, json={"allow_notify": ["10.0.0.1"]}, headers=headers)
    assert r.status_code == 422, r.text
    assert "allow_notify" in str(r.json()["detail"])
    # Empty is the default, and the form re-posts it on every save.
    r = await client.put(url, json={"allow_notify": []}, headers=headers)
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_group_also_notify_must_be_bare_addresses_on_technitium(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group = await _group(db_session, "technitium")
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/options"
    r = await client.put(url, json={"also_notify": ["10.0.0.1 port 5353"]}, headers=headers)
    assert r.status_code == 422, r.text
    assert "also_notify" in str(r.json()["detail"])
    r = await client.put(url, json={"also_notify": ["10.0.0.1", "2001:db8::1"]}, headers=headers)
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_a_bind_group_keeps_allow_notify(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group = await _group(db_session, "bind9")
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        json={"allow_notify": ["10.0.0.1"], "also_notify": ["10.0.0.2 port 5353"]},
        headers=headers,
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_zone_also_notify_is_gated_on_technitium(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group = await _group(db_session, "technitium")
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/zones"
    r = await client.post(
        url,
        json={"name": "n.test.", "zone_type": "primary", "also_notify": ["10.0.0.1 port 5353"]},
        headers=headers,
    )
    assert r.status_code == 422, r.text
    r = await client.post(
        url,
        json={"name": "n.test.", "zone_type": "primary", "also_notify": ["10.0.0.1"]},
        headers=headers,
    )
    assert r.status_code == 201, r.text
