"""A blank ``allow_recursion`` saves as the default, not as "nobody" (#1817).

An empty list renders ``allow-recursion { none; }`` on BIND9 and ``Deny`` on
Technitium, so clearing the Options field to reset it would lock every client
out of recursion. The group-options PUT stores the default instead; ``none``
stays the way to refuse everyone.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DEFAULT_ALLOW_RECURSION, DNSServer, DNSServerGroup
from app.services.dns.agent_config import render_bundle_body


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@t.io",
        display_name="sa",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    u.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _group(db: AsyncSession, driver: str) -> tuple[DNSServerGroup, DNSServer]:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", is_recursive=True)
    db.add(group)
    await db.flush()
    server = DNSServer(
        group_id=group.id,
        name=f"s-{uuid.uuid4().hex[:6]}",
        driver=driver,
        host=f"h-{uuid.uuid4().hex[:6]}",
        port=53,
    )
    db.add(server)
    await db.flush()
    return group, server


@pytest.mark.asyncio
@pytest.mark.parametrize("driver", ["bind9", "technitium"])
@pytest.mark.parametrize("blank", [[], [""], ["  "]])
async def test_blank_saves_as_the_default(
    client: AsyncClient, db_session: AsyncSession, driver: str, blank: list[str]
) -> None:
    headers = await _superadmin(db_session)
    group, server = await _group(db_session, driver)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/options"
    r = await client.put(url, json={"allow_recursion": ["10.1.0.0/16"]}, headers=headers)
    assert r.status_code == 200, r.text
    r = await client.put(url, json={"allow_recursion": blank}, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["allow_recursion"] == list(DEFAULT_ALLOW_RECURSION)
    body = (await render_bundle_body(db_session, server)).body
    assert body["options"]["allow_recursion"] == list(DEFAULT_ALLOW_RECURSION)


@pytest.mark.asyncio
async def test_none_still_refuses_everyone(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, "bind9")
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        json={"allow_recursion": ["none"]},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["allow_recursion"] == ["none"]


@pytest.mark.asyncio
async def test_an_omitted_field_is_left_alone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, "bind9")
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/options"
    r = await client.put(url, json={"allow_recursion": ["any"]}, headers=headers)
    assert r.status_code == 200, r.text
    r = await client.put(url, json={"forwarders": []}, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["allow_recursion"] == ["any"]
