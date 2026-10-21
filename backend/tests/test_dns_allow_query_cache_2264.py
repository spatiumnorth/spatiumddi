"""Group ``allow_query_cache`` takes effect or is refused (#2264)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.drivers.dns.base import ServerOptions
from app.drivers.dns.bind9 import BIND9Driver
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSServerOptions
from app.services.dns.agent_config import render_bundle_body


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
async def test_bind9_bundle_carries_a_set_value_and_omits_the_default(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group, server = await _group(db_session, "bind9")
    await db_session.commit()
    body = (await render_bundle_body(db_session, server)).body
    assert "allow_query_cache" not in body["options"]  # untouched group: unchanged bundle
    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        json={"allow_query_cache": ["10.0.0.0/8"]},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    body = (await render_bundle_body(db_session, server)).body
    assert body["options"]["allow_query_cache"] == ["10.0.0.0/8"]


@pytest.mark.asyncio
async def test_powerdns_bundle_never_carries_it(db_session: AsyncSession) -> None:
    group, server = await _group(db_session, "powerdns")
    db_session.add(DNSServerOptions(group_id=group.id, allow_query_cache=["10.0.0.0/8"]))
    await db_session.commit()
    body = (await render_bundle_body(db_session, server)).body
    assert "allow_query_cache" not in body["options"]


@pytest.mark.asyncio
@pytest.mark.parametrize("driver", ["powerdns", "technitium"])
async def test_non_default_refused_where_the_daemon_cannot_apply_it(
    client: AsyncClient, db_session: AsyncSession, driver: str
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, driver)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/options"
    r = await client.put(url, json={"allow_query_cache": ["10.0.0.0/8"]}, headers=headers)
    assert r.status_code == 422, r.text
    assert "allow_query_cache" in r.text
    # Re-posting the default is the way out and stays allowed.
    r = await client.put(
        url, json={"allow_query_cache": ["localhost", "localnets"]}, headers=headers
    )
    assert r.status_code == 200, r.text


def test_control_plane_template_agrees_with_the_agent_on_a_set_value() -> None:
    conf = BIND9Driver().render_server_config(
        None, ServerOptions(allow_query_cache=("10.0.0.0/8", "localhost"))
    )
    assert "allow-query-cache { 10.0.0.0/8; localhost; };" in conf
