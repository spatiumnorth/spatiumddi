"""A DoT group's forwarder pinned to port 53 is refused (#2128).

``10.0.0.1@53`` rendered as ``port 53 tls spatium-upstream-tls``: TLS to a
plaintext port. The API now refuses it; only entries a request introduces are
checked so a value stored earlier does not block an unrelated save.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServerGroup, DNSServerOptions

TLS = {"forward_transport": "tls", "forward_tls_hostname": "dns.example.net"}


async def _setup(db: AsyncSession, **opts) -> tuple[str, dict[str, str]]:
    u = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@t.io",
        display_name="sa",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    u.groups = []
    db.add(u)
    g = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(g)
    await db.flush()
    if opts:
        db.add(DNSServerOptions(group_id=g.id, **opts))
    await db.commit()
    return (
        f"/api/v1/dns/groups/{g.id}/options",
        {"Authorization": f"Bearer {create_access_token(str(u.id))}"},
    )


@pytest.mark.asyncio
async def test_new_port53_forwarder_in_a_dot_group_is_refused(
    client: AsyncClient, db_session: AsyncSession
):
    url, h = await _setup(db_session)
    r = await client.put(url, json={**TLS, "forwarders": ["10.0.0.1@53"]}, headers=h)
    assert r.status_code == 422, r.text
    assert "10.0.0.1@53" in r.json()["detail"]
    # nothing saved
    r = await client.put(url, json={**TLS, "forwarders": ["10.0.0.1", "10.0.0.2@853"]}, headers=h)
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_switching_to_dot_checks_the_stored_forwarders(
    client: AsyncClient, db_session: AsyncSession
):
    url, h = await _setup(db_session, forwarders=["10.0.0.1@53"], forward_transport="do53")
    r = await client.put(url, json=TLS, headers=h)
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_do53_group_keeps_port53(client: AsyncClient, db_session: AsyncSession):
    url, h = await _setup(db_session)
    r = await client.put(url, json={"forwarders": ["10.0.0.1@53"]}, headers=h)
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_stored_port53_does_not_block_an_unrelated_save(
    client: AsyncClient, db_session: AsyncSession
):
    url, h = await _setup(db_session, forwarders=["10.0.0.1@53"], **TLS)
    r = await client.put(
        url, json={**TLS, "forwarders": ["10.0.0.1@53"], "rrl_window": 20}, headers=h
    )
    assert r.status_code == 200, r.text
    # adding another is checked
    r = await client.put(url, json={**TLS, "forwarders": ["10.0.0.1@53", "10.0.0.9@53"]}, headers=h)
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_port53_spellings_and_other_ports(client: AsyncClient, db_session: AsyncSession):
    url, h = await _setup(db_session)
    # A leading zero is still port 53 to BIND; the validator accepts it.
    for bad in ("10.0.0.1@053", "2001:db8::1@53", "10.0.0.1 @ 53"):
        r = await client.put(url, json={**TLS, "forwarders": [bad]}, headers=h)
        assert r.status_code == 422, (bad, r.text)
    # Other explicit ports are the operator's call, and v6 without a port is fine.
    r = await client.put(
        url,
        json={**TLS, "forwarders": ["10.0.0.1@5353", "2001:db8::1", "2001:db8::2@853"]},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert r.json()["forwarder_warnings"] == []


@pytest.mark.asyncio
async def test_stored_port53_is_reported_on_get(client: AsyncClient, db_session: AsyncSession):
    url, h = await _setup(db_session, forwarders=["10.0.0.1@53", "10.0.0.2"], **TLS)
    r = await client.get(url, headers=h)
    assert r.status_code == 200, r.text
    warnings = r.json()["forwarder_warnings"]
    assert len(warnings) == 1 and "10.0.0.1@53" in warnings[0]


@pytest.mark.asyncio
async def test_do53_group_reports_no_forwarder_warning(
    client: AsyncClient, db_session: AsyncSession
):
    url, h = await _setup(db_session, forwarders=["10.0.0.1@53"], forward_transport="do53")
    r = await client.get(url, headers=h)
    assert r.json()["forwarder_warnings"] == []
