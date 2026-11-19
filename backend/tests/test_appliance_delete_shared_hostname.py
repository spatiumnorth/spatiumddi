"""Deleting one appliance never removes servers owned by another (#1810).

A re-imaged / re-paired box leaves a second appliance row with the same
hostname as the live one. Delete and its preview must remove only rows
provably the deleted appliance's own: an FK match, or (approved appliance
only) an unambiguous hostname match.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    APPLIANCE_STATE_REVOKED,
    Appliance,
)
from app.models.auth import User
from app.models.dhcp import DHCPServer
from app.models.dns import DNSServer, DNSServerGroup

PW = "test-pw-1810"


async def _admin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"admin-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Admin",
        hashed_password=hash_password(PW),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _appliance(db: AsyncSession, hostname: str, state: str) -> Appliance:
    a = Appliance(
        id=uuid.uuid4(),
        hostname=hostname,
        state=state,
        public_key_der=b"k",
        public_key_fingerprint=uuid.uuid4().hex * 2,
        cert_serial=uuid.uuid4().hex[:8],
    )
    db.add(a)
    await db.flush()
    return a


async def _servers(
    db: AsyncSession, host: str, appliance_id: uuid.UUID | None = None
) -> tuple[DNSServer, DHCPServer]:
    g = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:8]}", description="")
    db.add(g)
    await db.flush()
    dns = DNSServer(
        group_id=g.id,
        name=f"dns-{uuid.uuid4().hex[:6]}",
        driver="technitium",
        host=host,
        port=53,
        roles=["authoritative"],
        status="active",
        agent_id=uuid.uuid4(),
        appliance_id=appliance_id,
    )
    dhcp = DHCPServer(
        name=f"dhcp-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host=host,
        port=67,
        status="active",
        agent_id=uuid.uuid4(),
        appliance_id=appliance_id,
        ha_peer_url="http://10.0.0.2:8000/",
    )
    db.add_all([dns, dhcp])
    await db.flush()
    return dns, dhcp


async def _delete_and_check(
    client: AsyncClient,
    db: AsyncSession,
    headers: dict[str, str],
    victim: Appliance,
    keep: list[DNSServer | DHCPServer],
    gone: list[DNSServer | DHCPServer],
) -> None:
    vid = victim.id
    keep_ids = [(type(s), s.id) for s in keep]
    gone_ids = [(type(s), s.id) for s in gone]
    await db.commit()
    prev = await client.get(f"/api/v1/appliance/appliances/{vid}/dependents", headers=headers)
    assert prev.status_code == 200, prev.text
    listed = {d["id"] for d in prev.json()["dns"] + prev.json()["dhcp"]}
    for _, i in keep_ids:
        assert str(i) not in listed
    for _, i in gone_ids:
        assert str(i) in listed
    r = await client.request(
        "DELETE",
        f"/api/v1/appliance/appliances/{vid}",
        headers=headers,
        json={"password": PW},
    )
    assert r.status_code == 200, r.text
    db.expire_all()
    for m, i in keep_ids:
        assert (await db.execute(select(m).where(m.id == i))).scalar_one_or_none() is not None
    for m, i in gone_ids:
        assert (await db.execute(select(m).where(m.id == i))).scalar_one_or_none() is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "dup_state", [APPLIANCE_STATE_APPROVED, "pending", APPLIANCE_STATE_REVOKED]
)
@pytest.mark.parametrize("dup_host", ["ddipg-seed", "DDIPG-Seed"])
async def test_deleting_duplicate_keeps_live_appliances_servers(
    client: AsyncClient, db_session: AsyncSession, dup_state: str, dup_host: str
) -> None:
    headers = await _admin(db_session)
    await _appliance(db_session, "ddipg-seed", APPLIANCE_STATE_APPROVED)
    dup = await _appliance(db_session, dup_host, dup_state)
    dns, dhcp = await _servers(db_session, "ddipg-seed")
    await _delete_and_check(client, db_session, headers, dup, keep=[dns, dhcp], gone=[])


@pytest.mark.asyncio
@pytest.mark.parametrize("dup_state", ["pending", APPLIANCE_STATE_REVOKED])
async def test_unapproved_appliance_does_not_claim_servers_by_hostname(
    client: AsyncClient, db_session: AsyncSession, dup_state: str
) -> None:
    """No approved appliance shares the hostname, but the deleted row never
    ran an agent either: a host-only match is not provable ownership."""
    headers = await _admin(db_session)
    dup = await _appliance(db_session, "orphan-host", dup_state)
    dns, dhcp = await _servers(db_session, "orphan-host")
    await _delete_and_check(client, db_session, headers, dup, keep=[dns, dhcp], gone=[])


@pytest.mark.asyncio
async def test_fk_owned_rows_follow_the_fk_not_the_hostname(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    live = await _appliance(db_session, "shared", APPLIANCE_STATE_APPROVED)
    dup = await _appliance(db_session, "shared", "pending")
    live_dns, live_dhcp = await _servers(db_session, "shared", live.id)
    dup_dns, dup_dhcp = await _servers(db_session, "shared", dup.id)
    await _delete_and_check(
        client, db_session, headers, dup, keep=[live_dns, live_dhcp], gone=[dup_dns, dup_dhcp]
    )


@pytest.mark.asyncio
async def test_lone_approved_appliance_still_sweeps_its_hostname_rows(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    a = await _appliance(db_session, "Lone-Node", APPLIANCE_STATE_APPROVED)
    dns, dhcp = await _servers(db_session, "lone-node")
    await _delete_and_check(client, db_session, headers, a, keep=[], gone=[dns, dhcp])
