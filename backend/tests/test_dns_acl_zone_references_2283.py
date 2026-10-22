"""Renaming / deleting an ACL cited by a zone must not break the group (#2283)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSAcl, DNSAclEntry, DNSServer, DNSServerGroup, DNSZone
from app.services.dns.agent_config import build_config_bundle


async def _admin(db: AsyncSession) -> dict[str, str]:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"a-{tag}",
        email=f"{tag}@example.com",
        display_name="A",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _setup(db: AsyncSession, **zone_kw) -> tuple[DNSServerGroup, DNSAcl]:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(group)
    await db.flush()
    acl = DNSAcl(group_id=group.id, name="partners", description="")
    db.add(acl)
    await db.flush()
    db.add(DNSAclEntry(acl_id=acl.id, value="10.0.0.0/8", negate=False, order=0))
    if zone_kw:
        db.add(
            DNSZone(
                group_id=group.id,
                name="example.test.",
                zone_type="primary",
                kind="forward",
                primary_ns="ns1.example.test.",
                admin_email="hostmaster.example.test.",
                **zone_kw,
            )
        )
    await db.flush()
    return group, acl


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["allow_query", "allow_transfer"])
async def test_rename_and_delete_of_a_zone_cited_acl_are_refused(
    client: AsyncClient, db_session, field
):
    hdr = await _admin(db_session)
    group, acl = await _setup(db_session, **{field: ["partners"]})
    base = f"/api/v1/dns/groups/{group.id}/acls/{acl.id}"
    r = await client.put(base, json={"name": "renamed"}, headers=hdr)
    assert r.status_code == 409, r.text
    assert "example.test." in r.json()["detail"]["message"]
    r = await client.delete(base, headers=hdr)
    assert r.status_code == 409, r.text
    assert (await db_session.get(DNSAcl, acl.id)) is not None


@pytest.mark.asyncio
async def test_uncited_acl_renames_and_deletes(client: AsyncClient, db_session):
    hdr = await _admin(db_session)
    group, acl = await _setup(db_session, allow_query=["10.1.0.0/16"])
    base = f"/api/v1/dns/groups/{group.id}/acls/{acl.id}"
    r = await client.put(base, json={"name": "renamed"}, headers=hdr)
    assert r.status_code == 200, r.text
    r = await client.delete(base, headers=hdr)
    assert r.status_code == 204, r.text


@pytest.mark.asyncio
async def test_bundle_drops_dangling_zone_acl_and_stays_deny(db_session):
    group, _ = await _setup(
        db_session,
        allow_query=["gone-acl"],
        allow_transfer=["gone-acl", "192.0.2.0/24"],
        also_notify=["192.0.2.10"],
    )
    server = DNSServer(group_id=group.id, name="s1", driver="bind9", host="127.0.0.1", port=53)
    db_session.add(server)
    await db_session.flush()
    loaded = (
        await db_session.execute(select(DNSServer).where(DNSServer.id == server.id))
    ).scalar_one()
    bundle = await build_config_bundle(db_session, loaded)
    (z,) = [z for z in bundle["zones"] if z["name"] == "example.test."]
    assert "gone-acl" not in str(bundle["zones"])
    # Emptied allow-query must be deny, never absent (= inherit the server's).
    assert z["allow_query"] == ["none"]
    assert z["allow_transfer"] == ["192.0.2.0/24"]
    assert z["also_notify"] == ["192.0.2.10"]


@pytest.mark.asyncio
async def test_bundle_keeps_a_defined_zone_acl(db_session):
    group, _ = await _setup(db_session, allow_query=["partners"])
    server = DNSServer(group_id=group.id, name="s1", driver="bind9", host="127.0.0.1", port=53)
    db_session.add(server)
    await db_session.flush()
    loaded = (
        await db_session.execute(select(DNSServer).where(DNSServer.id == server.id))
    ).scalar_one()
    bundle = await build_config_bundle(db_session, loaded)
    (z,) = [z for z in bundle["zones"] if z["name"] == "example.test."]
    assert z["allow_query"] == ["partners"]
