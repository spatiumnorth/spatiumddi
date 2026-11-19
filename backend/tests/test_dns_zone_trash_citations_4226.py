"""#4226 — an ACL / TSIG key cited by a zone in the Trash is not deleted or
renamed from under it, and a zone whose cited name is gone is not restored."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.models.dns import DNSAcl, DNSAclEntry, DNSServerGroup, DNSTSIGKey, DNSZone
from tests.test_dns_acl_zone_references_2283 import _admin


async def _trashed_zone(client, db: AsyncSession, hdr, **zone_kw):
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(group)
    await db.flush()
    acl = DNSAcl(group_id=group.id, name="partners", description="")
    db.add(acl)
    key = DNSTSIGKey(
        group_id=group.id,
        name="xfer-key",
        algorithm="hmac-sha256",
        secret_encrypted=encrypt_str("c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0"),
    )
    db.add(key)
    await db.flush()
    db.add(DNSAclEntry(acl_id=acl.id, value="10.0.0.0/8", negate=False, order=0))
    zone = DNSZone(
        group_id=group.id,
        name="example.test.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.test.",
        admin_email="hostmaster.example.test.",
        **zone_kw,
    )
    db.add(zone)
    await db.commit()
    r = await client.delete(f"/api/v1/dns/groups/{group.id}/zones/{zone.id}", headers=hdr)
    assert r.status_code == 204, r.text
    return group, acl, key, zone


@pytest.mark.asyncio
async def test_acl_delete_and_rename_refused_while_a_trashed_zone_cites_it(
    client: AsyncClient, db_session: AsyncSession
):
    hdr = await _admin(db_session)
    group, acl, _key, _zone = await _trashed_zone(client, db_session, hdr, allow_query=["partners"])
    base = f"/api/v1/dns/groups/{group.id}/acls/{acl.id}"
    for r in (
        await client.delete(base, headers=hdr),
        await client.put(base, json={"name": "renamed"}, headers=hdr),
    ):
        assert r.status_code == 409, r.text
        msg = r.json()["detail"]["message"]
        assert "zone 'example.test. allow_query' in the Trash" in msg
        assert "Administration > Trash" in msg


@pytest.mark.asyncio
async def test_key_delete_and_rename_refused_while_a_trashed_zone_cites_it(
    client: AsyncClient, db_session: AsyncSession
):
    hdr = await _admin(db_session)
    group, _acl, key, _zone = await _trashed_zone(
        client, db_session, hdr, allow_transfer=["key xfer-key"]
    )
    base = f"/api/v1/dns/groups/{group.id}/tsig-keys/{key.id}"
    for r in (
        await client.delete(base, headers=hdr),
        await client.put(base, json={"name": "renamed"}, headers=hdr),
    ):
        assert r.status_code == 409, r.text
        msg = r.json()["detail"]["message"]
        assert "zone 'example.test.' allow_transfer in the Trash" in msg
        assert "Administration > Trash" in msg


@pytest.mark.asyncio
async def test_purging_the_trashed_zone_unblocks_the_acl_delete(
    client: AsyncClient, db_session: AsyncSession
):
    hdr = await _admin(db_session)
    group, acl, _key, zone = await _trashed_zone(client, db_session, hdr, allow_query=["partners"])
    r = await client.delete(f"/api/v1/admin/trash/dns_zone/{zone.id}", headers=hdr)
    assert r.status_code in (200, 204), r.text
    r = await client.delete(f"/api/v1/dns/groups/{group.id}/acls/{acl.id}", headers=hdr)
    assert r.status_code == 204, r.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value,kind,missing",
    [
        ("allow_query", ["partners"], "acl", "ACL 'partners'"),
        ("allow_transfer", ["key xfer-key"], "key", "TSIG key 'xfer-key'"),
    ],
)
async def test_restore_refused_when_the_cited_name_is_gone(
    client: AsyncClient, db_session: AsyncSession, field, value, kind, missing
):
    hdr = await _admin(db_session)
    group, acl, key, zone = await _trashed_zone(client, db_session, hdr, **{field: value})
    # The name goes away by a path the guards do not cover (a row trashed
    # before the guard counted the Trash, a direct DB edit).
    await db_session.delete(acl if kind == "acl" else key)
    await db_session.commit()
    r = await client.post(f"/api/v1/admin/trash/dns_zone/{zone.id}/restore", headers=hdr)
    assert r.status_code == 409, r.text
    assert missing in r.text and "no longer defines" in r.text
    got = await client.get(f"/api/v1/dns/groups/{group.id}/zones/{zone.id}", headers=hdr)
    assert got.status_code == 404  # still in the Trash


@pytest.mark.asyncio
async def test_restore_works_when_the_cited_names_are_defined(
    client: AsyncClient, db_session: AsyncSession
):
    hdr = await _admin(db_session)
    group, _acl, _key, zone = await _trashed_zone(
        client, db_session, hdr, allow_query=["partners"], allow_transfer=["KEY XFER-KEY."]
    )
    r = await client.post(f"/api/v1/admin/trash/dns_zone/{zone.id}/restore", headers=hdr)
    assert r.status_code == 200, r.text
    got = await client.get(f"/api/v1/dns/groups/{group.id}/zones/{zone.id}", headers=hdr)
    assert got.status_code == 200
    assert got.json()["allow_query"] == ["partners"]
