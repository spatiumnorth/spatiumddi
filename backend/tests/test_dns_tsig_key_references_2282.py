"""Renaming / deleting a cited TSIG key must not break the group (#2282).

``key <name>`` is cited from ACL entries, view match lists, the group's
address-match options and ``also_notify``, and zone ``allow_*`` /
``also_notify``. Removing the name left an undefined symbol in
``named.conf``: ``named-checkconf`` failed, the agent declined the whole
bundle, and the group stopped converging.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import (
    DNSAcl,
    DNSAclEntry,
    DNSServer,
    DNSServerGroup,
    DNSServerOptions,
    DNSTSIGKey,
    DNSView,
    DNSZone,
    DNSZoneUpdateAcl,
)
from app.services.dns.agent_config import build_config_bundle

KEY = "ext-key"


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


async def _group_with_key(db: AsyncSession) -> tuple[DNSServerGroup, DNSTSIGKey]:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(group)
    await db.flush()
    key = DNSTSIGKey(
        group_id=group.id,
        name=KEY,
        algorithm="hmac-sha256",
        secret_encrypted=encrypt_str("c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0"),
    )
    db.add(key)
    await db.flush()
    return group, key


async def _zone(db: AsyncSession, group: DNSServerGroup, **kw) -> DNSZone:
    z = DNSZone(
        group_id=group.id,
        name="example.test.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.test.",
        admin_email="hostmaster.example.test.",
        **kw,
    )
    db.add(z)
    await db.flush()
    return z


async def _cite(db: AsyncSession, group: DNSServerGroup, where: str) -> None:
    cite = f"key {KEY}"
    if where == "acl":
        acl = DNSAcl(group_id=group.id, name="partners", description="")
        db.add(acl)
        await db.flush()
        db.add(DNSAclEntry(acl_id=acl.id, value=cite, negate=False, order=0))
    elif where == "view":
        db.add(DNSView(group_id=group.id, name="ext", match_clients=[cite]))
    elif where == "option":
        db.add(DNSServerOptions(group_id=group.id, allow_transfer=[cite]))
    elif where == "option_also_notify":
        db.add(DNSServerOptions(group_id=group.id, also_notify=[f"192.0.2.9 key {KEY}"]))
    elif where == "zone_allow_transfer":
        await _zone(db, group, allow_transfer=[cite])
    elif where == "zone_allow_query":
        await _zone(db, group, allow_query=[cite])
    elif where == "zone_also_notify":
        await _zone(db, group, also_notify=[f"192.0.2.9 key {KEY}"])
    await db.flush()


WHERES = [
    "acl",
    "view",
    "option",
    "option_also_notify",
    "zone_allow_transfer",
    "zone_allow_query",
    "zone_also_notify",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("where", WHERES)
async def test_rename_of_a_cited_key_is_refused(client: AsyncClient, db_session, where):
    hdr = await _admin(db_session)
    group, key = await _group_with_key(db_session)
    await _cite(db_session, group, where)
    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/tsig-keys/{key.id}", json={"name": "renamed"}, headers=hdr
    )
    assert r.status_code == 409, r.text
    assert KEY in r.json()["detail"]["message"]
    assert len(r.json()["detail"]["references"]) == 1
    await db_session.refresh(key)
    assert key.name == KEY


@pytest.mark.asyncio
@pytest.mark.parametrize("where", WHERES)
async def test_delete_of_a_cited_key_is_refused(client: AsyncClient, db_session, where):
    hdr = await _admin(db_session)
    group, key = await _group_with_key(db_session)
    await _cite(db_session, group, where)
    r = await client.delete(f"/api/v1/dns/groups/{group.id}/tsig-keys/{key.id}", headers=hdr)
    assert r.status_code == 409, r.text
    assert KEY in r.json()["detail"]["message"]
    assert (await db_session.get(DNSTSIGKey, key.id)) is not None


@pytest.mark.asyncio
async def test_unreferenced_key_renames_and_deletes(client: AsyncClient, db_session):
    hdr = await _admin(db_session)
    group, key = await _group_with_key(db_session)
    base = f"/api/v1/dns/groups/{group.id}/tsig-keys/{key.id}"
    r = await client.put(base, json={"name": "renamed"}, headers=hdr)
    assert r.status_code == 200, r.text
    assert r.json()["name"] == "renamed"
    # Metadata-only edits of a cited key still work (same name re-posted).
    r = await client.delete(base, headers=hdr)
    assert r.status_code == 204, r.text


@pytest.mark.asyncio
async def test_same_name_resave_of_a_cited_key_is_allowed(client: AsyncClient, db_session):
    hdr = await _admin(db_session)
    group, key = await _group_with_key(db_session)
    await _cite(db_session, group, "acl")
    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/tsig-keys/{key.id}",
        json={"name": KEY, "notes": "n"},
        headers=hdr,
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_delete_reports_removed_update_grants(client: AsyncClient, db_session):
    hdr = await _admin(db_session)
    group, key = await _group_with_key(db_session)
    zone = await _zone(db_session, group)
    db_session.add(
        DNSZoneUpdateAcl(
            zone_id=zone.id,
            seq=0,
            action="grant",
            match_kind="tsig_key",
            tsig_key_id=key.id,
            name_scope="zonesub",
        )
    )
    await db_session.flush()
    r = await client.delete(f"/api/v1/dns/groups/{group.id}/tsig-keys/{key.id}", headers=hdr)
    assert r.status_code == 204, r.text
    assert r.headers.get("x-removed-update-grants") == "1"


@pytest.mark.asyncio
async def test_bundle_drops_a_stored_dangling_key_reference(db_session):
    """A row stored before the guard (or written around the API) cannot reach
    ``named.conf``: the bundle omits the undefined ``key`` element."""
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(group)
    await db_session.flush()
    dangling = "key gone-key"
    acl = DNSAcl(group_id=group.id, name="partners", description="")
    db_session.add(acl)
    await db_session.flush()
    db_session.add(DNSAclEntry(acl_id=acl.id, value=dangling, negate=False, order=0))
    db_session.add(DNSAclEntry(acl_id=acl.id, value="10.0.0.0/8", negate=False, order=1))
    db_session.add(DNSView(group_id=group.id, name="ext", match_clients=[dangling, "10.1.0.0/16"]))
    db_session.add(
        DNSServerOptions(
            group_id=group.id,
            allow_transfer=[dangling, "192.0.2.0/24"],
            also_notify=["192.0.2.9 key gone-key", "192.0.2.10"],
        )
    )
    await _zone(
        db_session, group, allow_transfer=[dangling], also_notify=["192.0.2.9 key gone-key"]
    )
    server = DNSServer(group_id=group.id, name="s1", driver="bind9", host="127.0.0.1", port=53)
    db_session.add(server)
    await db_session.flush()
    loaded = (
        await db_session.execute(select(DNSServer).where(DNSServer.id == server.id))
    ).scalar_one()
    bundle = await build_config_bundle(db_session, loaded)

    assert "gone-key" not in str(bundle["acls"])
    assert bundle["acls"][0]["entries"] == [{"value": "10.0.0.0/8", "negate": False}]
    (view,) = [v for v in bundle["views"] if v["name"] == "ext"]
    assert view["match_clients"] == ["10.1.0.0/16"]
    assert bundle["options"]["allow_transfer"] == ["192.0.2.0/24"]
    assert bundle["options"]["also_notify"] == ["192.0.2.10"]
    zones = [z for z in bundle["zones"] if z["name"] == "example.test."]
    # Emptied access lists fail CLOSED (``none``), never empty — see below.
    assert zones and all(z["allow_transfer"] == ["none"] and z["also_notify"] == [] for z in zones)


async def _bundle_for(db: AsyncSession, group: DNSServerGroup) -> dict:
    server = DNSServer(group_id=group.id, name="s1", driver="bind9", host="127.0.0.1", port=53)
    db.add(server)
    await db.flush()
    loaded = (await db.execute(select(DNSServer).where(DNSServer.id == server.id))).scalar_one()
    return await build_config_bundle(db, loaded)


@pytest.mark.asyncio
async def test_a_list_emptied_by_the_drop_fails_closed(db_session):
    """Dropping the only element must not WIDEN access. Every renderer reads
    an empty address-match list as "unset": the BIND9 agent renders an empty
    ``match-clients`` / options ``allow-query`` as ``any`` and omits an empty
    zone / view ``allow-query`` so it inherits. A key-only list therefore
    ships as ``none`` — which is what it effectively said once the key was
    gone — and a negated-only list too."""
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(group)
    await db_session.flush()
    gone = "key gone-key"
    db_session.add(
        DNSView(
            group_id=group.id,
            name="ext",
            match_clients=[gone],
            match_destinations=[f"!{gone}"],
            allow_query=[gone],
            # A dropped negation collapses the list too, survivors or not.
            allow_query_cache=[f"!{gone}", "10.0.0.0/8"],
        )
    )
    db_session.add(
        DNSServerOptions(
            group_id=group.id,
            allow_query=[gone],
            allow_query_cache=[gone],
            allow_recursion=[gone],
            allow_transfer=[gone],
            allow_notify=[gone],
            also_notify=["192.0.2.9 key gone-key"],
        )
    )
    await _zone(db_session, group, allow_query=[gone], allow_transfer=[f"! {gone}"])
    bundle = await _bundle_for(db_session, group)

    (view,) = [v for v in bundle["views"] if v["name"] == "ext"]
    for f in ("match_clients", "match_destinations", "allow_query", "allow_query_cache"):
        assert view[f] == ["none"], f
    opts = bundle["options"]
    # Only the options the bundle ships (allow_query_cache is not one).
    for f in ("allow_query", "allow_recursion", "allow_transfer", "allow_notify"):
        assert opts[f] == ["none"], f
    # also-notify is not an access list, and ``none`` is not legal there.
    assert opts["also_notify"] == []
    zones = [z for z in bundle["zones"] if z["name"] == "example.test."]
    assert zones and all(
        z["allow_query"] == ["none"] and z["allow_transfer"] == ["none"] for z in zones
    )


@pytest.mark.asyncio
async def test_key_names_compare_as_dns_names(client: AsyncClient, db_session):
    """BIND treats ``Ext-Key.`` and ``ext-key`` as one key. The guard must see
    the citation, and the bundle must not drop a citation BIND resolves."""
    hdr = await _admin(db_session)
    group, key = await _group_with_key(db_session)
    db_session.add(DNSServerOptions(group_id=group.id, allow_transfer=['key "EXT-KEY."']))
    await db_session.flush()
    r = await client.delete(f"/api/v1/dns/groups/{group.id}/tsig-keys/{key.id}", headers=hdr)
    assert r.status_code == 409, r.text
    bundle = await _bundle_for(db_session, group)
    assert bundle["options"]["allow_transfer"] == ['key "EXT-KEY."']


@pytest.mark.asyncio
async def test_a_healthy_bundle_is_unchanged_by_the_drop(db_session, monkeypatch):
    """Every element resolves → the drop is a no-op and the ETag is the one
    the pre-#2282 builder produced (the drop patched out to identity)."""
    from app.services.dns import agent_config

    group, _key = await _group_with_key(db_session)
    for where in ("acl", "view", "option"):
        await _cite(db_session, group, where)
    await _zone(
        db_session,
        group,
        allow_query=[f"key {KEY}", "10.0.0.0/8"],
        allow_transfer=[f"key {KEY}"],
        also_notify=[f"192.0.2.9 key {KEY}"],
    )
    with_drop = await _bundle_for(db_session, group)
    monkeypatch.setattr(
        agent_config, "_drop_undefined_key_refs", lambda elements, *a, **k: elements
    )
    loaded = (
        await db_session.execute(select(DNSServer).where(DNSServer.group_id == group.id))
    ).scalar_one()
    without = await build_config_bundle(db_session, loaded)
    assert with_drop["etag"] == without["etag"]
    assert with_drop["structural_etag"] == without["structural_etag"]
