"""Deleting a server group never takes a live scope with it, and says what it does take (#1399).

The DHCP page's Delete Server Group said "The group must be empty — move or
delete its servers first", and the server refused a group only while it held
servers. A group holding scopes deleted with 204: the FK cascade hard-deleted
every scope with its pools and reservations, none of them into Trash, although
a scope deleted on its own goes to Trash and can be restored. The guard that
refused a populated group was written when scopes hung off servers, so
counting servers covered them; the group-centric data model moved scopes onto
the group and kept counting servers only, under a comment that still promised
a 409 for "a populated group".

A group that holds a live scope is now refused (409) by the REST route and by
the operation's preview, which the approval queue and the Copilot read before
they queue or propose the delete. Scopes the operator already deleted (in
Trash) still go with the group, for good, and the preview says so.

DNS refused a group holding live zones already. A group whose zones are all in
Trash deletes and takes them with it; the console's dialog now says so, and
that behaviour is pinned here so a change to either side is seen.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPPool, DHCPScope, DHCPServerGroup, DHCPStaticAssignment
from app.models.dns import DNSServerGroup, DNSZone
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.ai.operations_risky import DeleteGroupArgs, _preview_delete_group


async def _admin(db: AsyncSession) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"gd-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Group Delete Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _dhcp_group_with_scope(
    client: AsyncClient, db: AsyncSession, headers: dict[str, str]
) -> tuple[uuid.UUID, uuid.UUID]:
    """A server-less DHCP group holding one disabled scope with a pool and a
    reservation, the reservation made through the API as an operator makes it.
    Returns ``(group_id, scope_id)``."""
    space = IPSpace(name=f"gd-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.97.0.0/16", name="root")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.97.9.0/24", name="lan")
    db.add(subnet)
    group = DHCPServerGroup(name=f"gd-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    scope = DHCPScope(
        group_id=group.id,
        subnet_id=subnet.id,
        name="gd-scope",
        is_active=False,
        address_family="ipv4",
    )
    db.add(scope)
    await db.flush()
    group_id, scope_id = group.id, scope.id
    await db.commit()

    pool = await client.post(
        f"/api/v1/dhcp/scopes/{scope_id}/pools",
        headers=headers,
        json={"name": "gd-pool", "start_ip": "10.97.9.100", "end_ip": "10.97.9.150"},
    )
    assert pool.status_code == 201, pool.text
    static = await client.post(
        f"/api/v1/dhcp/scopes/{scope_id}/statics",
        headers=headers,
        json={"ip_address": "10.97.9.20", "mac_address": "02:00:5e:10:20:31", "hostname": "gd"},
    )
    assert static.status_code == 201, static.text
    return group_id, scope_id


async def _count(db: AsyncSession, model: type, *where: object, trashed_too: bool = False) -> int:
    stmt = select(func.count()).select_from(model).where(*where)
    if trashed_too:
        stmt = stmt.execution_options(include_deleted=True)
    return (await db.execute(stmt)).scalar_one()


# ── DHCP ─────────────────────────────────────────────────────────────────────


async def test_a_dhcp_group_holding_a_scope_is_refused_and_keeps_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    group_id, scope_id = await _dhcp_group_with_scope(client, db_session, headers)

    resp = await client.delete(f"/api/v1/dhcp/server-groups/{group_id}", headers=headers)

    assert resp.status_code == 409, (
        f"DELETE of a group holding a live scope answered {resp.status_code}: the group "
        "must not take its scopes, pools and reservations with it, none of them into "
        f"Trash. {resp.text}"
    )
    detail = resp.json()["detail"]
    assert "1 scope" in detail, detail
    db_session.expire_all()
    assert await _count(db_session, DHCPServerGroup, DHCPServerGroup.id == group_id) == 1
    assert await _count(db_session, DHCPScope, DHCPScope.id == scope_id) == 1
    assert await _count(db_session, DHCPPool, DHCPPool.scope_id == scope_id) == 1
    assert (
        await _count(db_session, DHCPStaticAssignment, DHCPStaticAssignment.scope_id == scope_id)
        == 1
    )


async def test_the_preview_refuses_a_dhcp_group_holding_a_scope(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The approval queue and the Copilot read the preview before they queue or
    propose the delete; it said "Delete empty DHCP server group" over a group
    holding scopes."""
    user, headers = await _admin(db_session)
    group_id, _ = await _dhcp_group_with_scope(client, db_session, headers)

    preview = await _preview_delete_group(db_session, user, DeleteGroupArgs(group_id=group_id))

    assert preview.ok is False, preview.preview_text
    assert "1 scope" in (preview.detail or ""), preview.detail


async def test_scopes_already_in_trash_go_with_the_group_and_the_preview_says_so(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, headers = await _admin(db_session)
    group_id, scope_id = await _dhcp_group_with_scope(client, db_session, headers)
    deleted = await client.delete(f"/api/v1/dhcp/scopes/{scope_id}", headers=headers)
    assert deleted.status_code in (200, 204), deleted.text
    trash = await client.get("/api/v1/admin/trash", params={"type": "dhcp_scope"}, headers=headers)
    assert trash.status_code == 200, trash.text
    assert str(scope_id) in {row["id"] for row in trash.json()["items"]}, "precondition: in Trash"

    preview = await _preview_delete_group(db_session, user, DeleteGroupArgs(group_id=group_id))
    assert preview.ok is True, preview.detail
    text = preview.preview_text or ""
    assert (
        "1 scope" in text and "Trash" in text
    ), f"the preview does not say the group takes its scope in Trash with it: {text!r}"

    resp = await client.delete(f"/api/v1/dhcp/server-groups/{group_id}", headers=headers)
    assert resp.status_code == 204, resp.text
    db_session.expire_all()
    assert await _count(db_session, DHCPServerGroup, DHCPServerGroup.id == group_id) == 0
    assert await _count(db_session, DHCPScope, DHCPScope.id == scope_id, trashed_too=True) == 0


async def test_an_empty_dhcp_group_deletes(client: AsyncClient, db_session: AsyncSession) -> None:
    user, headers = await _admin(db_session)
    group = DHCPServerGroup(name=f"gd-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    group_id = group.id
    await db_session.commit()

    preview = await _preview_delete_group(db_session, user, DeleteGroupArgs(group_id=group_id))
    assert preview.ok is True, preview.detail
    resp = await client.delete(f"/api/v1/dhcp/server-groups/{group_id}", headers=headers)
    assert resp.status_code == 204, resp.text


# ── DNS (pinned: the console's dialog describes it) ──────────────────────────


async def test_a_dns_group_refuses_a_live_zone_and_takes_its_zones_in_trash(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    group = DNSServerGroup(name=f"gd-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    group_id = group.id
    await db_session.commit()
    made = await client.post(
        f"/api/v1/dns/groups/{group_id}/zones",
        headers=headers,
        json={"name": "group-delete.test"},
    )
    assert made.status_code == 201, made.text
    zone_id = made.json()["id"]

    live = await client.delete(f"/api/v1/dns/groups/{group_id}", headers=headers)
    assert live.status_code == 409, live.text

    trashed = await client.delete(f"/api/v1/dns/groups/{group_id}/zones/{zone_id}", headers=headers)
    assert trashed.status_code in (200, 204), trashed.text
    resp = await client.delete(f"/api/v1/dns/groups/{group_id}", headers=headers)
    assert resp.status_code == 204, resp.text
    db_session.expire_all()
    assert (
        await _count(db_session, DNSZone, DNSZone.id == uuid.UUID(zone_id), trashed_too=True) == 0
    )
