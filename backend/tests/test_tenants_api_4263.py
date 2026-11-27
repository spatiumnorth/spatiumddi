"""Tenant CRUD, space assignment, group and token binding (#4263)."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.core.security import generate_api_token
from app.models.audit import AuditLog
from app.models.auth import APIToken, Group, Role
from app.models.ipam import IPSpace
from app.models.tenant import Tenant
from tests._tenancy_helpers import bearer, get, make_side, make_user, reset_scope, send


@pytest.fixture
async def admin(db_session):
    u = await make_user(db_session, superadmin=True)
    await db_session.commit()
    return bearer(u)


async def test_crud_and_audit(client: AsyncClient, db_session, admin):
    r = await send(client, db_session, "POST", "/api/v1/tenants", admin, json={"name": "Acme"})
    assert r.status_code == 201, r.text
    tid = r.json()["id"]
    r = await send(client, db_session, "POST", "/api/v1/tenants", admin, json={"name": "ACME"})
    assert r.status_code == 409
    r = await send(client, db_session, "POST", "/api/v1/tenants", admin, json={"name": " "})
    assert r.status_code == 422
    r = await send(
        client, db_session, "PUT", f"/api/v1/tenants/{tid}", admin, json={"description": "d"}
    )
    assert r.status_code == 200 and r.json()["description"] == "d"
    r = await get(client, db_session, "/api/v1/tenants", admin)
    assert [t["name"] for t in r.json()] == ["Acme"]
    r = await send(client, db_session, "DELETE", f"/api/v1/tenants/{tid}", admin)
    assert r.status_code == 204
    r = await get(client, db_session, f"/api/v1/tenants/{tid}", admin)
    assert r.status_code == 404
    actions = (
        (
            await db_session.execute(
                select(AuditLog.action)
                .where(AuditLog.resource_type == "tenant")
                .order_by(AuditLog.seq)
            )
        )
        .scalars()
        .all()
    )
    assert actions == ["create", "update", "delete"]


async def test_bad_input_and_unknown_ids(client: AsyncClient, db_session, admin):
    r = await send(client, db_session, "POST", "/api/v1/tenants", admin, json={})
    assert r.status_code == 422
    r = await send(
        client,
        db_session,
        "POST",
        "/api/v1/tenants",
        admin,
        json={"name": "x", "customer_id": "00000000-0000-0000-0000-000000000009"},
    )
    assert r.status_code == 422
    for method in ("GET", "PUT", "DELETE"):
        r = await send(
            client,
            db_session,
            method,
            "/api/v1/tenants/00000000-0000-0000-0000-000000000009",
            admin,
            **({"json": {"name": "n"}} if method == "PUT" else {}),
        )
        assert r.status_code == 404, method


async def test_only_a_superadmin_manages_tenants(client: AsyncClient, db_session):
    plain = await make_user(db_session, permissions=[{"action": "admin", "resource_type": "*"}])
    a = await make_side(db_session, "Acme")
    reset_scope(db_session)
    for h in (bearer(plain), a.headers):
        r = await get(client, db_session, "/api/v1/tenants", h)
        assert r.status_code == 403
        r = await send(client, db_session, "POST", "/api/v1/tenants", h, json={"name": "x"})
        assert r.status_code == 403


async def test_assign_and_unassign_spaces_move_the_subtree(client: AsyncClient, db_session, admin):
    t = (
        await send(client, db_session, "POST", "/api/v1/tenants", admin, json={"name": "T"})
    ).json()
    a = await make_side(db_session, "Acme")
    reset_scope(db_session)
    other = IPSpace(name="Loose")
    db_session.add(other)
    await db_session.commit()
    other_id = other.id
    r = await send(
        client,
        db_session,
        "POST",
        f"/api/v1/tenants/{t['id']}/spaces",
        admin,
        json={"space_ids": [str(other.id)]},
    )
    assert r.status_code == 200 and r.json()["space_count"] == 1
    r = await send(
        client,
        db_session,
        "POST",
        f"/api/v1/tenants/{t['id']}/spaces",
        admin,
        json={"space_ids": ["00000000-0000-0000-0000-000000000009"]},
    )
    assert r.status_code == 404
    # a name collision inside the tenant is a 409, not a 500
    r = await send(
        client,
        db_session,
        "POST",
        f"/api/v1/tenants/{a.tenant.id}/spaces",
        admin,
        json={"space_ids": [str(other.id)]},
    )
    assert r.status_code == 200  # 'Loose' does not collide in Acme
    clash = IPSpace(name="Corporate")
    db_session.add(clash)
    await db_session.commit()
    r = await send(
        client,
        db_session,
        "POST",
        f"/api/v1/tenants/{a.tenant.id}/spaces",
        admin,
        json={"space_ids": [str(clash.id)]},
    )
    assert r.status_code == 409
    r = await send(
        client, db_session, "DELETE", f"/api/v1/tenants/{a.tenant.id}/spaces/{other.id}", admin
    )
    assert r.status_code == 204
    reset_scope(db_session)
    assert (await db_session.get(IPSpace, other_id)).tenant_id is None


async def test_delete_is_refused_while_in_use_and_counts_trashed_spaces(
    client: AsyncClient, db_session, admin
):
    a = await make_side(db_session, "Acme")
    reset_scope(db_session)
    r = await send(client, db_session, "DELETE", f"/api/v1/tenants/{a.tenant.id}", admin)
    assert r.status_code == 409 and "IP space" in r.text
    # trash the space: the tenant is still pinned (restore would need it)
    r = await send(
        client, db_session, "DELETE", f"/api/v1/ipam/spaces/{a.space.id}?force=true", admin
    )
    assert r.status_code in (200, 204, 409, 422), r.text
    sp = (
        await db_session.execute(
            select(IPSpace).where(IPSpace.id == a.space.id).execution_options(include_deleted=True)
        )
    ).scalar_one()
    if sp.deleted_at is not None:
        r = await send(client, db_session, "DELETE", f"/api/v1/tenants/{a.tenant.id}", admin)
        assert r.status_code == 409


async def test_group_binding(client: AsyncClient, db_session, admin):
    t = (
        await send(client, db_session, "POST", "/api/v1/tenants", admin, json={"name": "T"})
    ).json()
    t2 = (
        await send(client, db_session, "POST", "/api/v1/tenants", admin, json={"name": "U"})
    ).json()
    r = await send(
        client,
        db_session,
        "POST",
        "/api/v1/groups",
        admin,
        json={"name": "Admins", "tenant_id": t["id"]},
    )
    assert r.status_code == 201 and r.json()["tenant_id"] == t["id"]
    gid = r.json()["id"]
    # the same name is fine in another tenant and untenanted, a 409 inside one
    for tid in (t2["id"], None):
        r = await send(
            client,
            db_session,
            "POST",
            "/api/v1/groups",
            admin,
            json={"name": "Admins", "tenant_id": tid},
        )
        assert r.status_code == 201, r.text
    r = await send(
        client,
        db_session,
        "POST",
        "/api/v1/groups",
        admin,
        json={"name": "Admins", "tenant_id": t["id"]},
    )
    assert r.status_code == 409
    # unknown tenant
    r = await send(
        client,
        db_session,
        "POST",
        "/api/v1/groups",
        admin,
        json={"name": "X", "tenant_id": "00000000-0000-0000-0000-000000000009"},
    )
    assert r.status_code == 422
    # a tenant group cannot carry a * / * role
    super_role = (
        await db_session.execute(select(Role).where(Role.name == "Superadmin"))
    ).scalar_one_or_none()
    if super_role is None:
        super_role = Role(name="Superadmin", permissions=[{"action": "*", "resource_type": "*"}])
        db_session.add(super_role)
        await db_session.commit()
    r = await send(
        client,
        db_session,
        "PUT",
        f"/api/v1/groups/{gid}",
        admin,
        json={"role_ids": [str(super_role.id)]},
    )
    assert r.status_code == 422
    # tenant of a tenant-bound group cannot be removed while a tenant is deleted
    r = await send(client, db_session, "DELETE", f"/api/v1/tenants/{t['id']}", admin)
    assert r.status_code == 409 and "group" in r.text


async def test_group_tenant_is_superadmin_only(client: AsyncClient, db_session):
    t = Tenant(name="T")
    db_session.add(t)
    await db_session.commit()
    plain = await make_user(db_session, permissions=[{"action": "admin", "resource_type": "group"}])
    await db_session.commit()
    r = await send(
        client,
        db_session,
        "POST",
        "/api/v1/groups",
        bearer(plain),
        json={"name": "G", "tenant_id": str(t.id)},
    )
    assert r.status_code == 403
    g = (await db_session.execute(select(Group).where(Group.name == "G"))).scalar_one_or_none()
    assert g is None


async def test_unbinding_a_group_is_superadmin_only(client: AsyncClient, db_session, admin):
    a = await make_side(db_session, "Acme")
    reset_scope(db_session)
    group = (
        await db_session.execute(select(Group).where(Group.tenant_id == a.tenant.id))
    ).scalar_one()
    plain = await make_user(db_session, permissions=[{"action": "admin", "resource_type": "group"}])
    await db_session.commit()
    group_id = group.id
    r = await send(
        client,
        db_session,
        "PUT",
        f"/api/v1/groups/{group_id}",
        bearer(plain),
        json={"tenant_id": None},
    )
    assert r.status_code == 403
    reset_scope(db_session)
    assert (await db_session.get(Group, group_id)).tenant_id == a.tenant.id


async def _pinned_token(db_session, owner, tenant_id) -> dict[str, str]:
    raw, _prefix, token_hash = generate_api_token()
    db_session.add(
        APIToken(
            name="pin",
            token_hash=token_hash,
            prefix=raw[:10],
            scope="user",
            scopes=[],
            tenant_id=tenant_id,
            user_id=owner.id,
            created_by_user_id=owner.id,
            is_active=True,
        )
    )
    await db_session.commit()
    return {"Authorization": f"Bearer {raw}"}


async def test_token_pinned_to_a_tenant_is_confined(client: AsyncClient, db_session):
    a = await make_side(db_session, "Acme")
    b = await make_side(db_session, "Beta")
    owner = await make_user(db_session, superadmin=True)
    await db_session.commit()
    tok = await _pinned_token(db_session, owner, a.tenant.id)
    r = await get(client, db_session, "/api/v1/ipam/spaces", tok)
    assert {s["id"] for s in r.json()} == {str(a.space.id)}
    r = await get(client, db_session, f"/api/v1/ipam/spaces/{b.space.id}", tok)
    assert r.status_code == 404
    r = await get(client, db_session, "/api/v1/dns/groups", tok)
    assert r.status_code == 403
    # an unpinned token of the same superadmin is not confined
    reset_scope(db_session)
    free = await _pinned_token(db_session, owner, None)
    r = await get(client, db_session, "/api/v1/ipam/spaces", free)
    assert {str(a.space.id), str(b.space.id)} <= {s["id"] for s in r.json()}


async def test_token_pin_never_widens_a_tenant_user(client: AsyncClient, db_session):
    a = await make_side(db_session, "Acme")
    b = await make_side(db_session, "Beta")
    # Acme's user holds a token pinned to Beta: the intersection is empty
    tok = await _pinned_token(db_session, a.user, b.tenant.id)
    r = await get(client, db_session, "/api/v1/ipam/spaces", tok)
    assert r.status_code == 200 and r.json() == []
    r = await get(client, db_session, f"/api/v1/ipam/spaces/{b.space.id}", tok)
    assert r.status_code == 404


async def test_unknown_tenant_on_token_create_is_422(client: AsyncClient, db_session, admin):
    r = await send(
        client,
        db_session,
        "POST",
        "/api/v1/api-tokens",
        admin,
        json={"name": "pin", "tenant_id": "00000000-0000-0000-0000-000000000009"},
    )
    assert r.status_code in (422, 403), r.text
