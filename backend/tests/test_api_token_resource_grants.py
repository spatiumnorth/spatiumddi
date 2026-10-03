"""Resource-scoped API tokens (#374).

A token can bind to a single subnet / DNS zone; the binding only ever NARROWS
the owner. Covers in-scope allow, out-of-scope 403, the create-time
grant-exceeds-owner rejection, and unknown-resource 422.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, generate_api_token, hash_password
from app.models.auth import APIToken, User
from app.models.dns import DNSServerGroup, DNSZone
from app.models.ipam import IPBlock, IPSpace, Subnet


async def _make_user(db: AsyncSession, *, superadmin: bool) -> tuple[User, str]:
    user = User(
        username=f"tok-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Token User",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    db.add(user)
    await db.flush()
    return user, create_access_token(str(user.id))


async def _make_token(db: AsyncSession, owner: User, grants: list[dict] | None) -> str:
    raw, _prefix, token_hash = generate_api_token()
    db.add(
        APIToken(
            name=f"t-{uuid.uuid4().hex[:6]}",
            token_hash=token_hash,
            prefix=raw[:10],
            scope="user",
            scopes=[],
            resource_grants=grants,
            user_id=owner.id,
            created_by_user_id=owner.id,
            is_active=True,
        )
    )
    await db.flush()
    return raw


async def _make_subnet(db: AsyncSession, space: IPSpace, network: str) -> Subnet:
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name=f"b-{uuid.uuid4().hex[:5]}")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=network, name="sn", total_ips=254)
    db.add(subnet)
    await db.flush()
    return subnet


@pytest.mark.asyncio
async def test_subnet_token_in_scope_allow_out_of_scope_deny(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    owner, _ = await _make_user(db_session, superadmin=True)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    sub_x = await _make_subnet(db_session, space, "10.30.1.0/24")
    sub_y = await _make_subnet(db_session, space, "10.30.2.0/24")
    raw = await _make_token(
        db_session,
        owner,
        [{"action": "write", "resource_type": "subnet", "resource_id": str(sub_x.id)}],
    )
    await db_session.commit()
    hdr = {"Authorization": f"Bearer {raw}"}

    # In-scope: create an IP in the bound subnet → 201.
    r_ok = await client.post(
        f"/api/v1/ipam/subnets/{sub_x.id}/addresses",
        headers=hdr,
        json={"address": "10.30.1.10", "status": "allocated", "hostname": "in-scope"},
    )
    assert r_ok.status_code == 201, r_ok.text

    # Out-of-scope: same token, different subnet → 403 even though the owner
    # (superadmin) could do it.
    r_deny = await client.post(
        f"/api/v1/ipam/subnets/{sub_y.id}/addresses",
        headers=hdr,
        json={"address": "10.30.2.10", "status": "allocated", "hostname": "out-of-scope"},
    )
    assert r_deny.status_code == 403, r_deny.text


@pytest.mark.asyncio
async def test_subnet_token_cannot_create_subnets(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    owner, _ = await _make_user(db_session, superadmin=True)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    sub_x = await _make_subnet(db_session, space, "10.31.1.0/24")
    raw = await _make_token(
        db_session,
        owner,
        [{"action": "write", "resource_type": "subnet", "resource_id": str(sub_x.id)}],
    )
    await db_session.commit()

    r = await client.post(
        "/api/v1/ipam/subnets",
        headers={"Authorization": f"Bearer {raw}"},
        json={
            "space_id": str(space.id),
            "block_id": str(sub_x.block_id),
            "network": "10.31.9.0/24",
        },
    )
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_dns_zone_token_other_zone_denied(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    owner, _ = await _make_user(db_session, superadmin=True)
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(group)
    await db_session.flush()
    zone_a = DNSZone(group_id=group.id, name=f"a-{uuid.uuid4().hex[:6]}.test", kind="forward")
    zone_b = DNSZone(group_id=group.id, name=f"b-{uuid.uuid4().hex[:6]}.test", kind="forward")
    db_session.add_all([zone_a, zone_b])
    await db_session.flush()
    raw = await _make_token(
        db_session,
        owner,
        [{"action": "write", "resource_type": "dns_zone", "resource_id": str(zone_a.id)}],
    )
    await db_session.commit()
    hdr = {"Authorization": f"Bearer {raw}"}

    # Listing records in the bound zone is allowed (read covered by write? no —
    # GET maps to read; the grant action is write. A write grant doesn't cover
    # read on the coarse gate, so list 403s — but record CREATE in the bound
    # zone is allowed). Verify the cross-zone create is denied.
    r_deny = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones/{zone_b.id}/records",
        headers=hdr,
        json={"name": "www", "record_type": "A", "value": "10.0.0.1", "ttl": 300},
    )
    assert r_deny.status_code == 403, r_deny.text


@pytest.mark.asyncio
async def test_create_token_grant_exceeds_owner_rejected(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A non-superadmin with no subnet rights can't mint a subnet-write token."""
    _, token = await _make_user(db_session, superadmin=False)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    sub = await _make_subnet(db_session, space, "10.32.1.0/24")
    await db_session.commit()

    r = await client.post(
        "/api/v1/api-tokens",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "scoped",
            "stepup_password": "x",  # the owner's step-up (#1355)
            "resource_grants": [
                {"action": "write", "resource_type": "subnet", "resource_id": str(sub.id)}
            ],
        },
    )
    # 403 — can't grant more than yourself. (A user with zero RBAC can't even
    # reach the api-tokens surface? api-tokens is self-service, so they can;
    # the grant validation is what rejects.)
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_create_token_unknown_resource_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_user(db_session, superadmin=True)
    await db_session.commit()
    r = await client.post(
        "/api/v1/api-tokens",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "scoped",
            "stepup_password": "x",  # the owner's step-up (#1355)
            "resource_grants": [
                {
                    "action": "write",
                    "resource_type": "subnet",
                    "resource_id": str(uuid.uuid4()),
                }
            ],
        },
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_create_token_bad_resource_type_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_user(db_session, superadmin=True)
    await db_session.commit()
    r = await client.post(
        "/api/v1/api-tokens",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "scoped",
            "stepup_password": "x",  # the owner's step-up (#1355)
            "resource_grants": [
                {"action": "write", "resource_type": "ip_block", "resource_id": str(uuid.uuid4())}
            ],
        },
    )
    # Shape validator rejects unsupported resource_type at the schema layer.
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_subnet_token_cannot_mutate_other_subnet(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A token bound to subnet A can edit/delete A but 403s on subnet B
    (regression for the update/delete/resize escape found in review)."""
    owner, _ = await _make_user(db_session, superadmin=True)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    sub_a = await _make_subnet(db_session, space, "10.40.1.0/24")
    sub_b = await _make_subnet(db_session, space, "10.40.2.0/24")
    raw = await _make_token(
        db_session,
        owner,
        [{"action": "admin", "resource_type": "subnet", "resource_id": str(sub_a.id)}],
    )
    await db_session.commit()
    hdr = {"Authorization": f"Bearer {raw}"}

    # PUT other subnet → 403; PUT own subnet → 200. (Assign first so the HTTP
    # call isn't a side-effect inside an assert.)
    r_other = await client.put(
        f"/api/v1/ipam/subnets/{sub_b.id}", headers=hdr, json={"description": "x"}
    )
    assert r_other.status_code == 403
    r_own = await client.put(
        f"/api/v1/ipam/subnets/{sub_a.id}", headers=hdr, json={"description": "ok"}
    )
    assert r_own.status_code == 200
    # DELETE other subnet → 403.
    r_del = await client.delete(f"/api/v1/ipam/subnets/{sub_b.id}", headers=hdr)
    assert r_del.status_code == 403


@pytest.mark.asyncio
async def test_write_scoped_token_can_read_own_subnet(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A write-only grant implies read on the bound resource (#374 review #6)."""
    owner, _ = await _make_user(db_session, superadmin=True)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    sub = await _make_subnet(db_session, space, "10.41.1.0/24")
    raw = await _make_token(
        db_session,
        owner,
        [{"action": "write", "resource_type": "subnet", "resource_id": str(sub.id)}],
    )
    await db_session.commit()
    r = await client.get(
        f"/api/v1/ipam/subnets/{sub.id}", headers={"Authorization": f"Bearer {raw}"}
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_subnet_token_bulk_delete_skips_other_subnet(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Bulk-delete only touches IPs in the token's bound subnet (review #2)."""
    owner, _ = await _make_user(db_session, superadmin=True)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    sub_a = await _make_subnet(db_session, space, "10.42.1.0/24")
    sub_b = await _make_subnet(db_session, space, "10.42.2.0/24")
    # Superadmin session creates one IP in each subnet.
    _, admin_token = await _make_user(db_session, superadmin=True)
    await db_session.commit()
    admin_hdr = {"Authorization": f"Bearer {admin_token}"}
    ra = await client.post(
        f"/api/v1/ipam/subnets/{sub_a.id}/addresses",
        headers=admin_hdr,
        json={"address": "10.42.1.10", "status": "allocated", "hostname": "a"},
    )
    rb = await client.post(
        f"/api/v1/ipam/subnets/{sub_b.id}/addresses",
        headers=admin_hdr,
        json={"address": "10.42.2.10", "status": "allocated", "hostname": "b"},
    )
    assert ra.status_code == 201 and rb.status_code == 201
    ip_a, ip_b = ra.json()["id"], rb.json()["id"]

    # bulk-delete is a POST → maps to the 'write' action, so the token needs a
    # write/admin grant (a bare 'delete' grant wouldn't clear the coarse gate).
    raw = await _make_token(
        db_session,
        owner,
        [{"action": "admin", "resource_type": "subnet", "resource_id": str(sub_a.id)}],
    )
    await db_session.commit()
    resp = await client.post(
        "/api/v1/ipam/addresses/bulk-delete",
        headers={"Authorization": f"Bearer {raw}"},
        json={"ip_ids": [ip_a, ip_b], "permanent": True},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # ip_b (other subnet) is skipped, not deleted.
    assert ip_b in body.get("skipped", [])
