"""Structural IPAM routes need a per-type permission, not just the coarse gate.

The IPAM router's coarse gate admits any holder of an ``address_set`` grant on
a mutating request (so a set delegate can reach the per-IP gate), and it
ignores the grant's ``resource_id``. Every structural space / block / subnet
route therefore has to enforce its own per-type permission, or an "Address Set
Editor" scoped to one set can resize, merge, purge or delete anything.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.address_set import AddressSet
from app.models.auth import Group, Role, User
from app.models.ipam import IPBlock, IPSpace, Subnet


async def _user(db: AsyncSession, permissions: list[dict]) -> str:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"u-{uuid.uuid4().hex[:8]}@t.io",
        display_name="u",
        hashed_password=hash_password("password123"),
    )
    role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
    group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
    group.roles = [role]
    user.groups = [group]
    db.add_all([role, group, user])
    await db.flush()
    return create_access_token(str(user.id))


async def _world(db: AsyncSession) -> dict[str, Any]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    other = IPSpace(name=f"sp2-{uuid.uuid4().hex[:6]}")
    db.add_all([space, other])
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.0.5.0/24", name="s")
    sibling = Subnet(space_id=space.id, block_id=block.id, network="10.0.4.0/24", name="s2")
    db.add_all([subnet, sibling])
    await db.flush()
    aset = AddressSet(
        name="mine",
        subnet_id=subnet.id,
        range_kind="contiguous",
        start_address="10.0.5.50",
        end_address="10.0.5.99",
    )
    db.add(aset)
    await db.flush()
    return {
        "space": space,
        "other": other,
        "block": block,
        "subnet": subnet,
        "sibling": sibling,
        "set": aset,
    }


def _routes(w: dict[str, Any]) -> list[tuple[str, str, dict | None, str]]:
    """(method, path, body, kind) for every structural route; kind is the
    resource type whose permission each one needs."""
    s, b, sp = w["subnet"].id, w["block"].id, w["space"].id
    zone = {"create_for_ip_ids": [], "update_record_ids": [], "delete_stale_record_ids": []}
    return [
        ("POST", f"/subnets/{s}/resize/preview", {"new_cidr": "10.0.5.0/23"}, "subnet"),
        ("POST", f"/subnets/{s}/resize", {"new_cidr": "10.0.4.0/23"}, "subnet"),
        ("POST", f"/subnets/{s}/split/preview", {"new_prefix_length": 25}, "subnet"),
        (
            "POST",
            f"/subnets/{s}/split/commit",
            {"new_prefix_length": 25, "confirm_cidr": "10.0.5.0/24"},
            "subnet",
        ),
        (
            "POST",
            f"/subnets/{s}/merge/preview",
            {"sibling_subnet_ids": [str(w["sibling"].id)]},
            "subnet",
        ),
        (
            "POST",
            f"/subnets/{s}/merge/commit",
            {"sibling_subnet_ids": [str(w["sibling"].id)], "confirm_cidr": "10.0.4.0/23"},
            "subnet",
        ),
        ("POST", f"/subnets/{s}/orphans/purge", {"ip_ids": []}, "subnet"),
        ("POST", f"/subnets/{s}/discover", None, "subnet"),
        ("POST", f"/subnets/{s}/dns-sync/commit", zone, "subnet"),
        ("POST", f"/subnets/{s}/reverse-zones/backfill", None, "subnet"),
        (
            "POST",
            f"/subnets/{s}/domains",
            {"dns_zone_id": str(uuid.uuid4())},
            "subnet",
        ),
        ("DELETE", f"/subnets/{s}/domains/{uuid.uuid4()}", None, "subnet"),
        (
            "POST",
            "/subnets/bulk-edit",
            {"subnet_ids": [str(s)], "changes": {"description": "x"}},
            "subnet",
        ),
        ("POST", f"/blocks/{b}/allocate-subnet", {"prefix_len": 26, "name": "n"}, "subnet"),
        ("DELETE", f"/subnets/{s}", None, "subnet"),
        ("POST", f"/blocks/{b}/resize/preview", {"new_cidr": "10.0.0.0/15"}, "ip_block"),
        ("POST", f"/blocks/{b}/resize", {"new_cidr": "10.0.0.0/15"}, "ip_block"),
        (
            "POST",
            f"/blocks/{b}/move/preview",
            {"target_space_id": str(w["other"].id)},
            "ip_block",
        ),
        (
            "POST",
            f"/blocks/{b}/move/commit",
            {"target_space_id": str(w["other"].id), "confirmation_cidr": "10.0.0.0/16"},
            "ip_block",
        ),
        ("POST", f"/blocks/{b}/dns-sync/commit", zone, "ip_block"),
        ("POST", f"/blocks/{b}/reverse-zones/backfill", None, "ip_block"),
        ("DELETE", f"/blocks/{b}", None, "ip_block"),
        ("POST", f"/spaces/{sp}/dns-sync/commit", zone, "ip_space"),
        ("POST", f"/spaces/{sp}/reverse-zones/backfill", None, "ip_space"),
        ("DELETE", f"/spaces/{sp}", None, "ip_space"),
    ]


_ROUTE_COUNT = 25


@pytest.mark.asyncio
@pytest.mark.parametrize("idx", range(_ROUTE_COUNT))
async def test_address_set_delegate_denied_on_structural_routes(
    client: AsyncClient, db_session: AsyncSession, idx: int
) -> None:
    w = await _world(db_session)
    token = await _user(
        db_session,
        [{"action": "admin", "resource_type": "address_set", "resource_id": str(w["set"].id)}],
    )
    routes = _routes(w)
    assert len(routes) == _ROUTE_COUNT
    method, path, body, _kind = routes[idx]
    r = await client.request(
        method,
        f"/api/v1/ipam{path}",
        headers={"Authorization": f"Bearer {token}"},
        json=body,
    )
    assert r.status_code == 403, f"{method} {path}: {r.status_code} {r.text}"
    await db_session.refresh(w["block"])
    assert str(w["block"].network) == "10.0.0.0/16"


@pytest.mark.asyncio
@pytest.mark.parametrize("idx", range(_ROUTE_COUNT))
async def test_type_scoped_grant_for_other_type_denied(
    client: AsyncClient, db_session: AsyncSession, idx: int
) -> None:
    """write on a *different* IPAM type (here nat_mapping-adjacent ip_address)
    clears the coarse gate but must not reach structural routes."""
    w = await _world(db_session)
    routes = _routes(w)
    method, path, body, _kind = routes[idx]
    token = await _user(
        db_session,
        [
            {"action": "admin", "resource_type": "ip_address"},
            {"action": "admin", "resource_type": "custom_field"},
        ],
    )
    r = await client.request(
        method,
        f"/api/v1/ipam{path}",
        headers={"Authorization": f"Bearer {token}"},
        json=body,
    )
    assert r.status_code == 403, f"{method} {path}: {r.status_code} {r.text}"


_ALLOWED = [
    ("POST", "/subnets/{s}/resize/preview", {"new_cidr": "10.0.5.0/23"}, "subnet", "write"),
    ("POST", "/subnets/{s}/split/preview", {"new_prefix_length": 25}, "subnet", "write"),
    ("POST", "/subnets/{s}/orphans/purge", {"ip_ids": []}, "subnet", "write"),
    (
        "POST",
        "/subnets/{s}/dns-sync/commit",
        {"create_for_ip_ids": [], "update_record_ids": [], "delete_stale_record_ids": []},
        "subnet",
        "write",
    ),
    ("POST", "/blocks/{b}/resize/preview", {"new_cidr": "10.0.0.0/15"}, "ip_block", "write"),
    (
        "POST",
        "/blocks/{b}/move/preview",
        {"target_space_id": "{o}"},
        "ip_block",
        "write",
    ),
    ("DELETE", "/subnets/{s}", None, "subnet", "delete"),
    ("DELETE", "/blocks/{b}", None, "ip_block", "delete"),
    ("DELETE", "/spaces/{sp}", None, "ip_space", "delete"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path,body,rtype,action", _ALLOWED)
async def test_matching_type_permission_still_succeeds(
    client: AsyncClient,
    db_session: AsyncSession,
    method: str,
    path: str,
    body: dict | None,
    rtype: str,
    action: str,
) -> None:
    w = await _world(db_session)
    token = await _user(db_session, [{"action": action, "resource_type": rtype}])
    fmt = {
        "s": w["subnet"].id,
        "b": w["block"].id,
        "sp": w["space"].id,
        "o": w["other"].id,
    }
    if body and "target_space_id" in body:
        body = {"target_space_id": str(w["other"].id)}
    r = await client.request(
        method,
        "/api/v1/ipam" + path.format(**fmt),
        headers={"Authorization": f"Bearer {token}"},
        json=body,
    )
    assert r.status_code in (200, 202, 204), f"{method} {path}: {r.status_code} {r.text}"


@pytest.mark.asyncio
async def test_address_set_delegate_can_still_write_ips_in_set(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    w = await _world(db_session)
    token = await _user(
        db_session,
        [{"action": "write", "resource_type": "address_set", "resource_id": str(w["set"].id)}],
    )
    r = await client.post(
        f"/api/v1/ipam/subnets/{w['subnet'].id}/addresses",
        headers={"Authorization": f"Bearer {token}"},
        json={"address": "10.0.5.55", "hostname": "printer-1"},
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_address_set_delegate_denied_on_import_commit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    w = await _world(db_session)
    token = await _user(
        db_session,
        [{"action": "admin", "resource_type": "address_set", "resource_id": str(w["set"].id)}],
    )
    r = await client.post(
        "/api/v1/ipam/import/commit",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("x.json", b'{"subnets": []}', "application/json")},
        data={"space_id": str(w["space"].id)},
    )
    assert r.status_code == 403, r.text
