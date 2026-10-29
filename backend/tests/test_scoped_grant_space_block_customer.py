"""#3039: a grant scoped to ONE space / block / customer / site / provider reaches
that item (read, and with write, edit) and nothing else of its type."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, generate_api_token, hash_password
from app.models.auth import APIToken, Group, Role, User
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.models.ownership import Customer, Provider, Site


async def _holder(db: AsyncSession, permissions: list[dict], superadmin: bool = False) -> dict:
    user = User(
        username=f"sc-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@t.io",
        display_name="scoped",
        hashed_password=hash_password("password123"),
        is_superadmin=superadmin,
    )
    role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
    group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
    group.roles = [role]
    user.groups = [group]
    db.add_all([role, group, user])
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _rw(rtype: str, rid: uuid.UUID) -> list[dict]:
    return [
        {"action": a, "resource_type": rtype, "resource_id": str(rid)} for a in ("read", "write")
    ]


@pytest.mark.asyncio
async def test_space_scoped_grant(db_session: AsyncSession, client: AsyncClient) -> None:
    x = IPSpace(name=f"x-{uuid.uuid4().hex[:6]}")
    y = IPSpace(name=f"y-{uuid.uuid4().hex[:6]}")
    db_session.add_all([x, y])
    await db_session.flush()
    blk = IPBlock(space_id=x.id, network="10.0.0.0/16", name="b")
    db_session.add(blk)
    h = await _holder(db_session, _rw("ip_space", x.id))
    sa = await _holder(db_session, [], superadmin=True)
    await db_session.commit()

    assert (await client.get(f"/api/v1/ipam/spaces/{x.id}", headers=h)).status_code == 200
    r = await client.put(f"/api/v1/ipam/spaces/{x.id}", json={"description": "mine"}, headers=h)
    assert r.status_code == 200, r.text
    lst = await client.get("/api/v1/ipam/spaces", headers=h)
    assert lst.status_code == 200
    assert [s["id"] for s in lst.json()] == [str(x.id)]
    # Y and everything inside / beside X stays closed.
    assert (await client.get(f"/api/v1/ipam/spaces/{y.id}", headers=h)).status_code == 403
    r = await client.put(f"/api/v1/ipam/spaces/{y.id}", json={"description": "no"}, headers=h)
    assert r.status_code == 403
    assert (await client.get(f"/api/v1/ipam/blocks/{blk.id}", headers=h)).status_code == 403
    assert (await client.get("/api/v1/ipam/blocks", headers=h)).status_code == 403
    assert (await client.delete(f"/api/v1/ipam/spaces/{x.id}", headers=h)).status_code == 403
    # A binding to another resource is not the grant's to change.
    r = await client.put(
        f"/api/v1/ipam/spaces/{x.id}", json={"customer_id": str(uuid.uuid4())}, headers=h
    )
    assert r.status_code == 403
    # Superadmin unaffected.
    assert (await client.get(f"/api/v1/ipam/spaces/{y.id}", headers=sa)).status_code == 200
    assert len((await client.get("/api/v1/ipam/spaces", headers=sa)).json()) >= 2


@pytest.mark.asyncio
async def test_block_scoped_grant(db_session: AsyncSession, client: AsyncClient) -> None:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db_session.add(space)
    await db_session.flush()
    x = IPBlock(space_id=space.id, network="10.0.0.0/16", name="x")
    y = IPBlock(space_id=space.id, network="10.9.0.0/16", name="y")
    db_session.add_all([x, y])
    await db_session.flush()
    child = IPBlock(space_id=space.id, network="10.0.1.0/24", name="c", parent_block_id=x.id)
    sub = Subnet(space_id=space.id, block_id=x.id, network="10.0.5.0/24", name="s")
    db_session.add_all([child, sub])
    h = await _holder(db_session, _rw("ip_block", x.id))
    ro = await _holder(
        db_session, [{"action": "read", "resource_type": "ip_block", "resource_id": str(x.id)}]
    )
    sa = await _holder(db_session, [], superadmin=True)
    await db_session.commit()

    assert (await client.get(f"/api/v1/ipam/blocks/{x.id}", headers=h)).status_code == 200
    r = await client.put(f"/api/v1/ipam/blocks/{x.id}", json={"description": "mine"}, headers=h)
    assert r.status_code == 200, r.text
    lst = await client.get("/api/v1/ipam/blocks", headers=h)
    assert lst.status_code == 200
    assert [b["id"] for b in lst.json()] == [str(x.id)]
    # Y, the child block and the subnet inside X are not X.
    for other in (y.id, child.id):
        assert (await client.get(f"/api/v1/ipam/blocks/{other}", headers=h)).status_code == 403
        r = await client.put(f"/api/v1/ipam/blocks/{other}", json={"description": "no"}, headers=h)
        assert r.status_code == 403
    assert (await client.get(f"/api/v1/ipam/subnets/{sub.id}", headers=h)).status_code == 403
    assert (await client.get("/api/v1/ipam/spaces", headers=h)).status_code == 403
    assert (await client.delete(f"/api/v1/ipam/blocks/{x.id}", headers=h)).status_code == 403
    # Re-parenting X touches a block the grant does not name.
    r = await client.put(
        f"/api/v1/ipam/blocks/{child.id}", json={"parent_block_id": str(y.id)}, headers=h
    )
    assert r.status_code == 403
    r = await client.put(
        f"/api/v1/ipam/blocks/{x.id}", json={"site_id": str(uuid.uuid4())}, headers=h
    )
    assert r.status_code == 403
    # Read-only grant cannot write.
    assert (await client.get(f"/api/v1/ipam/blocks/{x.id}", headers=ro)).status_code == 200
    r = await client.put(f"/api/v1/ipam/blocks/{x.id}", json={"description": "n"}, headers=ro)
    assert r.status_code == 403
    # Superadmin unaffected.
    assert (await client.get(f"/api/v1/ipam/blocks/{y.id}", headers=sa)).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("rtype", "url", "make", "body"),
    [
        ("customer", "customers", lambda n: Customer(name=n), {"notes": "mine"}),
        ("site", "sites", lambda n: Site(name=n), {"notes": "mine"}),
        ("provider", "providers", lambda n: Provider(name=n), {"notes": "mine"}),
    ],
)
async def test_ownership_scoped_grant(
    db_session: AsyncSession, client: AsyncClient, rtype: str, url: str, make, body: dict
) -> None:
    x = make(f"x-{uuid.uuid4().hex[:6]}")
    y = make(f"y-{uuid.uuid4().hex[:6]}")
    db_session.add_all([x, y])
    await db_session.flush()
    h = await _holder(db_session, _rw(rtype, x.id))
    sa = await _holder(db_session, [], superadmin=True)
    await db_session.commit()

    base = f"/api/v1/{url}"
    g = await client.get(f"{base}/{x.id}", headers=h)
    assert g.status_code == 200, g.text
    r = await client.put(f"{base}/{x.id}", json=body, headers=h)
    assert r.status_code == 200, r.text
    lst = await client.get(base, headers=h)
    assert lst.status_code == 200, lst.text
    assert [i["id"] for i in lst.json()["items"]] == [str(x.id)]
    assert lst.json()["total"] == 1
    assert (await client.get(f"{base}/{y.id}", headers=h)).status_code == 403
    assert (await client.put(f"{base}/{y.id}", json=body, headers=h)).status_code == 403
    assert (await client.delete(f"{base}/{x.id}", headers=h)).status_code == 403
    assert (await client.post(base, json={"name": "new"}, headers=h)).status_code == 403
    assert (await client.get(f"{base}/{y.id}", headers=sa)).status_code == 200
    assert lst.json()["total"] == 1
    assert (await client.get(base, headers=sa)).json()["total"] >= 2


@pytest.mark.asyncio
async def test_scoped_customer_cannot_reach_summary_or_other_types(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    x = Customer(name=f"x-{uuid.uuid4().hex[:6]}")
    db_session.add(x)
    await db_session.flush()
    h = await _holder(db_session, _rw("customer", x.id))
    await db_session.commit()
    assert (await client.get(f"/api/v1/customers/{x.id}/summary", headers=h)).status_code == 403
    assert (await client.get("/api/v1/sites", headers=h)).status_code == 403


# ── Validation additions: the over-grant surface ─────────────────────────────

# Every route under one space / one block other than its own GET and PUT. Each
# must stay closed to a holder of a grant scoped to that item (allow-list).
_SPACE_SUBROUTES = [
    ("DELETE", ""),
    ("POST", "/dns-sync/commit"),
    ("GET", "/dns-sync/preview"),
    ("GET", "/effective-dhcp"),
    ("GET", "/effective-dns"),
    ("POST", "/find-free"),
    ("POST", "/reverse-zones/backfill"),
]
_BLOCK_SUBROUTES = [
    ("DELETE", ""),
    ("GET", "/aggregation-suggestions"),
    ("POST", "/allocate-subnet"),
    ("GET", "/available-subnets?prefix_len=24"),
    ("POST", "/dns-sync/commit"),
    ("GET", "/dns-sync/preview"),
    ("GET", "/effective-ddns"),
    ("GET", "/effective-dhcp"),
    ("GET", "/effective-dns"),
    ("GET", "/effective-fields"),
    ("GET", "/free-space"),
    ("POST", "/move/commit"),
    ("POST", "/move/preview"),
    ("POST", "/plan-allocation"),
    ("POST", "/resize"),
    ("POST", "/resize/preview"),
    ("POST", "/reverse-zones/backfill"),
]


@pytest.mark.asyncio
async def test_scoped_holder_reaches_no_other_route_of_the_item(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db_session.add(space)
    await db_session.flush()
    blk = IPBlock(space_id=space.id, network="10.0.0.0/16", name="b")
    db_session.add(blk)
    await db_session.flush()
    h = await _holder(db_session, _rw("ip_space", space.id) + _rw("ip_block", blk.id))
    await db_session.commit()

    for base, routes in (
        (f"/api/v1/ipam/spaces/{space.id}", _SPACE_SUBROUTES),
        (f"/api/v1/ipam/blocks/{blk.id}", _BLOCK_SUBROUTES),
    ):
        for method, tail in routes:
            kw = {"json": {}} if method == "POST" else {}
            r = await client.request(method, f"{base}{tail}", headers=h, **kw)
            assert r.status_code == 403, (method, base + tail, r.status_code, r.text)
        # Neither HEAD nor a trailing slash reaches the item's data.
        assert (await client.head(base, headers=h)).status_code in (403, 405)
        assert (await client.get(f"{base}/", headers=h)).status_code != 200


@pytest.mark.asyncio
async def test_scoped_writer_cannot_change_settings_descendants_inherit(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", do_not_probe=True)
    db_session.add(space)
    await db_session.flush()
    top = IPBlock(space_id=space.id, network="10.0.0.0/8", name="top")
    db_session.add(top)
    await db_session.flush()
    blk = IPBlock(
        space_id=space.id,
        network="10.1.0.0/16",
        name="b",
        parent_block_id=top.id,
        do_not_probe=True,
    )
    db_session.add(blk)
    await db_session.flush()
    h = await _holder(db_session, _rw("ip_space", space.id) + _rw("ip_block", blk.id))
    typed = await _holder(
        db_session,
        [{"action": a, "resource_type": "ip_block"} for a in ("read", "write")],
    )
    await db_session.commit()

    s_url = f"/api/v1/ipam/spaces/{space.id}"
    b_url = f"/api/v1/ipam/blocks/{blk.id}"
    for url, body in (
        (s_url, {"do_not_probe": False}),
        (s_url, {"ddns_enabled": True}),
        (s_url, {"ddns_ttl": 60}),
        (b_url, {"do_not_probe": False}),
        (b_url, {"ddns_enabled": True}),
        (b_url, {"ddns_inherit_settings": False}),
        (b_url, {"dns_inherit_settings": False}),
        (b_url, {"dhcp_inherit_settings": False}),
        (b_url, {"dns_split_horizon": True}),
        # Moving X out from under its parent touches the parent's subtree.
        (b_url, {"parent_block_id": None}),
    ):
        r = await client.put(url, json=body, headers=h)
        assert r.status_code == 403, (url, body, r.text)

    # Re-sending the current values (what the Edit dialogs do), or a null on a
    # field whose handler reads null as "unchanged", is not a change.
    r = await client.put(
        b_url,
        json={
            "description": "mine",
            "do_not_probe": True,
            "dns_inherit_settings": True,
            "dhcp_inherit_settings": True,
            "ddns_enabled": None,
        },
        headers=h,
    )
    assert r.status_code == 200, r.text
    r = await client.put(s_url, json={"description": "mine", "do_not_probe": True}, headers=h)
    assert r.status_code == 200, r.text

    # A type-level writer is not constrained by the scoped guard.
    r = await client.put(b_url, json={"do_not_probe": False}, headers=typed)
    assert r.status_code == 200, r.text
    assert r.json()["do_not_probe"] is False


@pytest.mark.asyncio
async def test_type_level_grants_still_see_everything(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    other = IPSpace(name=f"o-{uuid.uuid4().hex[:6]}")
    db_session.add_all([space, other])
    await db_session.flush()
    x = IPBlock(space_id=space.id, network="10.0.0.0/16", name="x")
    y = IPBlock(space_id=space.id, network="10.9.0.0/16", name="y")
    cx = Customer(name=f"cx-{uuid.uuid4().hex[:6]}")
    cy = Customer(name=f"cy-{uuid.uuid4().hex[:6]}")
    db_session.add_all([x, y, cx, cy])
    await db_session.flush()
    typed = await _holder(
        db_session,
        [
            {"action": "read", "resource_type": "ip_block"},
            {"action": "read", "resource_type": "customer"},
        ],
    )
    # A type-level read plus a scoped grant: the type-level one wins the list.
    both = await _holder(
        db_session,
        [
            {"action": "read", "resource_type": "ip_block"},
            {"action": "read", "resource_type": "ip_space"},
            {"action": "read", "resource_type": "customer"},
        ]
        + _rw("ip_block", x.id)
        + _rw("ip_space", space.id)
        + _rw("customer", cx.id),
    )
    await db_session.commit()

    for h in (typed, both):
        ids = {b["id"] for b in (await client.get("/api/v1/ipam/blocks", headers=h)).json()}
        assert {str(x.id), str(y.id)} <= ids
        assert (await client.get(f"/api/v1/ipam/blocks/{y.id}", headers=h)).status_code == 200
        c = (await client.get("/api/v1/customers", headers=h)).json()
        assert {str(cx.id), str(cy.id)} <= {i["id"] for i in c["items"]}
        assert c["total"] >= 2
        assert (await client.get(f"/api/v1/customers/{cy.id}", headers=h)).status_code == 200
    sp = (await client.get("/api/v1/ipam/spaces", headers=both)).json()
    assert {str(space.id), str(other.id)} <= {s["id"] for s in sp}
    # A type-level read is not a write on any one row.
    r = await client.put(f"/api/v1/ipam/blocks/{y.id}", json={"description": "n"}, headers=typed)
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_api_tokens_of_a_scoped_holder(db_session: AsyncSession, client: AsyncClient) -> None:
    x = IPSpace(name=f"x-{uuid.uuid4().hex[:6]}")
    y = IPSpace(name=f"y-{uuid.uuid4().hex[:6]}")
    db_session.add_all([x, y])
    await db_session.flush()
    blk = IPBlock(space_id=x.id, network="10.0.0.0/16", name="b")
    db_session.add(blk)
    await db_session.flush()
    sub = Subnet(space_id=x.id, block_id=blk.id, network="10.0.1.0/24", name="s")
    db_session.add(sub)
    owner = User(
        username=f"tk-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@t.io",
        display_name="scoped",
        hashed_password=hash_password("password123"),
    )
    role = Role(
        name=f"role-{uuid.uuid4().hex[:8]}",
        permissions=_rw("ip_space", x.id) + _rw("subnet", sub.id),
    )
    group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
    group.roles = [role]
    owner.groups = [group]
    db_session.add_all([role, group, owner])
    await db_session.flush()

    async def tok(grants: list[dict] | None) -> dict:
        raw, _p, token_hash = generate_api_token()
        db_session.add(
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
        await db_session.flush()
        return {"Authorization": f"Bearer {raw}"}

    plain = await tok(None)
    bound = await tok([{"action": "read", "resource_type": "subnet", "resource_id": str(sub.id)}])
    await db_session.commit()

    # An unbound token is its owner: the scoped space grant works, narrowed.
    assert (await client.get(f"/api/v1/ipam/spaces/{x.id}", headers=plain)).status_code == 200
    assert (await client.get(f"/api/v1/ipam/spaces/{y.id}", headers=plain)).status_code == 403
    lst = await client.get("/api/v1/ipam/spaces", headers=plain)
    assert [s["id"] for s in lst.json()] == [str(x.id)]
    # A token bound to one subnet narrows the owner: no space at all.
    assert (await client.get(f"/api/v1/ipam/spaces/{x.id}", headers=bound)).status_code == 403
    r = await client.put(f"/api/v1/ipam/spaces/{x.id}", json={"description": "n"}, headers=bound)
    assert r.status_code == 403
