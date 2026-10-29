"""Subnet Planner validate + apply follow New Subnet / New Block (#2984, #2985, #2986)."""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import CustomFieldDefinition, IPBlock, IPSpace
from tests.test_ipam_alias_cname_exclusive_2080 import _headers


async def _space(db: AsyncSession) -> tuple[str, dict[str, str]]:
    space = IPSpace(name=f"sp2984-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    await db.commit()
    return str(space.id), {}


async def _blk(db: AsyncSession, space: str, net: str, parent: str | None = None) -> str:
    b = IPBlock(
        space_id=uuid.UUID(space),
        network=net,
        name=net,
        parent_block_id=uuid.UUID(parent) if parent else None,
    )
    db.add(b)
    await db.flush()
    await db.commit()
    return str(b.id)


def _tree(anchor: str, net: str, *children: dict) -> dict:
    return {
        "id": "r",
        "network": net,
        "name": "root",
        "kind": "block",
        "existing_block_id": anchor,
        "children": list(children),
    }


def _sn(i: str, net: str, **kw) -> dict:
    return {"id": i, "network": net, "name": i, "kind": "subnet", **kw}


async def _validate(client, h, space, tree):
    r = await client.post(
        "/api/v1/ipam/plans/validate-tree",
        headers=h,
        json={"name": "v", "space_id": space, "tree": tree},
    )
    assert r.status_code == 200, r.text
    return r.json()


async def _plan(client, h, space, tree) -> str:
    c = await client.post(
        "/api/v1/ipam/plans", headers=h, json={"name": "p", "space_id": space, "tree": tree}
    )
    assert c.status_code == 201, c.text
    return c.json()["id"]


async def test_nested_anchor_validates_and_applies(client: AsyncClient, db_session: AsyncSession):
    h = await _headers(db_session)
    space, _ = await _space(db_session)
    top = await _blk(db_session, space, "10.233.0.0/16")
    mid = await _blk(db_session, space, "10.233.32.0/19", top)
    anchor = await _blk(db_session, space, "10.233.44.0/24", mid)
    tree = _tree(anchor, "10.233.44.0/24", _sn("a", "10.233.44.0/26"), _sn("b", "10.233.44.64/26"))
    v = await _validate(client, h, space, tree)
    assert v["ok"] is True, v
    pid = await _plan(client, h, space, tree)
    ap = await client.post(f"/api/v1/ipam/plans/{pid}/apply", headers=h)
    assert ap.status_code == 200, ap.text


async def test_nested_anchor_still_conflicts_with_real_overlaps(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    space, _ = await _space(db_session)
    top = await _blk(db_session, space, "10.234.0.0/16")
    anchor = await _blk(db_session, space, "10.234.96.0/19", top)
    await _blk(db_session, space, "10.234.120.0/24", anchor)  # existing child
    sibling = await _blk(db_session, space, "10.234.128.0/19", top)
    assert sibling
    tree = _tree(anchor, "10.234.96.0/19", _sn("a", "10.234.120.0/25"))
    v = await _validate(client, h, space, tree)
    assert v["ok"] is False
    assert all("10.234.0.0/16" not in c["message"] for c in v["conflicts"])
    assert any("10.234.120.0/24" in c["message"] for c in v["conflicts"])


async def test_gateway_outside_subnet_is_a_conflict(client: AsyncClient, db_session: AsyncSession):
    h = await _headers(db_session)
    space, _ = await _space(db_session)
    top = await _blk(db_session, space, "10.235.0.0/16")
    for gw in ("10.235.170.1", "10.235.162.0", "10.235.162.255", "nope"):
        tree = _tree(top, "10.235.0.0/16", _sn("a", "10.235.162.0/24", gateway=gw))
        v = await _validate(client, h, space, tree)
        assert v["ok"] is False, gw
        assert v["conflicts"][0]["kind"] == "invalid_gateway", gw
        pid = await _plan(client, h, space, tree)
        ap = await client.post(f"/api/v1/ipam/plans/{pid}/apply", headers=h)
        assert ap.status_code == 409, (gw, ap.text)
    ok = _tree(top, "10.235.0.0/16", _sn("a", "10.235.162.0/24", gateway="10.235.162.5"))
    assert (await _validate(client, h, space, ok))["ok"] is True


async def test_required_custom_field_is_a_conflict(client: AsyncClient, db_session: AsyncSession):
    h = await _headers(db_session)
    space, _ = await _space(db_session)
    top = await _blk(db_session, space, "10.236.0.0/16")
    tree = _tree(top, "10.236.0.0/16", _sn("a", "10.236.1.0/24"))
    assert (await _validate(client, h, space, tree))["ok"] is True  # control
    db_session.add(
        CustomFieldDefinition(
            resource_type="subnet",
            name="owner2986",
            label="Owner",
            field_type="text",
            is_required=True,
        )
    )
    await db_session.commit()
    v = await _validate(client, h, space, tree)
    assert v["ok"] is False
    assert "Owner (owner2986)" in v["conflicts"][0]["message"]
    pid = await _plan(client, h, space, tree)
    ap = await client.post(f"/api/v1/ipam/plans/{pid}/apply", headers=h)
    assert ap.status_code == 409, ap.text
    # inherited from the anchor chain satisfies it
    blk = await db_session.get(IPBlock, uuid.UUID(top))
    assert blk is not None
    blk.custom_fields = {"owner2986": "net-team"}
    await db_session.commit()
    assert (await _validate(client, h, space, tree))["ok"] is True


async def test_nested_anchor_still_refuses_outside_and_sibling_overlap(
    client: AsyncClient, db_session: AsyncSession
):
    """Skipping the anchor's ancestors must not open the rest of the space."""
    h = await _headers(db_session)
    space, _ = await _space(db_session)
    top = await _blk(db_session, space, "10.237.0.0/16")
    anchor = await _blk(db_session, space, "10.237.96.0/19", top)
    sibling = await _blk(db_session, space, "10.237.128.0/19", top)

    # A node outside the anchor, in free space of the anchor's parent.
    outside = _tree(anchor, "10.237.96.0/19", _sn("a", "10.237.200.0/24"))
    v = await _validate(client, h, space, outside)
    assert v["ok"] is False
    assert any(c["kind"] == "out_of_parent" for c in v["conflicts"]), v
    pid = await _plan(client, h, space, outside)
    assert (await client.post(f"/api/v1/ipam/plans/{pid}/apply", headers=h)).status_code == 409

    # A node overlapping a sibling block of the anchor.
    over = _tree(anchor, "10.237.96.0/19", _sn("a", "10.237.130.0/24"))
    v = await _validate(client, h, space, over)
    assert v["ok"] is False
    msgs = [c["message"] for c in v["conflicts"]]
    assert any(f"id={sibling}" in m for m in msgs), msgs
    assert all("10.237.0.0/16" not in m for m in msgs), msgs
    pid = await _plan(client, h, space, over)
    assert (await client.post(f"/api/v1/ipam/plans/{pid}/apply", headers=h)).status_code == 409


async def test_planner_and_new_subnet_share_one_gateway_rule(
    client: AsyncClient, db_session: AsyncSession
):
    """Every gateway New Subnet refuses, validate refuses with the same words,
    and every gateway it accepts, validate accepts (#2984)."""
    h = await _headers(db_session)
    space, _ = await _space(db_session)
    top = await _blk(db_session, space, "10.238.0.0/16")
    cases = [
        ("10.238.1.0/24", "10.238.9.1", False),
        ("10.238.2.0/24", "10.238.2.0", False),  # network address
        ("10.238.3.0/24", "10.238.3.255", False),  # broadcast address
        ("10.238.4.0/24", "nope", False),
        ("10.238.5.0/24", "10.238.5.7", True),
        ("10.238.6.0/31", "10.238.6.0", True),  # /31: no placeholder rows
    ]
    for net, gw, ok in cases:
        tree = _tree(top, "10.238.0.0/16", _sn("a", net, gateway=gw))
        v = await _validate(client, h, space, tree)
        r = await client.post(
            "/api/v1/ipam/subnets",
            headers=h,
            json={"space_id": space, "block_id": top, "network": net, "name": net, "gateway": gw},
        )
        if ok:
            assert v["ok"] is True, (net, gw, v)
            assert r.status_code == 201, (net, gw, r.text)
        else:
            assert v["ok"] is False, (net, gw)
            assert r.status_code == 422, (net, gw, r.text)
            assert v["conflicts"][0]["message"] == r.json()["detail"], (net, gw)


async def test_new_subnet_skip_auto_addresses_keeps_network_gateway(
    client: AsyncClient, db_session: AsyncSession
):
    """Without placeholder rows nothing holds the network address, so New
    Subnet still accepts it as the gateway (unchanged)."""
    h = await _headers(db_session)
    space, _ = await _space(db_session)
    top = await _blk(db_session, space, "10.239.0.0/16")
    r = await client.post(
        "/api/v1/ipam/subnets",
        headers=h,
        json={
            "space_id": space,
            "block_id": top,
            "network": "10.239.1.0/24",
            "name": "lo",
            "gateway": "10.239.1.0",
            "skip_auto_addresses": True,
        },
    )
    assert r.status_code == 201, r.text


async def test_required_block_custom_field_is_a_conflict(
    client: AsyncClient, db_session: AsyncSession
):
    """A planned block is held to New Block's Required fields (#2986)."""
    h = await _headers(db_session)
    space, _ = await _space(db_session)
    top = await _blk(db_session, space, "10.240.0.0/16")
    db_session.add(
        CustomFieldDefinition(
            resource_type="ip_block",
            name="site2986",
            label="Site",
            field_type="text",
            is_required=True,
        )
    )
    await db_session.commit()
    sub = {"id": "b", "network": "10.240.8.0/21", "name": "b", "kind": "block", "children": []}
    tree = _tree(top, "10.240.0.0/16", sub)
    v = await _validate(client, h, space, tree)
    assert v["ok"] is False
    assert [c["node_id"] for c in v["conflicts"]] == ["b"]  # not the existing anchor
    assert "Site (site2986)" in v["conflicts"][0]["message"]
    pid = await _plan(client, h, space, tree)
    assert (await client.post(f"/api/v1/ipam/plans/{pid}/apply", headers=h)).status_code == 409
    # New Block refuses the same.
    r = await client.post(
        "/api/v1/ipam/blocks",
        headers=h,
        json={"space_id": space, "parent_block_id": top, "network": "10.240.16.0/21"},
    )
    assert r.status_code == 422, r.text
