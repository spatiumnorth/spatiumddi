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
