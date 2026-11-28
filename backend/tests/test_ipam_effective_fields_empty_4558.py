"""An empty custom field value must not hide an ancestor's (#4558)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPBlock, IPSpace, Subnet
from tests.test_ipam_alias_cname_exclusive_2080 import _headers


@pytest.mark.asyncio
@pytest.mark.parametrize("empty", ["", None, "  ", []])
async def test_empty_value_inherits_from_block_chain(
    client: AsyncClient, db_session: AsyncSession, empty: object
) -> None:
    h = await _headers(db_session)
    space = IPSpace(name=f"sp4558-{uuid.uuid4().hex[:8]}", description="")
    db_session.add(space)
    await db_session.flush()
    top = IPBlock(
        space_id=space.id, network="10.84.0.0/16", name="top", custom_fields={"owner": "team-a"}
    )
    db_session.add(top)
    await db_session.flush()
    child = IPBlock(
        space_id=space.id,
        network="10.84.128.0/17",
        name="child",
        parent_block_id=top.id,
        custom_fields={"owner": empty},
    )
    db_session.add(child)
    await db_session.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=child.id,
        network="10.84.200.0/24",
        name="s",
        custom_fields={"owner": empty},
    )
    db_session.add(subnet)
    await db_session.commit()

    r = await client.get(f"/api/v1/ipam/blocks/{child.id}/effective-fields", headers=h)
    assert r.json()["custom_fields"]["owner"] == "team-a"
    assert r.json()["custom_field_sources"]["owner"] == f"block:{top.id}"

    r = await client.get(f"/api/v1/ipam/subnets/{subnet.id}/effective-fields", headers=h)
    assert r.json()["custom_fields"]["owner"] == "team-a"
    assert r.json()["custom_field_sources"]["owner"] == f"block:{top.id}"
