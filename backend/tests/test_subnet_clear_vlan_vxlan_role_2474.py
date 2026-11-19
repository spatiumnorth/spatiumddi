"""#2474 — Edit Subnet's clears of VLAN, VXLAN ID and Network role are stored.

``update_subnet`` used to dump the body with ``exclude_none=True``, which drops
every explicit null, so a clear closed the dialog and kept the old value.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.ipam import IPBlock, IPSpace


async def _setup(client: AsyncClient, db: AsyncSession) -> tuple[dict[str, str], dict]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="b")
    db.add(block)
    await db.commit()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    r = await client.post("/api/v1/vlans/routers", headers=headers, json={"name": "r1"})
    assert r.status_code == 201, r.text
    v = await client.post(
        f"/api/v1/vlans/routers/{r.json()['id']}/vlans",
        headers=headers,
        json={"vlan_id": 998, "name": "v998"},
    )
    assert v.status_code == 201, v.text
    sub = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": "10.1.0.0/24",
            "vxlan_id": 5001,
            "subnet_role": "voice",
            "vlan_ref_id": v.json()["id"],
        },
    )
    assert sub.status_code == 201, sub.text
    return headers, sub.json()


@pytest.mark.asyncio
async def test_explicit_nulls_clear_vlan_vxlan_and_role(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sub = await _setup(client, db_session)
    assert sub["vxlan_id"] == 5001 and sub["subnet_role"] == "voice"
    assert sub["vlan_ref_id"] is not None and sub["vlan_id"] == 998

    r = await client.put(
        f"/api/v1/ipam/subnets/{sub['id']}",
        headers=headers,
        json={"vlan_ref_id": None, "vxlan_id": None, "subnet_role": None},
    )
    assert r.status_code == 200, r.text
    got = (await client.get(f"/api/v1/ipam/subnets/{sub['id']}", headers=headers)).json()
    assert got["vxlan_id"] is None
    assert got["subnet_role"] is None
    assert got["vlan_ref_id"] is None
    # The tag was derived from the referenced VLAN, so it goes with it.
    assert got["vlan_id"] is None


@pytest.mark.asyncio
async def test_empty_role_string_clears_and_untouched_save_is_a_noop(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sub = await _setup(client, db_session)
    # The dialog's untouched Save resends what it loaded.
    same = {
        "vlan_ref_id": sub["vlan_ref_id"],
        "vxlan_id": sub["vxlan_id"],
        "subnet_role": sub["subnet_role"],
    }
    r = await client.put(f"/api/v1/ipam/subnets/{sub['id']}", headers=headers, json=same)
    assert r.status_code == 200, r.text
    assert r.json()["vxlan_id"] == 5001
    assert r.json()["subnet_role"] == "voice"
    assert r.json()["vlan_id"] == 998

    r = await client.put(
        f"/api/v1/ipam/subnets/{sub['id']}", headers=headers, json={"subnet_role": ""}
    )
    assert r.json()["subnet_role"] is None
    # Fields not sent are untouched.
    assert r.json()["vxlan_id"] == 5001


@pytest.mark.asyncio
async def test_clearing_ref_with_explicit_vlan_id_keeps_that_tag(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sub = await _setup(client, db_session)
    r = await client.put(
        f"/api/v1/ipam/subnets/{sub['id']}",
        headers=headers,
        json={"vlan_ref_id": None, "vlan_id": 998},
    )
    assert r.status_code == 200, r.text
    assert r.json()["vlan_ref_id"] is None
    assert r.json()["vlan_id"] == 998
