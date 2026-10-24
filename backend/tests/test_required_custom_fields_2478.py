"""#2478 — a Required custom field is enforced on block and subnet writes.

Create: every required field needs a value (own, or inherited from the block
chain). Update: only when the request sends ``custom_fields``, and only for a
field it sends or the row already holds, so turning a field Required later
does not make existing rows uneditable.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.ipam import CustomFieldDefinition, IPBlock, IPSpace


async def _setup(db: AsyncSession) -> tuple[dict[str, str], str, str]:
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
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="top")
    db.add(block)
    await db.commit()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    return headers, str(space.id), str(block.id)


async def _require(db: AsyncSession, resource_type: str, name: str) -> None:
    db.add(
        CustomFieldDefinition(
            resource_type=resource_type,
            name=name,
            label=name.title(),
            field_type="text",
            is_required=True,
        )
    )
    await db.commit()


async def _block(client, headers, sp, parent, net, **extra):
    return await client.post(
        "/api/v1/ipam/blocks",
        headers=headers,
        json={
            "space_id": sp,
            "parent_block_id": parent,
            "network": net,
            "name": net,
            **extra,
        },
    )


async def _subnet(client, headers, sp, blk, net, **extra):
    return await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={"space_id": sp, "block_id": blk, "network": net, **extra},
    )


@pytest.mark.asyncio
async def test_create_block_refuses_a_missing_required_field(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sp, top = await _setup(db_session)
    await _require(db_session, "ip_block", "tier")

    r = await _block(client, headers, sp, top, "10.1.0.0/16")
    assert r.status_code == 422, r.text
    assert "Tier" in r.json()["detail"]
    r = await _block(client, headers, sp, top, "10.1.0.0/16", custom_fields={"tier": "  "})
    assert r.status_code == 422, r.text

    r = await _block(client, headers, sp, top, "10.1.0.0/16", custom_fields={"tier": "gold"})
    assert r.status_code == 201, r.text
    assert r.json()["custom_fields"] == {"tier": "gold"}


@pytest.mark.asyncio
async def test_create_subnet_refuses_missing_and_accepts_inherited(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sp, top = await _setup(db_session)
    await _require(db_session, "subnet", "owner")

    r = await _subnet(client, headers, sp, top, "10.2.0.0/24")
    assert r.status_code == 422, r.text
    assert "Owner" in r.json()["detail"]

    r = await _subnet(client, headers, sp, top, "10.2.0.0/24", custom_fields={"owner": "neteng"})
    assert r.status_code == 201, r.text

    # A value the block chain carries satisfies the field.
    top_row = await db_session.get(IPBlock, uuid.UUID(top))
    top_row.custom_fields = {"owner": "from-block"}
    await db_session.commit()
    r = await _subnet(client, headers, sp, top, "10.3.0.0/24")
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_a_field_made_required_later_does_not_lock_existing_rows(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sp, top = await _setup(db_session)
    created = await _subnet(client, headers, sp, top, "10.4.0.0/24")
    assert created.status_code == 201
    sid = created.json()["id"]
    await _require(db_session, "subnet", "owner")

    # No custom_fields sent: untouched.
    r = await client.put(f"/api/v1/ipam/subnets/{sid}", headers=headers, json={"name": "renamed"})
    assert r.status_code == 200, r.text
    # custom_fields sent without the field the row never had: still fine.
    r = await client.put(
        f"/api/v1/ipam/subnets/{sid}", headers=headers, json={"custom_fields": {"other": "x"}}
    )
    assert r.status_code == 200, r.text
    # Sending the field empty is refused.
    r = await client.put(
        f"/api/v1/ipam/subnets/{sid}", headers=headers, json={"custom_fields": {"owner": ""}}
    )
    assert r.status_code == 422, r.text
    # Giving it a value is accepted, and then it cannot be blanked by omission.
    r = await client.put(
        f"/api/v1/ipam/subnets/{sid}", headers=headers, json={"custom_fields": {"owner": "neteng"}}
    )
    assert r.status_code == 200, r.text
    r = await client.put(f"/api/v1/ipam/subnets/{sid}", headers=headers, json={"custom_fields": {}})
    assert r.status_code == 422, r.text
    r = await client.put(f"/api/v1/ipam/subnets/{sid}", headers=headers, json={"description": "d"})
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_update_block_applies_the_same_rule(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sp, top = await _setup(db_session)
    made = await _block(client, headers, sp, top, "10.5.0.0/16")
    assert made.status_code == 201
    bid = made.json()["id"]
    await _require(db_session, "ip_block", "tier")

    r = await client.put(f"/api/v1/ipam/blocks/{bid}", headers=headers, json={"custom_fields": {}})
    assert r.status_code == 200, r.text  # legacy block, untouched
    r = await client.put(
        f"/api/v1/ipam/blocks/{bid}", headers=headers, json={"custom_fields": {"tier": ""}}
    )
    assert r.status_code == 422, r.text
    r = await client.put(
        f"/api/v1/ipam/blocks/{bid}", headers=headers, json={"custom_fields": {"tier": "gold"}}
    )
    assert r.status_code == 200, r.text
    r = await client.put(f"/api/v1/ipam/blocks/{bid}", headers=headers, json={"custom_fields": {}})
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_optional_fields_and_other_resource_types_are_unaffected(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sp, top = await _setup(db_session)
    await _require(db_session, "subnet", "owner")  # required on subnets only
    r = await _block(client, headers, sp, top, "10.6.0.0/16")
    assert r.status_code == 201, r.text
