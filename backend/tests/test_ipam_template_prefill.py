"""#1304 — an IPAM template's DDNS lock goes with its DDNS values.

A template that sets DDNS also turns the new subnet's (or block's)
``ddns_inherit_settings`` off, so the values it stamps take effect. The
create path fills only the fields a request leaves out (Pydantic
``model_fields_set``), so when the request carries every DDNS value the
template sets, none of them is the template's. The lock still fired, and the
new subnet's DDNS was pinned to the request's own values instead of
inheriting. The New Subnet dialog sent every DDNS field, so a template that
turned DDNS on produced a subnet with DDNS pinned OFF.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.ipam import IPAMTemplate, IPBlock, IPSpace

# Every DDNS value at the create schema's default: what a request that
# leaves DDNS alone, but names each field, carries.
DDNS_LEFT_ALONE = {
    "ddns_enabled": False,
    "ddns_hostname_policy": "client_or_generated",
    "ddns_domain_override": None,
    "ddns_ttl": None,
}


async def _admin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"tp-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="TP",
        hashed_password=hash_password("x" * 10),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _seed(db: AsyncSession, applies_to: str) -> tuple[IPSpace, IPBlock, IPAMTemplate]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.70.0.0/16", name="blk")
    template = IPAMTemplate(
        name=f"tpl-{uuid.uuid4().hex[:6]}",
        applies_to=applies_to,
        ddns_enabled=True,
        ddns_hostname_policy="always_generate",
        ddns_ttl=120,
    )
    db.add_all([block, template])
    await db.flush()
    await db.commit()
    return space, block, template


@pytest.mark.asyncio
async def test_subnet_template_ddns_lock_stays_off_when_the_request_sets_ddns(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    hdr = await _admin_headers(db_session)
    space, block, template = await _seed(db_session, "subnet")

    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=hdr,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": "10.70.1.0/24",
            "template_id": str(template.id),
            **DDNS_LEFT_ALONE,
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    # The request's own DDNS values were kept ...
    assert body["ddns_enabled"] is False
    assert body["ddns_hostname_policy"] == "client_or_generated"
    # ... so the template's lock did not come with them: the subnet still
    # inherits DDNS, as the same request without a template would.
    assert body["ddns_inherit_settings"] is True


@pytest.mark.asyncio
async def test_subnet_template_ddns_and_its_lock_apply_when_the_request_omits_ddns(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    hdr = await _admin_headers(db_session)
    space, block, template = await _seed(db_session, "subnet")

    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=hdr,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": "10.70.2.0/24",
            "template_id": str(template.id),
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["ddns_enabled"] is True
    assert body["ddns_hostname_policy"] == "always_generate"
    assert body["ddns_ttl"] == 120
    assert body["ddns_inherit_settings"] is False


@pytest.mark.asyncio
async def test_subnet_template_lock_comes_with_any_ddns_value_it_supplies(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    # The request turns DDNS off but says nothing about the hostname policy
    # or the TTL, so those two are the template's — and the lock comes with
    # them: the subnet keeps its own (off) DDNS rather than inheriting.
    hdr = await _admin_headers(db_session)
    space, block, template = await _seed(db_session, "subnet")

    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=hdr,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": "10.70.3.0/24",
            "template_id": str(template.id),
            "ddns_enabled": False,
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["ddns_enabled"] is False
    assert body["ddns_hostname_policy"] == "always_generate"
    assert body["ddns_ttl"] == 120
    assert body["ddns_inherit_settings"] is False


@pytest.mark.asyncio
async def test_block_template_ddns_lock_stays_off_when_the_request_sets_ddns(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    hdr = await _admin_headers(db_session)
    space, _, template = await _seed(db_session, "block")

    resp = await client.post(
        "/api/v1/ipam/blocks",
        headers=hdr,
        json={
            "space_id": str(space.id),
            "network": "10.71.0.0/16",
            "template_id": str(template.id),
            **DDNS_LEFT_ALONE,
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["ddns_enabled"] is False
    assert body["ddns_inherit_settings"] is True
