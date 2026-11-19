"""#2566 -- allocate-subnet applies the template's values, as POST /subnets does.

``allocate_subnet`` rebuilt the create body from a full ``model_dump``, so every
field read as caller-supplied and the template pre-fill filled nothing.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.ipam import IPAMTemplate, IPBlock, IPSpace


async def _setup(db: AsyncSession) -> tuple[dict[str, str], IPBlock, IPAMTemplate]:
    user = User(
        username=f"al-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="AL",
        hashed_password=hash_password("x" * 10),
        is_superadmin=True,
    )
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add_all([user, space])
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.60.0.0/16", name="b")
    template = IPAMTemplate(
        name=f"t-{uuid.uuid4().hex[:6]}",
        applies_to="subnet",
        tags={"env": "prod"},
        custom_fields={"owner": "netops"},
        ddns_enabled=True,
        ddns_hostname_policy="client_provided",
        ddns_domain_override="tpl.example.test",
        ddns_ttl=321,
    )
    db.add_all([block, template])
    await db.commit()
    hdr = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    return hdr, block, template


@pytest.mark.asyncio
async def test_allocate_fills_from_template(client: AsyncClient, db_session: AsyncSession) -> None:
    hdr, block, template = await _setup(db_session)
    r = await client.post(
        f"/api/v1/ipam/blocks/{block.id}/allocate-subnet",
        headers=hdr,
        json={"prefix_len": 24, "name": "n", "template_id": str(template.id)},
    )
    assert r.status_code == 201, r.text
    j = r.json()
    assert j["tags"] == {"env": "prod"}
    assert j["custom_fields"] == {"owner": "netops"}
    assert j["ddns_enabled"] is True
    assert j["ddns_ttl"] == 321
    assert j["ddns_domain_override"] == "tpl.example.test"
    assert j["applied_template_id"] == str(template.id)


@pytest.mark.asyncio
async def test_explicit_caller_values_beat_template(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    hdr, block, template = await _setup(db_session)
    r = await client.post(
        f"/api/v1/ipam/blocks/{block.id}/allocate-subnet",
        headers=hdr,
        json={
            "prefix_len": 24,
            "name": "n",
            "template_id": str(template.id),
            "tags": {"env": "dev"},
            "ddns_ttl": 5,
        },
    )
    assert r.status_code == 201, r.text
    j = r.json()
    assert j["tags"] == {"env": "dev"}
    assert j["ddns_ttl"] == 5
    assert j["custom_fields"] == {"owner": "netops"}
