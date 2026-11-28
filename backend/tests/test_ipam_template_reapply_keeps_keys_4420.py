"""#4420 -- a forced stamp merges tags / custom fields instead of replacing them.

Reapply to all (``force=True``) set the instance's whole ``tags`` and
``custom_fields`` to the template's, erasing every key an operator had set
that the template does not hold.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.ipam import IPAMTemplate, IPBlock, IPSpace, Subnet


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"ta-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="TA",
        hashed_password=hash_password("x" * 10),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.mark.asyncio
async def test_reapply_all_keeps_operator_keys(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    hdr = await _headers(db_session)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="b")
    db_session.add(block)
    await db_session.flush()
    template = IPAMTemplate(
        name=f"t-{uuid.uuid4().hex[:6]}",
        applies_to="subnet",
        tags={"xp_tpl": "t"},
        custom_fields={"tpl_cf": "new"},
    )
    db_session.add(template)
    await db_session.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.24.1.0/24",
        name="s",
        applied_template_id=template.id,
        tags={"xp_tpl": "old", "xp_own": "keep"},
        custom_fields={"tpl_cf": "old", "xp_own_note": "keep"},
    )
    # A second instance of a template that holds nothing: tags must not be emptied.
    bare = IPAMTemplate(name=f"t-{uuid.uuid4().hex[:6]}", applies_to="subnet")
    db_session.add_all([subnet, bare])
    await db_session.flush()
    other = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.24.2.0/24",
        name="o",
        applied_template_id=bare.id,
        tags={"mine": "1"},
        custom_fields={"mine_cf": "1"},
    )
    db_session.add(other)
    await db_session.commit()

    for tpl in (template, bare):
        resp = await client.post(f"/api/v1/ipam/templates/{tpl.id}/reapply-all", headers=hdr)
        assert resp.status_code == 200, resp.text
        assert resp.json()["instances_processed"] == 1

    await db_session.refresh(subnet)
    await db_session.refresh(other)
    assert subnet.tags == {"xp_tpl": "t", "xp_own": "keep"}
    assert subnet.custom_fields == {"tpl_cf": "new", "xp_own_note": "keep"}
    assert other.tags == {"mine": "1"}
    assert other.custom_fields == {"mine_cf": "1"}
