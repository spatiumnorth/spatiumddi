"""#3895 -- reapply-all names each skipped instance and leaves it as it was."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAMTemplate, IPBlock, IPSpace, Subnet
from tests.test_ipam_template_fields_written_1634 import _headers


@pytest.mark.asyncio
async def test_block_skipped_for_overlap_keeps_its_fields_and_says_why(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    hdr = await _headers(db_session)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.46.0.0/16", name="b", tags={"owner": "operator"})
    db_session.add(block)
    await db_session.flush()
    db_session.add(Subnet(space_id=space.id, block_id=block.id, network="10.46.0.0/25", name="s"))
    template = IPAMTemplate(
        name=f"t-{uuid.uuid4().hex[:6]}",
        applies_to="block",
        tags={"owner": "template"},
        child_layout={"children": [{"prefix": 26, "name_template": "{name}"}]},
    )
    db_session.add(template)
    await db_session.flush()
    block.applied_template_id = template.id
    await db_session.commit()

    resp = await client.post(f"/api/v1/ipam/templates/{template.id}/reapply-all", headers=hdr)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["instances_processed"] == 0 and body["instances_skipped"] == 1
    assert body["skipped"][0]["target_id"] == str(block.id)
    assert body["skipped"][0]["network"] == "10.46.0.0/16"
    assert "overlaps" in body["skipped"][0]["reason"]

    got = await client.get(f"/api/v1/ipam/blocks/{block.id}", headers=hdr)
    assert got.json()["tags"] == {"owner": "operator"}
