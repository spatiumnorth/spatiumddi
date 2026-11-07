"""Resize block's preview leaves the Trash out (#3710).

The preview walked a block's descendants with raw ``WITH RECURSIVE`` SQL, and
raw SQL skips the ORM soft-delete filter, so a subnet or child block sent to
the Trash was still counted, listed and (for subnets) summed by address rows.
The preview, and the commit's own fit checks, now read live rows only.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPSpace
from tests.test_ipam_alias_cname_exclusive_2080 import _headers


async def _block(client, h, space_id, network, parent=None) -> str:
    body = {"space_id": space_id, "network": network, "name": "b"}
    if parent:
        body["parent_block_id"] = parent
    r = await client.post("/api/v1/ipam/blocks", headers=h, json=body)
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


async def _subnet(client, h, space_id, block_id, network) -> str:
    r = await client.post(
        "/api/v1/ipam/subnets",
        headers=h,
        json={
            "space_id": space_id,
            "block_id": block_id,
            "network": network,
            "skip_reverse_zone": True,
        },
    )
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


async def _preview(client, h, block_id, new_cidr) -> dict:
    r = await client.post(
        f"/api/v1/ipam/blocks/{block_id}/resize/preview", headers=h, json={"new_cidr": new_cidr}
    )
    assert r.status_code == 200, r.text
    return r.json()


async def test_preview_counts_only_live_descendants(client: AsyncClient, db_session: AsyncSession):
    h = await _headers(db_session)
    space = IPSpace(name=f"sp3710-{uuid.uuid4().hex[:8]}", description="")
    db_session.add(space)
    await db_session.flush()
    await db_session.commit()
    sid = str(space.id)

    top = await _block(client, h, sid, "10.109.32.0/24")
    keep = await _subnet(client, h, sid, top, "10.109.32.0/26")
    gone = await _subnet(client, h, sid, top, "10.109.32.64/26")
    child = await _block(client, h, sid, "10.109.32.128/26", top)

    before = await _preview(client, h, top, "10.109.32.0/23")
    assert before["child_blocks_count"] == 1
    assert before["child_subnets_count"] == 2
    keep_rows = before["descendant_ip_addresses_total"]
    assert keep_rows > 0

    assert (await client.delete(f"/api/v1/ipam/subnets/{gone}", headers=h)).status_code == 204
    assert (await client.delete(f"/api/v1/ipam/blocks/{child}", headers=h)).status_code == 204

    after = await _preview(client, h, top, "10.109.32.0/23")
    assert after["child_blocks_count"] == 0
    assert after["child_blocks"] == []
    assert after["child_subnets_count"] == 1
    assert [s["id"] for s in after["child_subnets"]] == [keep]
    assert 0 < after["descendant_ip_addresses_total"] < keep_rows
