"""An IPv6 subnet's size is never printed as the 64-bit storage cap (#3322).

``Subnet.total_ips`` is clamped to BIGINT (2^63 - 1); Find Free, the CSV
export and the Resize preview printed that cap as the address count.

The API's ``int`` fields stay int64-safe (a generated Swift / Go client
decodes ``integer`` as 64-bit, and 2^64 would fail the whole response), so
the exact figure rides in a ``*_exact`` string beside each one.
"""

from __future__ import annotations

import csv
import io
import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.ipam_io.export import export_subtree
from tests.test_ipam_alias_cname_exclusive_2080 import _headers

CAP = 2**63 - 1


async def _v6(db: AsyncSession, subnet: str | None = None):
    space = IPSpace(name=f"sp3322-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="fd33:236:0:200::/56", name="b")
    db.add(block)
    await db.flush()
    sub = None
    if subnet:
        sub = Subnet(
            space_id=space.id,
            block_id=block.id,
            network=subnet,
            name="s",
            total_ips=CAP,
        )
        db.add(sub)
        await db.flush()
    await db.commit()
    return space, block, sub


async def test_find_free_reports_a_slash_64_as_2_64(client: AsyncClient, db_session: AsyncSession):
    h = await _headers(db_session)
    space, block, _ = await _v6(db_session)
    r = await client.post(
        f"/api/v1/ipam/spaces/{space.id}/find-free",
        headers=h,
        json={
            "prefix_length": 64,
            "address_family": 6,
            "count": 3,
            "parent_block_id": str(block.id),
        },
    )
    assert r.status_code == 200, r.text
    cands = r.json()["candidates"]
    assert len(cands) == 3
    assert all(c["free_addresses_exact"] == str(2**64) for c in cands)
    # The int field never leaves int64, so a generated client still decodes it.
    assert all(c["free_addresses"] == CAP for c in cands)


async def test_csv_export_sizes_ipv6_rows_from_the_cidr(db_session: AsyncSession):
    space, _, _ = await _v6(db_session, "fd33:236:0:201::/64")
    db_session.add(
        Subnet(
            space_id=space.id,
            block_id=(await _first_block(db_session, space)).id,
            network="fd33:236:0:202::/63",
            name="t",
            total_ips=CAP,
        )
    )
    await db_session.flush()
    data, _, _ = await export_subtree(db_session, space_id=space.id, format="csv")
    rows = {r["network"]: r for r in csv.DictReader(io.StringIO(data.decode()))}
    assert rows["fd33:236:0:201::/64"]["total_ips"] == str(2**64)
    assert rows["fd33:236:0:202::/63"]["total_ips"] == str(2**65)


async def _first_block(db: AsyncSession, space: IPSpace) -> IPBlock:
    from sqlalchemy import select

    return (await db.execute(select(IPBlock).where(IPBlock.space_id == space.id))).scalars().one()


async def test_resize_preview_growth_is_not_no_change(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    _, _, sub = await _v6(db_session, "fd33:236:0:202::/64")
    r = await client.post(
        f"/api/v1/ipam/subnets/{sub.id}/resize/preview",
        headers=h,
        json={"new_cidr": "fd33:236:0:202::/63"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_ips_before_exact"] == str(2**64)
    assert body["total_ips_after_exact"] == str(2**65)
    assert body["total_ips_before"] <= CAP and body["total_ips_after"] <= CAP


async def test_block_resize_preview_carries_exact_sizes(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    _, block, _ = await _v6(db_session)
    r = await client.post(
        f"/api/v1/ipam/blocks/{block.id}/resize/preview",
        headers=h,
        json={"new_cidr": "fd33:236:0:200::/55"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_ips_before_exact"] == str(2**72)
    assert body["total_ips_after_exact"] == str(2**73)
    assert body["total_ips_before"] == CAP and body["total_ips_after"] == CAP


async def test_ipv4_counts_are_unchanged(client: AsyncClient, db_session: AsyncSession):
    h = await _headers(db_session)
    space = IPSpace(name=f"sp3322v4-{uuid.uuid4().hex[:8]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.33.0.0/16", name="b4")
    db_session.add(block)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/ipam/spaces/{space.id}/find-free",
        headers=h,
        json={"prefix_length": 24, "address_family": 4, "count": 1},
    )
    assert r.status_code == 200, r.text
    (cand,) = r.json()["candidates"]
    assert cand["free_addresses"] == 254
    assert cand["free_addresses_exact"] == "254"


def test_openapi_count_fields_stay_int64_with_an_exact_string():
    from app.main import app

    schemas = app.openapi()["components"]["schemas"]
    for model, field in (
        ("FindFreeCandidate", "free_addresses"),
        ("SubnetResizePreviewResponse", "total_ips_before"),
        ("SubnetResizePreviewResponse", "total_ips_after"),
        ("BlockResizePreviewResponse", "total_ips_before"),
        ("BlockResizePreviewResponse", "total_ips_after"),
    ):
        props = schemas[model]["properties"]
        assert props[field]["type"] == "integer", (model, field)
        assert props[f"{field}_exact"]["type"] == "string", (model, field)


async def test_json_and_xlsx_exports_carry_the_true_size(db_session: AsyncSession):
    import json

    from openpyxl import load_workbook

    space, _, _ = await _v6(db_session, "fd33:236:0:201::/64")
    data, _, _ = await export_subtree(db_session, space_id=space.id, format="json")
    (row,) = json.loads(data)["subnets"]
    assert row["total_ips"] == 2**64
    data, _, _ = await export_subtree(db_session, space_id=space.id, format="xlsx")
    ws = load_workbook(io.BytesIO(data)).worksheets[0]
    header = [c.value for c in ws[1]]
    value = ws[2][header.index("total_ips")].value
    # Text, digit for digit: as a spreadsheet number (a double) openpyxl
    # writes 1.844674407370955E+19, which is 2^64 - 2048.
    assert value == str(2**64)
