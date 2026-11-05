"""An address whose subnet is in the Trash reads as absent by id (#3537).

``IPAddress`` is not soft-deletable, so a trashed subnet's addresses stay in the
table (that is what lets a restore bring them back) and the soft-delete filter
never hides them. The routes keyed on the address's own id used ``db.get`` and
never looked at the subnet: GET answered 200, and PUT stored the change,
including a MAC change that wrote an ``ip_mac_history`` row which then raised
new-device alerts after the restore. They now answer 404 like
``GET /subnets/{id}``, before any write, and answer normally again after a
restore.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress, IPBlock, IpMacHistory, IPSpace, Subnet
from tests.test_ipam_alias_cname_exclusive_2080 import _headers

MAC = "00:00:5e:00:53:c7"


async def _addr(db: AsyncSession, h: dict[str, str]) -> tuple[uuid.UUID, uuid.UUID]:
    space = IPSpace(name=f"sp3537-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.83.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.83.1.0/24", name="s")
    db.add(subnet)
    await db.flush()
    ip = IPAddress(subnet_id=subnet.id, address="10.83.1.10", status="allocated")
    db.add(ip)
    await db.commit()
    return subnet.id, ip.id


async def _mac_rows(db: AsyncSession, ip_id: uuid.UUID) -> int:
    return int(
        await db.scalar(
            select(func.count())
            .select_from(IpMacHistory)
            .where(IpMacHistory.ip_address_id == ip_id)
        )
        or 0
    )


@pytest.mark.asyncio
async def test_trashed_subnet_addresses_are_404_and_untouched(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    subnet_id, ip_id = await _addr(db_session, h)
    base = f"/api/v1/ipam/addresses/{ip_id}"
    assert (await client.get(base, headers=h)).status_code == 200

    r = await client.delete(f"/api/v1/ipam/subnets/{subnet_id}", headers=h)
    assert r.status_code == 204, r.text

    calls: list[tuple[str, str, dict[str, Any]]] = [
        ("GET", base, {}),
        ("PUT", base, {"json": {"mac_address": MAC}}),
        ("DELETE", base, {}),
        ("GET", f"{base}/mac-history", {}),
        ("GET", f"{base}/aliases", {}),
        ("POST", f"{base}/aliases", {"json": {"name": "a", "zone_id": str(uuid.uuid4())}}),
        ("GET", f"{base}/network-context", {}),
        ("GET", f"/api/v1/ipam/nat/by-ip/{ip_id}", {}),
    ]
    for method, url, kw in calls:
        resp = await client.request(method, url, headers=h, **kw)
        assert resp.status_code == 404, (method, url, resp.status_code, resp.text)

    # Bulk paths report the row as not found and change nothing.
    be = await client.post(
        "/api/v1/ipam/addresses/bulk-edit",
        headers=h,
        json={"ip_ids": [str(ip_id)], "changes": {"description": "x"}},
    )
    assert be.status_code == 200, be.text
    assert be.json()["updated_count"] == 0 and be.json()["not_found"] == [str(ip_id)]
    bd = await client.post(
        "/api/v1/ipam/addresses/bulk-delete", headers=h, json={"ip_ids": [str(ip_id)]}
    )
    assert bd.status_code == 200, bd.text
    assert bd.json()["deleted_count"] == 0 and bd.json()["not_found"] == [str(ip_id)]

    # Nothing was written: no history row, the address row is as it was.
    db_session.expire_all()
    assert await _mac_rows(db_session, ip_id) == 0
    row = (await db_session.execute(select(IPAddress).where(IPAddress.id == ip_id))).scalar_one()
    assert row.mac_address is None and row.description in (None, "")

    # After a restore the address is reachable again and the refused MAC left
    # nothing behind for an alert to find.
    rr = await client.post(f"/api/v1/admin/trash/subnet/{subnet_id}/restore", headers=h)
    assert rr.status_code == 200, rr.text
    assert (await client.get(base, headers=h)).status_code == 200
    assert (await client.get(f"{base}/mac-history", headers=h)).json() == []
    assert await _mac_rows(db_session, ip_id) == 0
    ok = await client.put(base, headers=h, json={"mac_address": MAC})
    assert ok.status_code == 200, ok.text
    assert await _mac_rows(db_session, ip_id) == 1


@pytest.mark.asyncio
async def test_acknowledging_a_sighting_under_a_trashed_subnet_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.services.ipam.new_device import acknowledge_sighting

    h = await _headers(db_session)
    subnet_id, ip_id = await _addr(db_session, h)
    hist = IpMacHistory(ip_address_id=ip_id, mac_address=MAC, classification="new")
    db_session.add(hist)
    await db_session.flush()
    hist_id = hist.id
    await db_session.commit()
    r = await client.delete(f"/api/v1/ipam/subnets/{subnet_id}", headers=h)
    assert r.status_code == 204, r.text

    assert await acknowledge_sighting(db_session, hist_id, None) is None
    db_session.expire_all()
    assert (await db_session.get(IpMacHistory, hist_id)).classification == "new"  # type: ignore[union-attr]
