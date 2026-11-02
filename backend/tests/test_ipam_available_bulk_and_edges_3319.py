"""Bulk allocate takes over an ``available`` row (#3319); a host never sits on
an IPv4 network / broadcast address, even on a subnet with no rows for them
(#3321)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.ipam import IPAddress, IPBlock, IPSpace


async def _rig(db: AsyncSession) -> tuple[dict[str, str], tuple[uuid.UUID, uuid.UUID]]:
    user = User(
        username=f"u3319-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.33.0.0/16", name="b")
    db.add(block)
    await db.flush()
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}, (space.id, block.id)


async def _subnet(
    client: AsyncClient,
    headers: dict[str, str],
    space: tuple[uuid.UUID, uuid.UUID],
    cidr: str,
    **kw: Any,
) -> dict[str, Any]:
    r = await client.post(
        "/api/v1/ipam/subnets",
        json={
            "space_id": str(space[0]),
            "block_id": str(space[1]),
            "network": cidr,
            "name": "s",
            **kw,
        },
        headers=headers,
    )
    assert r.status_code in (200, 201), r.text
    return r.json()


def _bulk(start: str, end: str, **kw: Any) -> dict[str, Any]:
    return {
        "range_start": start,
        "range_end": end,
        "hostname_template": "h{oct4}",
        "create_dns_records": False,
        **kw,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("on_collision", ["skip", "abort"])
async def test_bulk_allocate_takes_over_an_available_row(
    client: AsyncClient, db_session: AsyncSession, on_collision: str
) -> None:
    headers, space = await _rig(db_session)
    sn = await _subnet(client, headers, space, "10.33.1.0/28")
    sid = sn["id"]
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        json={"address": "10.33.1.5", "status": "available", "hostname": "old"},
        headers=headers,
    )
    assert r.status_code in (200, 201), r.text

    body = _bulk("10.33.1.5", "10.33.1.6", on_collision=on_collision)
    base = f"/api/v1/ipam/subnets/{sid}/bulk-allocate"
    pv = await client.post(f"{base}/preview", json=body, headers=headers)
    assert pv.status_code == 200, pv.text
    assert pv.json()["conflicts_in_use"] == 0
    assert pv.json()["will_create"] == 2

    r = await client.post(base, json=body, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["created"] == 2
    assert r.json()["skipped_in_use"] == 0

    db_session.expire_all()
    row = (
        await db_session.execute(
            select(IPAddress)
            .where(IPAddress.subnet_id == uuid.UUID(sid))
            .where(IPAddress.address == "10.33.1.5")
        )
    ).scalar_one()
    assert row.status == "allocated"
    assert row.hostname == "h5"


@pytest.mark.asyncio
async def test_bulk_allocate_still_skips_a_held_address(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, space = await _rig(db_session)
    sn = await _subnet(client, headers, space, "10.33.2.0/28")
    sid = sn["id"]
    await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        json={"address": "10.33.2.5", "status": "allocated", "hostname": "kept"},
        headers=headers,
    )
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/bulk-allocate/preview",
        json=_bulk("10.33.2.5", "10.33.2.6"),
        headers=headers,
    )
    assert r.json()["conflicts_in_use"] == 1


@pytest.mark.asyncio
async def test_skip_auto_subnet_refuses_a_host_on_network_or_broadcast(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, space = await _rig(db_session)
    sn = await _subnet(client, headers, space, "10.33.3.0/29", skip_auto_addresses=True)
    sid = sn["id"]
    for addr in ("10.33.3.0", "10.33.3.7"):
        r = await client.post(
            f"/api/v1/ipam/subnets/{sid}/addresses",
            json={"address": addr, "status": "allocated", "hostname": "e"},
            headers=headers,
        )
        assert r.status_code == 409, (addr, r.text)
        assert "network or broadcast" in r.text
    for n in range(1, 7):
        r = await client.post(
            f"/api/v1/ipam/subnets/{sid}/addresses",
            json={"address": f"10.33.3.{n}", "status": "allocated", "hostname": f"n{n}"},
            headers=headers,
        )
        assert r.status_code in (200, 201), r.text
    got = (await client.get(f"/api/v1/ipam/subnets/{sid}", headers=headers)).json()
    assert got["allocated_ips"] == 6 == got["total_ips"]
    assert got["utilization_percent"] == 100.0


@pytest.mark.asyncio
async def test_skip_auto_subnet_bulk_range_over_an_edge_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, space = await _rig(db_session)
    sn = await _subnet(client, headers, space, "10.33.4.0/29", skip_auto_addresses=True)
    sid = sn["id"]
    base = f"/api/v1/ipam/subnets/{sid}/bulk-allocate"
    for path in (f"{base}/preview", base):
        r = await client.post(path, json=_bulk("10.33.4.0", "10.33.4.2"), headers=headers)
        assert r.status_code == 422, r.text
        assert "10.33.4.0" in r.text
