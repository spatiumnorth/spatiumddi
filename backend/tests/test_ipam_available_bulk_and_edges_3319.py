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
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.ipam import IPAddress, IPBlock, IPSpace
from app.services.ai.operations import CreateIPAddressArgs, get_operation
from app.services.ipam_io.importer import commit_address_import, preview_address_import
from app.services.ipam_io.parser import ParsedPayload


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


@pytest.mark.asyncio
async def test_bulk_takeover_is_audited_as_a_reclaim(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The taken-over row keeps its id and the reclaim is audited with what it
    replaced, as for Specific IP (#2980)."""
    headers, space = await _rig(db_session)
    sid = (await _subnet(client, headers, space, "10.33.5.0/28"))["id"]
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        json={"address": "10.33.5.5", "status": "available", "hostname": "old"},
        headers=headers,
    )
    old_id = r.json()["id"]
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/bulk-allocate",
        json=_bulk("10.33.5.5", "10.33.5.5"),
        headers=headers,
    )
    assert r.status_code == 200 and r.json()["created"] == 1, r.text
    reclaims = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_id == old_id, AuditLog.resource_type == "ip_address"
                )
            )
        )
        .scalars()
        .all()
    )
    assert any((a.old_value or {}).get("hostname") == "old" for a in reclaims)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("cidr", "edge"),
    [("10.33.6.0/31", "10.33.6.0"), ("10.33.6.4/32", "10.33.6.4"), ("fd33::/120", "fd33::")],
)
async def test_no_boundary_refusal_where_the_address_is_a_host(
    client: AsyncClient, db_session: AsyncSession, cidr: str, edge: str
) -> None:
    """RFC 3021 /31 + /32 have no network / broadcast address, and an IPv6
    network address counts in the total."""
    headers, space = await _rig(db_session)
    if ":" in cidr:
        blk = IPBlock(space_id=space[0], network="fd33::/64", name="v6")
        db_session.add(blk)
        await db_session.commit()
        space = (space[0], blk.id)
    sid = (await _subnet(client, headers, space, cidr, skip_auto_addresses=True))["id"]
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        json={"address": edge, "status": "allocated", "hostname": "p2p"},
        headers=headers,
    )
    assert r.status_code in (200, 201), r.text


@pytest.mark.asyncio
async def test_copilot_create_refuses_a_boundary_address(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The operation layer (Copilot / request portal) refuses it in preview and
    in the unnamed apply, which inserts without going through the REST create."""
    headers, space = await _rig(db_session)
    sid = (await _subnet(client, headers, space, "10.33.7.0/29", skip_auto_addresses=True))["id"]
    admin = (
        await db_session.execute(select(User).where(User.username.like("u3319-%")))
    ).scalar_one()
    op = get_operation("create_ip_address")
    assert op is not None
    args = CreateIPAddressArgs(subnet_id=sid, address="10.33.7.7")
    preview = await op.preview(db_session, admin, args)
    assert not preview.ok and "network or broadcast" in (preview.detail or "")
    with pytest.raises(ValueError, match="network or broadcast"):
        await op.apply(db_session, admin, args)
    rows = (
        (await db_session.execute(select(IPAddress).where(IPAddress.subnet_id == uuid.UUID(sid))))
        .scalars()
        .all()
    )
    assert rows == []


@pytest.mark.asyncio
async def test_address_import_refuses_a_host_on_a_boundary(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, space = await _rig(db_session)
    sid = uuid.UUID(
        (await _subnet(client, headers, space, "10.33.8.0/29", skip_auto_addresses=True))["id"]
    )
    admin = (
        await db_session.execute(select(User).where(User.username.like("u3319-%")))
    ).scalar_one()
    payload = ParsedPayload(
        addresses=[
            {"address": "10.33.8.0", "hostname": "edge0"},
            {"address": "10.33.8.3", "hostname": "mid"},
            # The placeholder row itself is what belongs there, so it imports.
            {"address": "10.33.8.7", "status": "broadcast"},
        ]
    )
    preview = await preview_address_import(db_session, payload, subnet_id=sid)
    assert [e.network for e in preview.errors] == ["10.33.8.0"]
    assert {c.network for c in preview.creates} == {"10.33.8.3", "10.33.8.7"}

    result = await commit_address_import(
        db_session, payload, current_user=admin, subnet_id=sid, strategy="skip"
    )
    await db_session.commit()
    assert result.created == 2
    assert any("10.33.8.0" in e for e in result.errors)
    got = (await client.get(f"/api/v1/ipam/subnets/{sid}", headers=headers)).json()
    assert got["allocated_ips"] <= got["total_ips"]
