"""A sweep that finds exactly one host is still a sweep (#2581).

The parser kept ``hosts`` only for more than one ``<host>``, so a /29
sweep where one device answered was stored as a single-host scan: no
Stamp button, and ``stamp-discovered`` answered 422.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.nmap import NmapScan
from app.services.nmap.runner import is_sweep, parse_nmap_xml


def _host(address: str) -> str:
    return (
        '<host><status state="up" reason="echo-reply"/>'
        f'<address addr="{address}" addrtype="ipv4"/></host>'
    )


def _xml(*hosts: str) -> str:
    return f"<nmaprun>{''.join(hosts)}</nmaprun>"


def test_one_host_sweep_keeps_a_host_list() -> None:
    s = parse_nmap_xml(_xml(_host("10.0.0.5")), sweep=True)
    assert [h["address"] for h in s["hosts"]] == ["10.0.0.5"]
    assert s["address"] == "10.0.0.5"


def test_empty_sweep_is_an_empty_list_not_none() -> None:
    assert parse_nmap_xml(_xml(), sweep=True)["hosts"] == []


def test_single_address_scan_keeps_single_host_shape() -> None:
    assert parse_nmap_xml(_xml(_host("10.0.0.5")))["hosts"] is None
    assert parse_nmap_xml(_xml())["hosts"] is None


def test_sweep_is_decided_by_cidr_or_preset() -> None:
    assert is_sweep("10.0.0.0/29", "quick")
    assert is_sweep("10.0.0.1", "subnet_sweep")
    assert not is_sweep("10.0.0.1", "quick")


async def _setup(db: AsyncSession, summary: dict) -> tuple[str, NmapScan]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:8]}")
    db.add_all([user, space])
    await db.flush()
    block = IPBlock(space_id=space.id, name="b", network="10.0.0.0/16")
    db.add(block)
    await db.flush()
    db.add(Subnet(space_id=space.id, block_id=block.id, name="s", network="10.0.0.0/24"))
    scan = NmapScan(
        target_ip="10.0.0.0/29",
        preset="subnet_sweep",
        status="completed",
        finished_at=datetime.now(UTC),
        summary_json=summary,
    )
    db.add(scan)
    await db.flush()
    return create_access_token(str(user.id)), scan


async def test_stamp_one_host_sweep(client: AsyncClient, db_session: AsyncSession) -> None:
    summary = parse_nmap_xml(_xml(_host("10.0.0.5")), sweep=True)
    token, scan = await _setup(db_session, summary)
    r = await client.post(
        f"/api/v1/nmap/scans/{scan.id}/stamp-discovered",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["created"] == 1
    row = (
        await db_session.execute(select(IPAddress).where(IPAddress.address == "10.0.0.5"))
    ).scalar_one()
    assert row.status == "discovered"


async def test_stamp_empty_sweep_stamps_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token, scan = await _setup(db_session, parse_nmap_xml(_xml(), sweep=True))
    r = await client.post(
        f"/api/v1/nmap/scans/{scan.id}/stamp-discovered",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["created"] == 0


async def test_stamp_single_host_scan_still_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token, scan = await _setup(db_session, parse_nmap_xml(_xml(_host("10.0.0.5"))))
    r = await client.post(
        f"/api/v1/nmap/scans/{scan.id}/stamp-discovered",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 422


async def test_stamp_recounts_subnet_and_block(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#3320: a stamped ``discovered`` row counts toward utilization, so the
    subnet's and block's cached figures follow the stamp — a fresh insert and
    an ``available`` row bumped to ``discovered`` alike."""
    summary = parse_nmap_xml(_xml(_host("10.0.0.5"), _host("10.0.0.6")), sweep=True)
    token, scan = await _setup(db_session, summary)
    subnet = (
        await db_session.execute(select(Subnet).where(Subnet.network == "10.0.0.0/24"))
    ).scalar_one()
    subnet.total_ips = 254
    subnet_id, block_id = subnet.id, subnet.block_id
    db_session.add(IPAddress(subnet_id=subnet_id, address="10.0.0.6", status="available"))
    await db_session.commit()

    r = await client.post(
        f"/api/v1/nmap/scans/{scan.id}/stamp-discovered",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text
    assert (r.json()["created"], r.json()["bumped"]) == (1, 1)

    db_session.expire_all()
    sub = await db_session.get(Subnet, subnet_id)
    blk = await db_session.get(IPBlock, block_id)
    assert sub.allocated_ips == 2
    # A block counts its subnets' network + broadcast too (#2982).
    assert blk.allocated_ips == 4
