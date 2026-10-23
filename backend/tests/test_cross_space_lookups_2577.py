"""Cross-space lookups stay inside their own IP space (#2577, fix item 6).

IP spaces are independent networks: the same address, MAC and hostname can
legitimately exist in two of them. Every test here builds two spaces, A and B,
holding the same address (and where it matters the same MAC), acts in A's
context, and asserts B is left exactly as it was.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup
from app.models.dhcp_fingerprint import DHCPFingerprint
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.nmap import NmapScan

ADDR = "10.77.1.5"
MAC = "aa:bb:cc:25:77:01"


async def _admin(db: AsyncSession) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"u2577-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _space_with_subnet(db: AsyncSession, label: str) -> tuple[IPSpace, Subnet]:
    space = IPSpace(name=f"sp2577{label}-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.77.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.77.1.0/24",
        name=f"s{label}",
        total_ips=254,
    )
    db.add(subnet)
    await db.flush()
    return space, subnet


async def _two_spaces(db: AsyncSession) -> tuple[IPSpace, Subnet, IPSpace, Subnet]:
    space_a, subnet_a = await _space_with_subnet(db, "a")
    space_b, subnet_b = await _space_with_subnet(db, "b")
    return space_a, subnet_a, space_b, subnet_b


async def _ip(
    db: AsyncSession, subnet: Subnet, addr: str, *, status: str, mac: str | None = None
) -> IPAddress:
    row = IPAddress(subnet_id=subnet.id, address=addr, status=status, mac_address=mac)
    db.add(row)
    await db.flush()
    return row


async def _rows_in(db: AsyncSession, subnet_id: uuid.UUID) -> dict[str, IPAddress]:
    db.expire_all()
    res = await db.execute(select(IPAddress).where(IPAddress.subnet_id == subnet_id))
    return {str(r.address): r for r in res.scalars()}


# ── nmap stamp-discovered ──────────────────────────────────────────────


async def _scan(db: AsyncSession, *, ip_address_id: uuid.UUID | None = None) -> NmapScan:
    scan = NmapScan(
        target_ip="10.77.1.0/24",
        ip_address_id=ip_address_id,
        preset="quick",
        status="completed",
        summary_json={
            "hosts": [
                {"address": ADDR, "host_state": "up", "ports": []},
                {"address": "10.77.1.9", "host_state": "up", "ports": []},
            ]
        },
    )
    db.add(scan)
    await db.flush()
    return scan


@pytest.mark.asyncio
async def test_nmap_stamp_without_space_skips_ambiguous_hosts(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    _, subnet_a, _, subnet_b = await _two_spaces(db_session)
    await _ip(db_session, subnet_a, ADDR, status="available")
    await _ip(db_session, subnet_b, ADDR, status="available")
    scan = await _scan(db_session)
    a_id, b_id, scan_id = subnet_a.id, subnet_b.id, scan.id
    await db_session.commit()

    r = await client.post(f"/api/v1/nmap/scans/{scan_id}/stamp-discovered", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert sorted(body["skipped_ambiguous"]) == [ADDR, "10.77.1.9"]
    assert body["created"] == 0 and body["bumped"] == 0

    for subnet_id in (a_id, b_id):
        rows = await _rows_in(db_session, subnet_id)
        assert set(rows) == {ADDR}
        assert rows[ADDR].status == "available"
        assert rows[ADDR].last_seen_at is None


@pytest.mark.asyncio
async def test_nmap_stamp_with_space_writes_only_that_space(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    space_a, subnet_a, _, subnet_b = await _two_spaces(db_session)
    await _ip(db_session, subnet_a, ADDR, status="available")
    await _ip(db_session, subnet_b, ADDR, status="available")
    scan = await _scan(db_session)
    a_id, b_id, scan_id, space_a_id = subnet_a.id, subnet_b.id, scan.id, space_a.id
    await db_session.commit()

    r = await client.post(
        f"/api/v1/nmap/scans/{scan_id}/stamp-discovered",
        headers=headers,
        params={"space_id": str(space_a_id)},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["created"] == 1 and body["bumped"] == 1
    assert body["skipped_ambiguous"] == []

    rows_a = await _rows_in(db_session, a_id)
    assert rows_a[ADDR].status == "discovered"
    assert rows_a["10.77.1.9"].status == "discovered"
    rows_b = await _rows_in(db_session, b_id)
    assert set(rows_b) == {ADDR}
    assert rows_b[ADDR].status == "available"
    assert rows_b[ADDR].last_seen_at is None


@pytest.mark.asyncio
async def test_nmap_stamp_uses_the_scans_own_ipam_row_space(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A scan launched from an IPAM row carries that row's space."""
    _, headers = await _admin(db_session)
    _, subnet_a, _, subnet_b = await _two_spaces(db_session)
    await _ip(db_session, subnet_a, ADDR, status="available")
    row_b = await _ip(db_session, subnet_b, ADDR, status="available")
    scan = await _scan(db_session, ip_address_id=row_b.id)
    a_id, b_id, scan_id = subnet_a.id, subnet_b.id, scan.id
    await db_session.commit()

    r = await client.post(f"/api/v1/nmap/scans/{scan_id}/stamp-discovered", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["skipped_ambiguous"] == []

    rows_a = await _rows_in(db_session, a_id)
    assert set(rows_a) == {ADDR}
    assert rows_a[ADDR].status == "available"
    rows_b = await _rows_in(db_session, b_id)
    assert rows_b[ADDR].status == "discovered"
    assert "10.77.1.9" in rows_b


# ── passive profiling stamp ────────────────────────────────────────────


async def _fingerprint(db: AsyncSession) -> DHCPFingerprint:
    fp = DHCPFingerprint(
        mac_address=MAC,
        option_55="1,3,6",
        fingerbank_device_name="Pixel 7",
        fingerbank_device_class="Phone",
        fingerbank_manufacturer="Google",
        first_seen_at=datetime.now(UTC),
        last_seen_at=datetime.now(UTC),
    )
    db.add(fp)
    await db.flush()
    return fp


async def _server_serving(db: AsyncSession, subnet: Subnet) -> DHCPServer:
    group = DHCPServerGroup(name=f"g2577-{uuid.uuid4().hex[:6]}", description="")
    db.add(group)
    await db.flush()
    db.add(DHCPScope(group_id=group.id, subnet_id=subnet.id, name="scope"))
    server = DHCPServer(
        name=f"s2577-{uuid.uuid4().hex[:6]}",
        host="127.0.0.1",
        driver="kea",
        server_group_id=group.id,
    )
    db.add(server)
    await db.flush()
    return server


@pytest.mark.asyncio
async def test_fingerprint_stamp_stays_in_the_reporting_servers_space(
    db_session: AsyncSession,
) -> None:
    from app.services.profiling.passive import stamp_matching_ips

    _, subnet_a, _, subnet_b = await _two_spaces(db_session)
    ip_a = await _ip(db_session, subnet_a, ADDR, status="dhcp", mac=MAC)
    ip_b = await _ip(db_session, subnet_b, ADDR, status="dhcp", mac=MAC)
    server = await _server_serving(db_session, subnet_a)
    fp = await _fingerprint(db_session)
    await db_session.commit()

    stamped = await stamp_matching_ips(db_session, fingerprint=fp, server_id=server.id)
    await db_session.commit()
    assert stamped == 1

    await db_session.refresh(ip_a)
    await db_session.refresh(ip_b)
    assert ip_a.device_type == "Pixel 7"
    assert ip_b.device_type is None
    assert ip_b.device_manufacturer is None


@pytest.mark.asyncio
async def test_fingerprint_stamp_without_server_skips_a_mac_spread_across_spaces(
    db_session: AsyncSession,
) -> None:
    from app.services.profiling.passive import stamp_matching_ips

    _, subnet_a, _, subnet_b = await _two_spaces(db_session)
    ip_a = await _ip(db_session, subnet_a, ADDR, status="dhcp", mac=MAC)
    ip_b = await _ip(db_session, subnet_b, ADDR, status="dhcp", mac=MAC)
    fp = await _fingerprint(db_session)
    await db_session.commit()

    assert await stamp_matching_ips(db_session, fingerprint=fp) == 0
    await db_session.commit()
    await db_session.refresh(ip_a)
    await db_session.refresh(ip_b)
    assert ip_a.device_type is None
    assert ip_b.device_type is None


# ── MAC collision warning ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mac_collision_is_per_space(client: AsyncClient, db_session: AsyncSession) -> None:
    _, headers = await _admin(db_session)
    _, subnet_a, _, subnet_b = await _two_spaces(db_session)
    await db_session.commit()

    first = await client.post(
        f"/api/v1/ipam/subnets/{subnet_a.id}/addresses",
        headers=headers,
        json={"address": ADDR, "hostname": "host-a", "mac_address": MAC},
    )
    assert first.status_code == 201, first.text

    # Same MAC in space B: a different network, not a collision.
    other_space = await client.post(
        f"/api/v1/ipam/subnets/{subnet_b.id}/addresses",
        headers=headers,
        json={"address": ADDR, "hostname": "host-b", "mac_address": MAC},
    )
    assert other_space.status_code == 201, other_space.text

    # Same MAC again inside space A: still a collision.
    same_space = await client.post(
        f"/api/v1/ipam/subnets/{subnet_a.id}/addresses",
        headers=headers,
        json={"address": "10.77.1.6", "hostname": "host-a2", "mac_address": MAC},
    )
    assert same_space.status_code == 409, same_space.text
    warnings = same_space.json()["detail"]["warnings"]
    macs = [w for w in warnings if w["kind"] == "mac_collision"]
    assert len(macs) == 1
    assert macs[0]["existing_ip_id"] == first.json()["id"]

    # next-ip in B with a MAC only space A holds: not a collision either.
    mac2 = "aa:bb:cc:25:77:09"
    seed = await client.post(
        f"/api/v1/ipam/subnets/{subnet_a.id}/addresses",
        headers=headers,
        json={"address": "10.77.1.20", "hostname": "host-a3", "mac_address": mac2},
    )
    assert seed.status_code == 201, seed.text
    nxt = await client.post(
        f"/api/v1/ipam/subnets/{subnet_b.id}/next",
        headers=headers,
        json={"hostname": "host-b2", "mac_address": mac2},
    )
    assert nxt.status_code == 201, nxt.text


@pytest.mark.asyncio
async def test_mac_collision_on_update_ignores_other_spaces(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    _, subnet_a, _, subnet_b = await _two_spaces(db_session)
    await _ip(db_session, subnet_a, ADDR, status="allocated", mac=MAC)
    row_b = await _ip(db_session, subnet_b, ADDR, status="allocated")
    other_a = await _ip(db_session, subnet_a, "10.77.1.7", status="allocated")
    await db_session.commit()

    upd_b = await client.put(
        f"/api/v1/ipam/addresses/{row_b.id}", headers=headers, json={"mac_address": MAC}
    )
    assert upd_b.status_code == 200, upd_b.text

    upd_a = await client.put(
        f"/api/v1/ipam/addresses/{other_a.id}", headers=headers, json={"mac_address": MAC}
    )
    assert upd_a.status_code == 409, upd_a.text
    assert any(w["kind"] == "mac_collision" for w in upd_a.json()["detail"]["warnings"])


# ── new-device detection ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_known_fleet_is_per_space(db_session: AsyncSession) -> None:
    from app.services.ipam.discovery import record_mac_observation
    from app.services.ipam.new_device import CLASSIFICATION_KNOWN, CLASSIFICATION_NEW

    _, subnet_a, _, subnet_b = await _two_spaces(db_session)
    await _ip(db_session, subnet_a, ADDR, status="allocated", mac=MAC)
    seen_a = await _ip(db_session, subnet_a, "10.77.1.8", status="discovered")
    seen_b = await _ip(db_session, subnet_b, "10.77.1.8", status="discovered")
    await db_session.flush()

    res_b = await record_mac_observation(db_session, seen_b.id, MAC, source="sweep")
    assert res_b is not None
    assert res_b.classification == CLASSIFICATION_NEW
    assert res_b.is_first_seen_new

    res_a = await record_mac_observation(db_session, seen_a.id, MAC, source="sweep")
    assert res_a is not None
    assert res_a.classification == CLASSIFICATION_KNOWN


# ── NAT mapping IPAM link ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_nat_mapping_does_not_link_an_ambiguous_address(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    _, subnet_a, _, subnet_b = await _two_spaces(db_session)
    await _ip(db_session, subnet_a, ADDR, status="allocated")
    await _ip(db_session, subnet_b, ADDR, status="allocated")
    await db_session.commit()

    r = await client.post(
        "/api/v1/ipam/nat-mappings",
        headers=headers,
        json={
            "name": f"n-{uuid.uuid4().hex[:6]}",
            "kind": "1to1",
            "internal_ip": ADDR,
            "external_ip": "203.0.113.77",
        },
    )
    assert r.status_code == 201, r.text
    assert r.json()["internal_ip_address_id"] is None


@pytest.mark.asyncio
async def test_nat_mapping_links_within_the_internal_subnets_space(
    db_session: AsyncSession,
) -> None:
    from app.api.v1.ipam.nat import _resolve_ip_to_address_id

    _, subnet_a, _, subnet_b = await _two_spaces(db_session)
    await _ip(db_session, subnet_a, ADDR, status="allocated")
    row_b = await _ip(db_session, subnet_b, ADDR, status="allocated")
    await db_session.commit()

    assert await _resolve_ip_to_address_id(db_session, ADDR) is None
    assert await _resolve_ip_to_address_id(db_session, ADDR, subnet_id=subnet_b.id) == row_b.id


# ── Copilot find_switchport ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_find_switchport_reports_ambiguity_across_spaces(
    db_session: AsyncSession,
) -> None:
    from app.services.ai.tools.network import FindSwitchportArgs, find_switchport

    user, _ = await _admin(db_session)
    space_a, subnet_a, _, subnet_b = await _two_spaces(db_session)
    await _ip(db_session, subnet_a, ADDR, status="allocated", mac=MAC)
    await _ip(db_session, subnet_b, ADDR, status="allocated", mac="aa:bb:cc:25:77:02")
    await db_session.commit()

    ambiguous = await find_switchport(db_session, user, FindSwitchportArgs(ip=ADDR))
    assert "candidates" in ambiguous
    assert len(ambiguous["candidates"]) == 2

    scoped = await find_switchport(
        db_session, user, FindSwitchportArgs(ip=ADDR, space_id=str(space_a.id))
    )
    assert scoped.get("mac_address") == MAC
    assert scoped.get("ip_source") == "ipam"
