"""Tests for NAT mapping CRUD + IPAM cross-reference."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.ipam import IPAddress, IPBlock, IPSpace, NATMapping, Subnet


async def _make_user(db: AsyncSession) -> tuple[User, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user, create_access_token(str(user.id))


async def _make_subnet(db: AsyncSession) -> Subnet:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.10.0.0/16", name="b")
    db.add(block)
    await db.flush()
    sub = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.10.0.0/24",
        name="s",
    )
    db.add(sub)
    await db.flush()
    return sub


# ── Schema validation ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_1to1(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    await db_session.commit()
    h = {"Authorization": f"Bearer {token}"}
    r = await client.post(
        "/api/v1/ipam/nat-mappings",
        headers=h,
        json={
            "name": "web-1to1",
            "kind": "1to1",
            "internal_ip": "10.0.0.10",
            "external_ip": "203.0.113.5",
            "device_label": "fw-01",
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["kind"] == "1to1"
    assert body["internal_ip"] == "10.0.0.10"
    assert body["external_ip"] == "203.0.113.5"


@pytest.mark.asyncio
async def test_create_pat_requires_ports(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    await db_session.commit()
    h = {"Authorization": f"Bearer {token}"}

    # No ports → 422
    r = await client.post(
        "/api/v1/ipam/nat-mappings",
        headers=h,
        json={
            "name": "ssh-pat",
            "kind": "pat",
            "internal_ip": "10.0.0.10",
            "external_ip": "203.0.113.5",
        },
    )
    assert r.status_code == 422

    # Ports OK
    r = await client.post(
        "/api/v1/ipam/nat-mappings",
        headers=h,
        json={
            "name": "ssh-pat",
            "kind": "pat",
            "internal_ip": "10.0.0.10",
            "internal_port_start": 22,
            "internal_port_end": 22,
            "external_ip": "203.0.113.5",
            "external_port_start": 2222,
            "external_port_end": 2222,
            "protocol": "tcp",
        },
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_create_hide(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    sub = await _make_subnet(db_session)
    await db_session.commit()
    h = {"Authorization": f"Bearer {token}"}

    r = await client.post(
        "/api/v1/ipam/nat-mappings",
        headers=h,
        json={
            "name": "lan-hide",
            "kind": "hide",
            "internal_subnet_id": str(sub.id),
            "external_ip": "203.0.113.1",
        },
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_1to1_forbids_ports(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    await db_session.commit()
    h = {"Authorization": f"Bearer {token}"}
    r = await client.post(
        "/api/v1/ipam/nat-mappings",
        headers=h,
        json={
            "name": "bad",
            "kind": "1to1",
            "internal_ip": "10.0.0.10",
            "external_ip": "203.0.113.5",
            "internal_port_start": 80,
        },
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_invalid_kind(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    await db_session.commit()
    r = await client.post(
        "/api/v1/ipam/nat-mappings",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "x", "kind": "weird"},
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_port_range_inverted_rejected(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    await db_session.commit()
    r = await client.post(
        "/api/v1/ipam/nat-mappings",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "x",
            "kind": "pat",
            "internal_ip": "10.0.0.1",
            "external_ip": "203.0.113.5",
            "internal_port_start": 100,
            "internal_port_end": 50,
            "external_port_start": 100,
            "external_port_end": 200,
        },
    )
    assert r.status_code == 422


# ── CRUD lifecycle ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_crud_lifecycle(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    await db_session.commit()
    h = {"Authorization": f"Bearer {token}"}

    # Empty list.
    r = await client.get("/api/v1/ipam/nat-mappings", headers=h)
    assert r.status_code == 200
    assert r.json()["total"] == 0

    # Create.
    r = await client.post(
        "/api/v1/ipam/nat-mappings",
        headers=h,
        json={
            "name": "demo",
            "kind": "1to1",
            "internal_ip": "10.20.0.1",
            "external_ip": "198.51.100.7",
        },
    )
    nat_id = r.json()["id"]

    # Get one.
    r = await client.get(f"/api/v1/ipam/nat-mappings/{nat_id}", headers=h)
    assert r.status_code == 200
    assert r.json()["name"] == "demo"

    # Update — patch only the name.
    r = await client.patch(
        f"/api/v1/ipam/nat-mappings/{nat_id}",
        headers=h,
        json={"name": "demo-renamed"},
    )
    assert r.status_code == 200
    assert r.json()["name"] == "demo-renamed"

    # List with substring filter.
    r = await client.get("/api/v1/ipam/nat-mappings?q=renamed", headers=h)
    assert r.json()["total"] == 1

    # Filter by external_ip exact.
    r = await client.get("/api/v1/ipam/nat-mappings?external_ip=198.51.100.7", headers=h)
    assert r.json()["total"] == 1

    # Delete.
    r = await client.delete(f"/api/v1/ipam/nat-mappings/{nat_id}", headers=h)
    assert r.status_code == 204
    r = await client.get("/api/v1/ipam/nat-mappings", headers=h)
    assert r.json()["total"] == 0


@pytest.mark.asyncio
async def test_patch_kind_revalidates(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    await db_session.commit()
    h = {"Authorization": f"Bearer {token}"}

    r = await client.post(
        "/api/v1/ipam/nat-mappings",
        headers=h,
        json={
            "name": "morphme",
            "kind": "1to1",
            "internal_ip": "10.30.0.1",
            "external_ip": "198.51.100.10",
        },
    )
    nat_id = r.json()["id"]

    # Switching to PAT without supplying ports is invalid even though
    # the patch itself only carries 'kind' — the merged-state check
    # catches it.
    r = await client.patch(
        f"/api/v1/ipam/nat-mappings/{nat_id}",
        headers=h,
        json={"kind": "pat"},
    )
    assert r.status_code == 422


# ── IPAM cross-reference ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_nat_mapping_count_in_address_list(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_user(db_session)
    sub = await _make_subnet(db_session)

    ip = IPAddress(subnet_id=sub.id, address="10.10.0.42", status="allocated", hostname="srv")
    db_session.add(ip)
    await db_session.flush()

    db_session.add_all(
        [
            NATMapping(
                name="a",
                kind="1to1",
                internal_ip="10.10.0.42",
                external_ip="203.0.113.42",
            ),
            NATMapping(
                name="b",
                kind="1to1",
                internal_ip="10.10.0.42",
                external_ip="203.0.113.43",
            ),
        ]
    )
    await db_session.commit()

    h = {"Authorization": f"Bearer {token}"}
    r = await client.get(f"/api/v1/ipam/subnets/{sub.id}/addresses", headers=h)
    assert r.status_code == 200, r.text
    rows = r.json()
    target = next(row for row in rows if row["address"] == "10.10.0.42")
    assert target.get("nat_mapping_count") == 2


@pytest.mark.asyncio
async def test_nat_mapping_count_external_match(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_user(db_session)
    sub = await _make_subnet(db_session)

    # External-side IP also lands in IPAM (e.g. published service VIP).
    ip = IPAddress(subnet_id=sub.id, address="10.10.0.99", status="allocated")
    db_session.add(ip)
    await db_session.flush()

    db_session.add(
        NATMapping(
            name="c",
            kind="1to1",
            internal_ip="172.16.0.1",
            external_ip="10.10.0.99",
        )
    )
    await db_session.commit()

    h = {"Authorization": f"Bearer {token}"}
    r = await client.get(f"/api/v1/ipam/subnets/{sub.id}/addresses", headers=h)
    rows = r.json()
    target = next(row for row in rows if row["address"] == "10.10.0.99")
    assert target.get("nat_mapping_count") == 1


@pytest.mark.asyncio
async def test_by_subnet_lists_mapping_whose_external_ip_is_in_the_subnet(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#2617 — the NAT tab read internal IPs only while the badge counts both."""
    _, token = await _make_user(db_session)
    sub = await _make_subnet(db_session)
    db_session.add_all(
        [
            NATMapping(
                name="ext-in",
                kind="1to1",
                internal_ip="172.16.0.1",
                external_ip="10.10.0.10",
            ),
            NATMapping(
                name="int-in",
                kind="1to1",
                internal_ip="10.10.0.11",
                external_ip="203.0.113.11",
            ),
            NATMapping(
                name="neither",
                kind="1to1",
                internal_ip="172.16.0.2",
                external_ip="203.0.113.12",
            ),
        ]
    )
    await db_session.commit()

    h = {"Authorization": f"Bearer {token}"}
    r = await client.get(f"/api/v1/ipam/nat-mappings/by-subnet/{sub.id}", headers=h)
    assert r.status_code == 200, r.text
    assert sorted(m["name"] for m in r.json()) == ["ext-in", "int-in"]


@pytest.mark.asyncio
async def test_get_unknown_404(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    await db_session.commit()
    bogus = uuid.uuid4()
    r = await client.get(
        f"/api/v1/ipam/nat-mappings/{bogus}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 404
