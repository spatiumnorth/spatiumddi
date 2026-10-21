"""Deleting an integration target must not destroy operator content (#2287).

Every integration ownership FK is ON DELETE CASCADE and ``ip_address`` /
``dhcp_scope`` cascade from the subnet, so a bare ``db.delete(target)`` took
operator addresses, DHCP scopes and reservations in mirrored subnets with it.
The shared ``release_integration_rows`` runs in every delete handler.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServerGroup
from app.models.docker import DockerHost
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.kubernetes import KubernetesCluster
from app.models.proxmox import ProxmoxNode
from app.services.integration_ownership import INTEGRATION_OWNERSHIP

ROUTERS = Path(__file__).resolve().parents[1] / "app" / "api" / "v1"


async def _admin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


def _docker(space: IPSpace) -> DockerHost:
    return DockerHost(
        name=f"d-{uuid.uuid4().hex[:6]}",
        connection_type="tcp",
        endpoint="docker.example.test:2376",
        ipam_space_id=space.id,
        client_key_encrypted=b"",
    )


def _k8s(space: IPSpace) -> KubernetesCluster:
    return KubernetesCluster(
        name=f"k-{uuid.uuid4().hex[:6]}",
        api_server_url="https://k8s.example.test",
        token_encrypted=b"x",
        ipam_space_id=space.id,
    )


def _proxmox(space: IPSpace) -> ProxmoxNode:
    return ProxmoxNode(
        name=f"p-{uuid.uuid4().hex[:6]}",
        host="pve.example.test",
        token_secret_encrypted=b"x",
        ipam_space_id=space.id,
    )


CASES = [
    ("docker", _docker, "docker_host_id", "/api/v1/docker/hosts"),
    ("kubernetes", _k8s, "kubernetes_cluster_id", "/api/v1/kubernetes/clusters"),
    ("proxmox", _proxmox, "proxmox_node_id", "/api/v1/proxmox/nodes"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("name,factory,fk,url", CASES, ids=[c[0] for c in CASES])
async def test_target_delete_keeps_operator_content(
    client: AsyncClient, db_session: AsyncSession, name, factory, fk, url
) -> None:
    h = await _admin(db_session)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    target = factory(space)
    db_session.add(target)
    await db_session.flush()
    owner = {fk: target.id}

    def mk_subnet(cidr: str) -> tuple[IPBlock, Subnet]:
        blk = IPBlock(space_id=space.id, network=cidr, name=f"b-{cidr}", **owner)
        db_session.add(blk)
        return blk, Subnet(
            space_id=space.id, block_id=None, network=cidr, name=f"s-{cidr}", total_ips=254, **owner
        )

    async def add(cidr: str) -> Subnet:
        blk, sn = mk_subnet(cidr)
        await db_session.flush()
        sn.block_id = blk.id
        db_session.add(sn)
        await db_session.flush()
        return sn

    pure = await add("10.90.0.0/24")
    db_session.add(IPAddress(subnet_id=pure.id, address="10.90.0.5", status="used", **owner))
    mixed = await add("10.91.0.0/24")
    db_session.add(IPAddress(subnet_id=mixed.id, address="10.91.0.5", status="used", **owner))
    db_session.add(IPAddress(subnet_id=mixed.id, address="10.91.0.99", status="used"))
    edited = await add("10.92.0.0/24")
    db_session.add(
        IPAddress(
            subnet_id=edited.id,
            address="10.92.0.5",
            status="used",
            user_modified_at=datetime.now(UTC),
            **owner,
        )
    )
    scoped = await add("10.93.0.0/24")
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    scope = DHCPScope(group_id=grp.id, subnet_id=scoped.id)
    db_session.add(scope)
    await db_session.flush()
    ids = {k: v.id for k, v in dict(pure=pure, mixed=mixed, edited=edited, scoped=scoped).items()}
    scope_id = scope.id

    r = await client.delete(f"{url}/{target.id}", headers=h)
    assert r.status_code == 204, r.text
    db_session.expire_all()

    async def exists(model, pk) -> bool:
        return (await db_session.get(model, pk)) is not None

    # Purely mirrored: gone, block included.
    assert not await exists(Subnet, ids["pure"])
    left = (
        (await db_session.execute(select(IPBlock).where(IPBlock.network == "10.90.0.0/24")))
        .scalars()
        .all()
    )
    assert left == []
    # Operator content survives, un-claimed.
    for key in ("mixed", "edited", "scoped"):
        sn = await db_session.get(Subnet, ids[key])
        assert sn is not None, key
        assert getattr(sn, fk) is None, key
    assert await exists(DHCPScope, scope_id)
    addrs = {
        str(a.address): a for a in (await db_session.execute(select(IPAddress))).scalars().all()
    }
    assert "10.91.0.99" in addrs and getattr(addrs["10.91.0.99"], fk) is None
    assert "10.91.0.5" not in addrs  # purely mirrored address in a kept subnet
    assert "10.92.0.5" in addrs and getattr(addrs["10.92.0.5"], fk) is None
    assert addrs["10.92.0.5"].user_modified_at is None
    assert "10.90.0.5" not in addrs


def test_every_integration_delete_handler_releases_its_rows() -> None:
    """A new integration must call the shared release in its delete handler."""
    used: set[str] = set()
    for router in ROUTERS.glob("*/router.py"):
        used.update(
            re.findall(r'release_integration_rows\(\s*db,\s*own_fk="(\w+)"', router.read_text())
        )
    assert used == set(INTEGRATION_OWNERSHIP), set(INTEGRATION_OWNERSHIP) ^ used


def test_every_owner_fk_on_ipam_rows_is_registered() -> None:
    cols = {c.name for c in IPBlock.__table__.columns if c.foreign_keys}
    cols &= {c.name for c in Subnet.__table__.columns if c.foreign_keys}
    owner_cols = {
        c
        for c in cols
        if any(
            fk.ondelete == "CASCADE" and fk.column.table.name != "ip_space"
            for fk in IPBlock.__table__.c[c].foreign_keys
        )
        and c != "parent_block_id"
    }
    assert owner_cols == set(INTEGRATION_OWNERSHIP), owner_cols ^ set(INTEGRATION_OWNERSHIP)


@pytest.mark.asyncio
async def test_target_delete_keeps_registry_referenced_rows(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A purely mirrored address / subnet that an operator registry row points
    at (ON DELETE CASCADE) is operator content and must survive."""
    from decimal import Decimal

    from app.models.bacnet import BACnetDevice
    from app.models.ot import OTZone

    h = await _admin(db_session)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    target = _docker(space)
    db_session.add(target)
    await db_session.flush()
    owner = {"docker_host_id": target.id}
    blk = IPBlock(space_id=space.id, network="10.95.0.0/24", name="b", **owner)
    db_session.add(blk)
    await db_session.flush()
    sn_zone = Subnet(
        space_id=space.id, block_id=blk.id, network="10.95.0.0/25", name="z", total_ips=126, **owner
    )
    sn_dev = Subnet(
        space_id=space.id,
        block_id=blk.id,
        network="10.95.0.128/25",
        name="d",
        total_ips=126,
        **owner,
    )
    db_session.add_all([sn_zone, sn_dev])
    await db_session.flush()
    addr = IPAddress(subnet_id=sn_dev.id, address="10.95.0.130", status="used", **owner)
    db_session.add(addr)
    await db_session.flush()
    db_session.add(OTZone(subnet_id=sn_zone.id, purdue_level=Decimal("2.0")))
    db_session.add(BACnetDevice(ip_address_id=addr.id, subnet_id=sn_dev.id, device_instance=4242))
    await db_session.flush()
    ids = (sn_zone.id, sn_dev.id, addr.id)

    r = await client.delete(f"/api/v1/docker/hosts/{target.id}", headers=h)
    assert r.status_code == 204, r.text
    db_session.expire_all()
    for model, pk in zip((Subnet, Subnet, IPAddress), ids):
        row = await db_session.get(model, pk)
        assert row is not None, model
        assert getattr(row, "docker_host_id") is None
    assert (await db_session.scalar(select(OTZone))) is not None
    assert (await db_session.scalar(select(BACnetDevice))) is not None
