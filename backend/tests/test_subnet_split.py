"""Subnet-split service + endpoint tests.

End-to-end against the real DB. Covers preview output structure,
commit migration of IP rows / placeholders / DHCP scopes, conflict
detection (DHCP scope straddling a child boundary), and the
``confirm_cidr`` defence-in-depth.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPPool, DHCPScope, DHCPServerGroup
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.ipam.subnet_split import (
    SplitError,
    commit_subnet_split,
    preview_subnet_split,
)


async def _make_admin(db: AsyncSession) -> tuple[User, str]:
    user = User(
        username=f"sp-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Split Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user, create_access_token(str(user.id))


async def _make_subnet(db: AsyncSession, network: str = "10.0.0.0/24") -> Subnet:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network=network,
        name="parent",
        total_ips=254,
    )
    db.add(subnet)
    await db.flush()
    return subnet


@pytest.mark.asyncio
async def test_preview_emits_two_children_for_one_step(
    db_session: AsyncSession,
) -> None:
    """A /24 → /25 split yields exactly two children with /25 boundaries."""
    subnet = await _make_subnet(db_session, "10.0.0.0/24")

    preview = await preview_subnet_split(db_session, subnet, 25)
    assert preview.parent_cidr == "10.0.0.0/24"
    assert preview.new_prefix_length == 25
    cidrs = [c.cidr for c in preview.children]
    assert cidrs == ["10.0.0.0/25", "10.0.0.128/25"]
    assert preview.conflicts == []


@pytest.mark.asyncio
async def test_preview_rejects_invalid_prefix(db_session: AsyncSession) -> None:
    """Equal-or-shorter prefix is a validation conflict, not a raise."""
    subnet = await _make_subnet(db_session, "10.0.0.0/24")
    preview = await preview_subnet_split(db_session, subnet, 24)
    assert any(c.type == "validation" for c in preview.conflicts)
    preview2 = await preview_subnet_split(db_session, subnet, 23)
    assert any(c.type == "validation" for c in preview2.conflicts)


@pytest.mark.asyncio
async def test_commit_migrates_addresses(db_session: AsyncSession) -> None:
    """IPAddress rows on the parent get reattached to the child whose
    range contains them; default boundary placeholders get recreated."""
    subnet = await _make_subnet(db_session, "10.0.0.0/24")
    # Default-named boundaries.
    db_session.add(
        IPAddress(
            subnet_id=subnet.id,
            address="10.0.0.0",
            status="network",
            description="Network address",
        )
    )
    db_session.add(
        IPAddress(
            subnet_id=subnet.id,
            address="10.0.0.255",
            status="broadcast",
            description="Broadcast address",
        )
    )
    # Operator-allocated rows in each half.
    db_session.add(
        IPAddress(
            subnet_id=subnet.id,
            address="10.0.0.10",
            status="allocated",
            hostname="left-server",
        )
    )
    db_session.add(
        IPAddress(
            subnet_id=subnet.id,
            address="10.0.0.200",
            status="allocated",
            hostname="right-server",
        )
    )
    await db_session.flush()

    result = await commit_subnet_split(db_session, subnet, 25, confirm_cidr="10.0.0.0/24")
    assert result.parent_cidr == "10.0.0.0/24"
    assert len(result.children) == 2

    # Parent should be gone.
    deleted = await db_session.get(Subnet, subnet.id)
    assert deleted is None

    # Each child should own one operator IP.
    by_cidr = {str(c.network): c for c in result.children}
    left = by_cidr["10.0.0.0/25"]
    right = by_cidr["10.0.0.128/25"]

    left_rows = (
        (await db_session.execute(select(IPAddress).where(IPAddress.subnet_id == left.id)))
        .scalars()
        .all()
    )
    right_rows = (
        (await db_session.execute(select(IPAddress).where(IPAddress.subnet_id == right.id)))
        .scalars()
        .all()
    )
    left_addrs = {str(r.address) for r in left_rows}
    right_addrs = {str(r.address) for r in right_rows}

    # Each child has its operator IP + new boundary placeholders.
    assert "10.0.0.10" in left_addrs
    assert "10.0.0.200" in right_addrs
    assert "10.0.0.0" in left_addrs  # left network address
    assert "10.0.0.127" in left_addrs  # left broadcast
    assert "10.0.0.128" in right_addrs  # right network address
    assert "10.0.0.255" in right_addrs  # right broadcast


@pytest.mark.asyncio
async def test_commit_renamed_placeholder_survives(
    db_session: AsyncSession,
) -> None:
    """A boundary row with a custom hostname survives the split and
    lands on the child that contains its address."""
    subnet = await _make_subnet(db_session, "10.0.0.0/24")
    # Renamed broadcast (operator's anycast VIP, say).
    db_session.add(
        IPAddress(
            subnet_id=subnet.id,
            address="10.0.0.255",
            status="broadcast",
            hostname="anycast-vip",
            description="In use",
        )
    )
    await db_session.flush()

    result = await commit_subnet_split(db_session, subnet, 25, confirm_cidr="10.0.0.0/24")
    by_cidr = {str(c.network): c for c in result.children}
    right = by_cidr["10.0.0.128/25"]
    rows = (
        (await db_session.execute(select(IPAddress).where(IPAddress.subnet_id == right.id)))
        .scalars()
        .all()
    )
    addr_to_host = {str(r.address): r.hostname for r in rows}
    # The renamed row is preserved verbatim on the child that contains
    # it; it is NOT replaced by a default broadcast row.
    assert addr_to_host.get("10.0.0.255") == "anycast-vip"


@pytest.mark.asyncio
async def test_commit_rejects_wrong_confirm_cidr(
    db_session: AsyncSession,
) -> None:
    subnet = await _make_subnet(db_session, "10.0.0.0/24")
    with pytest.raises(SplitError) as exc:
        await commit_subnet_split(db_session, subnet, 25, confirm_cidr="10.0.0.0/25")
    assert exc.value.status_code == 422


@pytest.mark.asyncio
async def test_commit_rejects_dhcp_scope_straddling_boundary(
    db_session: AsyncSession,
) -> None:
    """A DHCP pool that crosses the planned child boundary blocks the split."""
    subnet = await _make_subnet(db_session, "10.0.0.0/24")
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(group)
    await db_session.flush()
    scope = DHCPScope(
        group_id=group.id,
        subnet_id=subnet.id,
        name="straddle",
        address_family="ipv4",
    )
    db_session.add(scope)
    await db_session.flush()
    # Pool 10.0.0.100 → 10.0.0.200 — crosses the /25 boundary at .128.
    db_session.add(
        DHCPPool(
            scope_id=scope.id,
            name="p",
            start_ip="10.0.0.100",
            end_ip="10.0.0.200",
            pool_type="dynamic",
        )
    )
    await db_session.flush()

    preview = await preview_subnet_split(db_session, subnet, 25)
    assert any(
        c.type == "dhcp_scope_straddles_boundary" for c in preview.conflicts
    ), preview.conflicts

    with pytest.raises(SplitError) as exc:
        await commit_subnet_split(db_session, subnet, 25, confirm_cidr="10.0.0.0/24")
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_commit_rebinds_dhcp_scope_to_one_child(
    db_session: AsyncSession,
) -> None:
    """A pool wholly inside one child rebinds the scope to that child."""
    subnet = await _make_subnet(db_session, "10.0.0.0/24")
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(group)
    await db_session.flush()
    scope = DHCPScope(
        group_id=group.id,
        subnet_id=subnet.id,
        name="left",
        address_family="ipv4",
    )
    db_session.add(scope)
    await db_session.flush()
    # Pool 10.0.0.10 → 10.0.0.100 — entirely in the left /25.
    db_session.add(
        DHCPPool(
            scope_id=scope.id,
            name="p",
            start_ip="10.0.0.10",
            end_ip="10.0.0.100",
            pool_type="dynamic",
        )
    )
    await db_session.flush()

    result = await commit_subnet_split(db_session, subnet, 25, confirm_cidr="10.0.0.0/24")
    by_cidr = {str(c.network): c for c in result.children}
    left = by_cidr["10.0.0.0/25"]

    refreshed_scope = await db_session.get(DHCPScope, scope.id)
    assert refreshed_scope is not None
    assert refreshed_scope.subnet_id == left.id


@pytest.mark.asyncio
async def test_endpoint_smoke(client: AsyncClient, db_session: AsyncSession) -> None:
    """HTTP preview + commit, end-to-end."""
    _, token = await _make_admin(db_session)
    subnet = await _make_subnet(db_session, "10.0.0.0/24")

    resp = await client.post(
        f"/api/v1/ipam/subnets/{subnet.id}/split/preview",
        headers={"Authorization": f"Bearer {token}"},
        json={"new_prefix_length": 26},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["children"]) == 4
    assert body["conflicts"] == []

    resp = await client.post(
        f"/api/v1/ipam/subnets/{subnet.id}/split/commit",
        headers={"Authorization": f"Bearer {token}"},
        json={"new_prefix_length": 26, "confirm_cidr": "10.0.0.0/24"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["parent_cidr"] == "10.0.0.0/24"
    assert len(body["children"]) == 4


@pytest.mark.asyncio
async def test_endpoint_rejects_bad_confirm(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_admin(db_session)
    subnet = await _make_subnet(db_session, "10.0.0.0/24")

    resp = await client.post(
        f"/api/v1/ipam/subnets/{subnet.id}/split/commit",
        headers={"Authorization": f"Bearer {token}"},
        json={"new_prefix_length": 25, "confirm_cidr": "wrong"},
    )
    assert resp.status_code == 422


_FLAGS = dict(
    pci_scope=True,
    hipaa_scope=True,
    internet_facing=True,
    subnet_role="management",
    do_not_probe=True,
    do_not_probe_reason="fragile PLCs",
    discovery_enabled=True,
    discovery_interval_minutes=45,
    dns_split_horizon=True,
)


@pytest.mark.asyncio
async def test_split_children_keep_compliance_and_probe_settings(
    db_session: AsyncSession,
) -> None:
    """#2414: children inherit PCI/HIPAA/internet-facing/role/do-not-probe."""
    subnet = await _make_subnet(db_session, "10.0.0.0/24")
    for k, v in _FLAGS.items():
        setattr(subnet, k, v)
    await db_session.flush()

    result = await commit_subnet_split(db_session, subnet, 25, confirm_cidr="10.0.0.0/24")
    assert len(result.children) == 2
    for child in result.children:
        for k, v in _FLAGS.items():
            assert getattr(child, k) == v, k
