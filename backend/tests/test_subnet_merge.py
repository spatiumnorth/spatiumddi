"""Subnet-merge service + endpoint tests.

End-to-end against the real DB. Covers the contiguity / family /
metadata-compat conflict paths, plus the happy commit path that
folds two adjacent /25s into a /24.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServerGroup
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.ipam.subnet_merge import (
    MergeError,
    commit_subnet_merge,
    preview_subnet_merge,
)


async def _make_admin(db: AsyncSession) -> tuple[User, str]:
    user = User(
        username=f"mg-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Merge Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user, create_access_token(str(user.id))


async def _make_pair(
    db: AsyncSession,
    cidr_a: str = "10.0.0.0/25",
    cidr_b: str = "10.0.0.128/25",
) -> tuple[Subnet, Subnet]:
    """Two contiguous /25s under one block in one space."""
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="b")
    db.add(block)
    await db.flush()
    a = Subnet(
        space_id=space.id,
        block_id=block.id,
        network=cidr_a,
        name="a",
        total_ips=126,
    )
    b = Subnet(
        space_id=space.id,
        block_id=block.id,
        network=cidr_b,
        name="b",
        total_ips=126,
    )
    db.add_all([a, b])
    await db.flush()
    return a, b


@pytest.mark.asyncio
async def test_preview_yields_supernet_for_contiguous_pair(
    db_session: AsyncSession,
) -> None:
    a, b = await _make_pair(db_session)
    preview = await preview_subnet_merge(db_session, a, [b.id])
    assert preview.merged_cidr == "10.0.0.0/24"
    assert preview.conflicts == []


@pytest.mark.asyncio
async def test_preview_non_contiguous_conflict(
    db_session: AsyncSession,
) -> None:
    """Two non-adjacent subnets cannot be summarised — surfaced as a conflict."""
    a, b = await _make_pair(db_session, "10.0.0.0/25", "10.0.1.0/25")
    preview = await preview_subnet_merge(db_session, a, [b.id])
    assert preview.merged_cidr is None
    assert any(c.type == "non_contiguous" for c in preview.conflicts)


@pytest.mark.asyncio
async def test_preview_metadata_mismatch(db_session: AsyncSession) -> None:
    """Different vlan_id on the two sources → metadata_mismatch."""
    a, b = await _make_pair(db_session)
    a.vlan_id = 10
    b.vlan_id = 20
    await db_session.flush()
    preview = await preview_subnet_merge(db_session, a, [b.id])
    assert any(c.type == "metadata_mismatch:vlan_id" for c in preview.conflicts)


@pytest.mark.asyncio
async def test_preview_block_mismatch(db_session: AsyncSession) -> None:
    """Sources under different parent blocks cannot be merged."""
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block_a = IPBlock(space_id=space.id, network="10.0.0.0/16", name="ba")
    block_b = IPBlock(space_id=space.id, network="172.16.0.0/16", name="bb")
    db_session.add_all([block_a, block_b])
    await db_session.flush()
    a = Subnet(space_id=space.id, block_id=block_a.id, network="10.0.0.0/25", name="a")
    b = Subnet(space_id=space.id, block_id=block_b.id, network="172.16.0.0/25", name="b")
    db_session.add_all([a, b])
    await db_session.flush()

    preview = await preview_subnet_merge(db_session, a, [b.id])
    assert any(c.type == "block_mismatch" for c in preview.conflicts)


@pytest.mark.asyncio
async def test_commit_merges_addresses(db_session: AsyncSession) -> None:
    """IP rows from both sources land on the merged subnet; sources gone."""
    a, b = await _make_pair(db_session)
    db_session.add(
        IPAddress(
            subnet_id=a.id,
            address="10.0.0.10",
            status="allocated",
            hostname="left",
        )
    )
    db_session.add(
        IPAddress(
            subnet_id=b.id,
            address="10.0.0.200",
            status="allocated",
            hostname="right",
        )
    )
    # Default-named boundary placeholders on each source.
    for s, addrs in (
        (a, ("10.0.0.0", "10.0.0.127")),
        (b, ("10.0.0.128", "10.0.0.255")),
    ):
        for addr in addrs:
            db_session.add(
                IPAddress(
                    subnet_id=s.id,
                    address=addr,
                    status=(
                        "network" if addr.endswith(".0") or addr == "10.0.0.128" else "broadcast"
                    ),
                    description=(
                        "Network address"
                        if addr.endswith(".0") or addr == "10.0.0.128"
                        else "Broadcast address"
                    ),
                )
            )
    await db_session.flush()

    result = await commit_subnet_merge(db_session, a, [b.id], confirm_cidr="10.0.0.0/24")
    assert str(result.merged_subnet.network) == "10.0.0.0/24"
    assert sorted(result.deleted_subnet_ids) == sorted([a.id, b.id])

    rows = (
        (
            await db_session.execute(
                select(IPAddress).where(IPAddress.subnet_id == result.merged_subnet.id)
            )
        )
        .scalars()
        .all()
    )
    addrs = {str(r.address) for r in rows}
    # Operator IPs survived.
    assert "10.0.0.10" in addrs
    assert "10.0.0.200" in addrs
    # New /24 boundary placeholders are present.
    assert "10.0.0.0" in addrs
    assert "10.0.0.255" in addrs
    # Old internal source-boundary rows (10.0.0.127 / 10.0.0.128) were
    # default-named so they got pruned.
    assert "10.0.0.127" not in addrs
    assert "10.0.0.128" not in addrs


@pytest.mark.asyncio
async def test_commit_rejects_wrong_confirm_cidr(
    db_session: AsyncSession,
) -> None:
    a, b = await _make_pair(db_session)
    with pytest.raises(MergeError) as exc:
        await commit_subnet_merge(db_session, a, [b.id], confirm_cidr="10.0.0.0/25")
    assert exc.value.status_code == 422


@pytest.mark.asyncio
async def test_commit_rejects_multiple_dhcp_scopes(
    db_session: AsyncSession,
) -> None:
    """Two scopes (one per source) → 409."""
    a, b = await _make_pair(db_session)
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(group)
    await db_session.flush()
    db_session.add(DHCPScope(group_id=group.id, subnet_id=a.id, name="a", address_family="ipv4"))
    # Distinct group to avoid the unique-(group, subnet) constraint
    # collision; in practice you can't have two scopes-on-same-group-on-
    # same-subnet anyway.
    group2 = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(group2)
    await db_session.flush()
    db_session.add(DHCPScope(group_id=group2.id, subnet_id=b.id, name="b", address_family="ipv4"))
    await db_session.flush()

    preview = await preview_subnet_merge(db_session, a, [b.id])
    assert any(c.type == "multiple_dhcp_scopes" for c in preview.conflicts)
    with pytest.raises(MergeError) as exc:
        await commit_subnet_merge(db_session, a, [b.id], confirm_cidr="10.0.0.0/24")
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_commit_rebinds_single_dhcp_scope(db_session: AsyncSession) -> None:
    """Exactly one source has a scope → it migrates onto the merged subnet."""
    a, b = await _make_pair(db_session)
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(group)
    await db_session.flush()
    scope = DHCPScope(group_id=group.id, subnet_id=a.id, name="a", address_family="ipv4")
    db_session.add(scope)
    await db_session.flush()

    result = await commit_subnet_merge(db_session, a, [b.id], confirm_cidr="10.0.0.0/24")
    refreshed = await db_session.get(DHCPScope, scope.id)
    assert refreshed is not None
    assert refreshed.subnet_id == result.merged_subnet.id


@pytest.mark.asyncio
async def test_endpoint_smoke(client: AsyncClient, db_session: AsyncSession) -> None:
    """Preview + commit through HTTP."""
    _, token = await _make_admin(db_session)
    a, b = await _make_pair(db_session)

    resp = await client.post(
        f"/api/v1/ipam/subnets/{a.id}/merge/preview",
        headers={"Authorization": f"Bearer {token}"},
        json={"sibling_subnet_ids": [str(b.id)]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["merged_cidr"] == "10.0.0.0/24"
    assert body["conflicts"] == []

    resp = await client.post(
        f"/api/v1/ipam/subnets/{a.id}/merge/commit",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "sibling_subnet_ids": [str(b.id)],
            "confirm_cidr": "10.0.0.0/24",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["merged_subnet"]["network"] == "10.0.0.0/24"
    assert sorted(body["deleted_subnet_ids"]) == sorted([str(a.id), str(b.id)])


_FLAGS = dict(
    pci_scope=True,
    hipaa_scope=True,
    internet_facing=True,
    subnet_role="management",
    do_not_probe=True,
    discovery_enabled=True,
)


@pytest.mark.asyncio
async def test_merge_of_agreeing_sources_keeps_settings(db_session: AsyncSession) -> None:
    """#2414: a merge of two sources that agree keeps their settings."""
    a, b = await _make_pair(db_session)
    for s in (a, b):
        for k, v in _FLAGS.items():
            setattr(s, k, v)
    await db_session.flush()
    preview = await preview_subnet_merge(db_session, a, [b.id])
    assert preview.conflicts == []
    result = await commit_subnet_merge(db_session, a, [b.id], confirm_cidr="10.0.0.0/24")
    for k, v in _FLAGS.items():
        assert getattr(result.merged_subnet, k) == v, k


@pytest.mark.asyncio
async def test_merge_unions_compliance_flags_and_previews_it(db_session: AsyncSession) -> None:
    """#2414: PCI on one source only -> merged is PCI, preview says so."""
    a, b = await _make_pair(db_session)
    b.pci_scope = True
    b.do_not_probe = True
    b.do_not_probe_reason = "fragile"
    await db_session.flush()
    preview = await preview_subnet_merge(db_session, a, [b.id])
    assert preview.conflicts == []
    assert any("pci_scope" in w for w in preview.warnings)
    assert any("do_not_probe" in w for w in preview.warnings)
    result = await commit_subnet_merge(db_session, a, [b.id], confirm_cidr="10.0.0.0/24")
    assert result.merged_subnet.pci_scope is True
    assert result.merged_subnet.do_not_probe is True
    assert result.merged_subnet.do_not_probe_reason == "fragile"
    assert result.merged_subnet.hipaa_scope is False


@pytest.mark.asyncio
async def test_merge_site_disagreement_is_a_conflict(db_session: AsyncSession) -> None:
    """#2414: sources in different kinds/sites are refused, not silently picked."""
    a, b = await _make_pair(db_session)
    a.subnet_role = "management"
    b.discovery_interval_minutes = 99
    b.kind = "multicast"
    await db_session.flush()
    preview = await preview_subnet_merge(db_session, a, [b.id])
    assert any(c.type == "metadata_mismatch:kind" for c in preview.conflicts)
    assert any("subnet_role" in w for w in preview.warnings)
    assert any("discovery_interval_minutes" in w for w in preview.warnings)
