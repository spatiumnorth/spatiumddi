"""spatiumddi#3511: a subnet, block or space delete's approval preview counts the
auto reverse zones the delete trashes, and their records.

A soft delete of a subnet, block or space adds the reverse zones its subnets
auto-created to its own batch, after the batch's walk (#1066 for a subnet,
#2734 for a block or a space), each with its records as a set-based child
(#1231). A zone a live subnet outside the delete still lives in is re-linked to
that subnet instead, and stays. The two-person approval preview rendered the
walk's counts alone, so it never named those zones or their records, and the
approve-time drift check, a string compare of the preview, could not see them
change between the request and the approval.

The tree:

    space A
      B  10.35.0.0/16
        s1 10.35.1.0/24    its auto reverse zone 1.35.10.in-addr.arpa., two PTRs
        s2 10.35.2.0/25    its auto reverse zone 2.35.10.in-addr.arpa., one PTR
    space C
      O  10.35.0.0/16
        s3 10.35.2.128/25  live in 2.35.10.in-addr.arpa., so that zone stays for it
"""

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
from app.models.change_request import ApprovalPolicy, ChangeRequest
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.ai.operations_risky import (
    DeleteBlockArgs,
    DeleteSpaceArgs,
    DeleteSubnetArgs,
    _preview_delete_block,
    _preview_delete_space,
    _preview_delete_subnet,
)


async def _superadmin(db: AsyncSession, name: str) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"{name}-{uuid.uuid4().hex[:8]}",
        email=f"{name}-{uuid.uuid4().hex[:8]}@example.test",
        display_name=name,
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _reverse_zone(group: DNSServerGroup, name: str, subnet: Subnet) -> DNSZone:
    return DNSZone(
        group_id=group.id,
        name=name,
        zone_type="primary",
        kind="reverse",
        primary_ns="ns1.example.test.",
        admin_email="admin.example.test.",
        is_auto_generated=True,
        linked_subnet_id=subnet.id,
    )


def _ptr(zone: DNSZone, host: int) -> DNSRecord:
    return DNSRecord(
        zone_id=zone.id,
        name=str(host),
        fqdn=f"{host}.{zone.name}",
        record_type="PTR",
        value=f"h{host}.example.test.",
    )


async def _tree(db: AsyncSession) -> dict[str, Any]:
    """Build the module docstring's tree and return its rows by name."""
    space = IPSpace(name=f"rz3511-{uuid.uuid4().hex[:6]}", description="")
    other = IPSpace(name=f"rz3511-other-{uuid.uuid4().hex[:6]}", description="")
    db.add_all([space, other])
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.35.0.0/16", name="B")
    other_block = IPBlock(space_id=other.id, network="10.35.0.0/16", name="O")
    db.add_all([block, other_block])
    await db.flush()
    s1 = Subnet(space_id=space.id, block_id=block.id, network="10.35.1.0/24", name="s1")
    s2 = Subnet(space_id=space.id, block_id=block.id, network="10.35.2.0/25", name="s2")
    s3 = Subnet(space_id=other.id, block_id=other_block.id, network="10.35.2.128/25", name="s3")
    db.add_all([s1, s2, s3])
    group = DNSServerGroup(name=f"rz3511-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    z1 = _reverse_zone(group, "1.35.10.in-addr.arpa.", s1)
    z2 = _reverse_zone(group, "2.35.10.in-addr.arpa.", s2)
    db.add_all([z1, z2])
    await db.flush()
    db.add_all([_ptr(z1, 10), _ptr(z1, 11), _ptr(z2, 12)])
    await db.commit()
    return {"space": space, "block": block, "s1": s1, "s2": s2, "s3": s3, "z1": z1, "z2": z2}


async def _zone_soft_deletes(db: AsyncSession) -> dict[str, Any]:
    """The ``soft_delete`` audit rows of DNS zones, by zone id: their ``cascaded``."""
    rows = (
        (
            await db.execute(
                select(AuditLog).where(
                    AuditLog.action == "soft_delete", AuditLog.resource_type == "dns_zone"
                )
            )
        )
        .scalars()
        .all()
    )
    return {row.resource_id: (row.old_value or {}).get("cascaded") for row in rows}


async def _assert_z2_stayed_for_s3(db: AsyncSession, tree: dict[str, Any]) -> None:
    zone = (
        await db.execute(
            select(DNSZone)
            .where(DNSZone.id == tree["z2"].id)
            .execution_options(include_deleted=True, populate_existing=True)
        )
    ).scalar_one()
    assert zone.deleted_at is None
    assert zone.linked_subnet_id == tree["s3"].id


@pytest.mark.asyncio
async def test_subnet_delete_preview_counts_the_reverse_zone_it_trashes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, headers = await _superadmin(db_session, "rz3511")
    tree = await _tree(db_session)
    s1, z1 = tree["s1"], tree["z1"]

    preview = await _preview_delete_subnet(db_session, user, DeleteSubnetArgs(subnet_id=s1.id))
    assert preview.ok, preview.detail
    assert "; cascades 1 DNS zone, 2 DNS records; " in preview.preview_text, preview.preview_text

    # What the delete trashes: the zone, in the subnet's batch, with its two records.
    resp = await client.delete(f"/api/v1/ipam/subnets/{s1.id}", headers=headers)
    assert resp.status_code == 204, resp.text
    assert await _zone_soft_deletes(db_session) == {str(z1.id): {"dns_record": 2}}


@pytest.mark.asyncio
async def test_subnet_delete_preview_leaves_out_a_zone_a_live_subnet_keeps(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """s2's zone stays for s3, so neither the preview nor the delete counts it,
    and the preview re-links nothing: it only reads."""
    user, headers = await _superadmin(db_session, "rz3511")
    tree = await _tree(db_session)
    s2, z2 = tree["s2"], tree["z2"]

    preview = await _preview_delete_subnet(db_session, user, DeleteSubnetArgs(subnet_id=s2.id))
    assert preview.ok, preview.detail
    assert "; cascades nothing (empty); " in preview.preview_text, preview.preview_text
    assert z2.linked_subnet_id == s2.id
    assert not (db_session.new or db_session.dirty or db_session.deleted)

    resp = await client.delete(f"/api/v1/ipam/subnets/{s2.id}", headers=headers)
    assert resp.status_code == 204, resp.text
    assert await _zone_soft_deletes(db_session) == {}
    await _assert_z2_stayed_for_s3(db_session, tree)


@pytest.mark.asyncio
async def test_block_delete_preview_counts_the_reverse_zones_it_trashes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, headers = await _superadmin(db_session, "rz3511")
    tree = await _tree(db_session)
    block, z1 = tree["block"], tree["z1"]

    preview = await _preview_delete_block(db_session, user, DeleteBlockArgs(block_id=block.id))
    assert preview.ok, preview.detail
    assert (
        " cascades 2 subnets, 1 DNS zone, 2 DNS records; " in preview.preview_text
    ), preview.preview_text

    resp = await client.delete(f"/api/v1/ipam/blocks/{block.id}", headers=headers)
    assert resp.status_code == 204, resp.text
    assert await _zone_soft_deletes(db_session) == {str(z1.id): {"dns_record": 2}}
    await _assert_z2_stayed_for_s3(db_session, tree)


@pytest.mark.asyncio
async def test_space_delete_preview_counts_the_reverse_zones_it_trashes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, headers = await _superadmin(db_session, "rz3511")
    tree = await _tree(db_session)
    space, z1 = tree["space"], tree["z1"]

    preview = await _preview_delete_space(db_session, user, DeleteSpaceArgs(space_id=space.id))
    assert preview.ok, preview.detail
    assert (
        " cascades 1 child block, 2 subnets, 1 DNS zone, 2 DNS records; " in preview.preview_text
    ), preview.preview_text

    resp = await client.delete(f"/api/v1/ipam/spaces/{space.id}", headers=headers)
    assert resp.status_code == 204, resp.text
    assert await _zone_soft_deletes(db_session) == {str(z1.id): {"dns_record": 2}}
    await _assert_z2_stayed_for_s3(db_session, tree)


async def _request_delete(
    client: AsyncClient, db: AsyncSession, tree: dict[str, Any], kind: str
) -> tuple[str, str, dict[str, str]]:
    """Put a delete of ``kind`` behind an approval policy and request it.
    Returns the change request's id and frozen preview, and an approver."""
    path, resource_type = {
        "subnet": (f"/api/v1/ipam/subnets/{tree['s1'].id}", "subnet"),
        "block": (f"/api/v1/ipam/blocks/{tree['block'].id}", "ip_block"),
        "space": (f"/api/v1/ipam/spaces/{tree['space'].id}", "ip_space"),
    }[kind]
    db.add(
        ApprovalPolicy(
            name=f"delete:{resource_type}",
            resource_type=resource_type,
            action="delete",
            min_count=None,
            enabled=True,
            applies_to_superadmin=True,
            ttl_hours=168,
            is_builtin=False,
        )
    )
    await db.flush()
    _, requester = await _superadmin(db, "rz3511-requester")
    _, approver = await _superadmin(db, "rz3511-approver")
    resp = await client.delete(path, headers=requester)
    assert resp.status_code == 202, resp.text
    return resp.json()["change_request_id"], resp.json()["preview_text"], approver


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["subnet", "block", "space"])
async def test_approval_refused_when_a_reverse_zone_the_delete_trashes_changed(
    client: AsyncClient, db_session: AsyncSession, kind: str
) -> None:
    """A PTR added to s1's zone between the request and the approval changes
    what the delete would trash, so the approval is refused and nothing goes."""
    tree = await _tree(db_session)
    cr_id, frozen, approver = await _request_delete(client, db_session, tree, kind)

    db_session.add(_ptr(tree["z1"], 13))
    await db_session.commit()

    resp = await client.post(f"/api/v1/change-requests/{cr_id}/approve", headers=approver, json={})
    assert resp.status_code == 409, f"{resp.status_code} {resp.text}; frozen preview: {frozen}"
    assert "scope changed" in resp.json()["detail"].lower()
    assert "1 DNS zone, 2 DNS records" in frozen, frozen
    cr = await db_session.get(ChangeRequest, uuid.UUID(cr_id))
    assert cr is not None and cr.state == "pending"
    for name in ("s1", "z1"):
        await db_session.refresh(tree[name])
        assert tree[name].deleted_at is None, name


@pytest.mark.asyncio
async def test_approval_of_an_unchanged_space_delete_trashes_what_it_previewed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Control: with nothing changed, the approved delete runs, and trashes the
    zone and the two records its preview named."""
    tree = await _tree(db_session)
    cr_id, frozen, approver = await _request_delete(client, db_session, tree, "space")

    resp = await client.post(f"/api/v1/change-requests/{cr_id}/approve", headers=approver, json={})
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "executed", resp.text
    assert "1 DNS zone, 2 DNS records" in frozen, frozen
    assert await _zone_soft_deletes(db_session) == {str(tree["z1"].id): {"dns_record": 2}}
    await _assert_z2_stayed_for_s3(db_session, tree)
