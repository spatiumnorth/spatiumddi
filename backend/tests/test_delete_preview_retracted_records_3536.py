"""spatiumddi#3536: a subnet, block or space delete's approval preview counts the
address records the delete retracts from zones that stay.

A soft delete of a subnet, block or space retracts the auto-generated records
of its subnets' addresses that live in zones that stay, and stamps them with
its batch, so a restore brings them back (#1906). The two-person approval
preview counted none of them, so the approver was not told that the delete
stops serving those names, and an address added between the request and the
approval could not make the approval refuse.

The tree:

    forward zone t3536.example.test. (stays: no subnet owns it)
    space A
      B  10.36.0.0/16
        s1 10.36.1.0/25     a DHCP scope with a lease and a reservation
          .10 host10        A in the forward zone, PTR 10 in 1.36.10.in-addr.arpa.
          .20 lease20       the lease's mirror: A in the forward zone
          .30 resv30        the reservation's mirror: A in the forward zone
          .40 orphan40      a lease mirror whose lease is gone: A in the forward zone
    space C
      O  10.36.0.0/16
        s3 10.36.1.128/25   live in 1.36.10.in-addr.arpa., so that zone stays for it
          .140 host140      A and PTR 140, which stay with s3

The lease and reservation mirrors go with their scope before the stamp, and
their records with them, so the retraction never sees them and the preview
counts none of them. The orphan goes before the stamp of a subnet delete only:
a block or space delete leaves it, and retracts its record.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.change_request import ApprovalPolicy, ChangeRequest
from app.models.dhcp import (
    DHCPLease,
    DHCPScope,
    DHCPServer,
    DHCPServerGroup,
    DHCPStaticAssignment,
)
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.ai.operations_risky import (
    DeleteBlockArgs,
    DeleteSpaceArgs,
    DeleteSubnetArgs,
    _preview_delete_block,
    _preview_delete_space,
    _preview_delete_subnet,
)

FORWARD = "t3536.example.test."
REVERSE = "1.36.10.in-addr.arpa."


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


def _zone(group: DNSServerGroup, name: str, *, linked: Subnet | None = None) -> DNSZone:
    return DNSZone(
        group_id=group.id,
        name=name,
        zone_type="primary",
        kind="reverse" if linked is not None else "forward",
        primary_ns="ns1.example.test.",
        admin_email="admin.example.test.",
        is_auto_generated=linked is not None,
        linked_subnet_id=linked.id if linked is not None else None,
    )


async def _address(
    db: AsyncSession,
    subnet: Subnet,
    host: int,
    hostname: str,
    zones: dict[str, DNSZone],
    *,
    ptr: bool = True,
    **mirror: Any,
) -> IPAddress:
    """An address of ``subnet`` with the records IPAM publishes for it: an A in
    the forward zone and, with ``ptr``, a PTR in the reverse zone."""
    addr = IPAddress(
        subnet_id=subnet.id,
        address=f"10.36.1.{host}",
        status=mirror.pop("status", "allocated"),
        hostname=hostname,
        **mirror,
    )
    db.add(addr)
    await db.flush()
    fwd, rev = zones["forward"], zones["reverse"]
    db.add(
        DNSRecord(
            zone_id=fwd.id,
            name=hostname,
            fqdn=f"{hostname}.{FORWARD}",
            record_type="A",
            value=f"10.36.1.{host}",
            auto_generated=True,
            ip_address_id=addr.id,
        )
    )
    if ptr:
        db.add(
            DNSRecord(
                zone_id=rev.id,
                name=str(host),
                fqdn=f"{host}.{REVERSE}",
                record_type="PTR",
                value=f"{hostname}.{FORWARD}",
                auto_generated=True,
                ip_address_id=addr.id,
            )
        )
    await db.flush()
    return addr


async def _tree(db: AsyncSession) -> dict[str, Any]:
    """Build the module docstring's tree and return its rows by name."""
    space = IPSpace(name=f"rr3536-{uuid.uuid4().hex[:6]}", description="")
    other = IPSpace(name=f"rr3536-other-{uuid.uuid4().hex[:6]}", description="")
    db.add_all([space, other])
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.36.0.0/16", name="B")
    other_block = IPBlock(space_id=other.id, network="10.36.0.0/16", name="O")
    db.add_all([block, other_block])
    await db.flush()
    s1 = Subnet(space_id=space.id, block_id=block.id, network="10.36.1.0/25", name="s1")
    s3 = Subnet(space_id=other.id, block_id=other_block.id, network="10.36.1.128/25", name="s3")
    group = DNSServerGroup(name=f"rr3536-{uuid.uuid4().hex[:6]}")
    dhcp_group = DHCPServerGroup(name=f"rr3536-{uuid.uuid4().hex[:6]}")
    db.add_all([s1, s3, group, dhcp_group])
    await db.flush()
    zones = {"forward": _zone(group, FORWARD), "reverse": _zone(group, REVERSE, linked=s1)}
    scope = DHCPScope(group_id=dhcp_group.id, subnet_id=s1.id, name="s1-scope")
    server = DHCPServer(name=f"kea-{uuid.uuid4().hex[:6]}", host="10.0.0.1", driver="kea")
    db.add_all([*zones.values(), scope, server])
    await db.flush()
    db.add(
        DHCPLease(
            server_id=server.id,
            scope_id=scope.id,
            ip_address="10.36.1.20",
            mac_address="02:00:00:36:00:20",
            state="active",
        )
    )
    reservation = DHCPStaticAssignment(
        scope_id=scope.id,
        ip_address="10.36.1.30",
        mac_address="02:00:00:36:00:30",
        hostname="resv30",
    )
    db.add(reservation)
    await db.flush()
    await _address(db, s1, 10, "host10", zones)
    await _address(db, s1, 20, "lease20", zones, ptr=False, status="dhcp", auto_from_lease=True)
    await _address(
        db,
        s1,
        30,
        "resv30",
        zones,
        ptr=False,
        status="static_dhcp",
        static_assignment_id=str(reservation.id),
    )
    await _address(db, s1, 40, "orphan40", zones, ptr=False, status="dhcp", auto_from_lease=True)
    await _address(db, s3, 140, "host140", zones)
    await db.commit()
    return {"space": space, "block": block, "s1": s1, "s3": s3, "zones": zones}


def _previewed_records(preview_text: str) -> int:
    """The DNS record count a preview names (none named is none)."""
    match = re.search(r"\b(\d+) DNS records?\b", preview_text)
    return int(match.group(1)) if match else 0


async def _batch_records(db: AsyncSession, root: Any) -> set[tuple[str, str]]:
    """The records stamped with ``root``'s deletion batch, as (name, type)."""
    model = type(root)
    stamped = (
        await db.execute(
            select(model.deletion_batch_id)
            .where(model.id == root.id)
            .execution_options(include_deleted=True)
        )
    ).scalar_one()
    assert stamped is not None, f"{model.__name__} {root.id} was not trashed"
    rows = (
        await db.execute(
            select(DNSRecord.name, DNSRecord.record_type)
            .where(DNSRecord.deletion_batch_id == stamped)
            .execution_options(include_deleted=True)
        )
    ).all()
    return {(name, rtype) for name, rtype in rows}


async def _live_record_names(db: AsyncSession) -> set[str]:
    rows = (
        await db.execute(
            select(DNSRecord.name).where(
                DNSRecord.auto_generated.is_(True), DNSRecord.deleted_at.is_(None)
            )
        )
    ).all()
    return {name for (name,) in rows}


# What each delete retracts from the zones that stay: host10's A and PTR, and
# for a block or space delete the orphan's A too.
RETRACTED = {
    "subnet": {("host10", "A"), ("10", "PTR")},
    "block": {("host10", "A"), ("10", "PTR"), ("orphan40", "A")},
    "space": {("host10", "A"), ("10", "PTR"), ("orphan40", "A")},
}
PREVIEWED = {
    "subnet": " cascades 1 DHCP scope, 1 DHCP reservation, 2 DNS records; ",
    "block": " cascades 1 subnet, 1 DHCP scope, 1 DHCP reservation, 3 DNS records; ",
    "space": " cascades 1 child block, 1 subnet, 1 DHCP scope, 1 DHCP reservation, 3 DNS records; ",
}


async def _preview(db: AsyncSession, user: User, tree: dict[str, Any], kind: str) -> str:
    if kind == "subnet":
        preview = await _preview_delete_subnet(db, user, DeleteSubnetArgs(subnet_id=tree["s1"].id))
    elif kind == "block":
        preview = await _preview_delete_block(db, user, DeleteBlockArgs(block_id=tree["block"].id))
    else:
        preview = await _preview_delete_space(db, user, DeleteSpaceArgs(space_id=tree["space"].id))
    assert preview.ok, preview.detail
    return preview.preview_text


def _path(tree: dict[str, Any], kind: str) -> str:
    return {
        "subnet": f"/api/v1/ipam/subnets/{tree['s1'].id}",
        "block": f"/api/v1/ipam/blocks/{tree['block'].id}",
        "space": f"/api/v1/ipam/spaces/{tree['space'].id}",
    }[kind]


def _root(tree: dict[str, Any], kind: str) -> Any:
    return tree["s1"] if kind == "subnet" else tree[kind]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["subnet", "block", "space"])
async def test_delete_preview_counts_the_records_it_retracts(
    client: AsyncClient, db_session: AsyncSession, kind: str
) -> None:
    """The preview names the records the delete then retracts, and only them."""
    user, headers = await _superadmin(db_session, "rr3536")
    tree = await _tree(db_session)

    preview = await _preview(db_session, user, tree, kind)
    assert PREVIEWED[kind] in preview, preview
    assert not (db_session.new or db_session.dirty or db_session.deleted)

    resp = await client.delete(_path(tree, kind), headers=headers)
    assert resp.status_code == 204, resp.text
    retracted = await _batch_records(db_session, _root(tree, kind))
    assert retracted == RETRACTED[kind]
    assert _previewed_records(preview) == len(retracted)
    # s3's records stay with it, in the zones that stay.
    assert {"host140", "140"} <= await _live_record_names(db_session)


async def _request_delete(
    client: AsyncClient, db: AsyncSession, tree: dict[str, Any], kind: str
) -> tuple[str, str, dict[str, str]]:
    """Put a delete of ``kind`` behind an approval policy and request it.
    Returns the change request's id and frozen preview, and an approver."""
    resource_type = {"subnet": "subnet", "block": "ip_block", "space": "ip_space"}[kind]
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
    _, requester = await _superadmin(db, "rr3536-requester")
    _, approver = await _superadmin(db, "rr3536-approver")
    resp = await client.delete(_path(tree, kind), headers=requester)
    assert resp.status_code == 202, resp.text
    return resp.json()["change_request_id"], resp.json()["preview_text"], approver


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["subnet", "block", "space"])
async def test_approval_refused_when_an_address_is_added_before_it(
    client: AsyncClient, db_session: AsyncSession, kind: str
) -> None:
    """An address added to s1, with its A and PTR, between the request and the
    approval changes what the delete would retract, so the approval is refused
    and nothing goes."""
    tree = await _tree(db_session)
    cr_id, frozen, approver = await _request_delete(client, db_session, tree, kind)

    await _address(db_session, tree["s1"], 50, "host50", tree["zones"])
    await db_session.commit()

    resp = await client.post(f"/api/v1/change-requests/{cr_id}/approve", headers=approver, json={})
    assert resp.status_code == 409, f"{resp.status_code} {resp.text}; frozen preview: {frozen}"
    assert "scope changed" in resp.json()["detail"].lower()
    assert PREVIEWED[kind] in frozen, frozen
    cr = await db_session.get(ChangeRequest, uuid.UUID(cr_id))
    assert cr is not None and cr.state == "pending"
    root = _root(tree, kind)
    await db_session.refresh(root)
    assert root.deleted_at is None
    assert {"host10", "10", "host50", "50"} <= await _live_record_names(db_session)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["subnet", "space"])
async def test_approval_of_an_unchanged_delete_retracts_what_it_previewed(
    client: AsyncClient, db_session: AsyncSession, kind: str
) -> None:
    """Control: with nothing changed, the approved delete runs, and retracts
    the records its preview counted."""
    tree = await _tree(db_session)
    cr_id, frozen, approver = await _request_delete(client, db_session, tree, kind)

    resp = await client.post(f"/api/v1/change-requests/{cr_id}/approve", headers=approver, json={})
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "executed", resp.text
    retracted = await _batch_records(db_session, _root(tree, kind))
    assert retracted == RETRACTED[kind]
    assert _previewed_records(frozen) == len(retracted), frozen
