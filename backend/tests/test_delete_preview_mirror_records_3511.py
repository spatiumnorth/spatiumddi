"""spatiumddi#3511, from the review of #3610: the reverse zone a subnet, block or
space delete trashes is counted without the records of the DHCP mirrors the
delete removes first.

The delete trashes, in its batch, each reverse zone its subnets auto-created
and no live subnet outside the delete still uses, with the records still in it
when the batch is stamped (#3511). Before the stamp it deletes the lease and
reservation mirrors of the batch's DHCP scopes, and for a subnet every lease
mirror, with their records (#3536). The preview counted the zone's records as
they stood, those mirrors' PTRs included, so it named more records than the
delete trashes, and any lease granted or expiring in the subnet changed the
preview, which made the approve-time drift check refuse the approval.

The tree:

    forward zone mirrors3511.example.test. (stays: no subnet owns it)
    space A
      B  10.37.0.0/16
        s1 10.37.1.0/24     a DHCP scope with a lease and a reservation; its
                            auto reverse zone 1.37.10.in-addr.arpa. goes with it
          .10 host10        an address: A and PTR 10
          .20 lease20       the lease's mirror: A and PTR 20, as DDNS publishes
          .30 resv30        the reservation's mirror: A and PTR 30
          .40 orphan40      a lease mirror whose lease is gone: A and PTR 40

A subnet delete removes all three mirrors first, so it trashes the zone with PTR
10 and retracts host10's A. A block or space delete leaves the orphan, so it
trashes PTR 10 and PTR 40 with the zone and retracts the A of host10 and of
orphan40.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
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

FORWARD = "mirrors3511.example.test."
REVERSE = "1.37.10.in-addr.arpa."


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
    tree: dict[str, Any],
    host: int,
    hostname: str,
    **mirror: Any,
) -> IPAddress:
    """An address of s1 with the records IPAM (or DDNS, for a lease's mirror)
    publishes for it: an A in the forward zone and a PTR in s1's reverse zone."""
    addr = IPAddress(
        subnet_id=tree["s1"].id,
        address=f"10.37.1.{host}",
        status=mirror.pop("status", "allocated"),
        hostname=hostname,
        **mirror,
    )
    db.add(addr)
    await db.flush()
    db.add_all(
        [
            DNSRecord(
                zone_id=tree["forward"].id,
                name=hostname,
                fqdn=f"{hostname}.{FORWARD}",
                record_type="A",
                value=f"10.37.1.{host}",
                auto_generated=True,
                ip_address_id=addr.id,
            ),
            DNSRecord(
                zone_id=tree["reverse"].id,
                name=str(host),
                fqdn=f"{host}.{REVERSE}",
                record_type="PTR",
                value=f"{hostname}.{FORWARD}",
                auto_generated=True,
                ip_address_id=addr.id,
            ),
        ]
    )
    await db.flush()
    return addr


async def _grant_lease(db: AsyncSession, tree: dict[str, Any], host: int) -> None:
    """A lease of s1's scope at ``.host``, with the mirror and the A and PTR
    DDNS publishes for it."""
    db.add(
        DHCPLease(
            server_id=tree["server"].id,
            scope_id=tree["scope"].id,
            ip_address=f"10.37.1.{host}",
            mac_address=f"02:00:00:37:00:{host:02x}",
            hostname=f"lease{host}",
            state="active",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    await _address(db, tree, host, f"lease{host}", status="dhcp", auto_from_lease=True)


async def _tree(db: AsyncSession) -> dict[str, Any]:
    """Build the module docstring's tree and return its rows by name."""
    space = IPSpace(name=f"mr3511-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.37.0.0/16", name="B")
    db.add(block)
    await db.flush()
    s1 = Subnet(space_id=space.id, block_id=block.id, network="10.37.1.0/24", name="s1")
    group = DNSServerGroup(name=f"mr3511-{uuid.uuid4().hex[:6]}")
    dhcp_group = DHCPServerGroup(name=f"mr3511-{uuid.uuid4().hex[:6]}")
    db.add_all([s1, group, dhcp_group])
    await db.flush()
    scope = DHCPScope(group_id=dhcp_group.id, subnet_id=s1.id, name="s1-scope")
    server = DHCPServer(name=f"kea-{uuid.uuid4().hex[:6]}", host="10.0.0.1", driver="kea")
    tree: dict[str, Any] = {
        "space": space,
        "block": block,
        "s1": s1,
        "forward": _zone(group, FORWARD),
        "reverse": _zone(group, REVERSE, linked=s1),
        "scope": scope,
        "server": server,
    }
    db.add_all([tree["forward"], tree["reverse"], scope, server])
    await db.flush()
    reservation = DHCPStaticAssignment(
        scope_id=scope.id,
        ip_address="10.37.1.30",
        mac_address="02:00:00:37:00:30",
        hostname="resv30",
    )
    db.add(reservation)
    await db.flush()
    await _address(db, tree, 10, "host10")
    await _grant_lease(db, tree, 20)
    await _address(
        db,
        tree,
        30,
        "resv30",
        status="static_dhcp",
        static_assignment_id=str(reservation.id),
    )
    await _address(db, tree, 40, "orphan40", status="dhcp", auto_from_lease=True)
    await db.commit()
    return tree


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


# What each delete trashes: the zone with the records still in it at the stamp,
# and the A records it retracts from the forward zone.
TRASHED = {
    "subnet": {("10", "PTR"), ("host10", "A")},
    "block": {("10", "PTR"), ("40", "PTR"), ("host10", "A"), ("orphan40", "A")},
    "space": {("10", "PTR"), ("40", "PTR"), ("host10", "A"), ("orphan40", "A")},
}
ZONE_RECORDS = {"subnet": 1, "block": 2, "space": 2}
PREVIEWED = {
    "subnet": "; cascades 1 DHCP scope, 1 DHCP reservation, 1 DNS zone, 2 DNS records; ",
    "block": " cascades 1 subnet, 1 DHCP scope, 1 DHCP reservation, 1 DNS zone, 4 DNS records; ",
    "space": (
        " cascades 1 child block, 1 subnet, 1 DHCP scope, 1 DHCP reservation, 1 DNS zone, "
        "4 DNS records; "
    ),
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


async def _assert_trashed_as_previewed(
    db: AsyncSession, tree: dict[str, Any], kind: str, preview: str
) -> None:
    trashed = await _batch_records(db, _root(tree, kind))
    assert trashed == TRASHED[kind]
    assert await _zone_soft_deletes(db) == {
        str(tree["reverse"].id): {"dns_record": ZONE_RECORDS[kind]}
    }
    assert _previewed_records(preview) == len(trashed), (
        f"the preview names {_previewed_records(preview)} DNS records, the delete "
        f"trashed {len(trashed)}: {preview}"
    )
    assert PREVIEWED[kind] in preview, preview


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["subnet", "block", "space"])
async def test_delete_preview_counts_the_zone_records_the_delete_trashes(
    client: AsyncClient, db_session: AsyncSession, kind: str
) -> None:
    """The reverse zone's records are counted as the delete stamps them: the
    PTRs of the mirrors it removes first are not."""
    user, headers = await _superadmin(db_session, "mr3511")
    tree = await _tree(db_session)

    preview = await _preview(db_session, user, tree, kind)
    assert not (db_session.new or db_session.dirty or db_session.deleted)

    resp = await client.delete(_path(tree, kind), headers=headers)
    assert resp.status_code == 204, resp.text
    await _assert_trashed_as_previewed(db_session, tree, kind, preview)


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
    _, requester = await _superadmin(db, "mr3511-requester")
    _, approver = await _superadmin(db, "mr3511-approver")
    resp = await client.delete(_path(tree, kind), headers=requester)
    assert resp.status_code == 202, resp.text
    return resp.json()["change_request_id"], resp.json()["preview_text"], approver


async def _expire_lease(db: AsyncSession, tree: dict[str, Any], host: int) -> None:
    """The lease at ``.host`` runs out, and the expiry sweep revokes its
    mirror's records and removes the mirror."""
    from app.tasks.dhcp_lease_cleanup import _sweep  # noqa: PLC0415

    lease = (
        await db.execute(select(DHCPLease).where(DHCPLease.ip_address == f"10.37.1.{host}"))
    ).scalar_one()
    lease.expires_at = datetime.now(UTC) - timedelta(hours=1)
    await db.commit()
    await _sweep()
    gone = (
        await db.execute(
            select(DNSRecord.name).where(DNSRecord.name.in_([str(host), f"lease{host}"]))
        )
    ).all()
    assert gone == [], gone


@pytest.mark.asyncio
@pytest.mark.parametrize("event", ["grant", "expiry"])
@pytest.mark.parametrize("kind", ["subnet", "block", "space"])
async def test_lease_churn_before_the_approval_leaves_the_delete_approvable(
    client: AsyncClient, db_session: AsyncSession, kind: str, event: str
) -> None:
    """A lease granted, or one expiring, between the request and the approval
    leaves the preview as it was: the delete removes every such mirror before
    its stamp, with its records. So the approval goes through, and the delete
    trashes what was previewed."""
    tree = await _tree(db_session)
    cr_id, frozen, approver = await _request_delete(client, db_session, tree, kind)

    if event == "grant":
        await _grant_lease(db_session, tree, 50)
        await db_session.commit()
    else:
        await _expire_lease(db_session, tree, 20)

    resp = await client.post(f"/api/v1/change-requests/{cr_id}/approve", headers=approver, json={})
    assert resp.status_code == 200, f"{resp.status_code} {resp.text}; frozen preview: {frozen}"
    assert resp.json()["state"] == "executed", resp.text
    await _assert_trashed_as_previewed(db_session, tree, kind, frozen)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["subnet", "block", "space"])
async def test_an_address_added_before_the_approval_still_refuses_it(
    client: AsyncClient, db_session: AsyncSession, kind: str
) -> None:
    """Control: an address that is not a DHCP mirror, added with its A and PTR
    between the request and the approval, changes what the delete trashes, so
    the approval is still refused and nothing goes."""
    tree = await _tree(db_session)
    cr_id, frozen, approver = await _request_delete(client, db_session, tree, kind)

    await _address(db_session, tree, 60, "host60")
    await db_session.commit()

    resp = await client.post(f"/api/v1/change-requests/{cr_id}/approve", headers=approver, json={})
    assert resp.status_code == 409, f"{resp.status_code} {resp.text}; frozen preview: {frozen}"
    assert "scope changed" in resp.json()["detail"].lower()
    cr = await db_session.get(ChangeRequest, uuid.UUID(cr_id))
    assert cr is not None and cr.state == "pending"
    root = _root(tree, kind)
    await db_session.refresh(root)
    assert root.deleted_at is None
