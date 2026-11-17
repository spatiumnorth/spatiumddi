"""spatiumddi#3511, from the review of #3610: a delete's approval preview
leaves out the records of every reservation mirror the delete removes first,
whichever subnet the mirror sits in.

Before its stamp a subnet, block or space delete removes the IPAM mirror of
each reservation of the DHCP scopes in its batch, with the mirror's records.
It finds the mirror by the reservation alone (``remove_ipam_for_scope_statics``),
so a mirror in another subnet goes too. The preview took a reservation's
mirror as removed only when the reservation's scope sat on the mirror's own
subnet. So for a reservation whose mirror sits in another subnet of the same
block or space, the preview counted records the delete never trashes: the
mirror's PTR with its reverse zone, and its A as retracted.

The tree:

    forward zone resv3511.example.test. (stays: no subnet owns it)
    space A
      B  10.38.0.0/16
        s1 10.38.1.0/24     a DHCP scope with a reservation at 10.38.2.30;
                            its auto reverse zone 1.38.10.in-addr.arpa.
          .10 host10        an address: A and PTR 10
        s2 10.38.2.0/24     no DHCP scope; its auto reverse zone
                            2.38.10.in-addr.arpa.
          .30 resv30        the reservation's mirror, outside its scope's
                            subnet: A and PTR 30

A delete of s1 removes the mirror, whose records are in zones that stay, so it
trashes s1's zone with PTR 10 and retracts host10's A. A delete of s2 leaves
the mirror, whose scope stays, so it trashes s2's zone with PTR 30 and
retracts resv30's A. A block or space delete removes the mirror first, so it
trashes s1's zone with PTR 10 and s2's zone with nothing left in it, and
retracts host10's A.
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
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServerGroup, DHCPStaticAssignment
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

FORWARD = "resv3511.example.test."
# The third octet of each subnet, which names its reverse zone.
OCTET = {"s1": 1, "s2": 2}


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
    subnet: str,
    host: int,
    hostname: str,
    **mirror: Any,
) -> IPAddress:
    """An address of ``subnet`` with the records IPAM publishes for it: an A
    in the forward zone and a PTR in the subnet's reverse zone."""
    ip = f"10.38.{OCTET[subnet]}.{host}"
    addr = IPAddress(
        subnet_id=tree[subnet].id,
        address=ip,
        status=mirror.pop("status", "allocated"),
        hostname=hostname,
        **mirror,
    )
    db.add(addr)
    await db.flush()
    reverse = tree[f"reverse-{subnet}"]
    db.add_all(
        [
            DNSRecord(
                zone_id=tree["forward"].id,
                name=hostname,
                fqdn=f"{hostname}.{FORWARD}",
                record_type="A",
                value=ip,
                auto_generated=True,
                ip_address_id=addr.id,
            ),
            DNSRecord(
                zone_id=reverse.id,
                name=str(host),
                fqdn=f"{host}.{reverse.name}",
                record_type="PTR",
                value=f"{hostname}.{FORWARD}",
                auto_generated=True,
                ip_address_id=addr.id,
            ),
        ]
    )
    await db.flush()
    return addr


async def _tree(db: AsyncSession) -> dict[str, Any]:
    """Build the module docstring's tree and return its rows by name."""
    space = IPSpace(name=f"rm3511-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.38.0.0/16", name="B")
    db.add(block)
    await db.flush()
    s1 = Subnet(space_id=space.id, block_id=block.id, network="10.38.1.0/24", name="s1")
    s2 = Subnet(space_id=space.id, block_id=block.id, network="10.38.2.0/24", name="s2")
    group = DNSServerGroup(name=f"rm3511-{uuid.uuid4().hex[:6]}")
    dhcp_group = DHCPServerGroup(name=f"rm3511-{uuid.uuid4().hex[:6]}")
    db.add_all([s1, s2, group, dhcp_group])
    await db.flush()
    scope = DHCPScope(group_id=dhcp_group.id, subnet_id=s1.id, name="s1-scope")
    tree: dict[str, Any] = {
        "space": space,
        "block": block,
        "s1": s1,
        "s2": s2,
        "forward": _zone(group, FORWARD),
        "reverse-s1": _zone(group, "1.38.10.in-addr.arpa.", linked=s1),
        "reverse-s2": _zone(group, "2.38.10.in-addr.arpa.", linked=s2),
        "scope": scope,
    }
    db.add_all([tree["forward"], tree["reverse-s1"], tree["reverse-s2"], scope])
    await db.flush()
    reservation = DHCPStaticAssignment(
        scope_id=scope.id,
        ip_address="10.38.2.30",
        mac_address="02:00:00:38:00:30",
        hostname="resv30",
    )
    db.add(reservation)
    await db.flush()
    await _address(db, tree, "s1", 10, "host10")
    mirror = await _address(
        db,
        tree,
        "s2",
        30,
        "resv30",
        status="static_dhcp",
        static_assignment_id=str(reservation.id),
    )
    tree["mirror-id"] = mirror.id
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


async def _mirror_records(db: AsyncSession) -> set[tuple[str, str]]:
    """The mirror's records, trashed or not, as (name, type). By name: a
    record its address left would have lost its ``ip_address_id``."""
    rows = (
        await db.execute(
            select(DNSRecord.name, DNSRecord.record_type)
            .where(DNSRecord.name.in_(["30", "resv30"]))
            .execution_options(include_deleted=True)
        )
    ).all()
    return {(name, rtype) for name, rtype in rows}


# Which delete: of s1 (the scope's subnet), of s2 (the mirror's), of B, of A.
KINDS = ["scope-subnet", "mirror-subnet", "block", "space"]

# What each delete trashes: the zones with the records still in them at the
# stamp, and the A records it retracts from the forward zone.
TRASHED = {
    "scope-subnet": {("10", "PTR"), ("host10", "A")},
    "mirror-subnet": {("30", "PTR"), ("resv30", "A")},
    "block": {("10", "PTR"), ("host10", "A")},
    "space": {("10", "PTR"), ("host10", "A")},
}
# Each trashed zone's audit row: the records stamped with it.
ZONES = {
    "scope-subnet": {"reverse-s1": {"dns_record": 1}},
    "mirror-subnet": {"reverse-s2": {"dns_record": 1}},
    "block": {"reverse-s1": {"dns_record": 1}, "reverse-s2": None},
    "space": {"reverse-s1": {"dns_record": 1}, "reverse-s2": None},
}
PREVIEWED = {
    "scope-subnet": "; cascades 1 DHCP scope, 1 DHCP reservation, 1 DNS zone, 2 DNS records; ",
    "mirror-subnet": "; cascades 1 DNS zone, 2 DNS records; ",
    "block": (
        " cascades 2 subnets, 1 DHCP scope, 1 DHCP reservation, 2 DNS zones, 2 DNS records; "
    ),
    "space": (
        " cascades 1 child block, 2 subnets, 1 DHCP scope, 1 DHCP reservation, 2 DNS zones, "
        "2 DNS records; "
    ),
}


def _root(tree: dict[str, Any], kind: str) -> Any:
    return {
        "scope-subnet": tree["s1"],
        "mirror-subnet": tree["s2"],
        "block": tree["block"],
        "space": tree["space"],
    }[kind]


async def _preview(db: AsyncSession, user: User, tree: dict[str, Any], kind: str) -> str:
    root = _root(tree, kind)
    if isinstance(root, Subnet):
        preview = await _preview_delete_subnet(db, user, DeleteSubnetArgs(subnet_id=root.id))
    elif kind == "block":
        preview = await _preview_delete_block(db, user, DeleteBlockArgs(block_id=root.id))
    else:
        preview = await _preview_delete_space(db, user, DeleteSpaceArgs(space_id=root.id))
    assert preview.ok, preview.detail
    return preview.preview_text


def _path(tree: dict[str, Any], kind: str) -> str:
    root = _root(tree, kind)
    collection = {Subnet: "subnets", IPBlock: "blocks", IPSpace: "spaces"}[type(root)]
    return f"/api/v1/ipam/{collection}/{root.id}"


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
async def test_delete_preview_leaves_out_a_reservation_mirror_in_another_subnet(
    client: AsyncClient, db_session: AsyncSession, kind: str
) -> None:
    """The records of a reservation's mirror outside its scope's subnet are
    counted as the delete treats them: left out when the delete takes the
    scope and so removes the mirror first, counted when the scope stays."""
    user, headers = await _superadmin(db_session, "rm3511")
    tree = await _tree(db_session)

    preview = await _preview(db_session, user, tree, kind)
    assert not (db_session.new or db_session.dirty or db_session.deleted)

    resp = await client.delete(_path(tree, kind), headers=headers)
    assert resp.status_code == 204, resp.text

    trashed = await _batch_records(db_session, _root(tree, kind))
    assert trashed == TRASHED[kind]
    assert await _zone_soft_deletes(db_session) == {
        str(tree[zone].id): cascaded for zone, cascaded in ZONES[kind].items()
    }
    # The delete keeps the mirror only while the reservation's scope stays.
    mirror = (
        await db_session.execute(select(IPAddress.id).where(IPAddress.id == tree["mirror-id"]))
    ).scalar_one_or_none()
    if kind == "mirror-subnet":
        assert mirror is not None
        assert await _mirror_records(db_session) == {("30", "PTR"), ("resv30", "A")}
    else:
        assert mirror is None
        assert await _mirror_records(db_session) == set()

    assert _previewed_records(preview) == len(trashed), (
        f"the preview names {_previewed_records(preview)} DNS records, the delete "
        f"trashed {len(trashed)}: {preview}"
    )
    assert PREVIEWED[kind] in preview, preview
