"""spatiumddi#1150 — a new subnet is in sync with DNS the moment it exists.

create_subnet adds the network / broadcast / gateway placeholder rows with
plain ``db.add()`` and never ran the DNS sync for the gateway, so under a
reverse zone the gateway's PTR was missing from the start: the drift check
(which expects it — the gateway is a named, reserved row) reported "1 DNS record
out of sync · 1 missing" on every new subnet, and Sync DNS offered exactly that
PTR. Re-driven on nightly-20260923: the reverse zone answered SOA, ``dig -x`` of
the gateway answered NXDOMAIN. The planner's apply path built the same
placeholder with the same gap, and never ran the reverse-zone step at all.

The gateway row's sync now runs at create (PTR only — ``_sync_dns_record``
skips the forward ``gateway.<zone>`` A on purpose), without the reverse-zone
catch-up inside it, so ``skip_reverse_zone`` keeps meaning what it says.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace


async def _admin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u1150-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _dns(db: AsyncSession) -> tuple[DNSServerGroup, DNSServer, DNSZone]:
    """A group served by one agent-based (BIND9) primary, with a forward zone."""
    grp = DNSServerGroup(name=f"g1150-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver="bind9",
        host="10.9.9.9",
        name=f"ns-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
    )
    zone = DNSZone(
        group_id=grp.id,
        name=f"gw-{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add_all([server, zone])
    await db.flush()
    return grp, server, zone


async def _space_block(db: AsyncSession, network: str, **dns: object) -> tuple[IPSpace, IPBlock]:
    space = IPSpace(name=f"sp1150-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=network, name="b", **dns)
    db.add(block)
    await db.flush()
    return space, block


async def _create_subnet(
    client: AsyncClient,
    headers: dict[str, str],
    space: IPSpace,
    block: IPBlock,
    network: str,
    **extra: object,
) -> str:
    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={"space_id": str(space.id), "block_id": str(block.id), "network": network, **extra},
    )
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


async def _drift(client: AsyncClient, headers: dict[str, str], sid: str) -> dict[str, int]:
    resp = await client.get(f"/api/v1/ipam/subnets/{sid}/dns-sync/summary", headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    return {k: body[k] for k in ("missing", "mismatched", "stale")}


async def _gateway_records(db: AsyncSession, sid: str) -> list[tuple[str, str, str, str]]:
    """(zone name, record type, name, value) of every record bound to the
    subnet's gateway row."""
    gw = (
        await db.execute(
            select(IPAddress).where(
                IPAddress.subnet_id == uuid.UUID(sid), IPAddress.hostname == "gateway"
            )
        )
    ).scalar_one()
    rows = (
        await db.execute(
            select(DNSZone.name, DNSRecord.record_type, DNSRecord.name, DNSRecord.value)
            .join(DNSZone, DNSZone.id == DNSRecord.zone_id)
            .where(DNSRecord.ip_address_id == gw.id, DNSRecord.auto_generated.is_(True))
        )
    ).all()
    return sorted(tuple(r) for r in rows)


async def _zone_names(db: AsyncSession, grp: DNSServerGroup) -> set[str]:
    rows = await db.execute(select(DNSZone.name).where(DNSZone.group_id == grp.id))
    return set(rows.scalars().all())


@pytest.mark.asyncio
async def test_a_bound_subnet_publishes_its_gateway_ptr_at_create(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The reproduced case: an explicit binding, so the reverse zone is
    auto-created; the gateway's PTR must be in it, queued for the agent."""
    headers = await _admin_headers(db_session)
    grp, server, zone = await _dns(db_session)
    space, block = await _space_block(db_session, "10.86.0.0/16")
    await db_session.commit()

    sid = await _create_subnet(
        client,
        headers,
        space,
        block,
        "10.86.23.0/24",
        dns_group_id=str(grp.id),
        dns_zone_id=str(zone.id),
    )

    assert await _gateway_records(db_session, sid) == [
        ("23.86.10.in-addr.arpa.", "PTR", "1", f"gateway.{zone.name}")
    ]
    assert await _drift(client, headers, sid) == {"missing": 0, "mismatched": 0, "stale": 0}
    ops = (
        await db_session.execute(
            select(DNSRecordOp.op, DNSRecordOp.record["name"].astext).where(
                DNSRecordOp.server_id == server.id,
                DNSRecordOp.zone_name == "23.86.10.in-addr.arpa.",
            )
        )
    ).all()
    assert [tuple(o) for o in ops] == [("create", "1")]


@pytest.mark.asyncio
async def test_an_inheriting_subnet_publishes_its_gateway_ptr_at_create(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    grp, _, zone = await _dns(db_session)
    space, block = await _space_block(
        db_session,
        "10.87.0.0/16",
        dns_group_ids=[str(grp.id)],
        dns_zone_id=str(zone.id),
        dns_inherit_settings=False,
    )
    await db_session.commit()

    sid = await _create_subnet(client, headers, space, block, "10.87.24.0/24")

    assert await _gateway_records(db_session, sid) == [
        ("24.87.10.in-addr.arpa.", "PTR", "1", f"gateway.{zone.name}")
    ]
    assert await _drift(client, headers, sid) == {"missing": 0, "mismatched": 0, "stale": 0}


@pytest.mark.asyncio
async def test_skip_reverse_zone_still_opts_out_and_the_ptr_lands_in_a_covering_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The operator opted out because a hand-made /16 reverse zone already
    covers the subnet. The drift check finds that zone and expects the
    gateway's PTR in it; the gateway's sync must publish there and must not
    create the /24 zone the operator declined."""
    headers = await _admin_headers(db_session)
    grp, _, zone = await _dns(db_session)
    db_session.add(
        DNSZone(
            group_id=grp.id,
            name="88.10.in-addr.arpa.",
            zone_type="primary",
            kind="reverse",
            primary_ns="ns1.example.",
            admin_email="admin.example.",
        )
    )
    space, block = await _space_block(db_session, "10.88.0.0/16")
    await db_session.commit()

    sid = await _create_subnet(
        client,
        headers,
        space,
        block,
        "10.88.25.0/24",
        dns_group_id=str(grp.id),
        dns_zone_id=str(zone.id),
        skip_reverse_zone=True,
    )

    assert "25.88.10.in-addr.arpa." not in await _zone_names(db_session, grp)
    assert await _gateway_records(db_session, sid) == [
        ("88.10.in-addr.arpa.", "PTR", "1.25", f"gateway.{zone.name}")
    ]
    assert await _drift(client, headers, sid) == {"missing": 0, "mismatched": 0, "stale": 0}


@pytest.mark.asyncio
async def test_skip_reverse_zone_with_nothing_covering_creates_no_zone_and_no_ptr(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    grp, _, zone = await _dns(db_session)
    space, block = await _space_block(db_session, "10.89.0.0/16")
    await db_session.commit()

    sid = await _create_subnet(
        client,
        headers,
        space,
        block,
        "10.89.26.0/24",
        dns_group_id=str(grp.id),
        dns_zone_id=str(zone.id),
        skip_reverse_zone=True,
    )

    assert await _zone_names(db_session, grp) == {zone.name}
    assert await _gateway_records(db_session, sid) == []
    assert await _drift(client, headers, sid) == {"missing": 0, "mismatched": 0, "stale": 0}


@pytest.mark.asyncio
async def test_a_group_only_binding_has_no_name_to_point_a_ptr_at(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """No forward zone, no FQDN: the reverse zone is still created (as
    before) and the gateway gets no PTR, which is also what drift expects."""
    headers = await _admin_headers(db_session)
    grp, _, zone = await _dns(db_session)
    space, block = await _space_block(db_session, "10.90.0.0/16")
    await db_session.commit()

    sid = await _create_subnet(
        client, headers, space, block, "10.90.27.0/24", dns_group_id=str(grp.id)
    )

    assert await _zone_names(db_session, grp) == {zone.name, "27.90.10.in-addr.arpa."}
    assert await _gateway_records(db_session, sid) == []
    assert await _drift(client, headers, sid) == {"missing": 0, "mismatched": 0, "stale": 0}


@pytest.mark.asyncio
async def test_plan_apply_gives_planned_subnets_their_reverse_zone_and_gateway_ptr(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The planner builds the same gateway placeholder and ran neither DNS
    step: its subnets had no reverse zone until their first allocation, and
    from then on the gateway's PTR was missing."""
    headers = await _admin_headers(db_session)
    grp, _, zone = await _dns(db_session)
    space = IPSpace(name=f"sp1150-{uuid.uuid4().hex[:8]}", description="")
    db_session.add(space)
    await db_session.commit()

    tree = {
        "id": "root",
        "network": "10.91.0.0/16",
        "kind": "block",
        "dns_group_id": str(grp.id),
        "dns_zone_id": str(zone.id),
        "children": [
            {"id": "inherits", "network": "10.91.1.0/24", "kind": "subnet"},
            {
                "id": "bound",
                "network": "10.91.2.0/24",
                "kind": "subnet",
                "dns_group_id": str(grp.id),
                "dns_zone_id": str(zone.id),
            },
        ],
    }
    resp = await client.post(
        "/api/v1/ipam/plans",
        headers=headers,
        json={"name": f"p-{uuid.uuid4().hex[:6]}", "space_id": str(space.id), "tree": tree},
    )
    assert resp.status_code == 201, resp.text
    applied = await client.post(f"/api/v1/ipam/plans/{resp.json()['id']}/apply", headers=headers)
    assert applied.status_code == 200, applied.text
    subnet_ids = applied.json()["subnet_ids"]
    assert len(subnet_ids) == 2

    for sid in subnet_ids:
        network = (await client.get(f"/api/v1/ipam/subnets/{sid}", headers=headers)).json()[
            "network"
        ]
        third = network.split(".")[2]
        assert await _gateway_records(db_session, sid) == [
            (f"{third}.91.10.in-addr.arpa.", "PTR", "1", f"gateway.{zone.name}")
        ], network
        assert await _drift(client, headers, sid) == {
            "missing": 0,
            "mismatched": 0,
            "stale": 0,
        }, network
