"""#2900 — the ``create_ip_address`` operation syncs DNS like the REST create.

The apply path is shared by the request portal's approve (#696) and the
copilot's propose/apply. It used to insert the row and publish nothing, so an
approved request with a hostname made an address with no A record.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.change_request import ChangeRequest
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.models.feature_module import FeatureModule
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services import feature_modules
from app.services.ai.operations import CreateIPAddressArgs, get_operation


async def _user(db: AsyncSession, name: str, superadmin: bool = True) -> User:
    user = User(
        username=f"{name}-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name=name,
        hashed_password=hash_password("password123"),
        is_superadmin=superadmin,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return user


async def _subnet_with_zone(db: AsyncSession, client: AsyncClient, admin: User):
    hdr = {"Authorization": f"Bearer {create_access_token(str(admin.id))}"}
    grp = DNSServerGroup(name=f"g2900-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host="10.9.9.9",
            name=f"ns-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    zone = DNSZone(
        group_id=grp.id,
        name=f"z2900-{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    space = IPSpace(name=f"sp2900-{uuid.uuid4().hex[:8]}", description="")
    db.add_all([zone, space])
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.98.0.0/16", name="b")
    db.add(block)
    await db.flush()
    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=hdr,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": "10.98.5.0/24",
            "dns_group_id": str(grp.id),
            "dns_zone_id": str(zone.id),
            "skip_reverse_zone": True,
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"], zone, hdr


async def _a_records(db: AsyncSession, zone_id: uuid.UUID) -> list[DNSRecord]:
    return list(
        (
            await db.execute(
                select(DNSRecord).where(DNSRecord.zone_id == zone_id, DNSRecord.record_type == "A")
            )
        )
        .scalars()
        .all()
    )


@pytest.mark.asyncio
async def test_apply_with_hostname_creates_a_record(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin = await _user(db_session, "admin")
    sid, zone, _ = await _subnet_with_zone(db_session, client, admin)
    zone_id = zone.id
    op = get_operation("create_ip_address")
    assert op is not None
    args = CreateIPAddressArgs(subnet_id=sid, address="10.98.5.10", hostname="web01")

    preview = await op.preview(db_session, admin, args)
    assert preview.ok and f"A web01.{zone.name.rstrip('.')}" in preview.preview_text

    await op.apply(db_session, admin, args)
    recs = await _a_records(db_session, zone_id)
    assert [(r.name, r.value) for r in recs] == [("web01", "10.98.5.10")]
    ip = (
        await db_session.execute(
            select(IPAddress).where(
                IPAddress.subnet_id == uuid.UUID(sid), IPAddress.address == "10.98.5.10"
            )
        )
    ).scalar_one()
    assert ip.forward_zone_id == zone_id


@pytest.mark.asyncio
async def test_apply_without_hostname_creates_no_record(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin = await _user(db_session, "admin")
    sid, zone, _ = await _subnet_with_zone(db_session, client, admin)
    zone_id = zone.id
    op = get_operation("create_ip_address")
    assert op is not None
    subnet = await db_session.get(Subnet, uuid.UUID(sid))
    assert subnet is not None
    before = subnet.allocated_ips
    await op.apply(db_session, admin, CreateIPAddressArgs(subnet_id=sid, address="10.98.5.11"))
    assert await _a_records(db_session, zone_id) == []
    # The no-hostname insert still runs REST's utilisation update.
    await db_session.refresh(subnet)
    assert subnet.allocated_ips == before + 1


@pytest.mark.asyncio
async def test_approved_portal_request_creates_a_record(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin = await _user(db_session, "admin")
    sid, zone, _ = await _subnet_with_zone(db_session, client, admin)
    zone_id = zone.id
    zone_name = zone.name.rstrip(".")
    db_session.add(FeatureModule(id="governance.requests", enabled=True))
    await db_session.flush()
    feature_modules.invalidate_cache()

    from app.models.auth import Group, Role

    requester = await _user(db_session, "req", superadmin=False)
    role = Role(
        name=f"r-{uuid.uuid4().hex[:6]}",
        permissions=[
            {"action": "write", "resource_type": "provisioning_request"},
            {"action": "read", "resource_type": "provisioning_request"},
            # Submit refuses a subnet the requester cannot read.
            {"action": "read", "resource_type": "subnet"},
        ],
    )
    grp = Group(name=f"g-{uuid.uuid4().hex[:6]}")
    grp.roles = [role]
    db_session.add_all([role, grp])
    requester.groups = [grp]
    await db_session.flush()
    req_hdr = {"Authorization": f"Bearer {create_access_token(str(requester.id))}"}
    approver = await _user(db_session, "appr")
    appr_hdr = {"Authorization": f"Bearer {create_access_token(str(approver.id))}"}

    resp = await client.post(
        "/api/v1/requests",
        headers=req_hdr,
        json={
            "kind": "ip_address",
            "args": {"subnet_id": sid, "address": "10.98.5.20", "hostname": "app01"},
            "justification": "Need a host for the app tier.",
        },
    )
    assert resp.status_code == 201, resp.text
    rid = resp.json()["id"]
    # A second request for the same name, queued while the first is still
    # pending: nothing clashes yet, so submit accepts it.
    resp = await client.post(
        "/api/v1/requests",
        headers=req_hdr,
        json={
            "kind": "ip_address",
            "args": {"subnet_id": sid, "address": "10.98.5.21", "hostname": "app01"},
            "justification": "Second host with a clashing name.",
        },
    )
    assert resp.status_code == 201, resp.text
    rid2 = resp.json()["id"]
    resp = await client.post(
        f"/api/v1/requests/{rid}/approve", headers=appr_hdr, json={"decision_note": "ok"}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "executed"
    recs = await _a_records(db_session, zone_id)
    assert [(r.name, r.value) for r in recs] == [("app01", "10.98.5.20")]
    # The record op that carries it to the agent is queued, not just the row.
    ops = (
        (await db_session.execute(select(DNSRecordOp).where(DNSRecordOp.zone_id == zone_id)))
        .scalars()
        .all()
    )
    assert any(o.op == "create" and (o.record or {}).get("name") == "app01" for o in ops), [
        (o.op, o.record) for o in ops
    ]

    # Now the name is taken, a new request for it is refused at submit
    # (#3243), in words that do not name the address holding it.
    resp = await client.post(
        "/api/v1/requests",
        headers=req_hdr,
        json={
            "kind": "ip_address",
            "args": {"subnet_id": sid, "address": "10.98.5.22", "hostname": "app01"},
            "justification": "Third host with a clashing name.",
        },
    )
    assert resp.status_code == 409, resp.text
    assert "10.98.5.20" not in resp.text

    # The second request, queued before the first was approved, collides
    # with it (the REST FQDN check). The approve refuses, and the transaction
    # boundary holds: no address row, no record. The request ends failed
    # with the clash spelled out for the requester (#2911).
    resp = await client.post(
        f"/api/v1/requests/{rid2}/approve", headers=appr_hdr, json={"decision_note": "ok"}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "failed"
    assert resp.json()["error"] == (
        f"The name app01.{zone_name} is already used by 10.98.5.20 in 10.98.5.0/24."
    )
    cr = await db_session.get(ChangeRequest, uuid.UUID(rid2))
    assert cr is not None
    await db_session.refresh(cr)
    assert cr.state == "failed"
    clash = (
        await db_session.execute(
            select(IPAddress).where(
                IPAddress.subnet_id == uuid.UUID(sid), IPAddress.address == "10.98.5.21"
            )
        )
    ).scalar_one_or_none()
    assert clash is None
    recs = await _a_records(db_session, zone_id)
    assert [(r.name, r.value) for r in recs] == [("app01", "10.98.5.20")]
