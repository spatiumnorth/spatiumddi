"""An operation-applied DHCP reservation mirrors into IPAM like REST (#2901).

The request portal's approve (#696) and the copilot's propose/apply both run
``_apply_create_dhcp_static``. It used to insert the reservation and commit,
skipping the IPAM ``static_dhcp`` mirror, the Windows write-through and the
subnet recount the REST ``create_static`` handler runs.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup, DHCPStaticAssignment
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from tests.test_self_service_requests import (
    MODULE,
    REQUESTER_PERMS,
    _auth,
    _enable_module,
    _user,
)

IP = "10.60.0.50"
MAC = "aa:bb:cc:dd:ee:29"


async def _estate(db: AsyncSession) -> tuple[DHCPScope, Subnet, IPBlock]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add_all([space, group])
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="root")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.60.0.0/24", name="lan")
    db.add(subnet)
    db.add(
        DHCPServer(
            name=f"s-{uuid.uuid4().hex[:6]}",
            driver="kea",
            host="127.0.0.1",
            server_group_id=group.id,
        )
    )
    await db.flush()
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, name="sc", address_family="ipv4")
    db.add(scope)
    await db.flush()
    return scope, subnet, block


async def _assert_mirrored(db: AsyncSession, subnet: Subnet, block: IPBlock) -> None:
    row = await db.scalar(
        select(IPAddress).where(IPAddress.subnet_id == subnet.id, IPAddress.address == IP)
    )
    assert row is not None, "no IPAM row at the reserved IP"
    assert row.status == "static_dhcp"
    st = await db.scalar(select(DHCPStaticAssignment))
    assert st is not None and st.ip_address_id == row.id
    assert str(row.static_assignment_id) == str(st.id)
    await db.refresh(subnet)
    await db.refresh(block)
    assert subnet.allocated_ips >= 1
    assert block.allocated_ips >= 1


@pytest.mark.asyncio
async def test_approved_portal_reservation_mirrors_into_ipam(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session, MODULE)
    scope, subnet, block = await _estate(db_session)
    _, req_token = await _user(db_session, name="req", permissions=REQUESTER_PERMS)
    _, appr_token = await _user(
        db_session,
        name="appr",
        permissions=[
            {"action": "approve", "resource_type": "change_request"},
            {"action": "read", "resource_type": "change_request"},
            {"action": "write", "resource_type": "dhcp_static"},
            {"action": "read", "resource_type": "dhcp_static"},
        ],
    )
    resp = await client.post(
        "/api/v1/requests",
        headers=_auth(req_token),
        json={
            "kind": "dhcp_reservation",
            "args": {"scope_id": str(scope.id), "ip_address": IP, "mac_address": MAC},
            "justification": "Printer needs a fixed address.",
        },
    )
    assert resp.status_code == 201, resp.text
    resp = await client.post(
        f"/api/v1/requests/{resp.json()['id']}/approve",
        headers=_auth(appr_token),
        json={"decision_note": "ok"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "executed"
    await _assert_mirrored(db_session, subnet, block)


@pytest.mark.asyncio
async def test_copilot_apply_mirrors_into_ipam(db_session: AsyncSession) -> None:
    from app.core.security import hash_password
    from app.models.auth import User
    from app.services.ai import operations

    scope, subnet, block = await _estate(db_session)
    user = User(
        username=f"c-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db_session.add(user)
    await db_session.flush()
    op = operations.get_operation("create_dhcp_static")
    args = op.args_model(scope_id=str(scope.id), ip_address=IP, mac_address=MAC)
    preview = await op.preview(db_session, user, args)
    assert "IPAM" in (preview.preview_text or "")
    await op.apply(db_session, user, args)
    await _assert_mirrored(db_session, subnet, block)


@pytest.mark.asyncio
async def test_apply_refuses_a_mac_already_reserved_in_the_group(
    db_session: AsyncSession,
) -> None:
    from fastapi import HTTPException

    from app.core.security import hash_password
    from app.models.auth import User
    from app.services.ai import operations

    scope, subnet, _ = await _estate(db_session)
    user = User(
        username=f"c-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db_session.add(user)
    await db_session.flush()
    op = operations.get_operation("create_dhcp_static")
    await op.apply(
        db_session, user, op.args_model(scope_id=str(scope.id), ip_address=IP, mac_address=MAC)
    )
    with pytest.raises(HTTPException) as exc:
        await op.apply(
            db_session,
            user,
            op.args_model(scope_id=str(scope.id), ip_address="10.60.0.51", mac_address=MAC),
        )
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_apply_refuses_a_mac_reserved_in_another_scope_of_the_group(
    db_session: AsyncSession,
) -> None:
    """#2902 — the group-wide MAC check, across two scopes."""
    from fastapi import HTTPException

    from app.core.security import hash_password
    from app.models.auth import User
    from app.services.ai import operations

    scope, subnet, _ = await _estate(db_session)
    subnet2 = Subnet(space_id=subnet.space_id, block_id=subnet.block_id, network="10.61.0.0/24")
    db_session.add(subnet2)
    await db_session.flush()
    scope2 = DHCPScope(
        group_id=scope.group_id, subnet_id=subnet2.id, name="sc2", address_family="ipv4"
    )
    db_session.add(scope2)
    user = User(
        username=f"c-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db_session.add(user)
    await db_session.flush()
    op = operations.get_operation("create_dhcp_static")
    await op.apply(
        db_session, user, op.args_model(scope_id=str(scope.id), ip_address=IP, mac_address=MAC)
    )
    with pytest.raises(HTTPException) as exc:
        await op.apply(
            db_session,
            user,
            op.args_model(scope_id=str(scope2.id), ip_address="10.61.0.9", mac_address=MAC),
        )
    assert exc.value.status_code == 409
    await db_session.rollback()
    n = len((await db_session.execute(select(DHCPStaticAssignment))).scalars().all())
    assert n == 1


@pytest.mark.asyncio
async def test_portal_reservation_whose_mac_was_reserved_meanwhile_ends_failed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#2911 — the MAC is reserved elsewhere in the group between submit and
    approve. apply()'s conflict check raises a 409; the request ends
    ``failed`` with that reason for the requester to read, not pending."""
    await _enable_module(db_session, MODULE)
    scope, _, _ = await _estate(db_session)
    _, req_token = await _user(db_session, name="req", permissions=REQUESTER_PERMS)
    appr, appr_token = await _user(
        db_session,
        name="appr",
        permissions=[
            {"action": "approve", "resource_type": "change_request"},
            {"action": "read", "resource_type": "change_request"},
            {"action": "write", "resource_type": "dhcp_static"},
            {"action": "read", "resource_type": "dhcp_static"},
        ],
    )
    appr_id = appr.id
    resp = await client.post(
        "/api/v1/requests",
        headers=_auth(req_token),
        json={
            "kind": "dhcp_reservation",
            "args": {"scope_id": str(scope.id), "ip_address": IP, "mac_address": MAC},
            "justification": "Printer needs a fixed address.",
        },
    )
    assert resp.status_code == 201, resp.text
    req_id = resp.json()["id"]

    # Someone reserves the same MAC at another address in the meantime.
    db_session.add(
        DHCPStaticAssignment(scope_id=scope.id, ip_address="10.60.0.77", mac_address=MAC)
    )
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/requests/{req_id}/approve",
        headers=_auth(appr_token),
        json={"decision_note": "ok"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["state"] == "failed"
    assert f"MAC {MAC} already reserved in this group" in body["error"]
    assert body["decided_by_user_id"] == str(appr_id)

    # The requester reads the same reason.
    row = (await client.get(f"/api/v1/requests/{req_id}", headers=_auth(req_token))).json()
    assert row["state"] == "failed"
    assert "already reserved" in row["error"]
    # Nothing was reserved at the requested address.
    db_session.expire_all()
    n = len((await db_session.execute(select(DHCPStaticAssignment))).scalars().all())
    assert n == 1
