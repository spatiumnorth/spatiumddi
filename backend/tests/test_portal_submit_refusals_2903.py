"""The request portal refuses at submit what the REST create refuses (#2903-#2905)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.change_request import ChangeRequest
from app.models.dhcp import DHCPScope, DHCPStaticAssignment
from app.models.ipam import IPAddress, Subnet
from tests.test_portal_dhcp_static_ipam_mirror_2901 import _estate
from tests.test_self_service_requests import (
    MODULE,
    REQUESTER_PERMS,
    _auth,
    _enable_module,
    _user,
)


async def _requester(db: AsyncSession) -> str:
    await _enable_module(db, MODULE)
    _, token = await _user(db, name="req", permissions=REQUESTER_PERMS)
    return token


async def _submit(client: AsyncClient, token: str, kind: str, args: dict):
    return await client.post(
        "/api/v1/requests",
        headers=_auth(token),
        json={"kind": kind, "args": args, "justification": "please"},
    )


async def _no_rows(db: AsyncSession) -> None:
    assert await db.scalar(select(func.count()).select_from(ChangeRequest)) == 0


@pytest.mark.asyncio
async def test_held_address_refused(client: AsyncClient, db_session: AsyncSession) -> None:
    tok = await _requester(db_session)
    _, subnet, _ = await _estate(db_session)
    db_session.add(IPAddress(subnet_id=subnet.id, address="10.60.0.50", status="allocated"))
    await db_session.flush()
    ok = await _submit(
        client, tok, "ip_address", {"subnet_id": str(subnet.id), "address": "10.60.0.51"}
    )
    assert ok.status_code == 201, ok.text
    resp = await _submit(
        client, tok, "ip_address", {"subnet_id": str(subnet.id), "address": "10.60.0.50"}
    )
    assert resp.status_code == 409, resp.text
    assert await db_session.scalar(select(func.count()).select_from(ChangeRequest)) == 1


@pytest.mark.asyncio
async def test_static_dhcp_without_mac_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tok = await _requester(db_session)
    _, subnet, _ = await _estate(db_session)
    resp = await _submit(
        client,
        tok,
        "ip_address",
        {"subnet_id": str(subnet.id), "address": "10.60.0.60", "status": "static_dhcp"},
    )
    assert resp.status_code == 422, resp.text
    await _no_rows(db_session)


@pytest.mark.asyncio
async def test_multicast_subnet_refused(client: AsyncClient, db_session: AsyncSession) -> None:
    tok = await _requester(db_session)
    _, subnet, _ = await _estate(db_session)
    mc = Subnet(
        space_id=subnet.space_id, block_id=subnet.block_id, network="239.1.1.0/24", kind="multicast"
    )
    db_session.add(mc)
    await db_session.flush()
    resp = await _submit(
        client, tok, "ip_address", {"subnet_id": str(mc.id), "address": "239.1.1.20"}
    )
    assert resp.status_code == 422, resp.text
    assert "multicast subnet" in resp.text
    await _no_rows(db_session)


async def _two_statics(db: AsyncSession) -> DHCPScope:
    scope, _, _ = await _estate(db)
    db.add_all(
        [
            DHCPStaticAssignment(
                scope_id=scope.id, ip_address="10.60.0.40", mac_address="02:00:5e:00:00:01"
            ),
            DHCPStaticAssignment(
                scope_id=scope.id, ip_address="10.60.0.41", mac_address="02:00:5e:00:00:02"
            ),
        ]
    )
    await db.flush()
    return scope


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "ip,mac",
    [
        ("10.60.0.40", "02:00:5e:00:00:99"),  # IP collision
        ("10.60.0.99", "02:00:5e:00:00:02"),  # MAC collision
        ("10.60.0.40", "02:00:5e:00:00:02"),  # IP matches one, MAC another
    ],
)
async def test_reservation_collisions_refused(
    client: AsyncClient, db_session: AsyncSession, ip: str, mac: str
) -> None:
    tok = await _requester(db_session)
    scope = await _two_statics(db_session)
    resp = await _submit(
        client,
        tok,
        "dhcp_reservation",
        {"scope_id": str(scope.id), "ip_address": ip, "mac_address": mac},
    )
    assert resp.status_code == 409, resp.text
    await _no_rows(db_session)


@pytest.mark.asyncio
async def test_clean_reservation_accepted(client: AsyncClient, db_session: AsyncSession) -> None:
    tok = await _requester(db_session)
    scope = await _two_statics(db_session)
    resp = await _submit(
        client,
        tok,
        "dhcp_reservation",
        {"scope_id": str(scope.id), "ip_address": "10.60.0.98", "mac_address": "02:00:5e:00:00:98"},
    )
    assert resp.status_code == 201, resp.text


@pytest.mark.asyncio
async def test_copilot_preview_does_not_raise_on_two_row_conflict(
    db_session: AsyncSession,
) -> None:
    from app.core.security import hash_password
    from app.models.auth import User
    from app.services.ai import operations

    scope = await _two_statics(db_session)
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
    args = op.args_model(
        scope_id=str(scope.id), ip_address="10.60.0.40", mac_address="02:00:5e:00:00:02"
    )
    preview = await op.preview(db_session, user, args)
    assert preview.ok and "already exists" in preview.preview_text
