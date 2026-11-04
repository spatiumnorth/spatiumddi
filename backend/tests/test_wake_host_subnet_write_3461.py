"""#3461: the copilot ``wake_host`` operation needs what
``POST /ipam/addresses/{id}/wake`` needs: read on ``use_network_tools`` AND
type-level write on ``subnet``."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.auth import Group, Role, User
from app.models.ipam import IPAddress, IPSpace, Subnet
from app.services import wol
from app.services.ai.operations import (
    OperationPermissionError,
    WakeHostArgs,
    get_operation,
    previewing_for_requester,
)


async def _user(db: AsyncSession, permissions: list[dict], superadmin: bool = False) -> User:
    user = User(
        username=f"wk-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@t.io",
        display_name="wk",
        hashed_password=hash_password("password123"),
        is_superadmin=superadmin,
    )
    role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
    group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
    group.roles = [role]
    user.groups = [group]
    db.add_all([role, group, user])
    await db.flush()
    return user


def _g(action: str, rtype: str) -> dict:
    return {"action": action, "resource_type": rtype}


async def _addr(db: AsyncSession) -> IPAddress:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    from app.models.ipam import IPBlock

    block = IPBlock(space_id=space.id, network="10.7.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.7.1.0/24", name="s")
    db.add(subnet)
    await db.flush()
    ip = IPAddress(
        subnet_id=subnet.id, address="10.7.1.5", status="allocated", mac_address="aa:bb:cc:dd:ee:ff"
    )
    db.add(ip)
    await db.flush()
    return ip


@pytest.mark.asyncio
async def test_wake_host_needs_subnet_write_at_preview_and_apply(db_session: AsyncSession) -> None:
    ip = await _addr(db_session)
    op = get_operation("wake_host")
    assert op is not None
    args = WakeHostArgs(address_id=str(ip.id))

    tools_only = await _user(db_session, [_g("read", "use_network_tools")])
    pv = await op.preview(db_session, tools_only, args)
    assert not pv.ok and pv.forbidden_detail is not None
    assert "subnet" in pv.detail
    with patch.object(wol, "wake_from_server", new=AsyncMock()) as send:
        with pytest.raises(OperationPermissionError):
            await op.apply(db_session, tools_only, args)
        send.assert_not_awaited()

    # A portal requester is not judged on it; the approver is.
    with previewing_for_requester():
        assert (await op.preview(db_session, tools_only, args)).ok


@pytest.mark.asyncio
async def test_wake_host_works_with_both_and_for_superadmin(db_session: AsyncSession) -> None:
    ip = await _addr(db_session)
    op = get_operation("wake_host")
    assert op is not None
    args = WakeHostArgs(address_id=str(ip.id))
    both = await _user(db_session, [_g("read", "use_network_tools"), _g("write", "subnet")])
    admin = await _user(db_session, [], superadmin=True)
    for u in (both, admin):
        assert (await op.preview(db_session, u, args)).ok
        with patch.object(
            wol,
            "wake_from_server",
            new=AsyncMock(
                return_value=wol.WolResult(mac="aa", broadcast="10.7.1.255", port=9, sent=True)
            ),
        ) as send:
            out = await op.apply(db_session, u, args)
            send.assert_awaited_once()
        assert out["sent"] is True
