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


async def _tagged_subnet(db: AsyncSession) -> Subnet:
    from app.models.ipam import IPBlock

    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.8.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id, block_id=block.id, network="10.8.1.0/24", name="s", kind="unicast"
    )
    db.add(subnet)
    await db.flush()
    db.add(
        IPAddress(
            subnet_id=subnet.id,
            address="10.8.1.5",
            status="allocated",
            mac_address="aa:bb:cc:dd:ee:01",
            tags={"wake": "nightly"},
        )
    )
    await db.flush()
    return subnet


@pytest.mark.asyncio
async def test_schedule_owner_without_subnet_write_wakes_nothing(db_session: AsyncSession) -> None:
    """A wake schedule fires as its owner, through ``resolve_wol_targets``
    (REST preview, run-now, the beat runner and the copilot schedule ops all
    call it). An owner who can read the subnet but could not wake its hosts by
    hand must not wake them on a schedule either."""
    from app.services.wol_scheduler import resolve_wol_targets

    subnet = await _tagged_subnet(db_session)
    tag_sel = {"mode": "address_tags", "tags": ["wake:nightly"]}
    subnet_sel = {"mode": "subnet", "subnet_ids": [str(subnet.id)]}

    read_only = await _user(db_session, [_g("write", "use_network_tools"), _g("read", "subnet")])
    assert (await resolve_wol_targets(db_session, read_only, tag_sel)).wakes == []
    by_subnet = await resolve_wol_targets(db_session, read_only, subnet_sel)
    assert by_subnet.wakes == []
    assert [s.reason for s in by_subnet.skipped] == ["no_permission"]

    writer = await _user(
        db_session,
        [_g("write", "use_network_tools"), _g("read", "subnet"), _g("write", "subnet")],
    )
    assert len((await resolve_wol_targets(db_session, writer, tag_sel)).wakes) == 1
    assert len((await resolve_wol_targets(db_session, writer, subnet_sel)).wakes) == 1


@pytest.mark.asyncio
async def test_scheduled_fire_rechecks_owner_subnet_write(db_session: AsyncSession) -> None:
    """The beat runner loads the owner fresh on every fire, so a schedule
    created while the owner could wake stops waking once they cannot."""
    import app.tasks.wol_scheduler as task
    from app.models.wol_schedule import WolSchedule

    await _tagged_subnet(db_session)
    owner = await _user(db_session, [_g("write", "use_network_tools"), _g("read", "subnet")])
    schedule = WolSchedule(
        name="nightly",
        enabled=True,
        target_selector={"mode": "address_tags", "tags": ["wake:nightly"]},
        schedule_cron="0 7 * * *",
        timezone="UTC",
        vantage={"kind": "server", "id": None},
        repeat_count=1,
        repeat_interval_ms=0,
        stagger_ms=0,
        port=9,
        created_by_user_id=owner.id,
    )
    db_session.add(schedule)
    await db_session.flush()
    db_session.expunge(owner)

    with patch("app.services.wol.wake_from_server", new=AsyncMock()) as send:
        summary = await task.run_wol_schedule(
            db_session,
            schedule,
            trigger="scheduled",
            actor_id=None,
            actor_display="scheduler",
            apply_gate=False,
        )
    send.assert_not_awaited()
    assert summary.get("sent", 0) == 0
