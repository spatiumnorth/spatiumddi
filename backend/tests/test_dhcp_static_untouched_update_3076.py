"""An update that changes nothing leaves a static's IPAM mirror alone (#3076)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp.statics import _same_value
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet


@pytest.mark.asyncio
async def test_same_values_do_not_revert_an_ipam_hostname_edit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add_all([user, space, group])
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="root")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.60.0.0/24", name="lan")
    db_session.add(subnet)
    db_session.add(
        DHCPServer(
            name=f"s-{uuid.uuid4().hex[:6]}",
            driver="kea",
            host="127.0.0.1",
            server_group_id=group.id,
        )
    )
    await db_session.flush()
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, name="sc", address_family="ipv4")
    db_session.add(scope)
    await db_session.flush()
    await db_session.refresh(user, ["groups"])
    scope_id, subnet_id = scope.id, subnet.id
    token = create_access_token(str(user.id))
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.post(
        f"/api/v1/dhcp/scopes/{scope_id}/statics",
        headers=headers,
        json={
            "ip_address": "10.60.0.20",
            "mac_address": "02:98:14:00:00:20",
            "hostname": "xp-st-a",
        },
    )
    assert resp.status_code == 201, resp.text
    static_id = resp.json()["id"]

    # An inline IPAM edit renames the address behind the statics list's back.
    row = (
        await db_session.execute(
            select(IPAddress).where(
                IPAddress.subnet_id == subnet_id, IPAddress.address == "10.60.0.20"
            )
        )
    ).scalar_one()
    row.hostname = "xp-st-b"
    await db_session.commit()

    # The dialog opened on the stale row sends every field back unchanged.
    resp = await client.put(
        f"/api/v1/dhcp/statics/{static_id}",
        headers=headers,
        json={
            "mac_address": "02:98:14:00:00:20",
            "ip_address": "10.60.0.20",
            "hostname": "xp-st-a",
            "description": "",
            "client_id": None,
        },
    )
    assert resp.status_code == 200, resp.text

    db_session.expire_all()
    row = (
        await db_session.execute(
            select(IPAddress).where(
                IPAddress.subnet_id == subnet_id, IPAddress.address == "10.60.0.20"
            )
        )
    ).scalar_one()
    assert row.hostname == "xp-st-b"


async def _static_with_ipam(
    client: AsyncClient, db_session: AsyncSession
) -> tuple[dict[str, str], str, uuid.UUID]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add_all([user, space, group])
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="root")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.61.0.0/24", name="lan")
    db_session.add(subnet)
    await db_session.flush()
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, name="sc", address_family="ipv4")
    db_session.add(scope)
    await db_session.flush()
    await db_session.refresh(user, ["groups"])
    scope_id, subnet_id = scope.id, subnet.id
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    await db_session.commit()
    resp = await client.post(
        f"/api/v1/dhcp/scopes/{scope_id}/statics",
        headers=headers,
        json={
            "ip_address": "10.61.0.20",
            "mac_address": "02:98:14:00:00:21",
            "hostname": "st-a",
            "description": "kept",
        },
    )
    assert resp.status_code == 201, resp.text
    return headers, resp.json()["id"], subnet_id


async def _ipam_hostname(db_session: AsyncSession, subnet_id: uuid.UUID) -> str | None:
    db_session.expire_all()
    row = (
        await db_session.execute(
            select(IPAddress).where(
                IPAddress.subnet_id == subnet_id, IPAddress.address == "10.61.0.20"
            )
        )
    ).scalar_one()
    return row.hostname


async def _update_audits(db_session: AsyncSession, static_id: str) -> int:
    rows = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_type == "dhcp_static_assignment",
                AuditLog.resource_id == static_id,
                AuditLog.action == "update",
            )
        )
    ).scalars()
    return len(list(rows))


@pytest.mark.asyncio
async def test_other_spellings_of_the_stored_values_are_not_a_change(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, static_id, subnet_id = await _static_with_ipam(client, db_session)
    row = (
        await db_session.execute(
            select(IPAddress).where(
                IPAddress.subnet_id == subnet_id, IPAddress.address == "10.61.0.20"
            )
        )
    ).scalar_one()
    row.hostname = "ipam-side"
    await db_session.commit()

    resp = await client.put(
        f"/api/v1/dhcp/statics/{static_id}",
        headers=headers,
        json={
            "mac_address": "02-98-14-00-00-21".upper(),
            "ip_address": " 10.61.0.20 ",
            "hostname": "ST-A.",
            "description": "kept",
            "client_id": "",
        },
    )
    assert resp.status_code == 200, resp.text
    assert await _ipam_hostname(db_session, subnet_id) == "ipam-side"
    # Nothing changed, so nothing is audited (as an unchanged record Save, #2463).
    assert await _update_audits(db_session, static_id) == 0


@pytest.mark.asyncio
async def test_a_real_change_still_writes_through_and_clears_a_description(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, static_id, subnet_id = await _static_with_ipam(client, db_session)

    resp = await client.put(
        f"/api/v1/dhcp/statics/{static_id}",
        headers=headers,
        json={"hostname": "st-b", "description": ""},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["hostname"] == "st-b"
    assert resp.json()["description"] == ""
    assert await _ipam_hostname(db_session, subnet_id) == "st-b"
    assert await _update_audits(db_session, static_id) == 1


@pytest.mark.parametrize(
    ("field", "stored", "sent", "same"),
    [
        ("ip_address", "2001:db8::1", "2001:DB8:0:0::1", True),
        ("ip_address", "10.0.0.1", "10.0.0.2", False),
        ("mac_address", "02:98:14:00:00:20", "0298.1400.0020", True),
        ("mac_address", "02:98:14:00:00:20", "02:98:14:00:00:21", False),
        ("hostname", "web01", "web01.", True),
        ("hostname", "web01", "web02", False),
        ("client_id", None, "", True),
        ("client_id", None, "01:02", False),
        ("duid", "00:01:00:01", "00010001", True),
        ("tags", {"a": 1}, {"a": 1}, True),
        ("tags", {"a": 1}, {"a": 2}, False),
    ],
)
def test_same_value_folds_spellings(field: str, stored: object, sent: object, same: bool) -> None:
    import ipaddress

    current = ipaddress.ip_address(stored) if field == "ip_address" else stored
    assert _same_value(field, current, sent) is same
