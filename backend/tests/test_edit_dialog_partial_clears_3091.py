"""#3091 — the edit dialogs now send only the fields the operator changed.

A clear is one of those changes, and it is the case a partial body can lose:
several of these update handlers dump with ``exclude_none``, so a cleared field
sent as null would be dropped and the clear would silently not happen. Each test
below PUTs exactly the body the dialog's ``changedFields`` diff produces for a
clear (the null / "" / {} / [] the form emits) and reads the row back, so the
contract the frontend relies on is pinned against the real handlers.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPPool, DHCPPXEProfile, DHCPServerGroup
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet

CIDR = "192.0.2.0/24"


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _tree(db: AsyncSession) -> tuple[IPBlock, Subnet, DHCPServerGroup]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=CIDR, name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=CIDR, name="s")
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add_all([subnet, grp])
    await db.flush()
    return block, subnet, grp


def _ok(r, code: int = 200) -> dict:
    assert r.status_code == code, r.text
    return r.json()


@pytest.mark.asyncio
async def test_edit_block_clears_reach_the_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    block, _, grp = await _tree(db_session)
    await db_session.commit()
    url = f"/api/v1/ipam/blocks/{block.id}"
    _ok(
        await client.put(
            url,
            headers=h,
            json={
                "description": "edge",
                "custom_fields": {"owner": "net"},
                "do_not_probe": True,
                "do_not_probe_reason": "plc",
                "dhcp_inherit_settings": False,
                "dhcp_server_group_id": str(grp.id),
            },
        )
    )
    # Toggling DHCP inherit back on: the dialog sends the flag and a null group.
    _ok(
        await client.put(
            url,
            headers=h,
            json={
                "description": "",
                "custom_fields": {},
                "do_not_probe": False,
                "do_not_probe_reason": "",
                "dhcp_inherit_settings": True,
                "dhcp_server_group_id": None,
            },
        )
    )
    after = _ok(await client.get(url, headers=h))
    assert after["description"] == ""
    assert after["custom_fields"] == {}
    assert after["do_not_probe"] is False
    assert after["do_not_probe_reason"] == ""
    assert after["dhcp_inherit_settings"] is True
    assert after["dhcp_server_group_id"] is None


@pytest.mark.asyncio
async def test_edit_block_inherit_off_sends_flag_and_value(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    block, _, grp = await _tree(db_session)
    await db_session.commit()
    url = f"/api/v1/ipam/blocks/{block.id}"
    # Inherit off + a value: the dialog's diff carries both.
    _ok(
        await client.put(
            url,
            headers=h,
            json={"dhcp_inherit_settings": False, "dhcp_server_group_id": str(grp.id)},
        )
    )
    after = _ok(await client.get(url, headers=h))
    assert after["dhcp_inherit_settings"] is False
    assert after["dhcp_server_group_id"] == str(grp.id)
    # Clearing the value while inherit stays off: null alone must clear it.
    _ok(await client.put(url, headers=h, json={"dhcp_server_group_id": None}))
    after = _ok(await client.get(url, headers=h))
    assert after["dhcp_inherit_settings"] is False
    assert after["dhcp_server_group_id"] is None


@pytest.mark.asyncio
async def test_edit_client_class_and_template_clears_reach_the_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    _, _, grp = await _tree(db_session)
    await db_session.commit()
    cc = _ok(
        await client.post(
            f"/api/v1/dhcp/server-groups/{grp.id}/client-classes",
            headers=h,
            json={
                "name": "phones",
                "description": "desk phones",
                "match_expression": "option[60].text == 'x'",
                "address_family": "ipv4",
                "options": {"routers": "192.0.2.1"},
            },
        ),
        201,
    )
    _ok(
        await client.put(
            f"/api/v1/dhcp/client-classes/{cc['id']}",
            headers=h,
            json={"description": "", "match_expression": "", "options": {}},
        )
    )
    row = next(
        c
        for c in _ok(
            await client.get(f"/api/v1/dhcp/server-groups/{grp.id}/client-classes", headers=h)
        )
        if c["id"] == cc["id"]
    )
    assert row["description"] == ""
    assert row["match_expression"] == ""
    assert row["options"] == {}

    tpl = _ok(
        await client.post(
            f"/api/v1/dhcp/server-groups/{grp.id}/option-templates",
            headers=h,
            json={
                "name": "t",
                "description": "office",
                "address_family": "ipv4",
                "options": {"routers": "192.0.2.1"},
            },
        ),
        201,
    )
    _ok(
        await client.put(
            f"/api/v1/dhcp/option-templates/{tpl['id']}",
            headers=h,
            json={"description": "", "options": {}},
        )
    )
    row = next(
        t
        for t in _ok(
            await client.get(f"/api/v1/dhcp/server-groups/{grp.id}/option-templates", headers=h)
        )
        if t["id"] == tpl["id"]
    )
    assert row["description"] == ""
    assert row["options"] == {}


@pytest.mark.asyncio
async def test_edit_group_scope_and_pool_clears_reach_the_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    _, subnet, grp = await _tree(db_session)
    pxe = DHCPPXEProfile(group_id=grp.id, name="pxe", next_server="192.0.2.5")
    db_session.add(pxe)
    await db_session.commit()

    # Server group: a blanked description and max-age.
    g_url = f"/api/v1/dhcp/server-groups/{grp.id}"
    _ok(
        await client.put(g_url, headers=h, json={"description": "core", "lease_cache_max_age": 600})
    )
    _ok(await client.put(g_url, headers=h, json={"description": "", "lease_cache_max_age": None}))
    g = _ok(await client.get(g_url, headers=h))
    assert g["description"] == ""
    assert g["lease_cache_max_age"] is None

    # Scope: blanked description / lease bounds / cache override / relays, and
    # the PXE detach, which is the clear_pxe_profile flag rather than a null.
    scope = _ok(
        await client.post(
            f"/api/v1/dhcp/subnets/{subnet.id}/dhcp-scopes",
            headers=h,
            json={
                "group_id": str(grp.id),
                "name": "s",
                "description": "lan",
                "lease_time": 3600,
                "min_lease_time": 600,
                "max_lease_time": 7200,
                "lease_cache_threshold": 0.25,
                "relay_addresses": ["192.0.2.1"],
                "pxe_profile_id": str(pxe.id),
            },
        ),
        201,
    )
    s_url = f"/api/v1/dhcp/scopes/{scope['id']}"
    _ok(
        await client.put(
            s_url,
            headers=h,
            json={
                "description": "",
                "min_lease_time": None,
                "max_lease_time": None,
                "lease_cache_threshold": None,
                "relay_addresses": [],
                "clear_pxe_profile": True,
            },
        )
    )
    s = _ok(await client.get(s_url, headers=h))
    assert s["description"] == ""
    assert s["min_lease_time"] is None
    assert s["max_lease_time"] is None
    assert s["lease_cache_threshold"] is None
    assert s["relay_addresses"] == []
    assert s["pxe_profile_id"] is None

    # Pool: a cleared class restriction goes as null.
    _ok(
        await client.post(
            f"/api/v1/dhcp/server-groups/{grp.id}/client-classes",
            headers=h,
            json={"name": "phones", "match_expression": "", "address_family": "ipv4"},
        ),
        201,
    )
    pool = _ok(
        await client.post(
            f"/api/v1/dhcp/scopes/{scope['id']}/pools",
            headers=h,
            json={
                "name": "p",
                "start_ip": "192.0.2.100",
                "end_ip": "192.0.2.150",
                "pool_type": "dynamic",
                "class_restriction": "phones",
            },
        ),
        201,
    )
    _ok(
        await client.put(
            f"/api/v1/dhcp/pools/{pool['id']}", headers=h, json={"class_restriction": None}
        )
    )
    p = next(
        x
        for x in _ok(await client.get(f"/api/v1/dhcp/scopes/{scope['id']}/pools", headers=h))
        if x["id"] == pool["id"]
    )
    assert p["class_restriction"] is None
    assert p["start_ip"] == "192.0.2.100"


@pytest.mark.asyncio
async def test_edit_address_clears_reach_the_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    _, subnet, _ = await _tree(db_session)
    ip = IPAddress(
        subnet_id=subnet.id,
        address="192.0.2.10",
        status="allocated",
        hostname="host1",
        description="printer",
        mac_address="00:11:22:33:44:55",
        role="server",
        custom_fields={"owner": "net"},
    )
    db_session.add(ip)
    await db_session.commit()
    url = f"/api/v1/ipam/addresses/{ip.id}"
    _ok(
        await client.put(
            url,
            headers=h,
            json={
                "hostname": None,
                "description": "",
                "mac_address": None,
                "role": None,
                "custom_fields": {},
                "force": False,
            },
        )
    )
    after = _ok(await client.get(url, headers=h))
    assert after["hostname"] in (None, "")
    assert after["description"] == ""
    assert after["mac_address"] is None
    assert after["role"] is None
    assert after["custom_fields"] == {}


@pytest.mark.asyncio
async def test_pd_pool_turned_into_address_pool_is_range_checked(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The dialog now sends only the type when the operator moves a pd pool to
    an address pool and leaves the range fields alone. Its stored start/end
    are the prefix placeholder, not a range, so the update must check them as
    one rather than accept a pool Kea would refuse."""
    h = await _headers(db_session)
    _, subnet, grp = await _tree(db_session)
    await db_session.commit()
    scope = _ok(
        await client.post(
            f"/api/v1/dhcp/subnets/{subnet.id}/dhcp-scopes",
            headers=h,
            json={"group_id": str(grp.id), "name": "s"},
        ),
        201,
    )
    pd = DHCPPool(
        scope_id=uuid.UUID(scope["id"]),
        name="pd",
        start_ip="2001:db8:100::",
        end_ip="2001:db8:100::",
        pool_type="pd",
        pd_prefix="2001:db8:100::/40",
        delegated_length=56,
    )
    db_session.add(pd)
    await db_session.commit()
    r = await client.put(f"/api/v1/dhcp/pools/{pd.id}", headers=h, json={"pool_type": "dynamic"})
    assert r.status_code == 422, r.text
    p = next(
        x
        for x in _ok(await client.get(f"/api/v1/dhcp/scopes/{scope['id']}/pools", headers=h))
        if x["id"] == str(pd.id)
    )
    assert p["pool_type"] == "pd"
