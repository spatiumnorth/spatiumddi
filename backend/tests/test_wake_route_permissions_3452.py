"""What ``POST /ipam/addresses/{id}/wake`` asks of its caller (#3452).

The IP detail disables Wake for a caller this route refuses, by asking the same
question the server does. Pinned here so the two cannot drift: read on
``use_network_tools`` AND write on subnets type-wide. A write grant scoped to
the address's own subnet does not reach the route, because the IPAM gate's
instance admit (#2438) keys on a ``subnet_id`` path parameter and this route
names the address.

The real UDP send is patched; no packet leaves the test process.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import Group, Role, User
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services import wol


async def _headers(db: AsyncSession, permissions: list[dict]) -> dict[str, str]:
    user = User(
        username=f"wk-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@t.io",
        display_name="wake",
        hashed_password=hash_password("password123"),
    )
    role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
    group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
    group.roles = [role]
    user.groups = [group]
    db.add_all([role, group, user])
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _wakeable_ip(db: AsyncSession) -> IPAddress:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.31.0.0/24", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.31.0.0/24", name="n")
    db.add(subnet)
    await db.flush()
    ip = IPAddress(subnet_id=subnet.id, address="10.31.0.9", mac_address="aa:bb:cc:00:31:09")
    db.add(ip)
    await db.flush()
    return ip


def _sent() -> AsyncMock:
    return AsyncMock(
        return_value=wol.WolResult(
            mac="aa:bb:cc:00:31:09",
            broadcast="10.31.0.255",
            port=9,
            sent=True,
            ran_from="server",
        )
    )


_TOOLS = {"action": "read", "resource_type": "use_network_tools"}


@pytest.mark.parametrize(
    ("label", "subnet_grant", "with_tools", "expected"),
    [
        pytest.param("both", "unscoped", True, 200, id="tools-and-subnet-write"),
        pytest.param("scoped", "scoped", True, 403, id="tools-and-scoped-subnet-write"),
        pytest.param("no-tools", "unscoped", False, 403, id="subnet-write-without-tools"),
        pytest.param("no-subnet", None, True, 403, id="tools-without-subnet-write"),
    ],
)
async def test_wake_route_permissions(
    client: AsyncClient,
    db_session: AsyncSession,
    label: str,
    subnet_grant: str | None,
    with_tools: bool,
    expected: int,
) -> None:
    ip = await _wakeable_ip(db_session)
    perms: list[dict] = [{"action": "read", "resource_type": "ip_address"}]
    if with_tools:
        perms.append(_TOOLS)
    if subnet_grant == "unscoped":
        perms.append({"action": "write", "resource_type": "subnet"})
    elif subnet_grant == "scoped":
        perms.append(
            {"action": "write", "resource_type": "subnet", "resource_id": str(ip.subnet_id)}
        )
    headers = await _headers(db_session, perms)
    await db_session.commit()

    send = _sent()
    with patch("app.services.wol.wake_from_server", new=send):
        r = await client.post(f"/api/v1/ipam/addresses/{ip.id}/wake", json={}, headers=headers)
    assert r.status_code == expected, (label, r.text)
    assert send.await_count == (1 if expected == 200 else 0), label
