"""#1690 — options 58/59 stay refused (T1/T2 are derived from each lease),
and a Kea import says it drops a subnet's ``renew-timer`` / ``rebind-timer``."""

from __future__ import annotations

import json
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServerGroup
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.dhcp_import.kea_parser import parse_kea_config


async def _setup(db: AsyncSession) -> tuple[dict[str, str], DHCPScope]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    space = IPSpace(name=f"s-{uuid.uuid4().hex[:6]}", description="")
    db.add_all([user, space])
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.71.0.0/24", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.71.0.0/24", name="s")
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add_all([subnet, group])
    await db.flush()
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, name="scope", lease_time=86400)
    db.add(scope)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}, scope


@pytest.mark.asyncio
@pytest.mark.parametrize("key", ["dhcp-renewal-time", "dhcp-rebinding-time", "code:58", "code:59"])
async def test_options_58_59_stay_refused(
    client: AsyncClient, db_session: AsyncSession, key: str
) -> None:
    headers, scope = await _setup(db_session)
    r = await client.put(
        f"/api/v1/dhcp/scopes/{scope.id}", json={"options": {key: 300}}, headers=headers
    )
    assert r.status_code == 422, r.text


def _kea(subnet_extra: dict[str, object]) -> bytes:
    sub = {
        "subnet": "192.0.2.0/24",
        "valid-lifetime": 1200,
        "pools": [{"pool": "192.0.2.10 - 192.0.2.50"}],
        **subnet_extra,
    }
    return json.dumps({"Dhcp4": {"subnet4": [sub]}}).encode()


def test_kea_import_warns_when_it_drops_timers() -> None:
    sc = parse_kea_config(_kea({"renew-timer": 600, "rebind-timer": 1050})).scopes[0]
    joined = " ".join(sc.parse_warnings)
    assert "renew-timer" in joined and "rebind-timer" in joined
    assert "600" in joined and "1050" in joined


def test_kea_import_silent_without_timers() -> None:
    assert parse_kea_config(_kea({})).scopes[0].parse_warnings == []
