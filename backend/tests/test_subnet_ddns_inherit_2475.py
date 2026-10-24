"""#2475 — a subnet dialog's DDNS tab can show and keep inheritance.

* ``GET .../effective-ddns`` reports what a subnet (or a new subnet in a
  block) resolves to and where from, so an inherited DDNS does not read as off.
* The flag-only body the dialog now sends while inheriting leaves inheritance
  on (the dialog no longer sends ``ddns_enabled`` then; the API still reads a
  ``ddns_enabled: true`` as an opt-out, #1065).
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.ipam import IPBlock, IPSpace


async def _setup(db: AsyncSession) -> tuple[dict[str, str], str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    # A block with DDNS on of its own (what a DDNS block template produces).
    block = IPBlock(
        space_id=space.id,
        network="10.0.0.0/8",
        name="ddns-block",
        ddns_enabled=True,
        ddns_inherit_settings=False,
        ddns_hostname_policy="always_generate",
    )
    db.add(block)
    await db.commit()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    return headers, str(space.id), str(block.id)


async def _subnet(client, headers, sp, blk, **extra) -> dict:
    r = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={"space_id": sp, "block_id": blk, "network": "10.1.0.0/24", **extra},
    )
    assert r.status_code == 201, r.text
    return r.json()


@pytest.mark.asyncio
async def test_effective_ddns_reports_inherited_on_and_source(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sp, blk = await _setup(db_session)
    sub = await _subnet(client, headers, sp, blk)
    assert sub["ddns_inherit_settings"] is True and sub["ddns_enabled"] is False

    got = (
        await client.get(f"/api/v1/ipam/subnets/{sub['id']}/effective-ddns", headers=headers)
    ).json()
    assert got["enabled"] is True
    assert got["hostname_policy"] == "always_generate"
    assert got["source"] == "block" and got["source_id"] == blk
    assert got["source_name"] == "ddns-block"

    # The same answer before the subnet exists (New Subnet's DDNS tab).
    got = (await client.get(f"/api/v1/ipam/blocks/{blk}/effective-ddns", headers=headers)).json()
    assert got["enabled"] is True and got["source"] == "block"


@pytest.mark.asyncio
async def test_effective_ddns_own_settings_when_not_inheriting(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sp, blk = await _setup(db_session)
    sub = await _subnet(client, headers, sp, blk, ddns_enabled=True)
    assert sub["ddns_inherit_settings"] is False
    got = (
        await client.get(f"/api/v1/ipam/subnets/{sub['id']}/effective-ddns", headers=headers)
    ).json()
    assert got["source"] == "subnet" and got["enabled"] is True


@pytest.mark.asyncio
async def test_inherit_only_body_reinherits_and_is_a_noop_when_repeated(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """What the dialog now sends while inheriting: the flag alone."""
    headers, sp, blk = await _setup(db_session)
    sub = await _subnet(client, headers, sp, blk, ddns_enabled=True)
    for _ in range(2):
        r = await client.put(
            f"/api/v1/ipam/subnets/{sub['id']}",
            headers=headers,
            json={"ddns_inherit_settings": True},
        )
        assert r.status_code == 200, r.text
        assert r.json()["ddns_inherit_settings"] is True
        assert r.json()["ddns_enabled"] is True


@pytest.mark.asyncio
async def test_enabled_alone_still_opts_out_of_inheritance(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#1065 stays: a body that only says ``ddns_enabled: true`` is an opt-in."""
    headers, sp, blk = await _setup(db_session)
    sub = await _subnet(client, headers, sp, blk)
    r = await client.put(
        f"/api/v1/ipam/subnets/{sub['id']}", headers=headers, json={"ddns_enabled": True}
    )
    assert r.json()["ddns_inherit_settings"] is False
