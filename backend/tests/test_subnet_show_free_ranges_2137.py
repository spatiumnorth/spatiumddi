"""#2137 — ``subnet.show_free_ranges``: a nullable display setting.

NULL means "use the default rule" (the UI hides the free-range rows for an
integration-owned or larger-than-/16 subnet), so a new subnet stores NULL; an
explicit value round-trips; an explicit null on update restores the default;
``integration_owner`` names the mirroring integration.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.ipam import IPBlock, IPSpace, Subnet


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
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="b")
    db.add(block)
    await db.commit()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    return headers, str(space.id), str(block.id)


async def _create(
    client: AsyncClient,
    headers: dict[str, str],
    ids: tuple[str, str],
    network: str,
    **extra: object,
) -> dict:
    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={"space_id": ids[0], "block_id": ids[1], "network": network, **extra},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_new_subnet_stores_null_default(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sp, blk = await _setup(db_session)
    body = await _create(client, headers, (sp, blk), "10.1.0.0/24")
    assert body["show_free_ranges"] is None
    assert body["integration_owner"] is None
    got = await client.get(f"/api/v1/ipam/subnets/{body['id']}", headers=headers)
    assert got.json()["show_free_ranges"] is None


@pytest.mark.asyncio
async def test_explicit_value_round_trips_on_create_and_update(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sp, blk = await _setup(db_session)
    body = await _create(client, headers, (sp, blk), "10.1.0.0/24", show_free_ranges=False)
    assert body["show_free_ranges"] is False

    r = await client.put(
        f"/api/v1/ipam/subnets/{body['id']}", headers=headers, json={"show_free_ranges": True}
    )
    assert r.status_code == 200, r.text
    assert r.json()["show_free_ranges"] is True

    # An unrelated update leaves it alone.
    r = await client.put(
        f"/api/v1/ipam/subnets/{body['id']}", headers=headers, json={"name": "renamed"}
    )
    assert r.json()["show_free_ranges"] is True

    # An explicit null restores the default.
    r = await client.put(
        f"/api/v1/ipam/subnets/{body['id']}", headers=headers, json={"show_free_ranges": None}
    )
    assert r.status_code == 200, r.text
    assert r.json()["show_free_ranges"] is None


@pytest.mark.asyncio
async def test_integration_owner_is_derived_from_the_ownership_fk(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.api.v1.ipam.router import SubnetResponse

    headers, sp, blk = await _setup(db_session)
    body = await _create(client, headers, (sp, blk), "10.2.0.0/24")
    row = await db_session.get(Subnet, uuid.UUID(body["id"]))
    assert row is not None
    assert SubnetResponse.model_validate(row).integration_owner is None
    # Stamped in memory only (never flushed): the FK target table is not
    # needed to prove the derivation.
    with db_session.no_autoflush:
        row.tailscale_tenant_id = uuid.uuid4()
        out = SubnetResponse.model_validate(row)
    assert out.integration_owner == "tailscale"
    assert out.show_free_ranges is None
    await db_session.rollback()


@pytest.mark.asyncio
async def test_copilot_subnet_summary_reports_setting_and_owner(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from sqlalchemy import select

    from app.services.ai.tools.ipam import SubnetSummaryArgs, get_subnet_summary

    headers, sp, blk = await _setup(db_session)
    body = await _create(client, headers, (sp, blk), "10.3.0.0/24", show_free_ranges=False)
    user = (
        (await db_session.execute(select(User).where(User.is_superadmin.is_(True))))
        .scalars()
        .first()
    )
    assert user is not None
    out = await get_subnet_summary(db_session, user, SubnetSummaryArgs(subnet_id=body["id"]))
    assert out["show_free_ranges"] is False
    assert out["integration_owner"] is None
