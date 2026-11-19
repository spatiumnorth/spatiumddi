"""#475 — DHCP scope hostname→IPAM sync-mode vocabulary + nullable-clear on update.

The scope modal emitted a ``none`` / ``ipam`` / ``learned`` vocabulary that the
API stored (lossily) as ``disabled`` / ``on_static_only`` / ``on_lease`` and then
echoed back raw — so the <select> couldn't render the response and edits snapped
back. The API now round-trips the canonical vocabulary (and still accepts the
legacy values from older clients), validates the sync mode on update, and lets an
explicit null clear a nullable lease-time column.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServerGroup
from app.models.ipam import IPBlock, IPSpace, Subnet

CIDR = "192.0.2.0/24"


async def _make_token(db: AsyncSession) -> str:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


async def _subnet_and_group(db: AsyncSession) -> tuple[Subnet, DHCPServerGroup]:
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
    return subnet, grp


async def _create(
    client: AsyncClient, h: dict, subnet: Subnet, grp: DHCPServerGroup, **extra
) -> dict:
    r = await client.post(
        f"/api/v1/dhcp/subnets/{subnet.id}/dhcp-scopes",
        headers=h,
        json={"group_id": str(grp.id), "name": "s", **extra},
    )
    assert r.status_code in (200, 201), r.text
    return r.json()


@pytest.mark.asyncio
async def test_canonical_sync_mode_round_trips(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _make_token(db_session)
    subnet, grp = await _subnet_and_group(db_session)
    await db_session.commit()
    h = {"Authorization": f"Bearer {token}"}

    body = await _create(client, h, subnet, grp, hostname_sync_mode="on_lease")
    # Echoed back canonical — the <select> value survives the round-trip.
    assert body["hostname_sync_mode"] == "on_lease"

    r = await client.put(
        f"/api/v1/dhcp/scopes/{body['id']}",
        headers=h,
        json={"hostname_sync_mode": "disabled"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["hostname_sync_mode"] == "disabled"


@pytest.mark.asyncio
async def test_legacy_sync_mode_values_mapped(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _make_token(db_session)
    h = {"Authorization": f"Bearer {token}"}
    for legacy, canonical in (
        ("ipam", "on_static_only"),
        ("learned", "on_lease"),
        ("none", "disabled"),
    ):
        subnet, grp = await _subnet_and_group(db_session)
        await db_session.commit()
        body = await _create(client, h, subnet, grp, hostname_sync_mode=legacy)
        assert body["hostname_sync_mode"] == canonical, f"{legacy} -> {body['hostname_sync_mode']}"


@pytest.mark.asyncio
async def test_update_clears_nullable_lease_time(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _make_token(db_session)
    subnet, grp = await _subnet_and_group(db_session)
    await db_session.commit()
    h = {"Authorization": f"Bearer {token}"}

    body = await _create(
        client, h, subnet, grp, lease_time=450, min_lease_time=300, max_lease_time=600
    )
    assert body["min_lease_time"] == 300

    # An explicit null must clear the column (exclude_none used to drop it).
    r = await client.put(
        f"/api/v1/dhcp/scopes/{body['id']}", headers=h, json={"min_lease_time": None}
    )
    assert r.status_code == 200, r.text
    assert r.json()["min_lease_time"] is None
    scope = await db_session.get(DHCPScope, uuid.UUID(body["id"]))
    await db_session.refresh(scope)
    assert scope.min_lease_time is None
    # An untouched field (max_lease_time) stays put.
    assert scope.max_lease_time == 600


@pytest.mark.asyncio
async def test_update_rejects_invalid_sync_mode(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _make_token(db_session)
    subnet, grp = await _subnet_and_group(db_session)
    await db_session.commit()
    h = {"Authorization": f"Bearer {token}"}

    body = await _create(client, h, subnet, grp)
    r = await client.put(
        f"/api/v1/dhcp/scopes/{body['id']}",
        headers=h,
        json={"hostname_sync_mode": "bogus"},
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_update_explicit_null_on_notnull_field_is_ignored_not_500(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    # exclude_unset lets explicit nulls through; a null on a NOT-NULL column
    # (name / is_active) or an unmanaged nullable one must be DROPPED, not
    # applied — else setattr(None) 500s on commit / silently wipes data.
    token = await _make_token(db_session)
    subnet, grp = await _subnet_and_group(db_session)
    await db_session.commit()
    h = {"Authorization": f"Bearer {token}"}

    body = await _create(client, h, subnet, grp, name="keep-me", description="keep-desc")
    r = await client.put(
        f"/api/v1/dhcp/scopes/{body['id']}",
        headers=h,
        json={"name": None, "description": None, "is_active": None},
    )
    assert r.status_code == 200, r.text
    scope = await db_session.get(DHCPScope, uuid.UUID(body["id"]))
    await db_session.refresh(scope)
    assert scope.name == "keep-me"  # NOT cleared
    assert scope.description == "keep-desc"
    assert scope.is_active is True
