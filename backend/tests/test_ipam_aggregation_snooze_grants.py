"""Aggregation snoozes require write on IP blocks and are audited.

The snooze map (``platform_settings.aggregation_snooze``) is shared by every
operator: snoozing or dismissing a candidate hides it from everyone's
aggregation badge. The IPAM router's coarse gate admits any IPAM write grant,
including a ``custom_field`` grant or an instance-scoped address-set grant, so
the snooze / dismiss / clear routes check type-level ``write`` on ``ip_block``
themselves, and every change they make is written to ``audit_log``.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.address_set import AddressSet
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.models.settings import PlatformSettings

BASE = "/api/v1/ipam/aggregation-snoozes"
KEY = "a" * 32


async def _user(
    db: AsyncSession,
    *,
    permissions: list[dict] | None = None,
    superadmin: bool = False,
) -> str:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@t.io",
        display_name="t",
        hashed_password=hash_password("password123"),
        is_superadmin=superadmin,
    )
    user.groups = []
    if permissions:
        role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
        group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
        group.roles = [role]
        user.groups = [group]
        db.add_all([role, group])
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


async def _address_set(db: AsyncSession) -> AddressSet:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.0.5.0/24", name="a")
    db.add(subnet)
    await db.flush()
    aset = AddressSet(
        name="delegated",
        subnet_id=subnet.id,
        range_kind="contiguous",
        start_address="10.0.5.50",
        end_address="10.0.5.99",
    )
    db.add(aset)
    await db.flush()
    return aset


def _h(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _snooze_map(db: AsyncSession) -> dict:
    db.expire_all()
    row = (await db.execute(select(PlatformSettings).limit(1))).scalar_one_or_none()
    return dict(row.aggregation_snooze) if row else {}


async def _audit_rows(db: AsyncSession) -> list[AuditLog]:
    return list(
        (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.resource_type == "aggregation_snooze")
                .order_by(AuditLog.seq)
            )
        )
        .scalars()
        .all()
    )


ACTIONS = [
    ("snooze", {"candidate_key": KEY, "days": 30}),
    ("dismiss", {"candidate_key": KEY}),
    ("clear", {"candidate_key": KEY}),
]


# ── narrow grants are refused ────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(("action", "body"), ACTIONS)
async def test_custom_field_writer_gets_403(
    client: AsyncClient, db_session: AsyncSession, action: str, body: dict
) -> None:
    token = await _user(
        db_session, permissions=[{"action": "write", "resource_type": "custom_field"}]
    )
    await db_session.commit()

    r = await client.post(f"{BASE}/{action}", headers=_h(token), json=body)
    assert r.status_code == 403, r.text
    assert KEY not in await _snooze_map(db_session)
    assert await _audit_rows(db_session) == []


@pytest.mark.asyncio
@pytest.mark.parametrize(("action", "body"), ACTIONS)
async def test_address_set_delegate_gets_403(
    client: AsyncClient, db_session: AsyncSession, action: str, body: dict
) -> None:
    aset = await _address_set(db_session)
    token = await _user(
        db_session,
        permissions=[
            {"action": "write", "resource_type": "address_set", "resource_id": str(aset.id)}
        ],
    )
    await db_session.commit()

    r = await client.post(f"{BASE}/{action}", headers=_h(token), json=body)
    assert r.status_code == 403, r.text
    assert KEY not in await _snooze_map(db_session)
    assert await _audit_rows(db_session) == []


@pytest.mark.asyncio
async def test_custom_field_writer_cannot_clear_an_existing_entry(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    db_session.add(PlatformSettings(id=1, aggregation_snooze={KEY: "permanent"}))
    token = await _user(
        db_session, permissions=[{"action": "write", "resource_type": "custom_field"}]
    )
    await db_session.commit()

    r = await client.post(f"{BASE}/clear", headers=_h(token), json={"candidate_key": KEY})
    assert r.status_code == 403, r.text
    assert (await _snooze_map(db_session)).get(KEY) == "permanent"


# ── block writers and superadmins are admitted, and audited ──────────────────


async def _walk_actions(client: AsyncClient, db: AsyncSession, token: str) -> None:
    r = await client.post(
        f"{BASE}/snooze", headers=_h(token), json={"candidate_key": KEY, "days": 30}
    )
    assert r.status_code == 204, r.text
    snoozed_until = (await _snooze_map(db))[KEY]
    assert snoozed_until != "permanent"

    r = await client.post(f"{BASE}/dismiss", headers=_h(token), json={"candidate_key": KEY})
    assert r.status_code == 204, r.text
    assert (await _snooze_map(db))[KEY] == "permanent"

    r = await client.post(f"{BASE}/clear", headers=_h(token), json={"candidate_key": KEY})
    assert r.status_code == 204, r.text
    assert KEY not in await _snooze_map(db)

    rows = await _audit_rows(db)
    assert [r.action for r in rows] == ["snooze", "dismiss", "clear_snooze"]
    assert all(r.resource_id == KEY and r.result == "success" for r in rows)
    assert rows[0].old_value == {"snoozed_until": None}
    assert rows[0].new_value == {"snoozed_until": snoozed_until}
    assert rows[1].old_value == {"snoozed_until": snoozed_until}
    assert rows[1].new_value == {"snoozed_until": "permanent"}
    assert rows[2].old_value == {"snoozed_until": "permanent"}
    assert rows[2].new_value == {"snoozed_until": None}


@pytest.mark.asyncio
async def test_block_writer_can_snooze_dismiss_and_clear(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _user(db_session, permissions=[{"action": "write", "resource_type": "ip_block"}])
    await db_session.commit()
    await _walk_actions(client, db_session, token)


@pytest.mark.asyncio
async def test_superadmin_can_snooze_dismiss_and_clear(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _user(db_session, superadmin=True)
    await db_session.commit()
    await _walk_actions(client, db_session, token)


@pytest.mark.asyncio
async def test_clearing_an_absent_key_writes_no_audit_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _user(db_session, superadmin=True)
    await db_session.commit()

    r = await client.post(f"{BASE}/clear", headers=_h(token), json={"candidate_key": KEY})
    assert r.status_code == 204, r.text
    assert await _audit_rows(db_session) == []
