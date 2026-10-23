"""Bulk IPAM handlers hold every row to the caller's write grants.

The IPAM router's coarse gate admits a caller holding any write grant on an
IPAM type, including an instance-scoped address-set grant (#103) or a grant on
a peripheral type such as ``custom_field``. Handlers that change many rows in
one request must then check each row against the caller's per-row grants
(subnet-wide write, or an address set covering the address). These tests pin
that for the stale-IP deprecate action: rows the caller may not write come
back in ``skipped`` and are left unchanged.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.address_set import AddressSet
from app.models.auth import Group, Role, User
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet

URL = "/api/v1/ipam/reports/stale-ips/deprecate"
STALE = datetime.now(UTC) - timedelta(days=100)

FULL_WRITER = [
    {"action": "write", "resource_type": rt}
    for rt in ("ip_space", "ip_block", "subnet", "ip_address")
]


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


class _World:
    space: IPSpace
    subnet_a: Subnet
    subnet_b: Subnet
    aset: AddressSet
    in_set: IPAddress  # subnet A, inside the address set
    a_outside: IPAddress  # subnet A, outside the address set
    b_rows: list[IPAddress]  # subnet B


async def _world(db: AsyncSession, b_count: int = 1) -> _World:
    w = _World()
    w.space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(w.space)
    await db.flush()
    block = IPBlock(space_id=w.space.id, network="10.0.0.0/16", name="b")
    db.add(block)
    await db.flush()
    w.subnet_a = Subnet(space_id=w.space.id, block_id=block.id, network="10.0.5.0/24", name="a")
    w.subnet_b = Subnet(space_id=w.space.id, block_id=block.id, network="10.0.6.0/24", name="b")
    db.add_all([w.subnet_a, w.subnet_b])
    await db.flush()
    w.aset = AddressSet(
        name="delegated",
        subnet_id=w.subnet_a.id,
        range_kind="contiguous",
        start_address="10.0.5.50",
        end_address="10.0.5.99",
    )
    db.add(w.aset)

    def _ip(subnet: Subnet, addr: str) -> IPAddress:
        return IPAddress(subnet_id=subnet.id, address=addr, status="allocated", last_seen_at=STALE)

    w.in_set = _ip(w.subnet_a, "10.0.5.60")
    w.a_outside = _ip(w.subnet_a, "10.0.5.10")
    w.b_rows = [_ip(w.subnet_b, f"10.0.6.{10 + i}") for i in range(b_count)]
    db.add_all([w.in_set, w.a_outside, *w.b_rows])
    await db.flush()
    return w


async def _status(db: AsyncSession, ip: IPAddress) -> str:
    return (await db.execute(select(IPAddress.status).where(IPAddress.id == ip.id))).scalar_one()


def _h(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ── address-set delegate ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_set_delegate_ip_ids_outside_set_are_skipped(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    w = await _world(db_session)
    token = await _user(
        db_session,
        permissions=[
            {"action": "write", "resource_type": "address_set", "resource_id": str(w.aset.id)}
        ],
    )
    await db_session.commit()

    ids = [w.in_set.id, w.a_outside.id, w.b_rows[0].id]
    r = await client.post(URL, headers=_h(token), json={"ip_ids": [str(i) for i in ids]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["deprecated_count"] == 1
    assert set(body["skipped"]) == {str(w.a_outside.id), str(w.b_rows[0].id)}
    assert await _status(db_session, w.in_set) == "deprecated"
    assert await _status(db_session, w.a_outside) == "allocated"
    assert await _status(db_session, w.b_rows[0]) == "allocated"


@pytest.mark.asyncio
async def test_set_delegate_all_matching_changes_only_rows_in_set(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    w = await _world(db_session)
    token = await _user(
        db_session,
        permissions=[
            {"action": "write", "resource_type": "address_set", "resource_id": str(w.aset.id)}
        ],
    )
    await db_session.commit()

    r = await client.post(
        URL,
        headers=_h(token),
        json={"all_matching": True, "stale_days": 90, "space_id": str(w.space.id)},
    )
    assert r.status_code == 200, r.text
    assert r.json()["deprecated_count"] == 1
    assert await _status(db_session, w.in_set) == "deprecated"
    assert await _status(db_session, w.a_outside) == "allocated"
    assert await _status(db_session, w.b_rows[0]) == "allocated"


@pytest.mark.asyncio
async def test_set_delegate_all_matching_cap_counts_writable_rows_only(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rows in subnets the caller cannot write do not take up the cap."""
    import app.services.ipam.stale_ips as stale_mod

    monkeypatch.setattr(stale_mod, "MAX_BULK_DEPRECATE", 1)
    w = await _world(db_session, b_count=3)
    # Drop the out-of-set row in A so the only writable stale row is in_set.
    await db_session.delete(w.a_outside)
    token = await _user(
        db_session,
        permissions=[
            {"action": "write", "resource_type": "address_set", "resource_id": str(w.aset.id)}
        ],
    )
    await db_session.commit()

    r = await client.post(
        URL,
        headers=_h(token),
        json={"all_matching": True, "stale_days": 90, "space_id": str(w.space.id)},
    )
    assert r.status_code == 200, r.text
    assert r.json()["deprecated_count"] == 1
    assert r.json()["capped"] is False
    assert await _status(db_session, w.in_set) == "deprecated"
    for row in w.b_rows:
        assert await _status(db_session, row) == "allocated"


# ── grant on a peripheral IPAM type only ─────────────────────────────────────


@pytest.mark.asyncio
async def test_peripheral_type_writer_changes_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    w = await _world(db_session)
    token = await _user(
        db_session, permissions=[{"action": "write", "resource_type": "custom_field"}]
    )
    await db_session.commit()

    ids = [w.in_set.id, w.a_outside.id, w.b_rows[0].id]
    r = await client.post(URL, headers=_h(token), json={"ip_ids": [str(i) for i in ids]})
    assert r.status_code == 200, r.text
    assert r.json()["deprecated_count"] == 0
    assert set(r.json()["skipped"]) == {str(i) for i in ids}

    r = await client.post(
        URL,
        headers=_h(token),
        json={"all_matching": True, "stale_days": 90, "space_id": str(w.space.id)},
    )
    # Nothing the caller may write matches the filter.
    assert r.status_code == 422, r.text
    for row in (w.in_set, w.a_outside, w.b_rows[0]):
        assert await _status(db_session, row) == "allocated"


# ── instance-scoped subnet writer ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_single_subnet_writer_changes_only_that_subnet(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    w = await _world(db_session)
    token = await _user(
        db_session,
        permissions=[
            {"action": "write", "resource_type": "custom_field"},
            {"action": "write", "resource_type": "subnet", "resource_id": str(w.subnet_a.id)},
        ],
    )
    await db_session.commit()

    ids = [w.in_set.id, w.a_outside.id, w.b_rows[0].id]
    r = await client.post(URL, headers=_h(token), json={"ip_ids": [str(i) for i in ids]})
    assert r.status_code == 200, r.text
    assert r.json()["deprecated_count"] == 2
    assert r.json()["skipped"] == [str(w.b_rows[0].id)]
    assert await _status(db_session, w.b_rows[0]) == "allocated"


@pytest.mark.asyncio
async def test_single_subnet_writer_all_matching_stays_in_subnet(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    w = await _world(db_session)
    token = await _user(
        db_session,
        permissions=[
            {"action": "write", "resource_type": "custom_field"},
            {"action": "write", "resource_type": "subnet", "resource_id": str(w.subnet_a.id)},
        ],
    )
    await db_session.commit()

    r = await client.post(
        URL,
        headers=_h(token),
        json={"all_matching": True, "stale_days": 90, "space_id": str(w.space.id)},
    )
    assert r.status_code == 200, r.text
    assert r.json()["deprecated_count"] == 2
    assert await _status(db_session, w.b_rows[0]) == "allocated"


# ── full writers are unaffected ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_full_ipam_writer_all_matching_unaffected(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    w = await _world(db_session)
    token = await _user(db_session, permissions=FULL_WRITER)
    await db_session.commit()

    r = await client.post(
        URL,
        headers=_h(token),
        json={"all_matching": True, "stale_days": 90, "space_id": str(w.space.id)},
    )
    assert r.status_code == 200, r.text
    assert r.json()["deprecated_count"] == 3
    assert r.json()["skipped"] == []


@pytest.mark.asyncio
async def test_superadmin_ip_ids_unaffected(client: AsyncClient, db_session: AsyncSession) -> None:
    w = await _world(db_session)
    token = await _user(db_session, superadmin=True)
    await db_session.commit()

    ids = [w.in_set.id, w.a_outside.id, w.b_rows[0].id]
    r = await client.post(URL, headers=_h(token), json={"ip_ids": [str(i) for i in ids]})
    assert r.status_code == 200, r.text
    assert r.json()["deprecated_count"] == 3
    assert r.json()["skipped"] == []
