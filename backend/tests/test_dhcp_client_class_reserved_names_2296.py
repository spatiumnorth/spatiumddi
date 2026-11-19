"""#2296 — operator client classes may not take names the renderer owns.

``DROP`` is the generated MAC-blocklist class: a user class with that name made
the agent skip the blocklist, which silently stopped blocking. Existing rows
with such a name keep working (and saving other fields) and are flagged.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPClientClass, DHCPServerGroup

RESERVED = [
    "DROP",
    "drop",
    "ALL",
    "KNOWN",
    "UNKNOWN",
    "BOOTP",
    "HA_server1",
    "VENDOR_CLASS_foo",
    "SPAWN_x",
    "spatium-device-cameras",
    "pxe-0123abcd-4567ef01",
    "voip-0123abcd",
]


async def _setup(db: AsyncSession) -> tuple[dict, DHCPServerGroup]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add_all([user, grp])
    await db.flush()
    token = create_access_token(str(user.id))
    await db.commit()
    return {"Authorization": f"Bearer {token}"}, grp


@pytest.mark.asyncio
@pytest.mark.parametrize("name", RESERVED)
async def test_create_with_reserved_name_is_refused(
    client: AsyncClient, db_session: AsyncSession, name: str
) -> None:
    h, grp = await _setup(db_session)
    r = await client.post(
        f"/api/v1/dhcp/server-groups/{grp.id}/client-classes",
        headers=h,
        json={"name": name, "match_expression": "", "address_family": "ipv4"},
    )
    assert r.status_code == 422, r.text
    assert "reserved" in r.text
    lst = await client.get(f"/api/v1/dhcp/server-groups/{grp.id}/client-classes", headers=h)
    assert lst.json() == []


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["DROP", "spatium-device-x", "voip-0123abcd"])
async def test_rename_to_reserved_name_is_refused(
    client: AsyncClient, db_session: AsyncSession, name: str
) -> None:
    h, grp = await _setup(db_session)
    r = await client.post(
        f"/api/v1/dhcp/server-groups/{grp.id}/client-classes",
        headers=h,
        json={"name": "phones", "match_expression": "", "address_family": "ipv4"},
    )
    assert r.status_code == 201, r.text
    cid = r.json()["id"]
    assert r.json()["reserved_name"] is False
    r = await client.put(f"/api/v1/dhcp/client-classes/{cid}", headers=h, json={"name": name})
    assert r.status_code == 422, r.text
    after = await client.get(f"/api/v1/dhcp/server-groups/{grp.id}/client-classes", headers=h)
    assert [c["name"] for c in after.json()] == ["phones"]


@pytest.mark.asyncio
async def test_ordinary_names_still_work(client: AsyncClient, db_session: AsyncSession) -> None:
    h, grp = await _setup(db_session)
    for name in ("voip-phones", "pxe-clients", "dropbox", "spatium-lab"):
        r = await client.post(
            f"/api/v1/dhcp/server-groups/{grp.id}/client-classes",
            headers=h,
            json={"name": name, "match_expression": "", "address_family": "ipv4"},
        )
        assert r.status_code == 201, (name, r.text)


@pytest.mark.asyncio
async def test_existing_reserved_row_keeps_working_and_is_flagged(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, grp = await _setup(db_session)
    row = DHCPClientClass(
        group_id=grp.id, name="DROP", match_expression="", description="", options={}
    )
    db_session.add(row)
    await db_session.commit()
    lst = await client.get(f"/api/v1/dhcp/server-groups/{grp.id}/client-classes", headers=h)
    assert lst.json()[0]["reserved_name"] is True
    # Editing another field of the old row is not blocked ...
    r = await client.put(
        f"/api/v1/dhcp/client-classes/{row.id}", headers=h, json={"description": "legacy"}
    )
    assert r.status_code == 200, r.text
    # ... and the rename away from it is allowed.
    r = await client.put(
        f"/api/v1/dhcp/client-classes/{row.id}", headers=h, json={"name": "legacy"}
    )
    assert r.status_code == 200, r.text
    assert r.json()["reserved_name"] is False
