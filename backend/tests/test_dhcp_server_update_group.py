"""``PUT /dhcp/servers/{id}`` can take a server out of its group (#1458).

The update handler built its changes with ``exclude_none=True``, so an
explicit ``server_group_id: null`` was dropped like an absent key: the call
answered 200 and the server stayed in its group. A server can be moved to
another group, and an ungrouped server is a valid state (create accepts it),
so clearing has to work too — without changing "null = leave it" for every
other field of the payload.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dhcp import DHCPServer, DHCPServerGroup


async def _token(db: AsyncSession) -> str:
    user = User(
        username=f"grp-{uuid.uuid4().hex[:6]}",
        email=f"grp-{uuid.uuid4().hex[:6]}@example.test",
        display_name="grp",
        hashed_password=hash_password("x"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _grouped_kea(db: AsyncSession) -> tuple[DHCPServer, DHCPServerGroup]:
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(group)
    await db.flush()
    server = DHCPServer(
        name=f"kea-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="10.0.0.3",
        port=67,
        server_group_id=group.id,
    )
    db.add(server)
    await db.flush()
    return server, group


@pytest.mark.asyncio
async def test_explicit_null_takes_the_server_out_of_its_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, _group = await _grouped_kea(db_session)
    token = await _token(db_session)
    await db_session.commit()

    resp = await client.put(
        f"/api/v1/dhcp/servers/{server.id}",
        json={"server_group_id": None},
        headers=_auth(token),
    )

    assert resp.status_code == 200, resp.text
    assert resp.json()["server_group_id"] is None
    await db_session.refresh(server)
    assert server.server_group_id is None

    audit = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_type == "dhcp_server",
                AuditLog.resource_id == str(server.id),
                AuditLog.action == "update",
            )
        )
    ).scalar_one()
    assert "server_group_id" in (audit.changed_fields or [])
    assert audit.new_value is not None
    assert audit.new_value["server_group_id"] is None


@pytest.mark.asyncio
async def test_omitting_the_key_leaves_the_group_alone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, group = await _grouped_kea(db_session)
    token = await _token(db_session)
    await db_session.commit()

    resp = await client.put(
        f"/api/v1/dhcp/servers/{server.id}",
        json={"description": "renamed"},
        headers=_auth(token),
    )

    assert resp.status_code == 200, resp.text
    await db_session.refresh(server)
    assert server.server_group_id == group.id
    assert server.description == "renamed"


@pytest.mark.asyncio
async def test_null_on_other_fields_still_means_leave_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Only ``server_group_id`` gains clear-on-null: ``name`` and ``host`` are
    NOT NULL, so treating their ``null`` as a write would be a 500."""
    server, group = await _grouped_kea(db_session)
    name = server.name
    token = await _token(db_session)
    await db_session.commit()

    resp = await client.put(
        f"/api/v1/dhcp/servers/{server.id}",
        json={"name": None, "host": None, "description": "x"},
        headers=_auth(token),
    )

    assert resp.status_code == 200, resp.text
    await db_session.refresh(server)
    assert server.name == name
    assert server.host == "10.0.0.3"
    assert server.server_group_id == group.id


@pytest.mark.asyncio
async def test_moving_to_another_group_still_works(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, _group = await _grouped_kea(db_session)
    other = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(other)
    token = await _token(db_session)
    await db_session.commit()

    resp = await client.put(
        f"/api/v1/dhcp/servers/{server.id}",
        json={"server_group_id": str(other.id)},
        headers=_auth(token),
    )

    assert resp.status_code == 200, resp.text
    await db_session.refresh(server)
    assert server.server_group_id == other.id
