"""#1540 — server create did not enforce one driver per group.

``DNS_DRIVERS.md`` §5.1 guarantees single-driver groups and the move
path has always 422'd a move that would mix drivers, but create (and a
driver change on update) never checked. A mixed group diverges
permanently and silently: record fan-out follows the primary's driver
while zone create/delete fan out to every agentless server, so the
group's servers end up holding different zones and records with no
warning.

Create and driver-change updates now reuse the move path's check
(``ensure_group_single_driver``) and answer 422. Already-mixed groups
stay readable — ``server_drivers`` still reports them honestly — they
just can't be manufactured through the API any more.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup


async def _superadmin(db: AsyncSession) -> str:
    user = User(
        username=f"root1540-{uuid.uuid4().hex[:6]}",
        email=f"root1540-{uuid.uuid4().hex[:6]}@example.com",
        display_name="root1540",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


async def _group(db: AsyncSession, name: str) -> DNSServerGroup:
    g = DNSServerGroup(name=name, description="")
    db.add(g)
    await db.flush()
    return g


async def _server(
    db: AsyncSession, group: DNSServerGroup, name: str, *, driver: str = "bind9"
) -> DNSServer:
    s = DNSServer(
        group_id=group.id,
        name=name,
        driver=driver,
        host=name,
        port=53,
        roles=["authoritative"],
        status="active",
    )
    db.add(s)
    await db.flush()
    return s


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _create_url(group_id: uuid.UUID) -> str:
    return f"/api/v1/dns/groups/{group_id}/servers"


# ── Create ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_second_driver_in_group_422s(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session)
    grp = await _group(db_session, "bind-group")
    await _server(db_session, grp, "ns1", driver="bind9")

    resp = await client.post(
        _create_url(grp.id),
        json={"name": "ns2", "driver": "powerdns", "host": "ns2"},
        headers=_auth(token),
    )
    assert resp.status_code == 422, resp.text
    assert "single-driver" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_create_same_driver_in_group_still_works(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session)
    grp = await _group(db_session, "bind-group-2")
    await _server(db_session, grp, "ns1", driver="bind9")

    resp = await client.post(
        _create_url(grp.id),
        json={"name": "ns2", "driver": "bind9", "host": "ns2"},
        headers=_auth(token),
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["driver"] == "bind9"


@pytest.mark.asyncio
async def test_create_first_server_in_empty_group_accepts_any_driver(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session)
    grp = await _group(db_session, "empty-group")

    resp = await client.post(
        _create_url(grp.id),
        json={"name": "ns1", "driver": "powerdns", "host": "ns1"},
        headers=_auth(token),
    )
    assert resp.status_code == 201, resp.text


# ── Driver change on update ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_driver_change_that_would_mix_the_group_422s(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session)
    grp = await _group(db_session, "bind-group-3")
    await _server(db_session, grp, "ns1", driver="bind9")
    srv = await _server(db_session, grp, "ns2", driver="bind9")

    resp = await client.put(
        f"{_create_url(grp.id)}/{srv.id}",
        json={"driver": "powerdns"},
        headers=_auth(token),
    )
    assert resp.status_code == 422, resp.text
    assert "single-driver" in resp.json()["detail"]

    await db_session.refresh(srv)
    assert srv.driver == "bind9"


@pytest.mark.asyncio
async def test_driver_change_for_a_lone_server_is_allowed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A group whose only server changes driver stays single-driver —
    the server's own current driver must not count against it."""
    token = await _superadmin(db_session)
    grp = await _group(db_session, "solo-group")
    srv = await _server(db_session, grp, "ns1", driver="bind9")

    resp = await client.put(
        f"{_create_url(grp.id)}/{srv.id}",
        json={"driver": "powerdns"},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["driver"] == "powerdns"


@pytest.mark.asyncio
async def test_driver_change_combined_with_move_is_checked_by_the_move(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Change driver AND move in one request: the move path validates
    the new driver against the target group. Refusing up front against
    the source group would block the legitimate combined change."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src-bind")
    await _server(db_session, src, "ns1", driver="bind9")
    srv = await _server(db_session, src, "ns2", driver="bind9")
    dst = await _group(db_session, "dst-pdns")
    await _server(db_session, dst, "ns9", driver="powerdns")

    resp = await client.put(
        f"{_create_url(src.id)}/{srv.id}",
        json={"driver": "powerdns", "group_id": str(dst.id)},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text
    body: dict[str, Any] = resp.json()
    assert body["driver"] == "powerdns"
    assert body["group_id"] == str(dst.id)
