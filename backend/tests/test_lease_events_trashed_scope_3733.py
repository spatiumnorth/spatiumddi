"""#3733: a lease-events batch writes nothing back into a scope in the Trash.

A scope delete puts the scope in the Trash and tears its leases down, with the
IPAM mirrors and the DDNS records they published. The agent keeps reporting
those leases: the renewals it had in flight, and every batch the API refused or
timed out while the delete ran, which it resends from its spool. The
lease-events handler wrote them back. A batch that had read its scope cache
before the delete inserted the leases again stamped with the trashed scope's
id (its locked read skipped the deleted rows); one that read it after inserted
them with no scope, through the global subnet match. Either way each got its
mirror and a live A record, because the subnet itself is live: a name the
operator removed resolved again, and the scope's addresses read as in use.

The handler now takes no event for an address of a scope of its group in the
Trash, and holds the scopes its events resolve to ``FOR KEY SHARE`` after its
lease rows, reading them again there, so a batch that read the scope as live
before the delete's stamp finds it gone after waiting.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncGenerator
from typing import Any

import pytest
from fastapi import Request
from httpx import ASGITransport, AsyncClient, Response
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.v1.dhcp import agents
from app.api.v1.dhcp.agents import _auth_agent
from app.db import get_db
from app.main import app
from app.models.dhcp import DHCPLease, DHCPScope, DHCPServer, DHCPServerGroup
from app.models.dns import DNSRecord, DNSZone
from app.models.ipam import IPAddress, Subnet
from tests.test_dhcp_scope_lease_teardown import _make_admin
from tests.test_lease_events_insert_order_3480 import _ddns_subnet, _lease

_SEEDED = ["10.31.1.10", "10.31.1.11"]
_NEW = "10.31.1.12"


@pytest.fixture
async def concurrent_client() -> AsyncGenerator[AsyncClient, None]:
    """A client whose every request runs on its own session + connection."""
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def _own_session() -> AsyncGenerator[AsyncSession, None]:
        async with factory() as session:
            yield session

    app.dependency_overrides[get_db] = _own_session
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(_auth_agent, None)
        await engine.dispose()


async def _estate(db: AsyncSession) -> tuple[DHCPServer, uuid.UUID, Subnet, dict[str, str]]:
    """A DDNS subnet with a scope bound to a group of one Kea server, whose
    agent auth is answered from an ``x-test-server`` header, and an admin."""
    _, token = await _make_admin(db)
    subnet, _block = await _ddns_subnet(db)
    tag = uuid.uuid4().hex[:6]
    grp = DHCPServerGroup(name=f"g-{tag}", description="")
    db.add(grp)
    await db.flush()
    server = DHCPServer(
        name=f"k-{tag}", driver="kea", host="127.0.0.1", port=67, server_group_id=grp.id
    )
    scope = DHCPScope(group_id=grp.id, subnet_id=subnet.id, is_active=True)
    db.add_all([server, scope])
    await db.commit()

    def _agent(request: Request) -> tuple[DHCPServer, dict[str, Any]]:
        assert request.headers["x-test-server"] == str(server.id)
        return server, {}

    app.dependency_overrides[_auth_agent] = _agent
    return server, scope.id, subnet, {"Authorization": f"Bearer {token}"}


async def _post(client: AsyncClient, server: DHCPServer, ips: list[str]) -> Response:
    return await client.post(
        "/api/v1/dhcp/agents/lease-events",
        headers={"x-test-server": str(server.id)},
        json={"leases": [_lease(ip, n) for n, ip in enumerate(ips)]},
    )


async def _counts(db: AsyncSession, server: DHCPServer, subnet: Subnet) -> dict[str, int]:
    """The server's leases, the subnet's lease mirrors, and the live DDNS
    records in the subnet's forward and reverse zones."""
    zones = select(DNSZone.id).where(
        or_(DNSZone.id == uuid.UUID(str(subnet.dns_zone_id)), DNSZone.linked_subnet_id == subnet.id)
    )
    return {
        "leases": (
            await db.execute(
                select(func.count()).select_from(DHCPLease).where(DHCPLease.server_id == server.id)
            )
        ).scalar_one(),
        "mirrors": (
            await db.execute(
                select(func.count())
                .select_from(IPAddress)
                .where(IPAddress.subnet_id == subnet.id, IPAddress.auto_from_lease.is_(True))
            )
        ).scalar_one(),
        "records": (
            await db.execute(
                select(func.count())
                .select_from(DNSRecord)
                .where(DNSRecord.zone_id.in_(zones), DNSRecord.auto_generated.is_(True))
            )
        ).scalar_one(),
    }


async def _seeded(client: AsyncClient, db: AsyncSession) -> tuple[Any, ...]:
    server, scope_id, subnet, admin = await _estate(db)
    assert (await _post(client, server, _SEEDED)).status_code == 200
    seeded = await _counts(db, server, subnet)
    assert seeded["leases"] == seeded["mirrors"] == 2 and seeded["records"] >= 2, seeded
    return server, scope_id, subnet, admin


_NOTHING = {"leases": 0, "mirrors": 0, "records": 0}


@pytest.mark.asyncio
async def test_a_batch_sent_after_the_scope_delete_writes_nothing_back(
    concurrent_client: AsyncClient, db_session: AsyncSession
) -> None:
    """The agent resends the batches the API refused while the delete ran, and
    renews what it still holds: none of it may land in the trashed scope's
    subnet, though the subnet is live."""
    server, scope_id, subnet, admin = await _seeded(concurrent_client, db_session)
    deleted = await concurrent_client.delete(f"/api/v1/dhcp/scopes/{scope_id}", headers=admin)
    assert deleted.status_code == 204, deleted.text
    assert await _counts(db_session, server, subnet) == _NOTHING

    late = await _post(concurrent_client, server, [*_SEEDED, _NEW])
    assert late.status_code == 200, late.text
    assert await _counts(db_session, server, subnet) == _NOTHING


@pytest.mark.asyncio
async def test_a_batch_that_read_the_scope_before_its_delete_writes_nothing_back(
    concurrent_client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A batch that read its scope cache while the scope was live, then waited
    while the delete committed (on the scope's lease rows, in the issue), must
    not insert the deleted leases again under the trashed scope's id."""
    server, scope_id, subnet, admin = await _seeded(concurrent_client, db_session)
    real = agents.lease_hostname_suppressed_subnets
    cached, deleted = asyncio.Event(), asyncio.Event()

    async def _held(db: AsyncSession, **kwargs: Any) -> Any:
        result = await real(db, **kwargs)
        cached.set()
        await asyncio.wait_for(deleted.wait(), timeout=30)
        return result

    monkeypatch.setattr(agents, "lease_hostname_suppressed_subnets", _held)
    batch = asyncio.create_task(_post(concurrent_client, server, [*_SEEDED, _NEW]))
    await asyncio.wait_for(cached.wait(), timeout=30)
    gone = await concurrent_client.delete(f"/api/v1/dhcp/scopes/{scope_id}", headers=admin)
    deleted.set()
    assert gone.status_code == 204, gone.text
    resp = await asyncio.wait_for(batch, timeout=60)
    assert resp.status_code == 200, resp.text
    assert await _counts(db_session, server, subnet) == _NOTHING


@pytest.mark.asyncio
async def test_a_new_live_scope_on_the_subnet_of_a_trashed_one_takes_its_leases(
    concurrent_client: AsyncClient, db_session: AsyncSession
) -> None:
    """The group may serve the subnet again with a new scope while the old one
    sits in the Trash: the events are the new scope's, and land."""
    server, scope_id, subnet, admin = await _seeded(concurrent_client, db_session)
    group_id = (await db_session.get(DHCPServer, server.id)).server_group_id
    deleted = await concurrent_client.delete(f"/api/v1/dhcp/scopes/{scope_id}", headers=admin)
    assert deleted.status_code == 204, deleted.text
    again = await concurrent_client.post(
        f"/api/v1/dhcp/subnets/{subnet.id}/dhcp-scopes",
        headers=admin,
        json={"group_id": str(group_id)},
    )
    assert again.status_code == 201, again.text
    new_scope = uuid.UUID(again.json()["id"])

    resp = await _post(concurrent_client, server, [_NEW])
    assert resp.status_code == 200, resp.text
    rows = (
        await db_session.execute(
            select(DHCPLease.ip_address, DHCPLease.scope_id).where(DHCPLease.server_id == server.id)
        )
    ).all()
    assert [(str(ip), sid) for ip, sid in rows] == [(_NEW, new_scope)]
    assert (await _counts(db_session, server, subnet))["mirrors"] == 1
