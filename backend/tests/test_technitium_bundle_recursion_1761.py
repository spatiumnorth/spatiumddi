"""The Technitium bundle carries the group's recursion ACL (#1761).

The Technitium agent maps ``recursion_enabled`` / ``allow_recursion`` onto
``settings/set recursion``. ``allow_recursion`` was never in the agent
bundle, so the ACL an operator typed could not reach the daemon. It is
Technitium-only: the BIND9 agent renders a bare ``recursion yes|no`` and no
other driver's etag moves with it.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServer, DNSServerGroup, DNSServerOptions
from app.services.dns.agent_config import render_bundle_body


async def _server(db: AsyncSession, driver: str, **opts: object) -> DNSServer:
    group = DNSServerGroup(name=f"r-{uuid.uuid4().hex[:6]}", is_recursive=True)
    db.add(group)
    await db.flush()
    server = DNSServer(
        group_id=group.id, name=f"s-{uuid.uuid4().hex[:6]}", driver=driver, host="10.0.0.10"
    )
    db.add(server)
    db.add(DNSServerOptions(group_id=group.id, **opts))
    await db.commit()
    return server


@pytest.mark.asyncio
async def test_technitium_bundle_carries_allow_recursion(db_session: AsyncSession) -> None:
    server = await _server(db_session, "technitium", allow_recursion=["10.0.0.0/8", "!10.9.0.0/16"])
    body = (await render_bundle_body(db_session, server)).body
    assert body["options"]["allow_recursion"] == ["10.0.0.0/8", "!10.9.0.0/16"]
    assert body["options"]["recursion_enabled"] is True


@pytest.mark.asyncio
async def test_group_not_recursive_still_folds_into_recursion_enabled(
    db_session: AsyncSession,
) -> None:
    server = await _server(db_session, "technitium", allow_recursion=["any"])
    grp = await db_session.get(DNSServerGroup, server.group_id)
    assert grp is not None
    grp.is_recursive = False
    await db_session.commit()
    body = (await render_bundle_body(db_session, server)).body
    assert body["options"]["recursion_enabled"] is False


@pytest.mark.asyncio
async def test_other_drivers_do_not_gain_the_key(db_session: AsyncSession) -> None:
    server = await _server(db_session, "bind9", allow_recursion=["10.0.0.0/8"])
    body = (await render_bundle_body(db_session, server)).body
    assert "allow_recursion" not in body["options"]
