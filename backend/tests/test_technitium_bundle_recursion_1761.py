"""The Technitium bundle carries the group's recursion ACL (#1761).

The Technitium agent maps ``recursion_enabled`` / ``allow_recursion`` onto
``settings/set recursion``. ``allow_recursion`` was never in the agent
bundle, so the ACL an operator typed could not reach the daemon. BIND9 reads
it too since #1786; PowerDNS's etag does not move with it.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DEFAULT_ALLOW_RECURSION, DNSServer, DNSServerGroup, DNSServerOptions
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
async def test_powerdns_does_not_gain_the_key(db_session: AsyncSession) -> None:
    server = await _server(db_session, "powerdns", allow_recursion=["10.0.0.0/8"])
    body = (await render_bundle_body(db_session, server)).body
    assert "allow_recursion" not in body["options"]


@pytest.mark.asyncio
async def test_bind9_bundle_carries_allow_recursion_and_etag_shifts(
    db_session: AsyncSession,
) -> None:
    """#1786: the BIND9 agent renders ``allow-recursion`` from this key."""
    server = await _server(db_session, "bind9", allow_recursion=["10.0.0.0/8"])
    first = await render_bundle_body(db_session, server)
    assert first.body["options"]["allow_recursion"] == ["10.0.0.0/8"]

    opts = (
        await db_session.execute(
            select(DNSServerOptions).where(DNSServerOptions.group_id == server.group_id)
        )
    ).scalar_one()
    opts.allow_recursion = ["10.0.0.0/8", "192.168.0.0/16"]
    await db_session.commit()
    second = await render_bundle_body(db_session, server)
    assert second.etag != first.etag


@pytest.mark.asyncio
@pytest.mark.parametrize("driver", ["technitium", "bind9"])
async def test_fresh_group_bundle_carries_the_non_open_default(
    db_session: AsyncSession, driver: str
) -> None:
    """#1817: a group created with no options set ships local + private networks."""
    server = await _server(db_session, driver)  # no allow_recursion given
    body = (await render_bundle_body(db_session, server)).body
    assert body["options"]["allow_recursion"] == list(DEFAULT_ALLOW_RECURSION)


@pytest.mark.asyncio
async def test_group_without_an_options_row_ships_the_default(
    db_session: AsyncSession,
) -> None:
    group = DNSServerGroup(name=f"r-{uuid.uuid4().hex[:6]}", is_recursive=True)
    db_session.add(group)
    await db_session.flush()
    server = DNSServer(group_id=group.id, name="s", driver="bind9", host="10.0.0.10")
    db_session.add(server)
    await db_session.commit()
    body = (await render_bundle_body(db_session, server)).body
    assert body["options"]["allow_recursion"] == list(DEFAULT_ALLOW_RECURSION)
