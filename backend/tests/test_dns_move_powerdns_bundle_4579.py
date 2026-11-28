"""What a PowerDNS server is told to serve after a zone or server move (#4579, C11).

The move tests assert database state. The agent renders only what its bundle
carries and deletes nothing it is not told about, so the contract that matters
to "what does the old server still serve" is the bundle each side receives:
the group the zone left must stop listing it, the group it joined must list it,
and a moved server must be handed its new group's zones and none of its old.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.services.dns.config_bundle import build_config_bundle


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username="root4579",
        email="root4579@example.com",
        display_name="root4579",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _group(db: AsyncSession, name: str) -> DNSServerGroup:
    g = DNSServerGroup(name=name, description="")
    db.add(g)
    await db.flush()
    return g


async def _pdns(db: AsyncSession, group: DNSServerGroup, name: str) -> DNSServer:
    s = DNSServer(
        group_id=group.id,
        name=name,
        driver="powerdns",
        host=name,
        port=53,
        roles=["authoritative"],
        status="active",
        is_primary=True,
    )
    db.add(s)
    await db.flush()
    return s


async def _zone(db: AsyncSession, group: DNSServerGroup, name: str) -> DNSZone:
    z = DNSZone(group_id=group.id, name=name, zone_type="primary")
    db.add(z)
    await db.flush()
    db.add(DNSRecord(zone_id=z.id, name="www", record_type="A", value="192.0.2.1", ttl=300))
    await db.flush()
    return z


async def _served(db: AsyncSession, server: DNSServer) -> set[str]:
    bundle = await build_config_bundle(db, server)
    return {z.name for z in bundle.zones}


@pytest.mark.asyncio
async def test_a_moved_zone_leaves_the_old_servers_bundle_and_joins_the_new(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    src = await _group(db_session, "pdns-src")
    dst = await _group(db_session, "pdns-dst")
    old = await _pdns(db_session, src, "pdns-a")
    new = await _pdns(db_session, dst, "pdns-b")
    moved = await _zone(db_session, src, "moved.example.")
    await _zone(db_session, src, "stays.example.")
    await _zone(db_session, dst, "already-there.example.")

    assert await _served(db_session, old) == {"moved.example.", "stays.example."}
    etag_before = (await build_config_bundle(db_session, old)).compute_etag()

    resp = await client.post(
        f"/api/v1/dns/groups/{src.id}/zones/{moved.id}/move/commit",
        json={
            "target_group_id": str(dst.id),
            "confirmation_zone_name": moved.name,
            "acknowledgements": [],
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text

    assert await _served(db_session, old) == {"stays.example."}
    assert await _served(db_session, new) == {"moved.example.", "already-there.example."}
    # The old agent long-polls on the etag; it must shift or the zone stays served.
    assert (await build_config_bundle(db_session, old)).compute_etag() != etag_before


@pytest.mark.asyncio
async def test_a_moved_server_is_handed_its_new_groups_zones_only(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    src = await _group(db_session, "pdns-src")
    dst = await _group(db_session, "pdns-dst")
    server = await _pdns(db_session, src, "pdns-a")
    await _zone(db_session, src, "old-group.example.")
    await _zone(db_session, dst, "new-group.example.")

    assert await _served(db_session, server) == {"old-group.example."}
    etag_before = (await build_config_bundle(db_session, server)).compute_etag()

    resp = await client.put(
        f"/api/v1/dns/groups/{src.id}/servers/{server.id}",
        json={"group_id": str(dst.id)},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    await db_session.refresh(server)

    assert await _served(db_session, server) == {"new-group.example."}
    assert (await build_config_bundle(db_session, server)).compute_etag() != etag_before
