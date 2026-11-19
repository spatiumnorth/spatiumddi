"""#1373 — the agent bundle lists a group's zones in a stable order.

Every list the structural fingerprint hashes is sorted — views, ACLs, TSIG
keys, catalog members, the records — except the zones, which were read with
no ORDER BY. Postgres then returns rows in the order its plan reads them: a
sequential scan, which a table as small as an appliance's zones usually
gets, returns each row where its newest version was written, and an UPDATE
writes a new version. Every record change updates its zone's row (``last_serial``),
so the zone moved to the end of the list, and the fingerprint, a hash of the
list as listed, moved with it: the agent re-rendered and reloaded the group
for a record change. With the serial out of the fingerprint this was the
rest of #1373 on any group of two zones or more (seen live: a record added
to one zone of a seeded group moved it from second to seventh in the
bundle's zone list).
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup
from app.services.dns.agent_config import build_config_bundle


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"ord-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Zone Order Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _group_with_server(db: AsyncSession) -> tuple[DNSServerGroup, DNSServer]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver="bind9",
        host=f"dns-{uuid.uuid4().hex[:6]}",
        name=f"dns-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
    )
    db.add(server)
    await db.flush()
    return grp, server


async def _zone(
    client: AsyncClient, headers: dict[str, str], grp: DNSServerGroup, name: str
) -> str:
    resp = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones", json={"name": name}, headers=headers
    )
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


async def _read_like_an_appliance(db: AsyncSession) -> None:
    """Read the zones with a sequential scan, the plan a small table usually
    gets. The test database holds enough zones for its planner to prefer the
    index on ``group_id``, which keeps the rows in place across an update and
    hides the reorder."""
    await db.execute(text("SET LOCAL enable_indexscan = off"))
    await db.execute(text("SET LOCAL enable_bitmapscan = off"))


@pytest.mark.asyncio
async def test_a_record_change_keeps_the_structural_etag_of_a_group_of_zones(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    grp, server = await _group_with_server(db_session)
    tag = uuid.uuid4().hex[:6]
    first, *_ = [await _zone(client, headers, grp, f"{c}{tag}.example.test") for c in "abc"]
    await _read_like_an_appliance(db_session)
    before = await build_config_bundle(db_session, server)

    resp = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{first}/records",
        json={"name": "www", "record_type": "A", "value": "192.0.2.10"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    await _read_like_an_appliance(db_session)
    after = await build_config_bundle(db_session, server)

    # The record reaches the agent, and the zone it went to stays where it was.
    assert after["etag"] != before["etag"]
    assert [z["name"] for z in after["zones"]] == [z["name"] for z in before["zones"]]
    assert after["structural_etag"] == before["structural_etag"]


@pytest.mark.asyncio
async def test_the_zones_are_listed_by_name(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _headers(db_session)
    grp, server = await _group_with_server(db_session)
    tag = uuid.uuid4().hex[:6]
    for name in (f"c{tag}.example.test", f"a{tag}.example.test", f"b{tag}.example.test"):
        await _zone(client, headers, grp, name)

    bundle = await build_config_bundle(db_session, server)

    names = [z["name"] for z in bundle["zones"]]
    assert names == sorted(names)
