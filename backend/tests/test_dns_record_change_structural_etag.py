"""#1373 — a record-only change in a group without views leaves the structural
etag alone.

The agent re-renders and reloads only when the bundle's structural etag
moves; a record-only change is meant to reach it as RFC 2136 ops instead
(``agent_config.py``: "Structural fingerprint excludes records and pending
ops so record-only changes don't trigger a full daemon reload"). Since #430
the zone payload also carries ``serial`` — the zone's last_serial, which the
agent's zone-state reporter reads — and every record change bumps it. With
the serial in the fingerprint, every record change on a flat group moved the
structural etag, and the BIND9 agent re-rendered the zone and froze, reloaded
and thawed it beside the RFC 2136 update. The serial now stays out of the
fingerprint with the records, and stays in the payload. Under views records
are part of the fingerprint on purpose, so a record change still re-renders
there.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSView
from app.services.dns.agent_config import build_config_bundle


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"rec-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Record Change Admin",
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


async def _zone(client: AsyncClient, headers: dict[str, str], grp: DNSServerGroup) -> str:
    resp = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones",
        json={"name": f"z{uuid.uuid4().hex[:6]}.example.test"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


async def _add_record(
    client: AsyncClient, headers: dict[str, str], grp: DNSServerGroup, zone_id: str
) -> None:
    resp = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone_id}/records",
        json={"name": "www", "record_type": "A", "value": "192.0.2.10"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text


def _shipped(bundle: dict[str, object], zone_id: str) -> list[dict[str, object]]:
    return [z for z in bundle["zones"] if z["id"] == zone_id]  # type: ignore[attr-defined, index]


@pytest.mark.asyncio
async def test_a_record_change_on_a_flat_group_keeps_the_structural_etag(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    grp, server = await _group_with_server(db_session)
    zone_id = await _zone(client, headers, grp)
    before = await build_config_bundle(db_session, server)

    await _add_record(client, headers, grp, zone_id)
    after = await build_config_bundle(db_session, server)

    # The record reaches the agent (the full etag moves, so its long-poll
    # answers), and the zone's serial still ships and has moved with it ...
    assert after["etag"] != before["etag"]
    (zone_before,), (zone_after,) = _shipped(before, zone_id), _shipped(after, zone_id)
    assert [r["name"] for r in zone_after["records"]] == ["www"]  # type: ignore[attr-defined]
    assert zone_after["serial"] > zone_before["serial"]  # type: ignore[operator]
    # ... but nothing the agent renders from changed, so it does not re-render.
    assert after["structural_etag"] == before["structural_etag"]


@pytest.mark.asyncio
async def test_under_views_a_record_change_still_re_renders(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """RFC 2136 cannot target a view, so under views records are structural on
    purpose: a record change must still move the structural etag there."""
    headers = await _headers(db_session)
    grp, server = await _group_with_server(db_session)
    db_session.add(DNSView(group_id=grp.id, name="internal", match_clients=["10.0.0.0/8"]))
    await db_session.commit()
    zone_id = await _zone(client, headers, grp)
    before = await build_config_bundle(db_session, server)

    await _add_record(client, headers, grp, zone_id)
    after = await build_config_bundle(db_session, server)

    assert after["structural_etag"] != before["structural_etag"]


@pytest.mark.asyncio
async def test_a_zone_level_change_on_a_flat_group_still_moves_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The fingerprint is not frozen: a change the agent renders from (here the
    zone's TTL) still moves it, serial bump or not."""
    headers = await _headers(db_session)
    grp, server = await _group_with_server(db_session)
    zone_id = await _zone(client, headers, grp)
    before = await build_config_bundle(db_session, server)

    resp = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone_id}", json={"ttl": 300}, headers=headers
    )
    assert resp.status_code == 200, resp.text
    after = await build_config_bundle(db_session, server)

    assert after["structural_etag"] != before["structural_etag"]
