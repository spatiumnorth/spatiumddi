"""#2281 — re-enabling an agent-based DNS server makes its agent re-render.

While a server is disabled it is left out of the record-op fan-out and its
agent keeps serving the config it last applied. In a group without views
records are not part of the structural etag, and the agent re-renders zone
files only when that etag moves, so before #2281 every record created,
changed or deleted while the server was off stayed missing or wrong on it
after it was enabled again. These tests drive the REST surface and assert on
the bundle the agent is served: what it carries, and whether it makes the
agent render (the structural etag against the one the agent last applied).
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecordOp, DNSServer, DNSServerGroup
from app.services.dns.agent_config import build_config_bundle


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"rs-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Resync Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _setup(
    client: AsyncClient, db: AsyncSession
) -> tuple[dict[str, str], DNSServerGroup, DNSServer, DNSServer, str]:
    """A flat group with two agent servers (so a record write still has an
    enabled server to fan out to while one is disabled) and one zone."""
    headers = await _headers(db)
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    servers = []
    for primary in (True, False):
        s = DNSServer(
            group_id=grp.id,
            driver="bind9",
            host=f"dns-{uuid.uuid4().hex[:6]}",
            name=f"dns-{uuid.uuid4().hex[:6]}",
            is_primary=primary,
            is_enabled=True,
        )
        db.add(s)
        servers.append(s)
    await db.commit()
    resp = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones",
        json={"name": f"z{uuid.uuid4().hex[:6]}.example.test"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return headers, grp, servers[0], servers[1], str(resp.json()["id"])


async def _record(
    client: AsyncClient, headers: dict[str, str], grp: DNSServerGroup, zone_id: str, name: str
) -> str:
    resp = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone_id}/records",
        json={"name": name, "record_type": "A", "value": "192.0.2.10"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


async def _set_enabled(
    client: AsyncClient,
    headers: dict[str, str],
    grp: DNSServerGroup,
    server: DNSServer,
    enabled: bool,
) -> None:
    resp = await client.put(
        f"/api/v1/dns/groups/{grp.id}/servers/{server.id}",
        json={"is_enabled": enabled},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text


def _records(bundle: dict[str, object], zone_id: str) -> dict[str, str]:
    (zone,) = [z for z in bundle["zones"] if z["id"] == zone_id]  # type: ignore[attr-defined, index]
    return {
        r["name"]: r["value"]  # type: ignore[index]
        for r in zone["records"]  # type: ignore[index]
        if r["type"] == "A"  # type: ignore[index]
    }


async def _queued(db: AsyncSession, server: DNSServer) -> list[DNSRecordOp]:
    return list(
        (
            await db.execute(
                select(DNSRecordOp).where(
                    DNSRecordOp.server_id == server.id,
                    DNSRecordOp.state.in_(("pending", "in_flight")),
                )
            )
        )
        .scalars()
        .all()
    )


@pytest.mark.asyncio
async def test_reenabled_server_re_renders_the_changes_made_while_it_was_off(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, grp, server, _other, zone_id = await _setup(client, db_session)
    changed = await _record(client, headers, grp, zone_id, "changed")
    deleted = await _record(client, headers, grp, zone_id, "deleted")
    # The agent applies this bundle, then drains the ops queued for the two
    # records above; from here on it serves exactly that.
    applied = await build_config_bundle(db_session, server)
    assert len(applied["pending_record_ops"]) == 2
    for op in await _queued(db_session, server):
        op.state = "applied"  # the agent's ack
    await db_session.commit()

    await _set_enabled(client, headers, grp, server, False)
    await _record(client, headers, grp, zone_id, "added")
    resp = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone_id}/records/{changed}",
        json={"value": "192.0.2.99"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    resp = await client.delete(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone_id}/records/{deleted}", headers=headers
    )
    assert resp.status_code == 204, resp.text
    # Disabled: none of the three reached this server as an op.
    assert await _queued(db_session, server) == []

    await _set_enabled(client, headers, grp, server, True)
    await db_session.refresh(server)
    after = await build_config_bundle(db_session, server)

    # The body carries the current records ...
    assert _records(after, zone_id) == {"changed": "192.0.2.99", "added": "192.0.2.10"}
    # ... and the agent renders them: its structural etag no longer matches
    # the one it applied, so it re-renders every zone from that body.
    assert after["structural_etag"] != applied["structural_etag"]


@pytest.mark.asyncio
async def test_ops_queued_before_the_disable_do_not_replay_over_the_re_render(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Each op carries the whole RRset as it was when queued (#773): one left
    from before the disable, shipped after the re-render, would put back a
    record deleted while the server was off."""
    headers, grp, server, _other, zone_id = await _setup(client, db_session)
    rec = await _record(client, headers, grp, zone_id, "gone")
    (stale,) = await _queued(db_session, server)

    await _set_enabled(client, headers, grp, server, False)
    resp = await client.delete(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone_id}/records/{rec}", headers=headers
    )
    assert resp.status_code == 204, resp.text
    await _set_enabled(client, headers, grp, server, True)

    await db_session.refresh(server)
    bundle = await build_config_bundle(db_session, server)
    assert "gone" not in _records(bundle, zone_id)
    assert [op["op_id"] for op in bundle["pending_record_ops"]] == []
    await db_session.refresh(stale)
    assert stale.state == "applied"
    assert await _queued(db_session, server) == []


@pytest.mark.asyncio
async def test_an_update_that_does_not_re_enable_leaves_the_structural_etag(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Only the disabled → enabled transition forces a re-render; saving an
    enabled server (here, with is_enabled re-sent) must not reload its zones."""
    headers, grp, server, _other, _zone_id = await _setup(client, db_session)
    before = await build_config_bundle(db_session, server)
    await db_session.commit()

    await _set_enabled(client, headers, grp, server, True)
    resp = await client.put(
        f"/api/v1/dns/groups/{grp.id}/servers/{server.id}",
        json={"notes": "edited"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text

    await db_session.refresh(server)
    after = await build_config_bundle(db_session, server)
    assert after["structural_etag"] == before["structural_etag"]
