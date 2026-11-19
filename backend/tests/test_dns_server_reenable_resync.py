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


# ── #2654: a dynamic zone's re-render waits for the server's ingest report ──


async def _ingest(
    client: AsyncClient, server: DNSServer, zone_name: str, live: dict[str, str]
) -> dict[str, object]:
    """``server``'s agent posts what its daemon serves in ``zone_name``."""
    from app.api.v1.dns.agents import _auth_agent  # noqa: PLC0415
    from app.main import app  # noqa: PLC0415

    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        resp = await client.post(
            "/api/v1/dns/agents/ingested-records",
            json={
                "zone_name": zone_name,
                "records": [
                    {"name": n, "record_type": "A", "value": v, "ttl": 300}
                    for n, v in sorted(live.items())
                ],
            },
        )
    finally:
        app.dependency_overrides.pop(_auth_agent, None)
    assert resp.status_code == 200, resp.text
    return dict(resp.json())


class _Agent:
    """What ``server``'s daemon serves in one zone, driven the way the agent
    drives it: a poll whose structural etag moved re-renders the zone from the
    bundle body (the database's copy), replacing whatever the daemon held."""

    def __init__(self, db: AsyncSession, server: DNSServer, zone_id: str) -> None:
        self.db, self.server, self.zone_id = db, server, zone_id
        self.live: dict[str, str] = {}
        self.etag: object = None

    async def poll(self) -> bool:
        await self.db.refresh(self.server)
        bundle = await build_config_bundle(self.db, self.server)
        await self.db.commit()
        rendered = bundle["structural_etag"] != self.etag
        if rendered:
            self.live = _records(bundle, self.zone_id)
            self.etag = bundle["structural_etag"]
        return rendered


async def _dynamic_setup(
    client: AsyncClient, db: AsyncSession
) -> tuple[dict[str, str], DNSServerGroup, DNSServer, DNSServer, str, str]:
    from app.models.dns import DNSZone  # noqa: PLC0415

    headers, grp, ns1, ns2, zone_id = await _setup(client, db)
    zone = await db.get(DNSZone, uuid.UUID(zone_id))
    assert zone is not None
    zone.dynamic_update_enabled = True
    await db.commit()
    return headers, grp, ns1, ns2, zone_id, zone.name.rstrip(".")


@pytest.mark.asyncio
async def test_a_record_learned_while_disabled_survives_the_re_enable_re_render(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The ddi-pg walk's case 8. A writer adds W on ns2 while ns2 is disabled;
    ns2 is enabled again. The agent's next poll after the PUT used to come
    back with the #2281 forced re-render, which replaced the zone with the
    database's copy (no W) a second or two later, before ns2's ingest report
    could mirror W. W was gone from ns2 and never reached ns1."""
    from app.models.dns import DNSRecord, DNSRecordOp  # noqa: PLC0415

    headers, grp, ns1, ns2, zone_id, zone_name = await _dynamic_setup(client, db_session)
    agent = _Agent(db_session, ns2, zone_id)
    await agent.poll()
    await _ingest(client, ns1, zone_name, {})
    await _ingest(client, ns2, zone_name, agent.live)

    await _set_enabled(client, headers, grp, ns2, False)
    agent.live["laptop7"] = "10.0.0.77"  # nsupdate straight to ns2
    assert (await _ingest(client, ns2, zone_name, agent.live))["skipped"] == "server_disabled"

    await _set_enabled(client, headers, grp, ns2, True)
    # The poll right after the PUT: no re-render yet, W still served.
    assert await agent.poll() is False
    assert agent.live.get("laptop7") == "10.0.0.77"

    # ns2's next sweep mirrors W and releases the owed re-render.
    r = await _ingest(client, ns2, zone_name, agent.live)
    assert r["added"] == 1 and r["zone_resync"] == "released"
    mirror = (
        (await db_session.execute(select(DNSRecord).where(DNSRecord.name == "laptop7")))
        .scalars()
        .all()
    )
    assert [(m.import_source, m.value) for m in mirror] == [("ddns_external", "10.0.0.77")]
    to_ns1 = (
        (
            await db_session.execute(
                select(DNSRecordOp).where(
                    DNSRecordOp.server_id == ns1.id, DNSRecordOp.op == "create"
                )
            )
        )
        .scalars()
        .all()
    )
    assert [o.record["name"] for o in to_ns1] == ["laptop7"]

    # The re-render now happens, and the database's copy keeps W.
    assert await agent.poll() is True
    assert agent.live.get("laptop7") == "10.0.0.77"


@pytest.mark.asyncio
async def test_a_dynamic_zone_server_still_catches_up_on_re_enable(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The #2281 guarantee (walk case 4) with the re-render deferred: records
    added and deleted while the server was off reach it once it reports."""
    headers, grp, _ns1, ns2, zone_id, zone_name = await _dynamic_setup(client, db_session)
    gone = await _record(client, headers, grp, zone_id, "gone")
    agent = _Agent(db_session, ns2, zone_id)
    await agent.poll()
    assert "gone" in agent.live
    await _ingest(client, ns2, zone_name, agent.live)

    await _set_enabled(client, headers, grp, ns2, False)
    await _record(client, headers, grp, zone_id, "added")
    resp = await client.delete(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone_id}/records/{gone}", headers=headers
    )
    assert resp.status_code == 204, resp.text
    await _set_enabled(client, headers, grp, ns2, True)

    assert await agent.poll() is False  # still the pre-disable copy
    await _ingest(client, ns2, zone_name, agent.live)
    assert await agent.poll() is True
    assert "added" in agent.live and "gone" not in agent.live


@pytest.mark.asyncio
async def test_the_re_render_goes_ahead_when_no_ingest_report_arrives(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A server whose reports never come (broken transfer, no ``dig``) is not
    left stale: the agent stale sweep releases the re-render after the wait.
    And disabling a server drops a re-render still owed from an earlier
    re-enable; the next re-enable owes a fresh one."""
    from datetime import UTC, datetime  # noqa: PLC0415

    from app.services.dns.server_resync import (  # noqa: PLC0415
        RESYNC_INGEST_WAIT,
        force_overdue_resyncs,
    )

    headers, grp, _ns1, ns2, zone_id, _zone_name = await _dynamic_setup(client, db_session)
    agent = _Agent(db_session, ns2, zone_id)
    await agent.poll()
    await _set_enabled(client, headers, grp, ns2, False)
    await _set_enabled(client, headers, grp, ns2, True)
    await db_session.refresh(ns2)
    assert ns2.zone_resync_pending_since is not None

    assert await force_overdue_resyncs(db_session) == []  # not overdue yet
    await db_session.commit()
    assert await agent.poll() is False

    ns2.zone_resync_pending_since = datetime.now(UTC) - RESYNC_INGEST_WAIT * 2
    await db_session.commit()
    assert [s.id for s in await force_overdue_resyncs(db_session)] == [ns2.id]
    await db_session.commit()
    assert await agent.poll() is True
    assert ns2.zone_resync_pending_since is None

    await _set_enabled(client, headers, grp, ns2, False)
    await _set_enabled(client, headers, grp, ns2, True)
    await _set_enabled(client, headers, grp, ns2, False)
    await db_session.refresh(ns2)
    assert ns2.zone_resync_pending_since is None
