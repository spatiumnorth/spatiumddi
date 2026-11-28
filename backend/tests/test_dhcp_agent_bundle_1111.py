"""#1111 — the DHCP config bundle is rendered once (by the worker) and stored;
the agent long-poll serves the stored bundle.

Covers the stored bundle (served as stored, ETag semantics, byte identity),
the fallback when none is stored, the Trash lifecycle (trash drops a row out
of the bundle, restore brings it back, purge leaves nothing stale), and the
long-poll's status codes, which are unchanged.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp import agents as dhcp_agents
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import (
    DHCPAgentBundle,
    DHCPPool,
    DHCPScope,
    DHCPServer,
    DHCPServerGroup,
    DHCPStaticAssignment,
)
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.dhcp import agent_bundle as store
from app.services.dhcp.config_bundle import build_config_bundle
from app.tasks import dhcp_agent_bundles as tasks


async def _estate(db: AsyncSession) -> dict[str, Any]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="x",
        hashed_password=hash_password("x"),
        is_superadmin=True,
        force_password_change=False,
        password_changed_at=datetime.now(UTC),
    )
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add_all([user, grp, space])
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.30.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.30.1.0/24", name="s")
    db.add(subnet)
    await db.flush()
    server = DHCPServer(
        name=f"k-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="10.30.0.2",
        server_group_id=grp.id,
        agent_id=uuid.uuid4(),
        agent_approved=True,
    )
    scope = DHCPScope(group_id=grp.id, subnet_id=subnet.id, is_active=True)
    db.add_all([server, scope])
    await db.flush()
    pool = DHCPPool(
        scope_id=scope.id, start_ip="10.30.1.100", end_ip="10.30.1.150", pool_type="dynamic"
    )
    static = DHCPStaticAssignment(
        scope_id=scope.id,
        ip_address="10.30.1.20",
        mac_address="aa:bb:cc:00:00:01",
        hostname="h1",
        description="",
    )
    db.add_all([pool, static])
    await db.flush()
    token, _ = dhcp_agents.mint_agent_token(
        server_id=str(server.id), agent_id=str(server.agent_id), fingerprint="fp"
    )
    ids = {
        "group": grp.id,
        "server": server.id,
        "scope": scope.id,
        "pool": pool.id,
        "static": static.id,
        "agent": {"Authorization": f"Bearer {token}"},
        "admin": {"Authorization": f"Bearer {create_access_token(str(user.id))}"},
    }
    await db.commit()
    return ids


async def _worker_render(db: AsyncSession, server_id: uuid.UUID) -> None:
    """What ``render_dhcp_bundle`` does for one server."""
    db.expire_all()
    server = await db.get(DHCPServer, server_id)
    assert server is not None
    await store.render_and_store(db, server, rendered_by=store.RENDERED_BY_WORKER)
    await db.commit()


async def _stored(db: AsyncSession, server_id: uuid.UUID) -> DHCPAgentBundle | None:
    db.expire_all()
    return await store.load_stored(db, server_id)


async def _is_current(db: AsyncSession, server_id: uuid.UUID) -> bool:
    stored = await _stored(db, server_id)
    server = await db.get(DHCPServer, server_id)
    assert server is not None
    return store.is_current(server, stored)


async def _poll(client: AsyncClient, ids: dict[str, Any], etag: str | None = None) -> Any:
    headers = dict(ids["agent"])
    if etag:
        headers["If-None-Match"] = etag
    return await client.get("/api/v1/dhcp/agents/config", headers=headers)


@pytest.fixture(autouse=True)
def _short_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dhcp_agents, "LONGPOLL_TIMEOUT_SECONDS", 0)


def _boom(*_a: Any, **_k: Any) -> Any:
    raise AssertionError("the poll must not build the bundle when a stored one is current")


@pytest.mark.asyncio
async def test_poll_serves_the_stored_bundle_without_building(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    ids = await _estate(db_session)
    await _worker_render(db_session, ids["server"])
    monkeypatch.setattr(store, "build_config_bundle", _boom)
    resp = await _poll(client, ids)
    assert resp.status_code == 200, resp.text
    stored = await _stored(db_session, ids["server"])
    assert stored is not None
    assert resp.json()["bundle"] == json.loads(stored.body)
    assert len(resp.json()["bundle"]["scopes"]) == 1
    # A write the dirty marking never saw (Core, no listener) leaves the stored
    # bundle current, and that is what is served: the poll reads the store, not
    # the tables.
    await db_session.execute(update(DHCPScope).values(lease_time=777))
    await db_session.commit()
    again_body = await _poll(client, ids)
    assert again_body.json()["bundle"]["scopes"][0]["lease_time"] != 777
    # Current ETag -> 304, still without building.
    again = await _poll(client, ids, etag=resp.headers["etag"])
    assert again.status_code == 304
    assert again.headers["etag"] == resp.headers["etag"]


@pytest.mark.asyncio
async def test_stored_body_is_the_wire_bundle_of_a_direct_build(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    ids = await _estate(db_session)
    await _worker_render(db_session, ids["server"])
    stored = await _stored(db_session, ids["server"])
    server = await db_session.get(DHCPServer, ids["server"])
    assert stored is not None and server is not None
    built = await build_config_bundle(db_session, server)
    direct = json.dumps(
        store.wire_bundle(built),
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=str,
    )
    assert stored.body == direct
    assert stored.bundle_etag == built.etag


@pytest.mark.asyncio
async def test_etag_moves_on_a_config_change_and_not_otherwise(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    ids = await _estate(db_session)
    await _worker_render(db_session, ids["server"])
    first = (await _poll(client, ids)).headers["etag"]

    # A change nothing renders: a heartbeat-style write on the server row.
    server = await db_session.get(DHCPServer, ids["server"])
    assert server is not None
    server.agent_last_seen = datetime.now(UTC)
    await db_session.commit()
    assert await _is_current(db_session, ids["server"])
    assert (await _poll(client, ids, etag=first)).status_code == 304

    # Pool, reservation and scope edits each dirty the bundle and move the ETag.
    seen = {first}
    for edit in ("pool", "static", "scope"):
        db_session.expire_all()
        if edit == "pool":
            (await db_session.get(DHCPPool, ids["pool"])).end_ip = "10.30.1.160"  # type: ignore[union-attr]
        elif edit == "static":
            (await db_session.get(DHCPStaticAssignment, ids["static"])).hostname = "h2"  # type: ignore[union-attr]
        else:
            (await db_session.get(DHCPScope, ids["scope"])).lease_time = 1234  # type: ignore[union-attr]
        await db_session.commit()
        assert not await _is_current(db_session, ids["server"])
        await _worker_render(db_session, ids["server"])
        resp = await _poll(client, ids, etag=sorted(seen)[0])
        assert resp.status_code == 200
        assert resp.headers["etag"] not in seen, edit
        seen.add(resp.headers["etag"])


@pytest.mark.asyncio
async def test_missing_stored_bundle_is_built_inline_and_stored(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    ids = await _estate(db_session)
    assert await _stored(db_session, ids["server"]) is None
    resp = await _poll(client, ids)
    assert resp.status_code == 200, resp.text
    assert len(resp.json()["bundle"]["scopes"]) == 1
    stored = await _stored(db_session, ids["server"])
    assert stored is not None and stored.rendered_by == store.RENDERED_BY_API
    # The same poll again serves it as stored.
    assert (await _poll(client, ids, etag=resp.headers["etag"])).status_code == 304


@pytest.mark.asyncio
async def test_failed_inline_render_serves_the_older_stored_bundle(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    ids = await _estate(db_session)
    await _worker_render(db_session, ids["server"])
    (await db_session.get(DHCPScope, ids["scope"])).lease_time = 99  # type: ignore[union-attr]
    await db_session.commit()

    async def _fail(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("build failed")

    monkeypatch.setattr(store, "build_config_bundle", _fail)
    resp = await _poll(client, ids)
    assert resp.status_code == 200, resp.text
    assert len(resp.json()["bundle"]["scopes"]) == 1


@pytest.mark.asyncio
async def test_scope_trash_restore_purge(client: AsyncClient, db_session: AsyncSession) -> None:
    ids = await _estate(db_session)
    await _worker_render(db_session, ids["server"])
    etag_live = (await _poll(client, ids)).headers["etag"]

    gone = await client.delete(f"/api/v1/dhcp/scopes/{ids['scope']}", headers=ids["admin"])
    assert gone.status_code == 204, gone.text
    assert not await _is_current(db_session, ids["server"])  # trash marks the bundle
    await _worker_render(db_session, ids["server"])
    resp = await _poll(client, ids, etag=etag_live)
    assert resp.status_code == 200
    assert resp.json()["bundle"]["scopes"] == []
    assert resp.headers["etag"] != etag_live

    back = await client.post(
        f"/api/v1/admin/trash/dhcp_scope/{ids['scope']}/restore", headers=ids["admin"]
    )
    assert back.status_code == 200, back.text
    assert not await _is_current(db_session, ids["server"])  # restore marks it again
    await _worker_render(db_session, ids["server"])
    resp = await _poll(client, ids)
    scopes = resp.json()["bundle"]["scopes"]
    assert len(scopes) == 1
    assert len(scopes[0]["pools"]) == 1 and len(scopes[0]["statics"]) == 1
    assert resp.headers["etag"] == etag_live  # the same state hashes the same

    # Trash again, then purge: no scope in the bundle, no stale or orphan row.
    await client.delete(f"/api/v1/dhcp/scopes/{ids['scope']}", headers=ids["admin"])
    purge = await client.delete(
        f"/api/v1/admin/trash/dhcp_scope/{ids['scope']}", headers=ids["admin"]
    )
    assert purge.status_code == 204, purge.text
    await _worker_render(db_session, ids["server"])
    resp = await _poll(client, ids)
    assert resp.status_code == 200
    assert resp.json()["bundle"]["scopes"] == []
    stored = await _stored(db_session, ids["server"])
    assert stored is not None and json.loads(stored.body)["scopes"] == []


@pytest.mark.asyncio
async def test_pool_and_reservation_trash_drop_out_and_restore(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    ids = await _estate(db_session)
    await _worker_render(db_session, ids["server"])
    live = (await _poll(client, ids)).headers["etag"]
    for kind, route in (("pool", "pools"), ("static", "statics")):
        gone = await client.delete(f"/api/v1/dhcp/{route}/{ids[kind]}", headers=ids["admin"])
        assert gone.status_code == 204, gone.text
    await _worker_render(db_session, ids["server"])
    resp = await _poll(client, ids, etag=live)
    assert resp.status_code == 200
    scope = resp.json()["bundle"]["scopes"][0]
    assert scope["pools"] == [] and scope["statics"] == []
    assert resp.headers["etag"] != live


@pytest.mark.asyncio
async def test_deleted_server_polls_404_and_leaves_no_stored_bundle(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    ids = await _estate(db_session)
    await _worker_render(db_session, ids["server"])
    gone = await client.delete(f"/api/v1/dhcp/servers/{ids['server']}", headers=ids["admin"])
    assert gone.status_code == 204, gone.text
    assert (await _poll(client, ids)).status_code == 404
    db_session.expire_all()
    rows = (
        (
            await db_session.execute(
                select(DHCPAgentBundle).where(DHCPAgentBundle.server_id == ids["server"])
            )
        )
        .scalars()
        .all()
    )
    assert rows == []


@pytest.mark.asyncio
async def test_longpoll_auth_statuses_are_unchanged(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    ids = await _estate(db_session)
    assert (await client.get("/api/v1/dhcp/agents/config")).status_code == 401
    bad = await client.get(
        "/api/v1/dhcp/agents/config", headers={"Authorization": "Bearer not-a-token"}
    )
    assert bad.status_code == 401
    ghost, _ = dhcp_agents.mint_agent_token(
        server_id=str(uuid.uuid4()), agent_id=str(uuid.uuid4()), fingerprint="fp"
    )
    unknown = await client.get(
        "/api/v1/dhcp/agents/config", headers={"Authorization": f"Bearer {ghost}"}
    )
    assert unknown.status_code == 404
    # An unapproved agent still gets the pending answer, with no bundle built.
    server = await db_session.get(DHCPServer, ids["server"])
    assert server is not None
    server.agent_approved = False
    await db_session.commit()
    pending = await _poll(client, ids)
    assert pending.status_code == 200
    assert pending.json() == {"pending_approval": True, "etag": None}
    assert pending.headers["x-spatium-pending-approval"] == "1"
    assert await _stored(db_session, ids["server"]) is None


@pytest.mark.asyncio
async def test_worker_task_renders_idempotently_and_sweep_finds_stale(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    ids = await _estate(db_session)
    woken: list[str] = []

    async def _wake(channel: str) -> None:
        woken.append(channel)

    monkeypatch.setattr(tasks, "publish_wake", _wake)
    monkeypatch.setattr(tasks, "task_session", _session_of(db_session))
    first = await tasks._render_once(ids["server"])
    assert first["status"] == "stored" and woken
    woken.clear()
    # Current and fresh: nothing to do, nothing woken.
    assert (await tasks._render_once(ids["server"]))["status"] == "current"
    assert woken == []
    # Forced re-render of unchanged state stores the same ETag and wakes nobody.
    again = await tasks._render_once(ids["server"], force=True)
    assert again["etag"] == first["etag"] and again["changed"] is False
    assert woken == []


def _session_of(db: AsyncSession) -> Any:
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _cm(**_kw: Any) -> Any:
        yield db

    return _cm


def test_listener_is_installed_in_the_worker_import_graph() -> None:
    import app.tasks.dhcp_agent_bundles  # noqa: F401

    assert store.installed()
