"""#3143 — two live DHCP agent processes on one server identity.

The DHCP side of #2044 / #2219. ``dhcp_server`` carries one
``agent_token_hash``: a cloned Kea VM (or two containers on one state dir)
kept the same ``agent_id``, so each registration and each heartbeat rotation
minted a token whose hash replaced the other's. The pair traded 401 "Stale
token" and re-registrations forever and both reported as one server.

Pinned here: one process owns the server. A new process takes over at once (a
replacement stays seamless and raises nothing); the one it displaced is
refused with 409 on its poll AND its registration while the owner is live,
mints no token, and its heartbeat neither rotates the token nor writes its
reports to the row; the episode surfaces on the server row, in the MCP tool
and in the ``dhcp_agent_duplicate_instance`` alert once it persists; the
survivor takes the server back by itself when the owner stops. An agent that
sends no instance id behaves exactly as before.
"""

from __future__ import annotations

import importlib.util
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp import agents as agents_api
from app.core.security import create_access_token, hash_password
from app.models.alerts import AlertRule
from app.models.auth import User
from app.models.dhcp import DHCPConfigOp, DHCPServer, DHCPServerGroup
from app.services.agents import instance_ownership
from app.services.ai.tools.dhcp import ListDHCPServersArgs, list_dhcp_servers
from app.services.alert_rule_catalogue import rule_type_names
from app.services.alerts import (
    RULE_TYPE_DHCP_AGENT_DUPLICATE_INSTANCE,
    RULE_TYPES,
    _matching_dhcp_agent_duplicate_instance_subjects,
)
from app.services.dhcp.agent_token import hash_token, mint_agent_token

CONFIG_URL = "/api/v1/dhcp/agents/config"
HEARTBEAT_URL = "/api/v1/dhcp/agents/heartbeat"
REGISTER_URL = "/api/v1/dhcp/agents/register"
INSTANCE = "X-Spatium-Agent-Instance"
DUPLICATE = "X-Spatium-Duplicate-Agent-Instance"
PSK = "k3143"


@pytest.fixture(autouse=True)
def _fast_polls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agents_api, "LONGPOLL_TIMEOUT_SECONDS", 1)
    monkeypatch.setenv("DHCP_AGENT_KEY", PSK)


async def _agent(db: AsyncSession) -> tuple[DHCPServer, dict[str, str]]:
    grp = DHCPServerGroup(name=f"g3143-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DHCPServer(
        name=f"kea-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="10.0.0.1",
        port=67,
        server_group_id=grp.id,
        agent_id=uuid.uuid4(),
        agent_registered=True,
        agent_approved=True,
        agent_fingerprint="fp",
    )
    db.add(server)
    await db.flush()
    token, _exp = mint_agent_token(str(server.id), str(server.agent_id), "fp")
    server.agent_token_hash = hash_token(token)
    return server, {"Authorization": f"Bearer {token}"}


async def _reload(db: AsyncSession, server_id: uuid.UUID) -> DHCPServer:
    return (
        await db.execute(
            select(DHCPServer)
            .where(DHCPServer.id == server_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


async def _poll(client: AsyncClient, headers: dict[str, str], instance: str | None):
    h = dict(headers)
    if instance is not None:
        h[INSTANCE] = instance
    return await client.get(CONFIG_URL, headers=h)


async def _register(client: AsyncClient, server: DHCPServer, instance: str | None):
    h = {"X-DHCP-Agent-Key": PSK}
    if instance is not None:
        h[INSTANCE] = instance
    return await client.post(
        REGISTER_URL,
        headers=h,
        json={
            "hostname": server.name,
            "driver": "kea",
            "fingerprint": "fp",
            "agent_id": str(server.agent_id),
            "group_name": f"auto-{uuid.uuid4().hex[:6]}",
        },
    )


async def _user_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u3143-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


# ── the config poll ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_second_live_process_is_refused_and_only_the_owner_gets_ops(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, headers = await _agent(db_session)
    await db_session.commit()
    server_id = server.id

    assert (await _poll(client, headers, "agent-a")).status_code == 200
    # B starts while A is still alive: the newest arrival wins.
    assert (await _poll(client, headers, "agent-b")).status_code == 200

    # A polls again: a second live agent, not a replacement. Refused with the
    # header the agent keys its steady back-off on — not 401/404, which would
    # send it to re-register.
    op = DHCPConfigOp(server_id=server_id, op_type="apply_config", payload={}, status="pending")
    db_session.add(op)
    await db_session.commit()
    refused = await _poll(client, headers, "agent-a")
    assert refused.status_code == 409, refused.text
    assert refused.headers.get(DUPLICATE) == "1"
    assert "DHCP server" in refused.json()["detail"]
    assert "pending_ops" not in refused.json()

    owner = await _poll(client, headers, "agent-b")
    assert owner.status_code == 200
    assert [o["op_id"] for o in owner.json()["pending_ops"]] == [str(op.id)]

    srv = await _reload(db_session, server_id)
    assert srv.agent_instance == "agent-b"
    assert srv.agent_instances_displaced == ["agent-a"]
    assert srv.duplicate_agent_last_at is not None
    assert srv.duplicate_agent_ip


@pytest.mark.asyncio
async def test_a_replacement_takes_over_at_once_and_raises_no_duplicate(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, headers = await _agent(db_session)
    await db_session.commit()
    server_id = server.id
    for instance in ("old", "new", "newer"):
        assert (await _poll(client, headers, instance)).status_code == 200
    srv = await _reload(db_session, server_id)
    assert srv.agent_instance == "newer"
    assert srv.agent_instances_displaced == ["old", "new"]
    assert srv.duplicate_agent_last_at is None
    assert await _matching_dhcp_agent_duplicate_instance_subjects(db_session, None) == []  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_a_poll_that_loses_ownership_while_it_waits_ships_nothing(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, headers = await _agent(db_session)
    await db_session.commit()
    real_refresh = agents_api.refresh_agent_server

    async def _taken_over(db: AsyncSession, srv: DHCPServer) -> None:
        await real_refresh(db, srv)
        srv.agent_instance = "new-agent"  # what the replacement's claim committed

    monkeypatch.setattr(agents_api, "refresh_agent_server", _taken_over)
    resp = await _poll(client, headers, "old-agent")
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_the_survivor_takes_the_server_back_when_the_owner_stops(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, headers = await _agent(db_session)
    await db_session.commit()
    server_id = server.id
    assert (await _poll(client, headers, "agent-a")).status_code == 200
    assert (await _poll(client, headers, "agent-b")).status_code == 200
    assert (await _poll(client, headers, "agent-a")).status_code == 409

    srv = await _reload(db_session, server_id)
    srv.agent_instance_seen_at = datetime.now(UTC) - instance_ownership.OWNER_GONE_AFTER * 2
    await db_session.commit()

    assert (await _poll(client, headers, "agent-a")).status_code == 200
    srv = await _reload(db_session, server_id)
    assert srv.agent_instance == "agent-a"
    assert srv.agent_instances_displaced == ["agent-b"]


@pytest.mark.asyncio
async def test_an_agent_that_sends_no_instance_is_never_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, headers = await _agent(db_session)
    await db_session.commit()
    assert (await _poll(client, headers, "agent-a")).status_code == 200
    assert (await _poll(client, headers, "agent-b")).status_code == 200
    plain = await _poll(client, headers, None)
    assert plain.status_code == 200
    srv = await _reload(db_session, server.id)
    assert srv.agent_instance == "agent-b"  # an id-less poll claims nothing


# ── registration and token rotation (the #2219 half) ────────────────────────


@pytest.mark.asyncio
async def test_the_refused_process_cannot_register_and_stale_the_owner(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Before #3143 the refused process's re-registration rewrote the one
    token hash, the owner's next call was 401 "Stale token", the owner
    re-registered, and so on forever."""
    server, owner_headers = await _agent(db_session)
    await db_session.commit()
    server_id = server.id
    groups_before = await db_session.scalar(select(func.count()).select_from(DHCPServerGroup))

    assert (await _poll(client, owner_headers, "agent-a")).status_code == 200
    assert (await _poll(client, owner_headers, "agent-b")).status_code == 200

    refused = await _register(client, server, "agent-a")
    assert refused.status_code == 409, refused.text
    assert refused.headers.get(DUPLICATE) == "1"
    assert "agent_token" not in refused.json()

    # The owner's token is still the server's token.
    assert (await _poll(client, owner_headers, "agent-b")).status_code == 200
    srv = await _reload(db_session, server_id)
    assert srv.duplicate_agent_last_at is not None
    # Refused before anything was written: no auto-created group.
    assert (
        await db_session.scalar(select(func.count()).select_from(DHCPServerGroup)) == groups_before
    )

    # The owner itself, a never-seen process and an id-less (older) agent all
    # still register as before.
    for instance in ("agent-b", None):
        ok = await _register(client, server, instance)
        assert ok.status_code == 200, ok.text
        assert ok.json()["agent_token"]


@pytest.mark.asyncio
async def test_a_displaced_process_may_register_once_the_owner_is_gone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, headers = await _agent(db_session)
    await db_session.commit()
    assert (await _poll(client, headers, "agent-a")).status_code == 200
    assert (await _poll(client, headers, "agent-b")).status_code == 200
    srv = await _reload(db_session, server.id)
    srv.agent_instance_seen_at = datetime.now(UTC) - instance_ownership.OWNER_GONE_AFTER * 2
    await db_session.commit()
    assert (await _register(client, server, "agent-a")).status_code == 200


@pytest.mark.asyncio
async def test_the_refused_processs_heartbeat_neither_rotates_nor_reports(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, headers = await _agent(db_session)
    await db_session.commit()
    server_id = server.id
    assert (await _poll(client, headers, "agent-a")).status_code == 200
    assert (await _poll(client, headers, "agent-b")).status_code == 200

    owner = await client.post(
        HEARTBEAT_URL,
        headers={**headers, INSTANCE: "agent-b"},
        json={"config": {"status": "ok", "etag": "e1"}, "daemon": {"status": "ok"}},
    )
    assert owner.status_code == 200, owner.text
    srv = await _reload(db_session, server_id)
    assert srv.config_apply_status == "ok"
    hash_before = srv.agent_token_hash

    monkeypatch.setattr(agents_api, "needs_rotation", lambda payload: True)
    refused = await client.post(
        HEARTBEAT_URL,
        headers={**headers, INSTANCE: "agent-a"},
        json={
            "config": {"status": "reverted", "error": "kea config-test: boom"},
            "daemon": {"status": "degraded", "reason": "not serving"},
            "agent_version": "9.9.9-clone",
        },
    )
    assert refused.status_code == 200, refused.text
    assert refused.json()["rotated_token"] is None
    srv = await _reload(db_session, server_id)
    assert srv.agent_token_hash == hash_before
    assert srv.config_apply_status == "ok"
    assert srv.daemon_status == "ok"
    assert srv.agent_version != "9.9.9-clone"
    # Liveness still counts.
    assert srv.agent_last_seen is not None

    # The owner still rotates; so does an agent that sends no id.
    rotated = await client.post(HEARTBEAT_URL, headers={**headers, INSTANCE: "agent-b"}, json={})
    assert rotated.json()["rotated_token"]
    token = rotated.json()["rotated_token"]
    legacy = await client.post(
        HEARTBEAT_URL,
        headers={"Authorization": f"Bearer {token}"},
        json={"config": {"status": "reverted", "error": "x"}},
    )
    assert legacy.status_code == 200
    assert legacy.json()["rotated_token"]
    srv = await _reload(db_session, server_id)
    assert srv.config_apply_status == "reverted"


# ── surfacing: server row, MCP tool, alert ──────────────────────────────────


@pytest.mark.asyncio
async def test_a_persisting_duplicate_is_surfaced_on_the_row_the_tool_and_the_alert(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, headers = await _agent(db_session)
    user = await _user_headers(db_session)
    await db_session.commit()
    server_id = server.id

    assert (await _poll(client, headers, "agent-a")).status_code == 200
    assert (await _poll(client, headers, "agent-b")).status_code == 200
    assert (await _poll(client, headers, "agent-a")).status_code == 409

    # One refusal is an overlapping rollout's old pod as much as a clone.
    srv = await _reload(db_session, server_id)
    assert not instance_ownership.duplicate_active(srv)
    assert await _matching_dhcp_agent_duplicate_instance_subjects(db_session, None) == []  # type: ignore[arg-type]

    srv.duplicate_agent_first_at = datetime.now(UTC) - timedelta(minutes=3)
    await db_session.commit()
    assert (await _register(client, srv, "agent-a")).status_code == 409

    srv = await _reload(db_session, server_id)
    assert instance_ownership.duplicate_active(srv)
    hits = await _matching_dhcp_agent_duplicate_instance_subjects(db_session, None)  # type: ignore[arg-type]
    assert [h[0] for h in hits] == [f"dhcp_server:{server_id}"]
    assert "Two DHCP agent processes" in hits[0][2]

    row = await client.get(f"/api/v1/dhcp/servers/{server_id}", headers=user)
    assert row.status_code == 200, row.text
    assert row.json()["duplicate_agent"] is True
    assert row.json()["duplicate_agent_ip"]
    assert row.json()["duplicate_agent_since"] is not None

    admin = (await db_session.execute(select(User).where(User.is_superadmin.is_(True)))).scalar()
    tool = await list_dhcp_servers(db_session, admin, ListDHCPServersArgs())  # type: ignore[arg-type]
    mine = next(t for t in tool if t["id"] == str(server_id))
    assert mine["duplicate_agent"] is True and mine["duplicate_agent_ip"]

    # The extra agent is stopped: ten minutes later the episode is over.
    srv.duplicate_agent_last_at = datetime.now(UTC) - timedelta(minutes=11)
    srv.duplicate_agent_first_at = datetime.now(UTC) - timedelta(minutes=15)
    await db_session.commit()
    await _reload(db_session, server_id)
    assert await _matching_dhcp_agent_duplicate_instance_subjects(db_session, None) == []  # type: ignore[arg-type]
    row = await client.get(f"/api/v1/dhcp/servers/{server_id}", headers=user)
    assert row.json()["duplicate_agent"] is False
    assert row.json()["duplicate_agent_ip"] is None


# ── the alert rule is seeded once, by the migration ────────────────────────

_MIGRATION = (
    Path(__file__).resolve().parents[1]
    / "alembic"
    / "versions"
    / "833ee80c8c6b_dhcp_server_agent_instance.py"
)


def _load_migration() -> Any:
    spec = importlib.util.spec_from_file_location("_mig_833ee80c8c6b", _MIGRATION)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.asyncio
async def test_migration_seeds_one_enabled_rule_and_respects_an_existing_one(
    db_session: AsyncSession,
) -> None:
    mig = _load_migration()

    async def count() -> int:
        return int(
            await db_session.scalar(
                select(func.count())
                .select_from(AlertRule)
                .where(AlertRule.rule_type == RULE_TYPE_DHCP_AGENT_DUPLICATE_INSTANCE)
            )
            or 0
        )

    async def run_seed() -> None:
        await db_session.execute(mig.SEED_DUPLICATE_INSTANCE_RULE_SQL, mig.seed_params())
        await db_session.commit()

    await run_seed()
    await run_seed()
    assert await count() == 1
    rule = await db_session.scalar(
        select(AlertRule).where(AlertRule.rule_type == RULE_TYPE_DHCP_AGENT_DUPLICATE_INSTANCE)
    )
    assert rule is not None
    assert rule.enabled and rule.severity == "warning"
    assert rule.name == "Two DHCP agents on one server"
    assert rule.notify_syslog and rule.notify_webhook and not rule.notify_smtp
    # The evaluator and the catalogue know the type the migration hard-codes.
    assert RULE_TYPE_DHCP_AGENT_DUPLICATE_INSTANCE in RULE_TYPES
    assert RULE_TYPE_DHCP_AGENT_DUPLICATE_INSTANCE in rule_type_names()

    await db_session.delete(rule)
    db_session.add(
        AlertRule(
            name="mine",
            rule_type=RULE_TYPE_DHCP_AGENT_DUPLICATE_INSTANCE,
            severity="critical",
            enabled=True,
        )
    )
    await db_session.commit()
    await run_seed()
    assert await count() == 1


# ── first registration, a deleted row, approval-required installs ──────────


@pytest.mark.asyncio
async def test_a_new_agent_still_registers_and_auto_creates_its_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The agent_id lookup now runs before the group auto-create; a first
    registration (unknown agent_id, unknown group) is unchanged by it."""
    agent_id = uuid.uuid4()
    group = f"auto-{uuid.uuid4().hex[:6]}"
    resp = await client.post(
        REGISTER_URL,
        headers={"X-DHCP-Agent-Key": PSK, INSTANCE: "first-process"},
        json={
            "hostname": f"kea-{uuid.uuid4().hex[:6]}",
            "driver": "kea",
            "fingerprint": "fp",
            "agent_id": str(agent_id),
            "group_name": group,
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["agent_token"]
    srv = (
        await db_session.execute(select(DHCPServer).where(DHCPServer.agent_id == agent_id))
    ).scalar_one()
    grp = (
        await db_session.execute(select(DHCPServerGroup).where(DHCPServerGroup.name == group))
    ).scalar_one()
    assert srv.server_group_id == grp.id
    # Registration names the process but does not claim the server; the
    # first poll does.
    assert srv.agent_instance is None


@pytest.mark.asyncio
async def test_a_deleted_rows_refused_process_re_registers_onto_a_new_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Pattern 3: a 404 sends the agent to re-register from its PSK. The
    ownership state lived on the deleted row, so even the process that row
    had refused registers again (and is not locked out)."""
    server, headers = await _agent(db_session)
    await db_session.commit()
    assert (await _poll(client, headers, "agent-a")).status_code == 200
    assert (await _poll(client, headers, "agent-b")).status_code == 200
    assert (await _register(client, server, "agent-a")).status_code == 409

    srv = await _reload(db_session, server.id)
    await db_session.delete(srv)
    await db_session.commit()

    resp = await _register(client, server, "agent-a")
    assert resp.status_code == 200, resp.text
    assert resp.json()["server_id"] != str(server.id)


@pytest.mark.asyncio
async def test_an_agent_awaiting_approval_claims_nothing_until_approved(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DHCP_REQUIRE_AGENT_APPROVAL: a pending agent's poll is answered with
    the pending marker, never 409, and claims nothing; once approved, its
    first poll takes the server."""
    monkeypatch.setenv("DHCP_REQUIRE_AGENT_APPROVAL", "true")
    agent_id = uuid.uuid4()
    reg = await client.post(
        REGISTER_URL,
        headers={"X-DHCP-Agent-Key": PSK, INSTANCE: "p1"},
        json={
            "hostname": f"kea-{uuid.uuid4().hex[:6]}",
            "driver": "kea",
            "fingerprint": "fp",
            "agent_id": str(agent_id),
        },
    )
    assert reg.status_code == 200, reg.text
    assert reg.json()["pending_approval"] is True
    headers = {"Authorization": f"Bearer {reg.json()['agent_token']}"}

    for instance in ("p1", "p2", "p1"):
        pending = await _poll(client, headers, instance)
        assert pending.status_code == 200, pending.text
        assert pending.json().get("pending_approval") is True
    srv = (
        await db_session.execute(select(DHCPServer).where(DHCPServer.agent_id == agent_id))
    ).scalar_one()
    assert srv.agent_instance is None and not srv.agent_instances_displaced

    srv.agent_approved = True
    await db_session.commit()
    assert (await _poll(client, headers, "p1")).status_code == 200
    srv = await _reload(db_session, srv.id)
    assert srv.agent_instance == "p1"
