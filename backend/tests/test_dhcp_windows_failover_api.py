"""#1110 — the failover views: group + scope REST routes and the MCP tool.

All three read the stored observations — never WinRM — through one report
builder, so the page and the copilot cannot disagree about a scope.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import (
    DHCPFailoverRelationship,
    DHCPScope,
    DHCPServer,
    DHCPServerGroup,
    DHCPServerScopeState,
)
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.dhcp.windows_failover import OBSERVATION_FRESH_FOR

CIDR = "10.60.0.0/24"
SID = "10.60.0.0"


async def _token(db: AsyncSession) -> tuple[str, User]:
    user = User(
        username=f"fo-{uuid.uuid4().hex[:6]}",
        email=f"fo-{uuid.uuid4().hex[:6]}@example.test",
        display_name="fo",
        hashed_password=hash_password("x"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id)), user


def _rel(server: DHCPServer, partner: str, **kw: Any) -> DHCPFailoverRelationship:
    fields: dict[str, Any] = {
        "server_id": server.id,
        "name": "dhcp1-dhcp2",
        "partner_server": partner,
        "mode": "LoadBalance",
        "state": "Normal",
        "load_balance_percent": 50,
        "max_client_lead_time_seconds": 3600,
        "enable_auth": True,
        "scope_ids": [SID],
    }
    fields.update(kw)
    return DHCPFailoverRelationship(**fields)


def _state(server: DHCPServer, cidr: str = CIDR, **kw: Any) -> DHCPServerScopeState:
    fields: dict[str, Any] = {
        "server_id": server.id,
        "scope_cidr": cidr,
        "is_active": True,
        "start_ip": "10.60.0.10",
        "end_ip": "10.60.0.200",
        "exclusions": [],
        "config_hash": "same",
    }
    fields.update(kw)
    return DHCPServerScopeState(**fields)


async def _world(db: AsyncSession) -> dict[str, Any]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.60.0.0/16", name="blk")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=CIDR, name="office")
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add_all([subnet, group])
    await db.flush()
    now = datetime.now(UTC)
    s1 = DHCPServer(
        name="dhcp1",
        driver="windows_dhcp",
        host="dhcp1.corp.example",
        port=67,
        server_group_id=group.id,
        scopes_observed_at=now,
        failover_observed_at=now,
    )
    s2 = DHCPServer(
        name="dhcp2",
        driver="windows_dhcp",
        host="10.0.0.2",
        port=67,
        server_group_id=group.id,
        scopes_observed_at=now,
        failover_observed_at=now,
    )
    db.add_all([s1, s2])
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, is_active=True)
    db.add(scope)
    await db.flush()
    return {"group": group, "s1": s1, "s2": s2, "scope": scope, "subnet": subnet}


@pytest.mark.asyncio
async def test_group_view_merges_a_relationship_across_its_partners(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    w = await _world(db_session)
    db_session.add_all(
        [
            _rel(w["s1"], "dhcp2.corp.example"),
            _rel(w["s2"], "dhcp1", load_balance_percent=50),
            _state(w["s1"]),
            _state(w["s2"]),
        ]
    )
    token, _ = await _token(db_session)
    await db_session.commit()

    resp = await client.get(
        f"/api/v1/dhcp/server-groups/{w['group'].id}/failover",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["windows_member_count"] == 2
    (rel,) = body["relationships"]
    assert rel["name"] == "dhcp1-dhcp2"
    assert rel["complete"] is True
    assert rel["partner_outside_group"] is None
    sides = {s["server_name"]: s for s in rel["sides"]}
    assert sides["dhcp1"]["partner_server_id"] == str(w["s2"].id)
    assert sides["dhcp2"]["partner_server_id"] == str(w["s1"].id)
    (scope,) = body["scopes"]
    assert scope["verdict"] == "failover"
    assert scope["safe"] is True
    assert scope["scope_id"] == str(w["scope"].id)
    owners = [s["server_name"] for s in scope["servers"] if s["reconcile_owner"]]
    assert owners == ["dhcp1"]


@pytest.mark.asyncio
async def test_scope_view_flags_two_uncoordinated_holders(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    w = await _world(db_session)
    db_session.add_all([_state(w["s1"]), _state(w["s2"], config_hash="other")])
    token, _ = await _token(db_session)
    await db_session.commit()

    resp = await client.get(
        f"/api/v1/dhcp/scopes/{w['scope'].id}/failover",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["verdict"] == "uncoordinated"
    assert body["safe"] is False
    assert "same address" in body["detail"]
    rows = {s["server_name"]: s for s in body["servers"]}
    assert rows["dhcp1"]["holds"] is True and rows["dhcp2"]["holds"] is True
    assert rows["dhcp1"]["in_sync"] is True  # the owner compares equal to itself
    assert rows["dhcp2"]["in_sync"] is False


@pytest.mark.asyncio
async def test_scope_view_marks_unknown_and_stale_members(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    w = await _world(db_session)
    w["s2"].scopes_observed_at = None  # never read
    w["s1"].scopes_observed_at = datetime.now(UTC) - OBSERVATION_FRESH_FOR - timedelta(minutes=5)
    db_session.add(_state(w["s1"]))
    token, _ = await _token(db_session)
    await db_session.commit()

    resp = await client.get(
        f"/api/v1/dhcp/scopes/{w['scope'].id}/failover",
        headers={"Authorization": f"Bearer {token}"},
    )
    body = resp.json()
    rows = {s["server_name"]: s for s in body["servers"]}
    assert rows["dhcp2"]["holds"] is None, "never read is unknown, not 'no'"
    assert rows["dhcp1"]["stale"] is True
    # A stale holder still counts for display — hiding it could hide a dual-serve.
    assert body["verdict"] == "single_server"
    assert rows["dhcp1"]["reconcile_owner"] is False, "a stale view is not being imported"


@pytest.mark.asyncio
async def test_scope_view_for_a_group_without_windows_members(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    w = await _world(db_session)
    for s in (w["s1"], w["s2"]):
        s.driver = "kea"
    token, _ = await _token(db_session)
    await db_session.commit()
    resp = await client.get(
        f"/api/v1/dhcp/scopes/{w['scope'].id}/failover",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "no_windows_members"


@pytest.mark.asyncio
async def test_group_view_shows_a_one_sided_relationship_and_a_read_failure(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    w = await _world(db_session)
    w["s2"].failover_error = "Access is denied."
    db_session.add_all([_rel(w["s1"], "dhcp9.elsewhere"), _state(w["s1"])])
    token, _ = await _token(db_session)
    await db_session.commit()

    body = (
        await client.get(
            f"/api/v1/dhcp/server-groups/{w['group'].id}/failover",
            headers={"Authorization": f"Bearer {token}"},
        )
    ).json()
    (rel,) = body["relationships"]
    assert rel["complete"] is False
    assert rel["partner_outside_group"] == "dhcp9.elsewhere"
    members = {m["server_name"]: m for m in body["members"]}
    assert members["dhcp2"]["failover_error"] == "Access is denied."
    (scope,) = body["scopes"]
    assert scope["verdict"] == "failover_one_sided"


@pytest.mark.asyncio
async def test_views_404(client: AsyncClient, db_session: AsyncSession) -> None:
    token, _ = await _token(db_session)
    await db_session.commit()
    h = {"Authorization": f"Bearer {token}"}
    assert (
        await client.get(f"/api/v1/dhcp/server-groups/{uuid.uuid4()}/failover", headers=h)
    ).status_code == 404
    assert (
        await client.get(f"/api/v1/dhcp/scopes/{uuid.uuid4()}/failover", headers=h)
    ).status_code == 404


@pytest.mark.asyncio
async def test_mcp_tool_returns_the_same_report_and_filters_to_risk(
    db_session: AsyncSession,
) -> None:
    from app.services.ai.tools.dhcp import (
        FindDHCPFailoverRelationshipsArgs,
        find_dhcp_failover_relationships,
    )

    w = await _world(db_session)
    db_session.add_all(
        [
            _state(w["s1"]),
            _state(w["s2"]),
            # A second, safely single-served scope.
            _state(w["s1"], cidr="10.60.1.0/24"),
        ]
    )
    _token_str, user = await _token(db_session)
    await db_session.flush()

    everything = await find_dhcp_failover_relationships(
        db_session, user, FindDHCPFailoverRelationshipsArgs()
    )
    (group,) = everything
    assert group["group_name"] == w["group"].name
    assert {s["cidr"]: s["verdict"] for s in group["scopes"]} == {
        CIDR: "uncoordinated",
        "10.60.1.0/24": "single_server",
    }
    # Serialised like the REST route — ISO timestamps, string ids.
    assert isinstance(group["members"][0]["scopes_observed_at"], str)

    risky = await find_dhcp_failover_relationships(
        db_session, user, FindDHCPFailoverRelationshipsArgs(only_at_risk=True)
    )
    assert [s["cidr"] for s in risky[0]["scopes"]] == [CIDR]
