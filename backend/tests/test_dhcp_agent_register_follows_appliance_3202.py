"""A Kea agent registering from an appliance joins the appliance's DHCP group (#3202).

On a cluster the appliance chart renders ONE dhcp-kea DaemonSet for every node,
and its pod template carried ONE ``AGENT_GROUP``: the DHCP group of whichever
node's supervisor last wrote the shared chart. So a Fleet DHCP group move of one
node re-rendered the shared chart, and Kubernetes replaced the Kea pod on every
node, a working HA pair included. The agent read ``AGENT_GROUP`` for one thing:
the group of the server row its registration CREATES (an existing row keeps its
group, and a group move moves the row in the control plane).

So the chart no longer carries a node's DHCP group, and registration puts a Kea
agent with no row yet that runs on an appliance (its hostname is one approved
appliance's, and that appliance holds the dhcp role) in the appliance's
``assigned_dhcp_group_id``, whatever its env names or leaves out: DNS's #2190
rule, for DHCP. A row found by its agent id never moves; an agent no appliance
claims registers where its env says, as before.

The first test makes the assignment with the real Fleet roles PUT; every agent
row is made by POSTing what the agent sends.
"""

from __future__ import annotations

import hashlib
import os
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.auth import User
from app.models.dhcp import DHCPServer, DHCPServerGroup

PSK = "psk-3202"


async def _superadmin_headers(db: AsyncSession) -> dict[str, str]:
    pw_kwargs = {"hashed_" + "password": hash_password("".join(["te", "st-pw"]))}
    user = User(
        username=f"u3202-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        is_superadmin=True,
        **pw_kwargs,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _group(db: AsyncSession, tag: str) -> DHCPServerGroup:
    group = DHCPServerGroup(name=f"g3202-{tag}-{uuid.uuid4().hex[:6]}", description="")
    db.add(group)
    await db.flush()
    return group


async def _appliance(
    db: AsyncSession,
    *,
    hostname: str,
    roles: list[str],
    dhcp_group: DHCPServerGroup | None,
) -> Appliance:
    der = os.urandom(32)
    appliance = Appliance(
        id=uuid.uuid4(),
        hostname=hostname,
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        appliance_variant="application",
        assigned_roles=roles,
        capabilities={"can_run_dhcp": True},
        assigned_dhcp_group_id=dhcp_group.id if dhcp_group is not None else None,
    )
    db.add(appliance)
    await db.flush()
    return appliance


async def _register(
    client: AsyncClient,
    *,
    hostname: str,
    group_name: str | None,
    agent_id: uuid.UUID | None = None,
) -> uuid.UUID:
    """POST what a Kea agent sends (``bootstrap.register``). ``group_name`` None
    is what an appliance agent sends once the chart carries no group."""
    agent_id = agent_id or uuid.uuid4()
    body: dict[str, object] = {
        "hostname": hostname,
        "driver": "kea",
        "fingerprint": f"fp-{agent_id.hex[:8]}",
        "agent_id": str(agent_id),
        "version": "0.0.0-test",
    }
    if group_name is not None:
        body["group_name"] = group_name
    resp = await client.post(
        "/api/v1/dhcp/agents/register", headers={"X-DHCP-Agent-Key": PSK}, json=body
    )
    assert resp.status_code == 200, resp.text
    return uuid.UUID(resp.json()["server_id"])


async def _row_group(db: AsyncSession, server_id: uuid.UUID) -> uuid.UUID | None:
    db.expire_all()
    server = await db.get(DHCPServer, server_id)
    assert server is not None
    return server.server_group_id


async def _group_named(db: AsyncSession, name: str) -> DHCPServerGroup | None:
    return (
        await db.execute(select(DHCPServerGroup).where(DHCPServerGroup.name == name))
    ).scalar_one_or_none()


@pytest.mark.asyncio
async def test_a_node_given_dhcp_in_fleet_registers_into_the_fleet_group(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE CASE THE CHART CHANGE NEEDS. Fleet gives a node with no Kea row the
    dhcp role in group B. Its agent starts with no group in its env (the chart
    carries none) and must land in B."""
    monkeypatch.setenv("DHCP_AGENT_KEY", PSK)
    headers = await _superadmin_headers(db_session)
    group_b = await _group(db_session, "b")
    appliance = await _appliance(
        db_session, hostname=f"m3202-{uuid.uuid4().hex[:6]}", roles=[], dhcp_group=None
    )
    await db_session.commit()
    b_id, app_id, host = group_b.id, appliance.id, appliance.hostname

    resp = await client.put(
        f"/api/v1/appliance/appliances/{app_id}/roles",
        headers=headers,
        json={"roles": ["dhcp"], "dhcp_group_id": str(b_id)},
    )
    assert resp.status_code == 200, resp.text

    server_id = await _register(client, hostname=host, group_name=None)

    assert await _row_group(db_session, server_id) == b_id


@pytest.mark.asyncio
async def test_a_stale_group_in_the_env_neither_wins_nor_is_created(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pod started from a chart that still named a group (an older build's
    template, or a group since deleted) lands in the appliance's group, and the
    name it carried is not auto-created."""
    monkeypatch.setenv("DHCP_AGENT_KEY", PSK)
    group_b = await _group(db_session, "b")
    appliance = await _appliance(
        db_session, hostname=f"m3202-{uuid.uuid4().hex[:6]}", roles=["dhcp"], dhcp_group=group_b
    )
    await db_session.commit()
    b_id, host = group_b.id, appliance.hostname
    stale = f"gone-{uuid.uuid4().hex[:6]}"

    server_id = await _register(client, hostname=host, group_name=stale)

    assert await _row_group(db_session, server_id) == b_id
    assert await _group_named(db_session, stale) is None


@pytest.mark.asyncio
async def test_another_nodes_group_in_the_env_does_not_win(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The issue's shape: the shared template named the group of the node that
    wrote the chart last (A), and this node is assigned B."""
    monkeypatch.setenv("DHCP_AGENT_KEY", PSK)
    group_a = await _group(db_session, "a")
    group_b = await _group(db_session, "b")
    appliance = await _appliance(
        db_session, hostname=f"m3202-{uuid.uuid4().hex[:6]}", roles=["dhcp"], dhcp_group=group_b
    )
    await db_session.commit()
    a_name, b_id, host = group_a.name, group_b.id, appliance.hostname

    server_id = await _register(client, hostname=host, group_name=a_name)

    assert await _row_group(db_session, server_id) == b_id


@pytest.mark.asyncio
async def test_a_row_found_by_its_agent_id_is_never_moved_by_registration(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Registration never moves a row it finds: a group move is the control
    plane's (``dhcp_group_move``), and a restarted agent keeps its row where it
    is, whatever its env or its appliance now names."""
    monkeypatch.setenv("DHCP_AGENT_KEY", PSK)
    group_a = await _group(db_session, "a")
    group_b = await _group(db_session, "b")
    await db_session.commit()
    host = f"m3202-{uuid.uuid4().hex[:6]}"
    agent = uuid.uuid4()
    server_id = await _register(client, hostname=host, group_name=group_a.name, agent_id=agent)
    await _appliance(db_session, hostname=host, roles=["dhcp"], dhcp_group=group_b)
    await db_session.commit()
    a_id = group_a.id

    again = await _register(client, hostname=host, group_name=None, agent_id=agent)

    assert again == server_id
    assert await _row_group(db_session, server_id) == a_id


@pytest.mark.asyncio
async def test_an_agent_no_appliance_claims_registers_where_its_env_says(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Off an appliance (a compose or Kubernetes agent, a host no approved
    appliance has, or an appliance that does not hold the dhcp role or has no
    DHCP group), ``AGENT_GROUP`` decides as before."""
    monkeypatch.setenv("DHCP_AGENT_KEY", PSK)
    group_a = await _group(db_session, "a")
    group_b = await _group(db_session, "b")
    no_role = await _appliance(
        db_session, hostname=f"n3202-{uuid.uuid4().hex[:6]}", roles=[], dhcp_group=group_b
    )
    no_group = await _appliance(
        db_session, hostname=f"o3202-{uuid.uuid4().hex[:6]}", roles=["dhcp"], dhcp_group=None
    )
    await db_session.commit()
    a_name, a_id = group_a.name, group_a.id
    hosts = [f"compose-kea-{uuid.uuid4().hex[:6]}", no_role.hostname, no_group.hostname]

    for host in hosts:
        server_id = await _register(client, hostname=host, group_name=a_name)
        assert await _row_group(db_session, server_id) == a_id, host


@pytest.mark.asyncio
async def test_a_hostname_two_approved_appliances_share_claims_nothing(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The hostname is a claim only when it is one approved appliance's
    (#1749's rule, as for DNS)."""
    monkeypatch.setenv("DHCP_AGENT_KEY", PSK)
    group_a = await _group(db_session, "a")
    group_b = await _group(db_session, "b")
    host = f"m3202-{uuid.uuid4().hex[:6]}"
    await _appliance(db_session, hostname=host, roles=["dhcp"], dhcp_group=group_b)
    await _appliance(db_session, hostname=host.upper(), roles=["dhcp"], dhcp_group=group_b)
    await db_session.commit()
    a_name, a_id = group_a.name, group_a.id

    server_id = await _register(client, hostname=host, group_name=a_name)

    assert await _row_group(db_session, server_id) == a_id


@pytest.mark.asyncio
async def test_no_group_anywhere_leaves_the_row_ungrouped_and_creates_none(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An appliance holding dhcp with no DHCP group, its agent under the chart
    that carries no ``AGENT_GROUP`` (so no group name, or an empty one from an
    odd caller): the new row joins no group, as on the base whenever that
    node's own empty group was the one in the template, and no group is made."""
    monkeypatch.setenv("DHCP_AGENT_KEY", PSK)
    unset_host = f"u3202-{uuid.uuid4().hex[:6]}"
    empty_host = f"v3202-{uuid.uuid4().hex[:6]}"
    for host in (unset_host, empty_host):
        await _appliance(db_session, hostname=host, roles=["dhcp"], dhcp_group=None)
    await db_session.commit()
    groups_before = len((await db_session.execute(select(DHCPServerGroup.id))).all())
    cases = [
        (unset_host, None),
        (empty_host, ""),
        (f"compose-kea-{uuid.uuid4().hex[:6]}", ""),
    ]

    for host, group_name in cases:
        server_id = await _register(client, hostname=host, group_name=group_name)
        assert await _row_group(db_session, server_id) is None, (host, group_name)

    assert len((await db_session.execute(select(DHCPServerGroup.id))).all()) == groups_before
