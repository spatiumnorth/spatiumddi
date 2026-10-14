"""#1757 — an appliance installed with an uppercase hostname.

The installer accepts ``Ddi-Member-1``. k3s lowercases the host's name for its
k8s Node (RFC 1123, ``GetHostnameAndIPs``) and names the etcd member
``<node name>-<8 hex>``, but ``Appliance.hostname`` keeps what was typed. Every
lookup of a Node by appliance hostname therefore missed: the demote quorum gate
read the member as having "no k8s Node", the cordon found no Node, and the
eviction was told a name the seed's DELETE could not find (a 404, which counts
as success, so the stale Node stayed).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import supervisor
from app.models.appliance import (
    CLUSTER_JOIN_STATE_EVICTING,
    CLUSTER_JOIN_STATE_LEFT,
    CLUSTER_ROLE_MEMBER,
)
from app.models.dhcp import DHCPServer
from app.models.dns import DNSServer, DNSServerGroup
from tests.test_appliance_control_plane_promote import _admin, _appliance, _hdr, _seed
from tests.test_appliance_demote_quorum import DEMOTE, _fake_kubeapi
from tests.test_appliance_evict_etcd import _beat, _row


def test_k8s_node_name_is_what_k3s_registers() -> None:
    from app.services.appliance.ownership import k8s_node_name

    assert k8s_node_name("Ddi-Member-1") == "ddi-member-1"
    assert k8s_node_name(" DDI-Member-1. ") == "ddi-member-1"
    assert k8s_node_name(None) == ""


@pytest.mark.asyncio
async def test_a_demote_finds_and_cordons_an_uppercase_hosts_node(
    db_session: AsyncSession, client: AsyncClient, monkeypatch
) -> None:
    token = await _admin(db_session)
    now = datetime.now(UTC)
    seed = await _seed(db_session)
    seed.last_seen_at = now
    m1 = await _appliance(
        db_session, "Ddi-Member-1", cluster_role=CLUSTER_ROLE_MEMBER, last_seen_at=now
    )
    m2 = await _appliance(
        db_session,
        "DDI-MEMBER-2",
        cluster_role=CLUSTER_ROLE_MEMBER,
        last_seen_at=now - timedelta(seconds=1),
    )
    await db_session.commit()
    # Kubernetes only ever knows the lowercase names.
    fake = _fake_kubeapi(monkeypatch, "ddi-member-1", "ddi-member-2")

    resp = await client.post(
        DEMOTE, json={"appliance_ids": [str(m1.id), str(m2.id)]}, headers=_hdr(token)
    )

    assert resp.status_code == 200, resp.text  # not "no k8s Node"
    assert fake.cordoned("ddi-member-1") and fake.cordoned("ddi-member-2")


@pytest.mark.asyncio
async def test_a_notready_uppercase_member_is_still_judged_by_its_node(
    db_session: AsyncSession, client: AsyncClient, monkeypatch
) -> None:
    token = await _admin(db_session)
    now = datetime.now(UTC)
    seed = await _seed(db_session)
    seed.last_seen_at = now
    m1 = await _appliance(db_session, "Ddi-M1", cluster_role=CLUSTER_ROLE_MEMBER, last_seen_at=now)
    m2 = await _appliance(db_session, "Ddi-M2", cluster_role=CLUSTER_ROLE_MEMBER, last_seen_at=now)
    await db_session.commit()
    monkeypatch.setattr(
        supervisor,
        "_node_ready_map",
        lambda: {"seed": True, "ddi-m1": True, "ddi-m2": False},
    )

    resp = await client.post(
        DEMOTE, json={"appliance_ids": [str(m1.id), str(m2.id)]}, headers=_hdr(token)
    )

    assert resp.status_code == 409, resp.text
    assert "Node NotReady" in resp.text and "no k8s Node" not in resp.text


@pytest.mark.asyncio
async def test_the_seed_is_asked_to_evict_by_the_nodes_lowercase_name(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    seed, token = await _row(
        db_session,
        f"seed-{uuid.uuid4().hex[:6]}",
        appliance_variant="control-plane",
        cluster_role="primary",
    )
    ghost, _ = await _row(
        db_session,
        "Ddi-Ghost-1",
        appliance_variant="appliance",
        node_ip="192.168.122.86",
        cluster_join_state=CLUSTER_JOIN_STATE_EVICTING,
        cluster_join_state_at=datetime.now(UTC),
        evict_requested=True,
    )
    await db_session.commit()

    out = await _beat(client, seed, token)

    assert out["evict_node_names"] == ["ddi-ghost-1"]
    assert out["replace_node_names"] == ["ddi-ghost-1"]
    assert out["evict_node_addresses"] == {"ddi-ghost-1": ["192.168.122.86"]}

    # The seed reports the name it acted on; the row settles.
    await _beat(client, seed, token, evict_pending={"ddi-ghost-1": "checking"})
    await db_session.refresh(ghost)
    assert ghost.cluster_join_reason == "checking"
    await _beat(client, seed, token, evicted_node_names=["ddi-ghost-1"])
    await db_session.refresh(ghost)
    assert ghost.cluster_join_state == CLUSTER_JOIN_STATE_LEFT
    assert ghost.evict_requested is False


# ── Appliance delete: case-blind, but never across an ambiguous hostname ──


async def _agent_dns(db: AsyncSession, host: str) -> DNSServer:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:8]}", description="")
    db.add(group)
    await db.flush()
    server = DNSServer(
        group_id=group.id,
        name=f"{host}-{uuid.uuid4().hex[:4]}",
        driver="bind9",
        host=host,
        port=53,
        roles=["authoritative"],
        status="active",
        agent_id=uuid.uuid4(),
    )
    db.add(server)
    await db.flush()
    return server


async def _agent_dhcp(db: AsyncSession, host: str) -> DHCPServer:
    server = DHCPServer(
        name=f"{host}-{uuid.uuid4().hex[:4]}",
        driver="kea",
        host=host,
        port=67,
        status="active",
        agent_id=uuid.uuid4(),
    )
    db.add(server)
    await db.flush()
    return server


async def _dependents(client: AsyncClient, token: str, appliance_id: uuid.UUID) -> set[str]:
    resp = await client.get(
        f"/api/v1/appliance/appliances/{appliance_id}/dependents", headers=_hdr(token)
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    return {d["id"] for d in body["dns"]} | {d["id"] for d in body["dhcp"]}


@pytest.mark.asyncio
async def test_an_uppercase_appliance_owns_the_server_its_agent_registered_lowercase(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """A DNS agent on k3s registers ``host`` = the Node's name (lowercase); a
    Kea agent on hostNetwork registers the kernel nodename as typed. Both are
    the appliance's own and both are found."""
    token = await _admin(db_session)
    ap = await _appliance(db_session, "Ddi-Upper-1")
    dns = await _agent_dns(db_session, "ddi-upper-1")
    dhcp = await _agent_dhcp(db_session, "Ddi-Upper-1")
    await db_session.commit()

    assert await _dependents(client, token, ap.id) == {str(dns.id), str(dhcp.id)}


@pytest.mark.asyncio
async def test_two_appliances_differing_only_in_case_never_claim_each_others_servers(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """The case-blind match must not widen the #1810 hazard: with two approved
    appliances whose hostnames differ only in case, a hostname is not a safe
    claim, so neither previews (or deletes) the other's agent rows — only rows
    whose FK names it."""
    token = await _admin(db_session)
    live = await _appliance(db_session, "ddi-twin")
    dup = await _appliance(db_session, "DDI-Twin")
    live_dns = await _agent_dns(db_session, "ddi-twin")
    live_dhcp = await _agent_dhcp(db_session, "ddi-twin")
    dup_owned = await _agent_dns(db_session, "DDI-Twin")
    dup_owned.appliance_id = dup.id
    await db_session.commit()
    ids = {"live_dns": live_dns.id, "live_dhcp": live_dhcp.id, "dup_owned": dup_owned.id}

    assert await _dependents(client, token, dup.id) == {str(dup_owned.id)}
    assert await _dependents(client, token, live.id) == set()

    resp = await client.request(
        "DELETE",
        f"/api/v1/appliance/appliances/{dup.id}",
        headers=_hdr(token),
        json={"password": "password123"},
    )
    assert resp.status_code == 200, resp.text
    db_session.expire_all()
    assert await db_session.get(DNSServer, ids["live_dns"]) is not None
    assert await db_session.get(DHCPServer, ids["live_dhcp"]) is not None
    assert await db_session.get(DNSServer, ids["dup_owned"]) is None


@pytest.mark.asyncio
async def test_rolling_upgrade_resolves_one_approved_appliance_case_blind(
    db_session: AsyncSession,
) -> None:
    from app.models.appliance import APPLIANCE_STATE_REVOKED
    from app.services.upgrades.per_node import _resolve_appliance

    live = await _appliance(db_session, "Ddi-Roll-1")
    old = await _appliance(db_session, "ddi-roll-1")
    old.state = APPLIANCE_STATE_REVOKED  # the row a re-pair leaves behind
    await db_session.commit()

    got = await _resolve_appliance(db_session, "ddi-roll-1")
    assert got is not None and got.id == live.id

    # Two approved rows meeting on the Node name: ambiguous, never a guess.
    old.state = live.state
    await db_session.commit()
    assert await _resolve_appliance(db_session, "ddi-roll-1") is None
