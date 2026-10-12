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
