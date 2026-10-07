"""#1284 — a replaced node settles ``left`` only once the seed's etcd drops it.

Replace flags the row ``evict_requested``; the seed deletes the node's k8s Node
and, since #1284, removes its etcd member too (k3s removes a server's member
only through its Node, and a node can be an etcd voter with no Node). The
backend's side:
- it hands the seed each evicting node's addresses, so a member that has no
  name yet can be matched by its peer URL;
- a name the seed reports as still pending keeps its row ``evicting``, with the
  seed's reason on it;
- a name the seed reports as evicted settles ``left`` and drops that reason;
- it names the nodes it has asked to join, so the seed never takes a node
  promoted again after its eviction for a late arrival of the evicted one.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    CLUSTER_JOIN_STATE_EVICTING,
    CLUSTER_JOIN_STATE_LEFT,
    Appliance,
)
from app.models.settings import PlatformSettings
from app.services.appliance.ca import generate_session_token


async def _row(db: AsyncSession, hostname: str, **kw: object) -> tuple[Appliance, str]:
    settings_row = await db.get(PlatformSettings, 1)
    if settings_row is None:
        settings_row = PlatformSettings(id=1)
        db.add(settings_row)
    settings_row.supervisor_registration_enabled = True
    token, token_hash = generate_session_token()
    row = Appliance(
        id=uuid.uuid4(),
        hostname=hostname,
        state=APPLIANCE_STATE_APPROVED,
        public_key_der=b"fake-key",
        public_key_fingerprint=uuid.uuid4().hex + uuid.uuid4().hex,
        cert_serial=uuid.uuid4().hex[:8],
        deployment_kind="appliance",
        session_token_hash=token_hash,
        **kw,
    )
    db.add(row)
    await db.flush()
    return row, token


async def _seed_and_ghost(db: AsyncSession) -> tuple[Appliance, str, Appliance]:
    seed, token = await _row(
        db,
        f"seed-{uuid.uuid4().hex[:6]}",
        appliance_variant="control-plane",
        cluster_role="primary",
    )
    ghost, _ = await _row(
        db,
        f"member-{uuid.uuid4().hex[:6]}",
        appliance_variant="appliance",
        node_ip="192.168.122.86",
        node_ips=["192.168.122.86", "fd00::86"],
        cluster_join_state=CLUSTER_JOIN_STATE_EVICTING,
        cluster_join_state_at=datetime.now(UTC),
        evict_requested=True,
    )
    await db.commit()
    return seed, token, ghost


async def _beat(client: AsyncClient, seed: Appliance, token: str, **body: object) -> dict:
    resp = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={"appliance_id": str(seed.id), "session_token": token, **body},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_the_seed_gets_each_evicting_nodes_addresses(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    seed, token, ghost = await _seed_and_ghost(db_session)

    out = await _beat(client, seed, token)

    assert ghost.hostname in out["evict_node_names"]
    assert out["evict_node_addresses"][ghost.hostname] == ["192.168.122.86", "fd00::86"]


@pytest.mark.asyncio
async def test_the_seed_is_told_which_nodes_are_asked_to_join(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Replace on a failed joiner exists so the same node can be promoted
    again. The seed watches an evicted name for late etcd members; a promoted
    node is wanted, and only the backend knows that."""
    seed, token, ghost = await _seed_and_ghost(db_session)
    again, again_token = await _row(
        db_session,
        f"member-{uuid.uuid4().hex[:6]}",
        appliance_variant="appliance",
        cluster_join_state="joining",
        desired_cluster_role="member",
        desired_k3s_server_url="https://10.0.0.1:6443",
        desired_k3s_join_token_encrypted=b"enc",
    )
    await db_session.commit()

    out = await _beat(client, seed, token)

    assert out["join_node_names"] == [again.hostname]
    assert ghost.hostname not in out["join_node_names"]
    # Only the seed needs the list.
    assert (await _beat(client, again, again_token))["join_node_names"] == []


@pytest.mark.asyncio
async def test_a_pending_eviction_stays_evicting_with_the_seeds_reason(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    seed, token, ghost = await _seed_and_ghost(db_session)
    why = (
        f"waiting for the seed's etcd to drop {ghost.hostname}: etcd member "
        f"5652301283934544556 {ghost.hostname}-7d1c4ad1 still listed"
    )

    out = await _beat(client, seed, token, evict_pending={ghost.hostname: why})

    await db_session.refresh(ghost)
    assert ghost.cluster_join_state == CLUSTER_JOIN_STATE_EVICTING
    assert ghost.evict_requested is True
    assert ghost.cluster_join_reason == why
    assert ghost.hostname in out["evict_node_names"]  # still asked of the seed


@pytest.mark.asyncio
async def test_an_eviction_etcd_agreed_to_settles_left_and_drops_the_reason(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    seed, token, ghost = await _seed_and_ghost(db_session)
    await _beat(client, seed, token, evict_pending={ghost.hostname: "checking"})

    out = await _beat(client, seed, token, evicted_node_names=[ghost.hostname])

    await db_session.refresh(ghost)
    assert ghost.cluster_join_state == CLUSTER_JOIN_STATE_LEFT
    assert ghost.evict_requested is False
    assert ghost.cluster_join_reason is None
    assert ghost.hostname not in out["evict_node_names"]


@pytest.mark.asyncio
async def test_a_pending_reason_never_touches_a_row_that_is_not_evicting(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    seed, token, _ghost = await _seed_and_ghost(db_session)
    live, _ = await _row(
        db_session,
        f"member-{uuid.uuid4().hex[:6]}",
        appliance_variant="appliance",
        cluster_role="member",
        cluster_join_state="ready",
    )
    await db_session.commit()

    await _beat(client, seed, token, evict_pending={live.hostname: "stale reason"})

    await db_session.refresh(live)
    assert live.cluster_join_reason is None
    assert live.cluster_join_state == "ready"
