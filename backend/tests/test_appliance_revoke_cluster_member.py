"""Revoking a node of a formed control-plane cluster is refused (#1884).

The soft-delete (``DELETE /appliances/{id}``) takes the row out of its peers'
firewall sets, but nothing takes the node out of etcd, so a member revoked in
place stays an etcd voter with a Ready Node that its peers no longer admit.
The Fleet tab disables Revoke on control-plane rows and the deployment docs say
"demote it first"; the API now says the same:

* a member of a formed cluster answers 409, names demote and Replace, and
  stays approved;
* the seed answers 409 too, and names what is left to it (it can be neither
  demoted nor replaced);
* the same member once demoted (``cluster_role`` cleared at ``left``) revokes;
* the only control-plane node keeps its own refusal (#272).
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    APPLIANCE_STATE_REVOKED,
    CLUSTER_JOIN_STATE_LEFT,
    CLUSTER_JOIN_STATE_READY,
    CLUSTER_ROLE_MEMBER,
    CLUSTER_ROLE_PRIMARY,
    Appliance,
)
from app.models.auth import User

PASSWORD = "test-pw-1884"


async def _superadmin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"admin-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test Admin",
        hashed_password=hash_password(PASSWORD),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _appliance(
    db: AsyncSession,
    hostname: str,
    *,
    variant: str | None = None,
    cluster_role: str | None = None,
    join_state: str | None = None,
) -> Appliance:
    row = Appliance(
        id=uuid.uuid4(),
        hostname=hostname,
        state=APPLIANCE_STATE_APPROVED,
        public_key_der=b"fake-key-" + hostname.encode(),
        public_key_fingerprint=uuid.uuid4().hex * 2,
        cert_serial=uuid.uuid4().hex[:8],
        appliance_variant=variant,
        cluster_role=cluster_role,
        cluster_join_state=join_state,
    )
    db.add(row)
    await db.flush()
    return row


async def _three_node_cluster(db: AsyncSession) -> tuple[Appliance, Appliance, Appliance]:
    seed = await _appliance(
        db,
        "ddi-seed",
        variant="control-plane",
        cluster_role=CLUSTER_ROLE_PRIMARY,
        join_state=CLUSTER_JOIN_STATE_READY,
    )
    m1 = await _appliance(
        db, "ddi-member-1", cluster_role=CLUSTER_ROLE_MEMBER, join_state=CLUSTER_JOIN_STATE_READY
    )
    m2 = await _appliance(
        db, "ddi-member-2", cluster_role=CLUSTER_ROLE_MEMBER, join_state=CLUSTER_JOIN_STATE_READY
    )
    return seed, m1, m2


async def _revoke(client: AsyncClient, headers: dict[str, str], row: Appliance):
    return await client.request(
        "DELETE",
        f"/api/v1/appliance/appliances/{row.id}",
        headers=headers,
        json={"password": PASSWORD},
    )


@pytest.mark.asyncio
async def test_revoking_a_live_cluster_member_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin_headers(db_session)
    _, m1, _ = await _three_node_cluster(db_session)
    await db_session.commit()
    m1_id = m1.id

    resp = await _revoke(client, headers, m1)

    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    assert "ddi-member-1" in detail
    assert "Demote it from the cluster first" in detail
    assert "Replace" in detail
    db_session.expire_all()
    row = await db_session.get(Appliance, m1_id)
    assert row is not None
    assert row.state == APPLIANCE_STATE_APPROVED
    assert row.revoked_at is None


@pytest.mark.asyncio
async def test_revoking_the_primary_of_a_formed_cluster_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Other control-plane rows exist, so #272's only-node guard lets it by;
    it is still the etcd seed, which demote and Replace both refuse, so the
    refusal must not send the operator to either."""
    headers = await _superadmin_headers(db_session)
    seed, _, _ = await _three_node_cluster(db_session)
    await db_session.commit()
    seed_id = seed.id

    resp = await _revoke(client, headers, seed)

    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    assert "ddi-seed" in detail
    assert "etcd seed" in detail
    assert "Demote the other members first" in detail
    assert "Replace…" not in detail
    db_session.expire_all()
    row = await db_session.get(Appliance, seed_id)
    assert row is not None and row.state == APPLIANCE_STATE_APPROVED


@pytest.mark.asyncio
async def test_a_demoted_node_can_be_revoked(client: AsyncClient, db_session: AsyncSession) -> None:
    """A demote that settles ``left`` clears ``cluster_role``; the node is a
    standalone appliance again and revokes as one."""
    headers = await _superadmin_headers(db_session)
    _, m1, _ = await _three_node_cluster(db_session)
    m1.cluster_role = None
    m1.cluster_join_state = CLUSTER_JOIN_STATE_LEFT
    await db_session.commit()
    m1_id = m1.id

    resp = await _revoke(client, headers, m1)

    assert resp.status_code == 200, resp.text
    db_session.expire_all()
    row = await db_session.get(Appliance, m1_id)
    assert row is not None and row.state == APPLIANCE_STATE_REVOKED


@pytest.mark.asyncio
async def test_the_only_control_plane_node_keeps_its_own_refusal(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin_headers(db_session)
    seed = await _appliance(
        db_session,
        "ddi-lone-seed",
        variant="control-plane",
        cluster_role=CLUSTER_ROLE_PRIMARY,
        join_state=CLUSTER_JOIN_STATE_READY,
    )
    await db_session.commit()

    resp = await _revoke(client, headers, seed)

    assert resp.status_code == 409, resp.text
    assert "only control-plane node" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_an_appliance_outside_the_cluster_still_revokes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin_headers(db_session)
    await _three_node_cluster(db_session)
    agent = await _appliance(db_session, "ddi-agent-1")
    await db_session.commit()

    resp = await _revoke(client, headers, agent)

    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == APPLIANCE_STATE_REVOKED
