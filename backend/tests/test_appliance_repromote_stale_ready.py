"""#1903 — re-promoting a Replace-evicted node settles only on ITS join's verdict.

A node evicted by Replace whose box is still up keeps ``ready <seed>`` in its
cluster-join sidecar. Promoted again against the same seed it reports that
``ready`` before any join runs; the row used to settle as a member from it.
The promote now stamps a transition id, the heartbeat answers it, and a
terminal verdict counts only when the node echoes the id of the join it fired.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import supervisor as sup
from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    CLUSTER_JOIN_STATE_JOINING,
    CLUSTER_JOIN_STATE_LEFT,
    CLUSTER_ROLE_MEMBER,
    CLUSTER_ROLE_PRIMARY,
    Appliance,
)
from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services.appliance.ca import generate_session_token

pytestmark = pytest.mark.asyncio

HB = "/api/v1/appliance/supervisor/heartbeat"


async def _admin(db: AsyncSession) -> str:
    user = User(
        username="cpadmin",
        email="cpadmin@example.com",
        display_name="cpadmin",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


async def _appliance(db: AsyncSession, hostname: str, **kw: object) -> tuple[Appliance, str]:
    der = os.urandom(32)
    token, token_hash = generate_session_token()
    row = Appliance(
        id=uuid.uuid4(),
        hostname=hostname,
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        session_token_hash=token_hash,
        **kw,  # type: ignore[arg-type]
    )
    db.add(row)
    await db.flush()
    return row, token


async def _beat(client: AsyncClient, row: Appliance, token: str, **fields: object) -> dict:
    resp = await client.post(
        HB, json={"appliance_id": str(row.id), "session_token": token, **fields}
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _setup(db: AsyncSession) -> tuple[str, Appliance, str, Appliance, str]:
    settings_row = await db.get(PlatformSettings, 1)
    if settings_row is None:
        settings_row = PlatformSettings(id=1)
        db.add(settings_row)
    settings_row.supervisor_registration_enabled = True
    admin = await _admin(db)
    await _appliance(
        db,
        "seed",
        appliance_variant="control-plane",
        cluster_role=CLUSTER_ROLE_PRIMARY,
        node_ip="10.0.0.1",
        k3s_join_token_encrypted=encrypt_str("K10::servertoken"),
    )
    # The Replace-evicted box: settled ``left``, nothing asked of it.
    evicted, etok = await _appliance(
        db,
        "evicted",
        appliance_variant="appliance",
        cluster_join_state=CLUSTER_JOIN_STATE_LEFT,
        cluster_join_state_at=datetime.now(UTC),
    )
    other, otok = await _appliance(db, "fresh", appliance_variant="appliance")
    await db.commit()
    return admin, evicted, etok, other, otok


async def _promote(client: AsyncClient, admin: str, *rows: Appliance) -> None:
    resp = await client.post(
        "/api/v1/appliance/fleet/control-plane/promote",
        json={"appliance_ids": [str(r.id) for r in rows]},
        headers={"Authorization": f"Bearer {admin}"},
    )
    assert resp.status_code == 200, resp.text


def test_unproven_verdict_rule() -> None:
    f = sup._unproven_join_verdict
    assert f("T2", "member", "ready", "")
    assert f("T2", "member", "failed", "T1")
    assert not f("T2", "member", "ready", "T2")
    assert not f("T2", "member", "joining", "")  # progress, not a verdict
    assert not f("T2", "member", "ready", None)  # a supervisor that predates the field
    assert not f(None, "member", "ready", "")  # no promote stamped an id
    assert not f("T2", None, "ready", "")  # nothing in flight
    # A verdict younger than the promote is this promote's, id or not: the join
    # an older supervisor fired (then upgraded) holds no fire record.
    assert not f("T2", "member", "ready", "", 5.0, 300.0)
    assert f("T2", "member", "ready", "", 3600.0, 300.0)
    assert f("T2", "member", "ready", "", 5.0, None)  # no promote age: nothing proven
    assert f("T2", "member", "ready", "", -1.0, 300.0)  # an age from the future


async def test_stale_ready_does_not_settle_a_repromote(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin, evicted, etok, other, _ = await _setup(db_session)
    await _promote(client, admin, evicted, other)
    await db_session.refresh(evicted)
    tid = evicted.cluster_transition_id
    assert tid and evicted.cluster_join_state == CLUSTER_JOIN_STATE_JOINING
    assert evicted.cluster_transition_at is not None

    # The answer names the promote the node must prove.
    out = await _beat(
        client,
        evicted,
        etok,
        cluster_join_state="ready",
        cluster_join_reason="https://10.0.0.1:6443",
        cluster_transition_id="",
    )
    assert out["desired_cluster_role"] == "member"
    assert out["desired_cluster_transition_id"] == tid

    await db_session.refresh(evicted)
    assert evicted.cluster_join_state == CLUSTER_JOIN_STATE_JOINING
    assert evicted.cluster_role is None
    assert evicted.desired_cluster_role == "member"  # still asked to join

    # An old ``failed`` is no more this promote's than the ``ready`` was.
    await _beat(
        client,
        evicted,
        etok,
        cluster_join_state="failed",
        cluster_join_reason="old",
        cluster_transition_id="",
    )
    await db_session.refresh(evicted)
    assert evicted.cluster_join_state == CLUSTER_JOIN_STATE_JOINING

    # The join fires and its own verdict, carrying the id, settles the node.
    await _beat(
        client,
        evicted,
        etok,
        cluster_join_state="ready",
        cluster_join_reason="https://10.0.0.1:6443",
        cluster_transition_id=tid,
    )
    await db_session.refresh(evicted)
    assert evicted.cluster_role == CLUSTER_ROLE_MEMBER
    assert evicted.desired_cluster_role is None
    out = await _beat(client, evicted, etok)
    assert out["desired_cluster_transition_id"] is None


async def test_each_promote_gets_a_fresh_id(client: AsyncClient, db_session: AsyncSession) -> None:
    admin, evicted, etok, other, _ = await _setup(db_session)
    await _promote(client, admin, evicted, other)
    await db_session.refresh(evicted)
    first = evicted.cluster_transition_id
    # Cleared (as the operator's "clear stuck state" does), then promoted again.
    evicted.desired_cluster_role = None
    evicted.cluster_join_state = CLUSTER_JOIN_STATE_LEFT
    other.desired_cluster_role = None
    await db_session.commit()
    await _promote(client, admin, evicted, other)
    await db_session.refresh(evicted)
    assert evicted.cluster_transition_id and evicted.cluster_transition_id != first


async def test_a_supervisor_without_the_field_still_settles(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin, evicted, etok, other, _ = await _setup(db_session)
    await _promote(client, admin, evicted, other)
    await _beat(
        client,
        evicted,
        etok,
        cluster_join_state="ready",
        cluster_join_reason="https://10.0.0.1:6443",
    )
    await db_session.refresh(evicted)
    assert evicted.cluster_role == CLUSTER_ROLE_MEMBER


async def test_a_ready_younger_than_the_promote_settles_without_an_id(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Supervisor upgraded mid-join: the join was fired before the fire record
    existed, so the node echoes ``""``; its ``ready`` is younger than the promote,
    so it proves the promote and the row settles — the supervisor is never asked
    to fire again over a working membership."""
    admin, evicted, etok, other, _ = await _setup(db_session)
    await _promote(client, admin, evicted, other)
    await db_session.refresh(evicted)
    evicted.cluster_transition_at = datetime.now(UTC) - timedelta(minutes=5)
    await db_session.commit()

    # Before the ready lands, the answer carries the promote's age, not its time.
    out = await _beat(client, evicted, etok, cluster_join_state="joining")
    assert 290 <= out["desired_cluster_transition_age_s"] <= 400

    out = await _beat(
        client,
        evicted,
        etok,
        cluster_join_state="ready",
        cluster_join_reason="https://10.0.0.1:6443",
        cluster_transition_id="",
        cluster_join_state_age_s=12.0,
    )
    await db_session.refresh(evicted)
    assert evicted.cluster_role == CLUSTER_ROLE_MEMBER
    assert evicted.desired_cluster_role is None
    assert out["desired_cluster_role"] is None
    assert out["desired_cluster_transition_age_s"] is None


async def test_a_ready_older_than_the_promote_does_not_settle(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin, evicted, etok, other, _ = await _setup(db_session)
    await _promote(client, admin, evicted, other)
    await db_session.refresh(evicted)
    evicted.cluster_transition_at = datetime.now(UTC) - timedelta(minutes=5)
    await db_session.commit()

    out = await _beat(
        client,
        evicted,
        etok,
        cluster_join_state="ready",
        cluster_join_reason="https://10.0.0.1:6443",
        cluster_transition_id="",
        cluster_join_state_age_s=86400.0,
    )
    await db_session.refresh(evicted)
    assert evicted.cluster_join_state == CLUSTER_JOIN_STATE_JOINING
    assert evicted.cluster_role is None
    assert out["desired_cluster_role"] == "member"
    assert out["desired_cluster_transition_id"] == evicted.cluster_transition_id
