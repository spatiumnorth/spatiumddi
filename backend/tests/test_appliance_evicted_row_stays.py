"""#1317 — an evicted row stays evicted, whatever the node it belonged to reports.

Replace flags a row for eviction; the seed evicts the node and the row settles
``left`` (#1284: once etcd agrees). The replaced node may still be alive: a
failed joiner back on its standalone control plane, or a member the operator is
retiring. Its supervisor goes on reporting what its host runner last wrote, and
the heartbeat handler applied any reported join state, so:

- a failed joiner's late ``failed`` overwrote ``left`` and the Fleet showed an
  evicted node as a failed joiner again (seen live: the row read ``left``, then
  ``failed``, stamped by the node's own heartbeat seconds later). The
  supervisor re-fires a failed join on its own, so a retry can still be
  running when Replace is accepted; its verdict arrives when it ends;
- a live member's ``ready`` (never retired by the supervisor) re-settled the row
  as a member on its very next heartbeat.

An evicted row — ``evicting``, or ``left`` with nothing asked of the node — now
ignores the node's reported join state. A row something IS asked of (a new
promote, a demote in flight) and a row whose bookkeeping was cleared (#590's
self-heal) behave as before.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.testing import capture_logs

from app.api.v1.appliance import supervisor as sup
from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    CLUSTER_JOIN_STATE_EVICTING,
    CLUSTER_JOIN_STATE_FAILED,
    CLUSTER_JOIN_STATE_JOINING,
    CLUSTER_JOIN_STATE_LEAVING,
    CLUSTER_JOIN_STATE_LEFT,
    CLUSTER_JOIN_STATE_READY,
    CLUSTER_ROLE_MEMBER,
    DESIRED_CLUSTER_ROLE_MEMBER,
    DESIRED_CLUSTER_ROLE_NONE,
    Appliance,
)
from app.models.settings import PlatformSettings
from app.services.appliance.ca import generate_session_token

_LATE = "could not reach the seed — check the firewall and tcp/6443 + tcp/2379-2380"


async def _node(db: AsyncSession, **kw: object) -> tuple[Appliance, str]:
    settings_row = await db.get(PlatformSettings, 1)
    if settings_row is None:
        settings_row = PlatformSettings(id=1)
        db.add(settings_row)
    settings_row.supervisor_registration_enabled = True
    token, token_hash = generate_session_token()
    row = Appliance(
        id=uuid.uuid4(),
        hostname=f"member-{uuid.uuid4().hex[:6]}",
        state=APPLIANCE_STATE_APPROVED,
        public_key_der=b"fake-key",
        public_key_fingerprint=uuid.uuid4().hex + uuid.uuid4().hex,
        cert_serial=uuid.uuid4().hex[:8],
        deployment_kind="appliance",
        appliance_variant="appliance",
        session_token_hash=token_hash,
        **kw,
    )
    db.add(row)
    await db.commit()
    return row, token


async def _report(
    client: AsyncClient, row: Appliance, token: str, state: str, reason: str | None = None
) -> None:
    resp = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={
            "appliance_id": str(row.id),
            "session_token": token,
            "cluster_join_state": state,
            "cluster_join_reason": reason,
        },
    )
    assert resp.status_code == 200, resp.text


def test_which_reports_an_evicted_row_ignores() -> None:
    ignores = sup._evicted_row_ignores_report
    # evicting: nothing the node says moves the row
    for reported in ("failed", "joining", "ready", "left"):
        assert ignores(CLUSTER_JOIN_STATE_EVICTING, None, True, reported), reported
    # evicted and settled: only `left` itself is a no-op worth applying
    for reported in ("failed", "joining", "ready", "leaving"):
        assert ignores(CLUSTER_JOIN_STATE_LEFT, None, False, reported), reported
    assert not ignores(CLUSTER_JOIN_STATE_LEFT, None, False, "left")
    # something is asked of the node: its reports count
    assert not ignores(CLUSTER_JOIN_STATE_LEFT, DESIRED_CLUSTER_ROLE_MEMBER, False, "failed")
    assert not ignores(CLUSTER_JOIN_STATE_LEAVING, DESIRED_CLUSTER_ROLE_NONE, False, "left")
    # not evicted at all
    assert not ignores(CLUSTER_JOIN_STATE_JOINING, DESIRED_CLUSTER_ROLE_MEMBER, False, "failed")
    assert not ignores(CLUSTER_JOIN_STATE_FAILED, None, False, "failed")
    assert not ignores(None, None, False, "ready")  # a cleared row: #590's self-heal


@pytest.mark.asyncio
async def test_a_late_failed_does_not_move_a_row_that_settled_left(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The live shape: Replace settled the failed joiner ``left``; the node, still
    alive, then reported ``failed``."""
    settled_at = datetime.now(UTC) - timedelta(seconds=30)
    row, token = await _node(
        db_session,
        cluster_join_state=CLUSTER_JOIN_STATE_LEFT,
        cluster_join_state_at=settled_at,
    )

    await _report(client, row, token, CLUSTER_JOIN_STATE_FAILED, _LATE)

    await db_session.refresh(row)
    assert row.cluster_join_state == CLUSTER_JOIN_STATE_LEFT
    assert row.cluster_join_reason is None
    assert row.cluster_join_state_at == settled_at  # nothing changed, nothing restamped


@pytest.mark.asyncio
async def test_a_late_failed_does_not_move_a_row_still_evicting(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    row, token = await _node(
        db_session,
        cluster_join_state=CLUSTER_JOIN_STATE_EVICTING,
        cluster_join_state_at=datetime.now(UTC),
        evict_requested=True,
    )

    await _report(client, row, token, CLUSTER_JOIN_STATE_FAILED, _LATE)

    await db_session.refresh(row)
    assert row.cluster_join_state == CLUSTER_JOIN_STATE_EVICTING
    assert row.evict_requested is True
    assert row.cluster_join_reason is None


@pytest.mark.asyncio
async def test_a_replaced_live_member_cannot_re_add_itself(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """``ready`` is never retired by the supervisor. Without the guard a live
    replaced member flipped back to ``ready`` and re-settled as a member on its
    next heartbeat, so Replace could not stick for a node that is alive."""
    row, token = await _node(
        db_session,
        cluster_join_state=CLUSTER_JOIN_STATE_LEFT,
        cluster_join_state_at=datetime.now(UTC),
    )

    await _report(client, row, token, CLUSTER_JOIN_STATE_READY)

    await db_session.refresh(row)
    assert row.cluster_join_state == CLUSTER_JOIN_STATE_LEFT
    assert row.cluster_role is None


@pytest.mark.asyncio
async def test_a_node_that_keeps_reporting_costs_one_log_line(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    row, token = await _node(
        db_session,
        cluster_join_state=CLUSTER_JOIN_STATE_LEFT,
        cluster_join_state_at=datetime.now(UTC),
    )

    with capture_logs() as events:
        for _ in range(3):
            await _report(client, row, token, CLUSTER_JOIN_STATE_READY)
        await _report(client, row, token, CLUSTER_JOIN_STATE_FAILED, _LATE)

    ignored = [e for e in events if e["event"] == "control_plane_evicted_node_report_ignored"]
    assert [(e["row_state"], e["reported"]) for e in ignored] == [
        ("left", "ready"),
        ("left", "failed"),
    ]
    assert ignored[0]["hostname"] == row.hostname


@pytest.mark.asyncio
async def test_a_new_promote_makes_the_nodes_reports_count_again(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    row, token = await _node(
        db_session,
        cluster_join_state=CLUSTER_JOIN_STATE_JOINING,
        cluster_join_state_at=datetime.now(UTC),
        desired_cluster_role=DESIRED_CLUSTER_ROLE_MEMBER,
        desired_k3s_server_url="https://10.0.0.1:6443",
        desired_k3s_join_token_encrypted=b"enc",
    )

    await _report(client, row, token, CLUSTER_JOIN_STATE_FAILED, _LATE)

    await db_session.refresh(row)
    assert row.cluster_join_state == CLUSTER_JOIN_STATE_FAILED
    assert row.cluster_join_reason == _LATE


@pytest.mark.asyncio
async def test_a_cleared_row_still_self_heals_on_ready(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#590 — a row whose bookkeeping was cleared mid-join (state None) settles
    as a member when the node reports ``ready``. It was never evicted."""
    row, token = await _node(db_session)

    await _report(client, row, token, CLUSTER_JOIN_STATE_READY)

    await db_session.refresh(row)
    assert row.cluster_join_state == CLUSTER_JOIN_STATE_READY
    assert row.cluster_role == CLUSTER_ROLE_MEMBER


@pytest.mark.asyncio
async def test_a_demote_in_flight_still_lands(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    row, token = await _node(
        db_session,
        cluster_role=CLUSTER_ROLE_MEMBER,
        cluster_join_state=CLUSTER_JOIN_STATE_LEAVING,
        cluster_join_state_at=datetime.now(UTC),
        desired_cluster_role=DESIRED_CLUSTER_ROLE_NONE,
    )

    await _report(client, row, token, CLUSTER_JOIN_STATE_LEFT)

    await db_session.refresh(row)
    assert row.cluster_join_state == CLUSTER_JOIN_STATE_LEFT
    assert row.cluster_role is None
    assert row.desired_cluster_role is None
