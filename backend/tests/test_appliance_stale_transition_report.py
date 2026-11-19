"""#1806 — a demoting member's row must not read ``ready`` during its leave.

Demote stamps ``leaving`` on the row; the node's supervisor keeps reporting its
last verdict (``ready``) until its leave runner writes its own state. The
heartbeat handler applied it, so the Fleet / cluster view showed the leaving
member as healthy. The mirror race: a promoted node that was once demoted still
reports ``left`` while its row says ``joining``.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import supervisor as sup
from app.models.appliance import (
    CLUSTER_JOIN_STATE_EVICTING,
    CLUSTER_JOIN_STATE_FAILED,
    CLUSTER_JOIN_STATE_JOINING,
    CLUSTER_JOIN_STATE_LEAVING,
    CLUSTER_JOIN_STATE_LEFT,
    CLUSTER_JOIN_STATE_READY,
    CLUSTER_ROLE_MEMBER,
    DESIRED_CLUSTER_ROLE_MEMBER,
    DESIRED_CLUSTER_ROLE_NONE,
)
from tests.test_appliance_evicted_row_stays import _node, _report


def test_which_reports_are_stale_in_a_transition() -> None:
    stale = sup._stale_report_in_transition
    none_role, member_role = DESIRED_CLUSTER_ROLE_NONE, DESIRED_CLUSTER_ROLE_MEMBER
    for r in ("ready", "joining"):
        assert stale(CLUSTER_JOIN_STATE_LEAVING, none_role, r)
    for r in ("left", "failed", "leaving"):
        assert not stale(CLUSTER_JOIN_STATE_LEAVING, none_role, r)
    for r in ("left", "leaving"):
        assert stale(CLUSTER_JOIN_STATE_JOINING, member_role, r)
    for r in ("ready", "failed", "joining"):
        assert not stale(CLUSTER_JOIN_STATE_JOINING, member_role, r)
    # no transition in flight: nothing is stale (#590 self-heal etc.)
    assert not stale(CLUSTER_JOIN_STATE_READY, None, "ready")
    assert not stale(None, None, "ready")


async def _leaving(db: AsyncSession):
    return await _node(
        db,
        cluster_role=CLUSTER_ROLE_MEMBER,
        cluster_join_state=CLUSTER_JOIN_STATE_LEAVING,
        cluster_join_state_at=datetime.now(UTC),
        desired_cluster_role=DESIRED_CLUSTER_ROLE_NONE,
    )


@pytest.mark.asyncio
async def test_ready_does_not_overwrite_leaving(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    row, token = await _leaving(db_session)
    started_at = row.cluster_join_state_at
    for _ in range(3):  # the node reports ready on every heartbeat
        await _report(client, row, token, CLUSTER_JOIN_STATE_READY)
    await db_session.refresh(row)
    assert row.cluster_join_state == CLUSTER_JOIN_STATE_LEAVING
    # The #590 staleness clock still measures the leave, so a leave whose
    # runner never starts is offered the clear-state hatch on time.
    assert row.cluster_join_state_at == started_at
    assert row.cluster_role == CLUSTER_ROLE_MEMBER
    assert row.desired_cluster_role == DESIRED_CLUSTER_ROLE_NONE


@pytest.mark.asyncio
async def test_leaving_then_left_still_completes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    row, token = await _leaving(db_session)
    await _report(client, row, token, CLUSTER_JOIN_STATE_READY)
    await _report(client, row, token, CLUSTER_JOIN_STATE_LEAVING)
    await db_session.refresh(row)
    assert row.cluster_join_state == CLUSTER_JOIN_STATE_LEAVING
    await _report(client, row, token, CLUSTER_JOIN_STATE_LEFT)
    await db_session.refresh(row)
    assert row.cluster_join_state == CLUSTER_JOIN_STATE_EVICTING
    assert row.cluster_role is None


@pytest.mark.asyncio
async def test_failed_leave_is_still_reported(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    row, token = await _leaving(db_session)
    await _report(client, row, token, CLUSTER_JOIN_STATE_FAILED, "boom")
    await db_session.refresh(row)
    assert row.cluster_join_state == CLUSTER_JOIN_STATE_FAILED
    assert row.desired_cluster_role is None


@pytest.mark.asyncio
async def test_stale_left_does_not_overwrite_joining(
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
    await _report(client, row, token, CLUSTER_JOIN_STATE_LEFT)
    await db_session.refresh(row)
    assert row.cluster_join_state == CLUSTER_JOIN_STATE_JOINING
    await _report(client, row, token, CLUSTER_JOIN_STATE_READY)
    await db_session.refresh(row)
    assert row.cluster_role == CLUSTER_ROLE_MEMBER
    assert row.desired_cluster_role is None
