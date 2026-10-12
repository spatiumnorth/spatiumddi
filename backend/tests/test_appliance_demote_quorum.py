"""#1541 (walk finding 2) — a demote is refused while a control-plane member is down.

On the walk, member-2 was powered off for two minutes and both members were
demoted in one call. member-1's leave removed its own etcd member through its
LOCAL etcd, a follower whose view still counted the idle link to member-2 as
active, so etcd's own quorum guard passed and the seed was left one live voter
of two: no quorum and no api for 3 min 52 s. The backend had accepted the
demote although member-2's Node had been NotReady for at least 77 s.

So the control plane now judges first: a voter is live when its supervisor
heartbeated recently AND its k8s Node reads Ready. Any unhealthy voter that is
not being demoted refuses the demote (409, named); an unhealthy voter that is
being demoted is accepted only when the survivors keep a live majority at
every step of the leave.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import supervisor
from app.api.v1.appliance.supervisor import _demote_quorum_refusal, _VoterHealth
from app.models.appliance import (
    CLUSTER_JOIN_STATE_LEAVING,
    CLUSTER_ROLE_MEMBER,
    DESIRED_CLUSTER_ROLE_NONE,
)
from app.services.appliance import k8s
from tests.test_appliance_control_plane_promote import _admin, _appliance, _hdr, _seed

DEMOTE = "/api/v1/appliance/fleet/control-plane/demote"


def _v(name: str, live: bool = True) -> _VoterHealth:
    return _VoterHealth(name=name, live=live, why="" if live else "Node NotReady")


# ── the arithmetic (pure) ────────────────────────────────────────────


def test_a_healthy_three_to_one_is_allowed() -> None:
    assert _demote_quorum_refusal([_v("seed"), _v("m1"), _v("m2")], {"m1", "m2"}) is None


def test_the_walks_case_is_refused_and_names_the_dead_member() -> None:
    """3 voters, m2 powered off, both demoted. m2 is a target, so it is the
    arithmetic that refuses: after m1 (live) leaves, 1 of the remaining 2
    voters is live — not a majority."""
    why = _demote_quorum_refusal([_v("seed"), _v("m1"), _v("m2", live=False)], {"m1", "m2"})
    assert why is not None
    assert "1 of the remaining 2" in why
    assert "'m2'" in why


def test_an_unhealthy_member_that_stays_refuses_even_when_the_count_passes() -> None:
    """5 voters, m3 down and NOT demoted, m4 + m5 demoted: 2 of the final 3
    are live, a majority — but that end state could not lose another node."""
    voters = [_v("seed"), _v("m1"), _v("m2"), _v("m3", live=False), _v("m4"), _v("m5")]
    why = _demote_quorum_refusal(voters, {"m4", "m5"})
    assert why is not None and "'m3'" in why


def test_demoting_the_dead_member_is_allowed_when_a_majority_stays_live() -> None:
    """5 voters, m4 down, m4 + m5 demoted: m5 leaves, 3 of the remaining 4 are
    live. m4 waits in ``leaving`` until it comes back to run its leave."""
    voters = [_v("seed"), _v("m1"), _v("m2"), _v("m3"), _v("m4", live=False)]
    assert _demote_quorum_refusal(voters, {"m4", "m5"}) is None
    voters.append(_v("m5"))
    assert _demote_quorum_refusal(voters, {"m4", "m5"}) is None


def test_demoting_two_dead_members_of_five_is_refused() -> None:
    """5 voters, m3 + m4 down, demote m4 + m5... m3 is not a target: refused.
    And demote m3 + m4 (both dead) with all others live: 3 of 5 live and
    nothing live leaves — the cluster keeps the quorum it has, allowed."""
    voters = [_v("seed"), _v("m1"), _v("m2"), _v("m3", live=False), _v("m4", live=False)]
    assert _demote_quorum_refusal(voters, {"m4", "m5"}) is not None
    assert _demote_quorum_refusal(voters, {"m3", "m4"}) is None


def test_every_step_of_the_leave_keeps_quorum_when_the_last_does() -> None:
    """The docstring's claim, checked by brute force: for every voter count up
    to 7, every live/dead split and every leaving set, the rule passes only if
    every intermediate state (k live leavers gone) keeps a live majority."""
    from itertools import combinations

    for n in range(1, 8):
        names = [f"n{i}" for i in range(n)]
        for dead_k in range(n + 1):
            for dead in combinations(names, dead_k):
                voters = [_v(x, live=x not in dead) for x in names]
                for leave_k in range(n):
                    for leaving in combinations(names, leave_k):
                        if any(x in dead for x in names if x not in leaving):
                            continue  # refused outright, tested above
                        live = n - dead_k
                        live_leaving = sum(1 for x in leaving if x not in dead)
                        safe = all(2 * (live - k) > n - k for k in range(live_leaving + 1))
                        ok = _demote_quorum_refusal(voters, set(leaving)) is None
                        assert ok == safe, (n, dead, leaving)


# ── the endpoint ─────────────────────────────────────────────────────


async def _three(db: AsyncSession, *, m2_seen_ago: timedelta = timedelta(0)):
    now = datetime.now(UTC)
    seed = await _seed(db)
    seed.last_seen_at = now
    m1 = await _appliance(db, "m1", cluster_role=CLUSTER_ROLE_MEMBER, last_seen_at=now)
    m2 = await _appliance(
        db, "m2", cluster_role=CLUSTER_ROLE_MEMBER, last_seen_at=now - m2_seen_ago
    )
    return seed, m1, m2


@pytest.mark.asyncio
async def test_the_walks_demote_is_refused_on_a_stale_heartbeat(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token = await _admin(db_session)
    _, m1, m2 = await _three(db_session, m2_seen_ago=timedelta(minutes=2))
    await db_session.commit()

    resp = await client.post(
        DEMOTE, json={"appliance_ids": [str(m1.id), str(m2.id)]}, headers=_hdr(token)
    )

    assert resp.status_code == 409, resp.text
    assert "'m2'" in resp.text and "last heartbeat" in resp.text
    await db_session.refresh(m1)
    assert m1.desired_cluster_role is None  # nothing was stamped


@pytest.mark.asyncio
async def test_a_notready_node_refuses_the_demote(
    db_session: AsyncSession, client: AsyncClient, monkeypatch
) -> None:
    """The heartbeat can still be fresh (a supervisor answering from a node
    whose kubelet is wedged); the Node's Ready condition is the second check."""
    token = await _admin(db_session)
    _, m1, m2 = await _three(db_session)
    await db_session.commit()
    monkeypatch.setattr(
        supervisor, "_node_ready_map", lambda: {"seed": True, "m1": True, "m2": False}
    )

    resp = await client.post(
        DEMOTE, json={"appliance_ids": [str(m1.id), str(m2.id)]}, headers=_hdr(token)
    )

    assert resp.status_code == 409, resp.text
    assert "'m2'" in resp.text and "Node NotReady" in resp.text


@pytest.mark.asyncio
async def test_a_member_with_no_node_counts_as_down(
    db_session: AsyncSession, client: AsyncClient, monkeypatch
) -> None:
    token = await _admin(db_session)
    _, m1, m2 = await _three(db_session)
    await db_session.commit()
    monkeypatch.setattr(supervisor, "_node_ready_map", lambda: {"seed": True, "m1": True})

    resp = await client.post(
        DEMOTE, json={"appliance_ids": [str(m1.id), str(m2.id)]}, headers=_hdr(token)
    )

    assert resp.status_code == 409, resp.text
    assert "no k8s Node" in resp.text


@pytest.mark.asyncio
async def test_a_healthy_cluster_demotes(
    db_session: AsyncSession, client: AsyncClient, monkeypatch
) -> None:
    token = await _admin(db_session)
    _, m1, m2 = await _three(db_session)
    await db_session.commit()
    monkeypatch.setattr(
        supervisor, "_node_ready_map", lambda: {"seed": True, "m1": True, "m2": True}
    )

    resp = await client.post(
        DEMOTE, json={"appliance_ids": [str(m1.id), str(m2.id)]}, headers=_hdr(token)
    )

    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_an_unreadable_node_list_is_a_503_not_a_guess(
    db_session: AsyncSession, client: AsyncClient, monkeypatch
) -> None:
    token = await _admin(db_session)
    _, m1, m2 = await _three(db_session)
    await db_session.commit()

    def _boom() -> dict[str, bool]:
        raise k8s.KubeapiUnavailableError("node list returned 500")

    monkeypatch.setattr(supervisor, "_node_ready_map", _boom)

    resp = await client.post(
        DEMOTE, json={"appliance_ids": [str(m1.id), str(m2.id)]}, headers=_hdr(token)
    )

    assert resp.status_code == 503, resp.text


@pytest.mark.asyncio
async def test_a_leave_already_in_flight_counts_as_leaving(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """Five voters; m3 + m4 are already leaving (an earlier demote) and m4 has
    gone quiet mid-reset. Demoting m1 + m2 now would remove three live voters
    (m1, m2, m3) from five with one dead: 1 of the remaining 2 live. The
    in-flight leaver is a target of the arithmetic, not a voter that stays."""
    token = await _admin(db_session)
    now = datetime.now(UTC)
    seed = await _seed(db_session)
    seed.last_seen_at = now
    m1 = await _appliance(db_session, "m1", cluster_role=CLUSTER_ROLE_MEMBER, last_seen_at=now)
    m2 = await _appliance(db_session, "m2", cluster_role=CLUSTER_ROLE_MEMBER, last_seen_at=now)
    for name, seen in (("m3", now), ("m4", now - timedelta(minutes=5))):
        await _appliance(
            db_session,
            name,
            cluster_role=CLUSTER_ROLE_MEMBER,
            desired_cluster_role=DESIRED_CLUSTER_ROLE_NONE,
            cluster_join_state=CLUSTER_JOIN_STATE_LEAVING,
            last_seen_at=seen,
        )
    await db_session.commit()

    resp = await client.post(
        DEMOTE, json={"appliance_ids": [str(m1.id), str(m2.id)]}, headers=_hdr(token)
    )

    # The odd-count check sees 3 effective members (m3/m4 already excluded)
    # and 3 - 2 = 1 is odd, so it is the quorum check that refuses.
    assert resp.status_code == 409, resp.text
    assert "1 of the remaining 2" in resp.text


# ── who the refusal names (#1659 walk, C3) ───────────────────────────


def test_the_refusal_names_every_unhealthy_voter() -> None:
    """A staying member that reads down and a demoted one that is down are
    both named, each marked, so the operator is not sent to fix one node
    while the other goes unmentioned."""
    voters = [_v("seed", live=False), _v("m1"), _v("m2", live=False)]
    why = _demote_quorum_refusal(voters, {"m1", "m2"})
    assert why is not None
    assert "'seed' (Node NotReady; staying)" in why
    assert "'m2' (Node NotReady; being demoted)" in why
    assert "0 of the remaining 2" in why
    assert "Bring it back, or Replace it" in why


@pytest.mark.asyncio
async def test_a_stale_seed_heartbeat_does_not_hide_the_powered_off_member(
    db_session: AsyncSession, client: AsyncClient, monkeypatch
) -> None:
    """The walk's C3: m2 powered off (Node NotReady, heartbeat stale) and the
    seed's own heartbeat stalled too (#1805) while its Node stayed Ready. On
    k3s the seed is judged by its Node, so the refusal names m2 — and only
    m2 — instead of the seed."""
    token = await _admin(db_session)
    seed, m1, m2 = await _three(db_session, m2_seen_ago=timedelta(seconds=94))
    seed.last_seen_at = datetime.now(UTC) - timedelta(seconds=95)
    await db_session.commit()
    monkeypatch.setattr(
        supervisor, "_node_ready_map", lambda: {"seed": True, "m1": True, "m2": False}
    )

    resp = await client.post(
        DEMOTE, json={"appliance_ids": [str(m1.id), str(m2.id)]}, headers=_hdr(token)
    )

    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    assert "'m2'" in detail and "Node NotReady" in detail
    assert "'seed'" not in detail
    assert "1 of the remaining 2" in detail
    await db_session.refresh(m1)
    assert m1.desired_cluster_role is None


@pytest.mark.asyncio
async def test_a_seed_whose_node_is_notready_still_refuses(
    db_session: AsyncSession, client: AsyncClient, monkeypatch
) -> None:
    """Fail closed: dropping the seed's heartbeat from the judgement does not
    make it unconditionally live — its Node is still read."""
    token = await _admin(db_session)
    _, m1, m2 = await _three(db_session)
    await db_session.commit()
    monkeypatch.setattr(
        supervisor, "_node_ready_map", lambda: {"seed": False, "m1": True, "m2": True}
    )

    resp = await client.post(
        DEMOTE, json={"appliance_ids": [str(m1.id), str(m2.id)]}, headers=_hdr(token)
    )

    assert resp.status_code == 409, resp.text
    assert "'seed' (Node NotReady; staying)" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_off_k3s_a_stale_seed_heartbeat_still_refuses(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """With no Node list to read the heartbeat is the only evidence, so a
    stale seed still refuses (and is named)."""
    token = await _admin(db_session)
    seed, m1, m2 = await _three(db_session)
    seed.last_seen_at = datetime.now(UTC) - timedelta(minutes=3)
    await db_session.commit()

    resp = await client.post(
        DEMOTE, json={"appliance_ids": [str(m1.id), str(m2.id)]}, headers=_hdr(token)
    )

    assert resp.status_code == 409, resp.text
    assert "'seed'" in resp.json()["detail"]
