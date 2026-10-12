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

import copy
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import supervisor
from app.api.v1.appliance.supervisor import _demote_quorum_refusal, _VoterHealth
from app.models.appliance import (
    CLUSTER_JOIN_STATE_JOINING,
    CLUSTER_JOIN_STATE_LEAVING,
    CLUSTER_ROLE_MEMBER,
    DESIRED_CLUSTER_ROLE_MEMBER,
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


# ── #1750 — the leaving node is cordoned ─────────────────────────────
#
# A fake kubeapi holding real Node documents, so each test asserts on the
# Node the cluster would end up with (cordoned? marked?) rather than on which
# helper was called. Every other kubeapi request raises, so nothing in the
# heartbeat reaches a network.

ANN = supervisor.DEMOTE_CORDON_ANNOTATION


class _FakeNodes:
    def __init__(self, names: tuple[str, ...], cordoned: tuple[str, ...] = ()) -> None:
        self.nodes: dict[str, dict] = {
            n: {"metadata": {"name": n}, "spec": {"unschedulable": n in cordoned}} for n in names
        }
        self.calls: list[tuple[str, str]] = []
        self.on_patch = None

    def get_node(self, name: str):
        self.calls.append(("get", name))
        node = self.nodes.get(name)
        return (200, copy.deepcopy(node)) if node is not None else (404, None)

    def patch_node(self, name: str, patch: dict):
        if self.on_patch is not None:
            self.on_patch(name)
        node = self.nodes.get(name)
        if node is None:
            self.calls.append(("patch-404", name))
            return 404, "kubeapi status 404"
        ann = node.setdefault("metadata", {}).setdefault("annotations", {})
        for k, v in ((patch.get("metadata") or {}).get("annotations") or {}).items():
            if v is None:
                ann.pop(k, None)
            else:
                ann[k] = v
        if "unschedulable" in (patch.get("spec") or {}):
            node.setdefault("spec", {})["unschedulable"] = patch["spec"]["unschedulable"]
            self.calls.append(("cordon" if patch["spec"]["unschedulable"] else "uncordon", name))
        return 200, None

    def cordoned(self, name: str) -> bool:
        return bool(self.nodes[name]["spec"].get("unschedulable"))

    def marked(self, name: str) -> bool:
        return ANN in ((self.nodes[name].get("metadata") or {}).get("annotations") or {})


def _fake_kubeapi(monkeypatch, *names: str, cordoned: tuple[str, ...] = ()) -> _FakeNodes:
    fake = _FakeNodes(names, cordoned)

    def _no_network(*_a, **_kw):
        raise k8s.KubeapiUnavailableError("test: no kubeapi")

    monkeypatch.setattr(k8s, "get_config", lambda: object())
    monkeypatch.setattr(k8s, "_request", _no_network)
    monkeypatch.setattr(k8s, "get_node", fake.get_node)
    monkeypatch.setattr(k8s, "patch_node", fake.patch_node)
    monkeypatch.setattr(supervisor, "_node_ready_map", lambda: {n: True for n in ("seed", *names)})
    return fake


def _clear_url(row) -> str:
    return f"/api/v1/appliance/fleet/control-plane/{row.id}/clear-cluster-state"


@pytest.mark.asyncio
async def test_a_demote_cordons_each_target_before_stamping(
    db_session: AsyncSession, client: AsyncClient, monkeypatch
) -> None:
    token = await _admin(db_session)
    _, m1, m2 = await _three(db_session)
    await db_session.commit()
    fake = _fake_kubeapi(monkeypatch, "m1", "m2")
    # The handler shares this session, so these are the rows it stamps.
    rows = {"m1": m1, "m2": m2}
    seen_at_cordon: dict[str, str | None] = {}
    fake.on_patch = lambda name: seen_at_cordon.setdefault(name, rows[name].desired_cluster_role)

    resp = await client.post(
        DEMOTE, json={"appliance_ids": [str(m1.id), str(m2.id)]}, headers=_hdr(token)
    )

    assert resp.status_code == 200, resp.text
    assert fake.cordoned("m1") and fake.cordoned("m2")
    assert fake.marked("m1") and fake.marked("m2")
    # Cordoned while neither row was stamped yet: nothing reached the
    # supervisor (and so the leave runner) ahead of the cordon.
    assert seen_at_cordon == {"m1": None, "m2": None}
    await db_session.refresh(m1)
    assert m1.desired_cluster_role == DESIRED_CLUSTER_ROLE_NONE


@pytest.mark.asyncio
async def test_a_refused_demote_cordons_nothing(
    db_session: AsyncSession, client: AsyncClient, monkeypatch
) -> None:
    token = await _admin(db_session)
    _, m1, m2 = await _three(db_session, m2_seen_ago=timedelta(minutes=2))
    await db_session.commit()
    fake = _fake_kubeapi(monkeypatch, "m1", "m2")

    resp = await client.post(
        DEMOTE, json={"appliance_ids": [str(m1.id), str(m2.id)]}, headers=_hdr(token)
    )

    assert resp.status_code == 409, resp.text
    assert not fake.cordoned("m1") and not fake.cordoned("m2")
    assert [c for c in fake.calls if c[0] != "get"] == []


@pytest.mark.asyncio
async def test_a_cordon_failure_does_not_fail_the_demote(
    db_session: AsyncSession, client: AsyncClient, monkeypatch
) -> None:
    token = await _admin(db_session)
    _, m1, m2 = await _three(db_session)
    await db_session.commit()
    _fake_kubeapi(monkeypatch, "m1", "m2")
    monkeypatch.setattr(k8s, "patch_node", lambda *_a: (0, "ServiceAccount not mounted"))

    resp = await client.post(
        DEMOTE, json={"appliance_ids": [str(m1.id), str(m2.id)]}, headers=_hdr(token)
    )

    assert resp.status_code == 200, resp.text
    await db_session.refresh(m1)
    assert m1.desired_cluster_role == DESIRED_CLUSTER_ROLE_NONE


async def _leaving_member(db_session: AsyncSession, hostname: str):
    from tests.test_appliance_evict_etcd import _row

    return await _row(
        db_session,
        hostname,
        appliance_variant="appliance",
        cluster_role=CLUSTER_ROLE_MEMBER,
        desired_cluster_role=DESIRED_CLUSTER_ROLE_NONE,
        cluster_join_state=CLUSTER_JOIN_STATE_LEAVING,
        cluster_join_state_at=datetime.now(UTC),
    )


async def _sessions(db_session: AsyncSession, *rows) -> dict[str, str]:
    """Give demote-test rows a supervisor heartbeat session."""
    from app.models.settings import PlatformSettings  # noqa: PLC0415
    from app.services.appliance.ca import generate_session_token  # noqa: PLC0415

    settings_row = await db_session.get(PlatformSettings, 1)
    if settings_row is None:
        settings_row = PlatformSettings(id=1)
        db_session.add(settings_row)
    settings_row.supervisor_registration_enabled = True
    tokens = {}
    for row in rows:
        tok, tok_hash = generate_session_token()
        row.session_token_hash = tok_hash
        row.cert_serial = row.cert_serial or "c0ffee00"
        tokens[row.hostname] = tok
    await db_session.commit()
    return tokens


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reason",
    [
        # rc != 0 from --leave-self: etcd refused the removal, k3s restarted.
        "leave refused: this node's etcd member removal was not confirmed by the "
        "cluster, so the node was not reset (see etcd-evict.log)",
        # wiped, but the standalone k3s never came Ready.
        "leave failed; k3s not Ready",
    ],
)
async def test_a_failed_leave_uncordons_the_node(
    db_session: AsyncSession, client: AsyncClient, monkeypatch, reason: str
) -> None:
    from tests.test_appliance_evict_etcd import _beat

    member, member_token = await _leaving_member(db_session, "m-failed")
    await db_session.commit()
    fake = _fake_kubeapi(monkeypatch, "m-failed")
    fake.nodes["m-failed"]["spec"]["unschedulable"] = True
    fake.nodes["m-failed"]["metadata"]["annotations"] = {ANN: "true"}

    await _beat(
        client, member, member_token, cluster_join_state="failed", cluster_join_reason=reason
    )

    assert not fake.cordoned("m-failed") and not fake.marked("m-failed")
    await db_session.refresh(member)
    assert member.cluster_role == CLUSTER_ROLE_MEMBER
    assert member.desired_cluster_role is None

    # The supervisor re-reports ``failed`` until it sees no desired role; the
    # branch does not fire again (desired is gone), so one uncordon only.
    await _beat(
        client, member, member_token, cluster_join_state="failed", cluster_join_reason=reason
    )
    assert [c for c in fake.calls if c[0] == "uncordon"] == [("uncordon", "m-failed")]


@pytest.mark.asyncio
async def test_a_failed_leave_keeps_an_operators_own_cordon(
    db_session: AsyncSession, client: AsyncClient, monkeypatch
) -> None:
    """The node was cordoned before the demote (maintenance, say). The demote
    leaves it alone and unmarked, so the failed leave leaves it cordoned."""
    from tests.test_appliance_evict_etcd import _beat

    token = await _admin(db_session)
    _, m1, m2 = await _three(db_session)
    await db_session.commit()
    fake = _fake_kubeapi(monkeypatch, "m1", "m2", cordoned=("m1",))

    resp = await client.post(
        DEMOTE, json={"appliance_ids": [str(m1.id), str(m2.id)]}, headers=_hdr(token)
    )
    assert resp.status_code == 200, resp.text
    assert fake.cordoned("m1") and not fake.marked("m1")
    assert fake.cordoned("m2") and fake.marked("m2")

    # Both leaves fail.
    tokens = await _sessions(db_session, m1, m2)
    for row in (m1, m2):
        await _beat(client, row, tokens[row.hostname], cluster_join_state="failed")

    assert fake.cordoned("m1"), "an operator's cordon must survive a failed leave"
    assert not fake.cordoned("m2") and not fake.marked("m2")


@pytest.mark.asyncio
async def test_uncordoning_a_node_that_is_gone_is_harmless(
    db_session: AsyncSession, client: AsyncClient, monkeypatch
) -> None:
    from tests.test_appliance_evict_etcd import _beat

    member, member_token = await _leaving_member(db_session, "m-gone")
    await db_session.commit()
    fake = _fake_kubeapi(monkeypatch)  # no Node at all
    warned: list[str] = []
    monkeypatch.setattr(supervisor.logger, "warning", lambda ev, **_kw: warned.append(ev))

    await _beat(client, member, member_token, cluster_join_state="failed")

    assert ("get", "m-gone") in fake.calls
    assert not [c for c in fake.calls if c[0] != "get"]
    assert "control_plane_uncordon_failed" not in warned


@pytest.mark.asyncio
async def test_a_completed_leave_is_never_uncordoned(
    db_session: AsyncSession, client: AsyncClient, monkeypatch
) -> None:
    """``left`` hands the row to the seed's eviction, which deletes the Node.
    Nothing on that path — nor a later ``failed`` the wiped node reports from
    a stale sidecar — may touch the Node."""
    from tests.test_appliance_evict_etcd import _beat

    member, member_token = await _leaving_member(db_session, "m-left")
    await db_session.commit()
    fake = _fake_kubeapi(monkeypatch, "m-left")
    fake.nodes["m-left"]["spec"]["unschedulable"] = True
    fake.nodes["m-left"]["metadata"]["annotations"] = {ANN: "true"}

    await _beat(client, member, member_token, cluster_join_state="left")
    await _beat(client, member, member_token, cluster_join_state="failed")

    assert fake.cordoned("m-left")
    assert [c for c in fake.calls if c[0] in ("cordon", "uncordon")] == []


@pytest.mark.asyncio
async def test_clear_cluster_state_on_an_abandoned_demote_uncordons(
    db_session: AsyncSession, client: AsyncClient, monkeypatch
) -> None:
    token = await _admin(db_session)
    member, _ = await _leaving_member(db_session, "m-stuck")
    await db_session.commit()
    fake = _fake_kubeapi(monkeypatch, "m-stuck")
    fake.nodes["m-stuck"]["spec"]["unschedulable"] = True
    fake.nodes["m-stuck"]["metadata"]["annotations"] = {ANN: "true"}

    resp = await client.post(_clear_url(member), json={"force": True}, headers=_hdr(token))

    assert resp.status_code == 200, resp.text
    assert not fake.cordoned("m-stuck") and not fake.marked("m-stuck")


@pytest.mark.asyncio
async def test_clear_cluster_state_keeps_an_operators_cordon(
    db_session: AsyncSession, client: AsyncClient, monkeypatch
) -> None:
    token = await _admin(db_session)
    member, _ = await _leaving_member(db_session, "m-stuck2")
    await db_session.commit()
    fake = _fake_kubeapi(monkeypatch, "m-stuck2", cordoned=("m-stuck2",))

    resp = await client.post(_clear_url(member), json={"force": True}, headers=_hdr(token))

    assert resp.status_code == 200, resp.text
    assert fake.cordoned("m-stuck2")


@pytest.mark.asyncio
async def test_a_retried_demote_cordons_again(
    db_session: AsyncSession, client: AsyncClient, monkeypatch
) -> None:
    """A failed leave released the node; demoting it again cordons it again —
    and a cordon the failed leave could not release (kubeapi blip) still reads
    as the demote's own, not the operator's, so the retry's failure releases it."""
    from tests.test_appliance_evict_etcd import _beat

    token = await _admin(db_session)
    _, m1, m2 = await _three(db_session)
    await db_session.commit()
    fake = _fake_kubeapi(monkeypatch, "m1", "m2")
    body = {"appliance_ids": [str(m1.id), str(m2.id)]}

    assert (await client.post(DEMOTE, json=body, headers=_hdr(token))).status_code == 200
    # m2's leave fails and its uncordon is lost; m1's fails and is released.
    tokens = await _sessions(db_session, m1, m2)
    real_patch = fake.patch_node
    monkeypatch.setattr(
        k8s,
        "patch_node",
        lambda name, patch: (0, "blip") if name == "m2" else real_patch(name, patch),
    )
    for row in (m1, m2):
        await _beat(client, row, tokens[row.hostname], cluster_join_state="failed")
    monkeypatch.setattr(k8s, "patch_node", real_patch)
    assert not fake.cordoned("m1") and fake.cordoned("m2") and fake.marked("m2")

    # Retry. Rows report ``ready`` again (k3s back up as a member).
    for row in (m1, m2):
        await _beat(client, row, tokens[row.hostname], cluster_join_state="ready")
    resp = await client.post(DEMOTE, json=body, headers=_hdr(token))
    assert resp.status_code == 200, resp.text
    assert fake.cordoned("m1") and fake.marked("m1")
    assert fake.cordoned("m2") and fake.marked("m2")

    for row in (m1, m2):
        await _beat(client, row, tokens[row.hostname], cluster_join_state="failed")
    assert not fake.cordoned("m1") and not fake.cordoned("m2")


@pytest.mark.asyncio
async def test_a_re_promote_does_not_inherit_the_demotes_cordon(
    db_session: AsyncSession, client: AsyncClient, monkeypatch
) -> None:
    """A re-joined node normally registers a fresh Node. If it re-uses one an
    earlier demote cordoned, the join's ``ready`` settle releases it — and
    only the demote's cordon, never an operator's."""
    from tests.test_appliance_evict_etcd import _beat, _row

    ours, ours_token = await _row(
        db_session,
        "m-back",
        appliance_variant="appliance",
        desired_cluster_role=DESIRED_CLUSTER_ROLE_MEMBER,
        cluster_join_state=CLUSTER_JOIN_STATE_JOINING,
    )
    theirs, theirs_token = await _row(
        db_session,
        "m-maint",
        appliance_variant="appliance",
        desired_cluster_role=DESIRED_CLUSTER_ROLE_MEMBER,
        cluster_join_state=CLUSTER_JOIN_STATE_JOINING,
    )
    await db_session.commit()
    fake = _fake_kubeapi(monkeypatch, "m-back", "m-maint", cordoned=("m-maint",))
    fake.nodes["m-back"]["spec"]["unschedulable"] = True
    fake.nodes["m-back"]["metadata"]["annotations"] = {ANN: "true"}

    await _beat(client, ours, ours_token, cluster_join_state="ready")
    await _beat(client, theirs, theirs_token, cluster_join_state="ready")

    await db_session.refresh(ours)
    assert ours.cluster_role == CLUSTER_ROLE_MEMBER
    assert not fake.cordoned("m-back") and not fake.marked("m-back")
    assert fake.cordoned("m-maint")


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
