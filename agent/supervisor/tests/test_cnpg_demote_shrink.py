"""#1541 — a demote scales the control plane down; only a Replace holds it.

The walk of #1659 (finding 1): a demoted node's ``left`` hands its row to the
seed's eviction, the same path a dead-node Replace takes, and #1059's hold
armed on every eviction tick. Neither of the hold's releases can fire after a
demote — the committed count is already at its new size on the eviction tick,
and no replacement will bring it back — so a cluster demoted to one node kept
three CNPG instances and three api / frontend / worker / redis replicas, with
their pods Pending on the lone seed, until an operator promoted again.

Two separate things kept it there, and both are pinned here:

* the hold (``_ReplaceHold``) armed on the demote's eviction: now only the
  names the backend sends as ``replace_node_names`` arm it (``_replace_names``);
* behind it, ``patch_cnpg_instances``'s readiness deferral: the departed
  nodes' instances never report ready again, so ``readyInstances <
  instances`` for good. ``_DemoteShrink`` lifts it for a demote, and only for
  a size no smaller than what is ready.
"""

from __future__ import annotations

import inspect

import yaml

from spatium_supervisor import heartbeat, k8s_api
from spatium_supervisor.heartbeat import _DemoteShrink, _ReplaceHold, _replace_names
from tests.test_cnpg_instances_rendered import _Cluster

M1, M2 = "ddipg-member-1", "ddipg-member-2"


def _tick(kube: _Cluster, hold: _ReplaceHold, shrink: _DemoteShrink, cp_size: int,
          body_out: dict) -> None:
    """The heartbeat's cp-size block, in its order (see the structural test
    below, which pins that ``heartbeat_once`` reads its inputs this way)."""
    why = hold.reason(_replace_names(body_out), cp_size)
    allow = shrink.allow(body_out.get("demote_evict_node_names") or [], cp_size)
    pg = k8s_api.patch_cnpg_instances(
        cp_size, scale_down=not why, hold_reason=why, shrink_past_unready=allow
    )
    hold.settle(cp_size, pg.current)
    shrink.settle(cp_size, pg.spec_after(cp_size))
    cnpg_instances = pg.spec_after(cp_size)
    if cnpg_instances is not None:
        k8s_api.apply_control_plane_overrides(
            heartbeat._release_size(cp_size, why, cnpg_instances), "",
            cnpg_instances=cnpg_instances,
        )


def _replicas(kube: _Cluster) -> int:
    return yaml.safe_load(kube.config)["api"]["replicas"]


def test_a_demote_to_one_node_scales_everything_to_one(monkeypatch) -> None:
    """The walk's 3 -> 1. Both members left etcd and reset before reporting
    ``left``, so on the eviction tick their instances are already unready
    (ready 1 of 3) and the committed count is 1."""
    kube = _Cluster(3)
    monkeypatch.setattr(k8s_api, "_request", kube)
    hold, shrink = _ReplaceHold(), _DemoteShrink()
    _tick(kube, hold, shrink, 3, {})
    assert kube.spec["instances"] == 3 and _replicas(kube) == 3

    kube.ready = 1
    _tick(kube, hold, shrink, 1, {
        "evict_node_names": [M1, M2],
        "replace_node_names": [],
        "demote_evict_node_names": [M1, M2],
    })

    assert not hold.armed
    assert kube.spec["instances"] == 1 and kube.rendered == 1
    assert _replicas(kube) == 1
    assert not shrink.armed  # done: the spec is at the committed count

    # The seed confirms etcd, the rows settle ``left``: quiet ticks stay at 1.
    for _ in range(3):
        _tick(kube, hold, shrink, 1, {"evict_node_names": [], "replace_node_names": [],
                                      "demote_evict_node_names": []})
        assert kube.spec["instances"] == 1 and _replicas(kube) == 1


def test_the_shrink_outlives_the_eviction_when_the_first_write_fails(monkeypatch) -> None:
    """The eviction settles in a tick or two; a scale-down whose write failed
    on the eviction tick must still land after the names are gone."""
    kube = _Cluster(3, ready=1)
    kube.fail_cluster_patch = True
    monkeypatch.setattr(k8s_api, "_request", kube)
    hold, shrink = _ReplaceHold(), _DemoteShrink()

    _tick(kube, hold, shrink, 1, {"evict_node_names": [M1, M2], "replace_node_names": [],
                                  "demote_evict_node_names": [M1, M2]})
    assert kube.spec["instances"] == 3 and shrink.armed

    kube.fail_cluster_patch = False
    _tick(kube, hold, shrink, 1, {"evict_node_names": [], "replace_node_names": [],
                                  "demote_evict_node_names": []})
    assert kube.spec["instances"] == 1 and _replicas(kube) == 1
    assert not shrink.armed


def test_a_replace_still_holds(monkeypatch) -> None:
    """#1059 unchanged: a Replace's eviction tick keeps the size and the
    release, and the demote path does not loosen it."""
    kube = _Cluster(3, ready=2)
    monkeypatch.setattr(k8s_api, "_request", kube)
    hold, shrink = _ReplaceHold(), _DemoteShrink()

    _tick(kube, hold, shrink, 2, {"evict_node_names": [M2], "replace_node_names": [M2],
                                  "demote_evict_node_names": []})

    assert hold.armed and not shrink.armed
    assert kube.spec["instances"] == 3 and kube.rendered == 3


def test_a_replace_beside_a_demote_still_holds(monkeypatch) -> None:
    kube = _Cluster(3, ready=1)
    monkeypatch.setattr(k8s_api, "_request", kube)
    hold, shrink = _ReplaceHold(), _DemoteShrink()

    _tick(kube, hold, shrink, 1, {"evict_node_names": [M1, M2], "replace_node_names": [M2],
                                  "demote_evict_node_names": [M1]})

    assert hold.armed
    assert kube.spec["instances"] == 3


# ---- _replace_names --------------------------------------------------------------------


def test_only_the_replaces_arm_the_hold() -> None:
    assert _replace_names({"evict_node_names": [M1, M2], "replace_node_names": [M2]}) == [M2]
    assert _replace_names({"evict_node_names": [M1], "replace_node_names": []}) == []


def test_a_backend_without_the_split_holds_on_every_eviction() -> None:
    """An older control plane never evicted a demoted node, so every eviction
    it sends is a Replace: keep holding on them."""
    assert _replace_names({"evict_node_names": [M1, ""]}) == [M1]
    assert _replace_names({"evict_node_names": [M1], "replace_node_names": None}) == [M1]
    assert _replace_names({}) == []


# ---- _DemoteShrink ---------------------------------------------------------------------


def test_the_shrink_is_off_until_a_demote_names_a_node() -> None:
    s = _DemoteShrink()
    assert s.allow([], 1) is False
    assert s.allow(["", None], 1) is False
    assert s.allow([M1], 1) is True and s.armed


def test_a_promote_after_the_demote_ends_the_shrink() -> None:
    s = _DemoteShrink()
    s.allow([M1, M2], 1)
    s.settle(1, 3)  # deferred: the Cluster is still at 3
    assert s.armed

    assert s.allow([], 3) is False
    assert not s.armed


def test_an_unreadable_cluster_keeps_the_shrink() -> None:
    s = _DemoteShrink()
    s.allow([M1], 1)
    s.settle(1, None)
    assert s.armed


# ---- patch_cnpg_instances(shrink_past_unready=…) ---------------------------------------


def test_the_shrink_writes_past_the_departed_instances(monkeypatch) -> None:
    kube = _Cluster(3, ready=1)
    monkeypatch.setattr(k8s_api, "_request", kube)

    res = k8s_api.patch_cnpg_instances(1, shrink_past_unready=True)

    assert res.scaled and not res.deferred
    assert kube.spec["instances"] == 1


def test_the_shrink_never_goes_below_what_is_ready(monkeypatch) -> None:
    """A size below the ready count could make CloudNativePG remove a healthy
    instance once the Cluster is whole: still deferred."""
    kube = _Cluster(5, ready=4)
    monkeypatch.setattr(k8s_api, "_request", kube)

    res = k8s_api.patch_cnpg_instances(3, shrink_past_unready=True)

    assert res.deferred == "readyInstances 4 < instances 5"
    assert kube.spec["instances"] == 5


def test_without_the_shrink_the_deferral_is_unchanged(monkeypatch) -> None:
    kube = _Cluster(3, ready=1)
    monkeypatch.setattr(k8s_api, "_request", kube)

    res = k8s_api.patch_cnpg_instances(1)

    assert res.deferred == "readyInstances 1 < instances 3"
    assert kube.spec["instances"] == 3


def test_the_hold_wins_over_the_shrink(monkeypatch) -> None:
    kube = _Cluster(3, ready=1)
    monkeypatch.setattr(k8s_api, "_request", kube)

    res = k8s_api.patch_cnpg_instances(
        1, scale_down=False, hold_reason="replacing", shrink_past_unready=True
    )

    assert res.deferred == "replacing"
    assert kube.spec["instances"] == 3


# ---- the heartbeat reads its inputs this way -------------------------------------------


def test_the_heartbeat_arms_the_hold_on_replaces_only_and_passes_the_shrink() -> None:
    src = inspect.getsource(heartbeat.heartbeat_once)
    assert "_replace_hold.reason(_replace_names(body_out), cp_size)" in src
    assert 'body_out.get("evict_node_names") or [], cp_size)' not in src
    assert '_demote_shrink.allow(body_out.get("demote_evict_node_names") or [], cp_size)' in src
    patch_at = src.index("k8s_api.patch_cnpg_instances(")
    assert "shrink_past_unready=shrink" in src[patch_at:patch_at + 200]
    assert "_demote_shrink.settle(cp_size, pg_scale.spec_after(cp_size))" in src
