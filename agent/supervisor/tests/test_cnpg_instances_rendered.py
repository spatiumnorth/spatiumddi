"""#1313 — the chart renders the CNPG instance count the supervisor's patch left.

The helm-controller re-applies the kept CNPG ``Cluster`` on every upgrade, as a
server-side apply that may not force a conflict. ``patch_cnpg_instances``
writes ``spec.instances`` with its own merge-patch, so the field has a second
owner, and an upgrade that renders a DIFFERENT count fails on the conflict.
During a dead-node replace #1059's hold keeps the Cluster at 3 while the
committed count is 2, so rendering ``cp_size`` failed every upgrade; the
helm-controller's recovery then uninstalled the whole release (api, worker,
beat, frontend) and each reinstall failed the same way until the replacement
was promoted. The invariant these tests pin: after every heartbeat tick, the
``cnpg.instances`` the HelmChartConfig renders equals the Cluster's own
``spec.instances``, so the chart never asks to change what the patch wrote.

And while that hold is armed the release does not re-size at all
(``heartbeat._release_size``): a replace is never a scale-down by intent, and
re-sizing to the short count rolled the api, worker and beat (``REDIS_URL``
lists one sentinel per replica) and cut the api to 2 while the dead node's
replica still read Ready, so the rollout retired both live replicas.
"""

from __future__ import annotations

import inspect
import json

import yaml

from spatium_supervisor import heartbeat, k8s_api
from spatium_supervisor.heartbeat import _ReplaceHold

_AFFINITY = {
    "enablePodAntiAffinity": True,
    "podAntiAffinityType": "required",
    "topologyKey": "kubernetes.io/hostname",
}
_HOLD = ("replacing ['ddipg-member-2']: the committed count 2 is short until the "
         "replacement is promoted")


class _Cluster:
    """A kubeapi stand-in holding one CNPG Cluster and the spatium-control
    HelmChart / HelmChartConfig, enough for both supervisor writes."""

    def __init__(self, instances: int, *, ready: int | None = None):
        self.spec = {"instances": instances, "affinity": dict(_AFFINITY)}
        self.ready = instances if ready is None else ready
        self.reported = instances
        self.chart = yaml.safe_dump({"postgresql": {"cnpg": {"instances": 1}}})
        self.config: str | None = None
        self.config_writes = 0
        self.fail_cluster_patch = False
        self.fail_cluster_read: str = ""   # "" | "status" | "transport"

    def __call__(self, method, path, body=None, content_type=None):
        if "/clusters/" in path:
            if method == "GET":
                if self.fail_cluster_read == "transport":
                    raise RuntimeError(f"kubeapi GET {path}: timed out")
                if self.fail_cluster_read == "status":
                    return 500, b"etcdserver: leader changed"
                return 200, json.dumps({"spec": self.spec, "status": {
                    "readyInstances": self.ready, "instances": self.reported}}).encode()
            if self.fail_cluster_patch:
                return 500, b"etcdserver: request timed out"
            self.spec.update(json.loads(body)["spec"])
            return 200, b"{}"
        if "/helmchartconfigs" in path:
            if method == "GET":
                if self.config is None:
                    return 404, b""
                return 200, json.dumps({"spec": {"valuesContent": self.config}}).encode()
            self.config = json.loads(body)["spec"]["valuesContent"]
            self.config_writes += 1
            return (201 if method == "POST" else 200), b"{}"
        if "/helmcharts/" in path:
            return 200, json.dumps({"spec": {"valuesContent": self.chart}}).encode()
        return 404, b""

    @property
    def rendered(self) -> int | None:
        doc = yaml.safe_load(self.config or "") or {}
        return ((doc.get("postgresql") or {}).get("cnpg") or {}).get("instances")


def _tick(kube: _Cluster, hold: _ReplaceHold, cp_size: int, evicting: list[str] = ()) -> None:
    """The heartbeat's cp-size block, in its order: the Cluster first, then the
    HelmChartConfig with the count the Cluster was left at, the release sized by
    ``_release_size`` — or nothing, on a tick that could not read the Cluster."""
    why = hold.reason(list(evicting), cp_size)
    pg = k8s_api.patch_cnpg_instances(cp_size, scale_down=not why, hold_reason=why)
    hold.settle(cp_size, pg.current)
    cnpg_instances = pg.spec_after(cp_size)
    if cnpg_instances is not None:
        k8s_api.apply_control_plane_overrides(
            heartbeat._release_size(cp_size, why, cnpg_instances), "",
            cnpg_instances=cnpg_instances,
        )


def test_the_chart_renders_the_cluster_count_through_a_replace(monkeypatch) -> None:
    """Formation, a dead-node replace held by #1059, the promote, and a real
    demote: after every tick the rendered count is the Cluster's own."""
    kube = _Cluster(1)
    monkeypatch.setattr(k8s_api, "_request", kube)
    hold = _ReplaceHold()

    _tick(kube, hold, 3)                                   # the promote to three
    assert kube.spec["instances"] == 3 and kube.rendered == 3
    kube.ready = kube.reported = 3

    _tick(kube, hold, 2, ["ddipg-member-2"])               # the eviction tick
    assert kube.spec["instances"] == 3 and kube.rendered == 3
    assert yaml.safe_load(kube.config)["api"]["replicas"] == 3   # nor does the rest

    kube.ready = 2
    for _ in range(5):                                     # the replacement installs
        _tick(kube, hold, 2)
        assert kube.spec["instances"] == 3 and kube.rendered == 3

    kube.ready = 3
    _tick(kube, hold, 3)                                   # the replacement is promoted
    assert kube.spec["instances"] == 3 and kube.rendered == 3
    assert not hold.armed

    _tick(kube, hold, 1)                                   # a deliberate demote, whole cluster
    assert kube.spec["instances"] == 1 and kube.rendered == 1


def test_a_failed_cluster_patch_renders_the_count_the_cluster_kept(monkeypatch) -> None:
    kube = _Cluster(1)
    kube.fail_cluster_patch = True
    monkeypatch.setattr(k8s_api, "_request", kube)

    _tick(kube, _ReplaceHold(), 3)

    assert kube.spec["instances"] == 1 and kube.rendered == 1


def test_a_tick_that_cannot_read_the_cluster_leaves_the_release_alone(monkeypatch) -> None:
    """Mid-replace, the Cluster held at 3 and the chart rendering 3: a tick
    whose read of the Cluster fails must not render cp_size (2), which is the
    very scale-down the hold defers, and the conflict again."""
    kube = _Cluster(3)
    monkeypatch.setattr(k8s_api, "_request", kube)
    hold = _ReplaceHold()
    _tick(kube, hold, 2, ["ddipg-member-2"])               # the eviction tick
    assert kube.spec["instances"] == 3 and kube.rendered == 3
    before = kube.config

    for failure in ("transport", "status"):
        kube.fail_cluster_read = failure
        _tick(kube, hold, 2)
        assert kube.config == before                       # nothing re-rendered
        assert kube.spec["instances"] == 3

    kube.fail_cluster_read = ""
    _tick(kube, hold, 2)                                   # a readable tick again
    assert kube.spec["instances"] == 3 and kube.rendered == 3


# ---- CnpgScale.spec_after ------------------------------------------------------------


def _scale(monkeypatch, kube, *args, **kwargs) -> k8s_api.CnpgScale:
    monkeypatch.setattr(k8s_api, "_request", kube)
    return k8s_api.patch_cnpg_instances(*args, **kwargs)


def test_spec_after_a_held_scale_down_is_the_count_read(monkeypatch) -> None:
    res = _scale(monkeypatch, _Cluster(3), 2, scale_down=False, hold_reason=_HOLD)
    assert res.deferred == _HOLD and res.spec_after(2) == 3


def test_spec_after_a_scale_down_cnpg_would_refuse_is_the_count_read(monkeypatch) -> None:
    res = _scale(monkeypatch, _Cluster(3, ready=2), 2)
    assert res.deferred == "readyInstances 2 < instances 3" and res.spec_after(2) == 3


def test_spec_after_a_written_change_is_the_count_asked_for(monkeypatch) -> None:
    assert _scale(monkeypatch, _Cluster(3), 2).spec_after(2) == 2      # a real demote
    assert _scale(monkeypatch, _Cluster(1), 3).spec_after(3) == 3      # a promote
    assert _scale(monkeypatch, _Cluster(3), 3).spec_after(3) == 3      # nothing to do


def test_spec_after_with_no_cluster_to_read_is_the_count_asked_for(monkeypatch) -> None:
    """No Cluster yet (early boot): the chart creates it with this count."""
    res = _scale(monkeypatch, lambda *a, **k: (404, b""), 3)
    assert res.current is None and res.spec_after(3) == 3


def test_spec_after_an_unreadable_cluster_is_unknown(monkeypatch) -> None:
    """A failed read is not an absent Cluster: the count it holds is unknown."""
    for failure in ("transport", "status"):
        kube = _Cluster(3)
        kube.fail_cluster_read = failure
        res = _scale(monkeypatch, kube, 2, scale_down=False, hold_reason=_HOLD)
        assert res.error and res.current is None
        assert res.spec_after(2) is None


def test_spec_after_a_failed_patch_is_the_count_the_cluster_kept(monkeypatch) -> None:
    kube = _Cluster(1)
    kube.fail_cluster_patch = True
    res = _scale(monkeypatch, kube, 3)
    assert res.error and res.spec_after(3) == 1


# ---- the render and the heartbeat's order ---------------------------------------------


def test_the_overrides_render_the_count_given_and_size_everything_else_by_cp_size(
    monkeypatch,
) -> None:
    kube = _Cluster(3)
    monkeypatch.setattr(k8s_api, "_request", kube)

    ok, err = k8s_api.apply_control_plane_overrides(2, "", cnpg_instances=3)

    assert (ok, err) == (True, None)
    values = yaml.safe_load(kube.config)
    assert values["postgresql"]["cnpg"]["instances"] == 3
    assert values["api"]["replicas"] == values["worker"]["replicas"] == 2
    assert values["redis"]["sentinel"]["replicas"] == 2


def test_without_a_count_the_overrides_render_cp_size_as_before(monkeypatch) -> None:
    kube = _Cluster(3)
    monkeypatch.setattr(k8s_api, "_request", kube)

    k8s_api.apply_control_plane_overrides(3, "")

    assert kube.rendered == 3


def test_the_heartbeat_patches_the_cluster_before_it_renders_the_chart() -> None:
    """The heartbeat must size the Cluster first and hand the chart the count
    that left — never ``cp_size`` on its own again."""
    src = inspect.getsource(heartbeat.heartbeat_once)
    patch_at = src.index("k8s_api.patch_cnpg_instances(")
    render_at = src.index("k8s_api.apply_control_plane_overrides(")
    assert patch_at < render_at
    assert "cnpg_instances = pg_scale.spec_after(cp_size)" in src[patch_at:render_at]
    assert "if cnpg_instances is None:" in src[patch_at:render_at]
    assert "cnpg_instances=cnpg_instances" in src[render_at:render_at + 400]


# ---- a replace re-sizes nothing (heartbeat._release_size) ------------------------------


def test_a_replace_writes_nothing_to_the_release(monkeypatch) -> None:
    """From the eviction tick to the promote the committed count is one short,
    by bookkeeping only. Held, the HelmChartConfig is never written, so the
    helm-controller has nothing to upgrade at either end: no rollout, and no
    scale-down beside the dead node's replica."""
    kube = _Cluster(1)
    monkeypatch.setattr(k8s_api, "_request", kube)
    hold = _ReplaceHold()
    _tick(kube, hold, 3)                                   # formed at three
    kube.ready = kube.reported = 3
    formed, writes = kube.config, kube.config_writes

    _tick(kube, hold, 2, ["ddipg-member-2"])               # the eviction tick
    kube.ready = 2
    for _ in range(20):                                    # the replacement installs
        _tick(kube, hold, 2)
    kube.ready = 3
    _tick(kube, hold, 3)                                   # the replacement is promoted
    _tick(kube, hold, 3)

    assert kube.config_writes == writes and kube.config == formed
    values = yaml.safe_load(kube.config)
    assert values["api"]["replicas"] == values["worker"]["replicas"] == 3
    assert values["frontend"]["replicas"] == 3
    assert values["redis"]["sentinel"]["replicas"] == 3
    assert kube.spec["instances"] == 3 and not hold.armed


def test_a_demote_during_the_replace_shrinks_the_release(monkeypatch) -> None:
    """The operator gives up on the slot and demotes the survivor: the hold
    ends (below the count the eviction carried) and the release follows."""
    kube = _Cluster(3)
    monkeypatch.setattr(k8s_api, "_request", kube)
    hold = _ReplaceHold()
    _tick(kube, hold, 2, ["ddipg-member-2"])               # the eviction tick
    assert yaml.safe_load(kube.config)["api"]["replicas"] == 3

    _tick(kube, hold, 1)                                   # the demote

    assert not hold.armed
    assert yaml.safe_load(kube.config)["api"]["replicas"] == 1
    assert kube.rendered == kube.spec["instances"]


def test_release_size_is_the_committed_count_without_a_hold() -> None:
    for cp_size in (1, 2, 3, 5):
        assert heartbeat._release_size(cp_size, "", 3) == cp_size


def test_release_size_under_the_hold_is_the_count_the_cluster_is_held_at() -> None:
    assert heartbeat._release_size(2, _HOLD, 3) == 3       # the eviction / install ticks
    assert heartbeat._release_size(3, _HOLD, 3) == 3       # the promote tick
    assert heartbeat._release_size(4, _HOLD, 5) == 5       # five nodes, one replaced


def test_release_size_never_renders_below_the_committed_count() -> None:
    """A Cluster smaller than the count (no Cluster yet: spec_after is the
    count asked for) never pulls the release down: the hold only keeps it up."""
    assert heartbeat._release_size(3, _HOLD, 1) == 3
    assert heartbeat._release_size(2, _HOLD, 2) == 2


def test_the_heartbeat_renders_the_release_at_the_held_size() -> None:
    src = inspect.getsource(heartbeat.heartbeat_once)
    hold_at = src.index("hold = _replace_hold.reason(")
    render_at = src.index("k8s_api.apply_control_plane_overrides(")
    assert hold_at < render_at
    assert "release_size = _release_size(cp_size, hold, cnpg_instances)" in src[hold_at:render_at]
    call = src[render_at:render_at + 200]
    assert call.split("(", 1)[1].lstrip().startswith("release_size,")
