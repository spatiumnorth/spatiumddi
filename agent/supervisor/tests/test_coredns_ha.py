"""#590 / #750 — ensure_coredns_ha matches cluster DNS to the node count.

k3s ships CoreDNS as a single replica that deterministically lands on the
seed and takes the k8s-default 300s to evict — a hard seed kill silences
all Service/pod-FQDN resolution (the api readiness gate's Postgres and
Redis lookups included) for longer than any recovery budget. #590 answered
that with 2 replicas + fast-evict tolerations + REQUIRED anti-affinity.

#750 is the other half: that shape only works once a second node exists.
On a single node the patch rewrites the pod template, so a new ReplicaSet
appears whose pods cannot schedule (required anti-affinity, one node)
while the old one cannot drain (minAvailable 1, zero new pods Ready) —
a rollout stuck forever, blocking every later coredns change.

These tests pin both halves: stock stays stock on one node (no patch at
all), an already-deadlocked appliance is reverted to stock, a real cluster
still gets the HA shape with one replica per node (#1718) and k3s's own
tolerations, so k3s's re-apply at a server start changes nothing (#1753), a rollout
that could not land is deferred rather than authored, and kubeapi errors
surface.
"""

from __future__ import annotations

import json

import pytest

from spatium_supervisor import k8s_api

_NODES_PATH = "/api/v1/nodes"


class _Recorder:
    """Fake ``_request`` that answers the node list and the coredns GET.

    ``ensure_coredns_ha`` reads ``/api/v1/nodes`` before it reads the
    Deployment, so the fake has to route on path rather than method.
    """

    def __init__(
        self,
        get_status: int,
        get_body: str,
        patch_status: int = 200,
        *,
        nodes: int = 1,
        schedulable: int | None = None,
        nodes_status: int = 200,
    ):
        self._get = (get_status, get_body)
        self._patch_status = patch_status
        self._nodes = nodes
        self._schedulable = nodes if schedulable is None else schedulable
        self._nodes_status = nodes_status
        self.calls: list[tuple[str, str, bytes | None]] = []

    def _node_list(self) -> str:
        items = []
        for i in range(self._nodes):
            ready = "True" if i < self._schedulable else "False"
            items.append({
                "metadata": {"name": f"n{i}"},
                "spec": {},
                "status": {"conditions": [{"type": "Ready", "status": ready}]},
            })
        return json.dumps({"items": items})

    def __call__(self, method, path, body=None, content_type=None, timeout=None):
        self.calls.append((method, path, body))
        if method == "GET" and path == _NODES_PATH:
            if self._nodes_status != 200:
                return (self._nodes_status, "forbidden")
            return (200, self._node_list())
        if method == "GET":
            return self._get
        return (self._patch_status, "{}")

    @property
    def patched(self) -> bool:
        return any(m == "PATCH" for m, _, _ in self.calls)

    @property
    def patch_body(self) -> dict:
        for method, _, body in self.calls:
            if method == "PATCH" and body is not None:
                return json.loads(body)
        return {}


_STOCK_TOLERATIONS = [
    {"key": "CriticalAddonsOnly", "operator": "Exists"},
    {"key": "node-role.kubernetes.io/control-plane", "operator": "Exists",
     "effect": "NoSchedule"},
]

_FAST_TOLERATIONS = [
    {"key": "node.kubernetes.io/unreachable", "operator": "Exists",
     "effect": "NoExecute", "tolerationSeconds": 20},
    {"key": "node.kubernetes.io/not-ready", "operator": "Exists",
     "effect": "NoExecute", "tolerationSeconds": 20},
]

_REQUIRED_SPREAD = {
    "podAntiAffinity": {
        "requiredDuringSchedulingIgnoredDuringExecution": [{
            "topologyKey": "kubernetes.io/hostname",
            "labelSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
        }],
    },
}

_PREFERRED_SPREAD = {
    "podAntiAffinity": {
        "preferredDuringSchedulingIgnoredDuringExecution": [{"weight": 100}]}
}


def _deploy(replicas: int, tolerations: list, affinity: dict | None = None) -> str:
    tmpl_spec: dict = {"tolerations": tolerations}
    if affinity is not None:
        tmpl_spec["affinity"] = affinity
    return json.dumps({"spec": {"replicas": replicas,
                                "template": {"spec": tmpl_spec}}})


# ── Single node: stock is the target ────────────────────────────────────────

def test_single_node_stock_manifest_is_left_alone(monkeypatch) -> None:
    """The #750 fix in one assertion: on one node the stock manifest already
    IS the target, so a fresh install never patches, never creates a second
    ReplicaSet, and therefore cannot deadlock."""
    rec = _Recorder(200, _deploy(1, _STOCK_TOLERATIONS), nodes=1)
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.ensure_coredns_ha()

    assert (changed, err) == (False, None)
    assert not rec.patched


def test_single_node_deadlock_is_reverted_to_stock(monkeypatch) -> None:
    """An appliance already stuck in the deadlock — replicas 2 + required
    anti-affinity on one node — heals: back to one replica, fast-evict
    tolerations dropped, affinity removed (``null`` deletes the key under a
    merge-patch, restoring the stock template and its hash)."""
    rec = _Recorder(
        200,
        _deploy(2, _STOCK_TOLERATIONS + _FAST_TOLERATIONS, _REQUIRED_SPREAD),
        nodes=1,
    )
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.ensure_coredns_ha()

    assert (changed, err) == (True, None)
    spec = rec.patch_body["spec"]
    assert spec["replicas"] == 1
    assert spec["template"]["spec"]["tolerations"] == _STOCK_TOLERATIONS
    assert spec["template"]["spec"]["affinity"] is None


def test_single_node_keeps_sibling_affinity_terms(monkeypatch) -> None:
    """A merge-patch recurses into objects, so nulling the whole ``affinity``
    would take a stock ``nodeAffinity`` with it. Null just the one key when
    there are siblings — the heal then costs a rollout, which is the cheaper
    of the two prices."""
    mixed = {
        "nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {}},
        **_REQUIRED_SPREAD,
    }
    rec = _Recorder(
        200, _deploy(2, _STOCK_TOLERATIONS + _FAST_TOLERATIONS, mixed), nodes=1
    )
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.ensure_coredns_ha()

    assert (changed, err) == (True, None)
    assert rec.patch_body["spec"]["template"]["spec"]["affinity"] == {
        "podAntiAffinity": None
    }


def test_single_node_reverts_a_half_applied_fast_evict_template(monkeypatch) -> None:
    """One leftover fast-evict toleration is still a fast-evict toleration on a
    box with nowhere to reschedule the evicted pod."""
    rec = _Recorder(200, _deploy(1, _STOCK_TOLERATIONS + _FAST_TOLERATIONS[:1]), nodes=1)
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.ensure_coredns_ha()

    assert (changed, err) == (True, None)
    assert rec.patch_body["spec"]["template"]["spec"]["tolerations"] == _STOCK_TOLERATIONS


def test_single_node_preferred_spread_is_also_reverted(monkeypatch) -> None:
    """A pre-#633 build's preferred anti-affinity is not the required one, so
    it must not read as "stock" and be left behind on a single node."""
    rec = _Recorder(
        200, _deploy(1, _STOCK_TOLERATIONS, _PREFERRED_SPREAD), nodes=1
    )
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.ensure_coredns_ha()

    assert (changed, err) == (True, None)
    assert rec.patch_body["spec"]["template"]["spec"]["affinity"] is None


# ── Two or more nodes: the #590 HA shape ────────────────────────────────────

def test_two_nodes_stock_manifest_gets_the_ha_shape(monkeypatch) -> None:
    rec = _Recorder(200, _deploy(1, _STOCK_TOLERATIONS), nodes=2)
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.ensure_coredns_ha()

    assert (changed, err) == (True, None)
    spec = rec.patch_body["spec"]
    assert spec["replicas"] == 2
    # #1753 — k3s's own tolerations, and nothing else: the merge-patch
    # REPLACES the list, and k3s's re-apply then finds nothing to change.
    assert spec["template"]["spec"]["tolerations"] == _STOCK_TOLERATIONS
    assert spec["template"]["spec"]["affinity"] == _REQUIRED_SPREAD


def test_idempotent_when_converged(monkeypatch) -> None:
    rec = _Recorder(200, _deploy(2, _STOCK_TOLERATIONS, _REQUIRED_SPREAD), nodes=2)
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.ensure_coredns_ha()

    assert (changed, err) == (False, None)
    assert not rec.patched


def test_preferred_spread_from_earlier_build_is_upgraded(monkeypatch) -> None:
    # The first cut of this reconciler used preferred anti-affinity, which
    # parked BOTH replicas on the seed when it fired on the single-node
    # firstboot (k8s never rebalances running pods) — the "HA" DNS died
    # with the seed anyway. A cluster patched by that build must be
    # re-patched to the required form, not short-circuited as converged.
    rec = _Recorder(
        200,
        _deploy(2, _STOCK_TOLERATIONS + _FAST_TOLERATIONS, _PREFERRED_SPREAD),
        nodes=2,
    )
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.ensure_coredns_ha()

    assert (changed, err) == (True, None)
    assert rec.patch_body["spec"]["template"]["spec"]["affinity"] == _REQUIRED_SPREAD


@pytest.mark.parametrize("fast", [_FAST_TOLERATIONS, _FAST_TOLERATIONS[:1]])
def test_fast_evict_from_an_earlier_build_is_removed_on_a_real_cluster(
        monkeypatch, fast) -> None:
    """#1753 — the pre-fix HA template (both fast-evict tolerations, or a
    half-applied one) is put back to k3s's own tolerations, once."""
    rec = _Recorder(200, _deploy(2, _STOCK_TOLERATIONS + fast, _REQUIRED_SPREAD), nodes=2)
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.ensure_coredns_ha()

    assert (changed, err) == (True, None)
    assert rec.patch_body["spec"]["template"]["spec"]["tolerations"] == _STOCK_TOLERATIONS


@pytest.mark.parametrize("nodes", [2, 3])
def test_k3s_reapply_leaves_the_ha_template_converged(monkeypatch, nodes) -> None:
    """#1753 — k3s force re-applies its bundled coredns.yaml at every server
    start. It sets the tolerations to its own two entries and does not set
    replicas or affinity. A converged HA deployment after that re-apply must
    still read as converged, so no node's return rolls CoreDNS out at all.
    It used to roll out twice: once for the re-apply, which dropped the
    fast-evict pair, and once for the patch that put it back."""
    after_k3s_reapply = _deploy(nodes, _STOCK_TOLERATIONS, _REQUIRED_SPREAD)
    rec = _Recorder(200, after_k3s_reapply, nodes=nodes)
    monkeypatch.setattr(k8s_api, "_request", rec)

    assert k8s_api.ensure_coredns_ha() == (False, None)
    assert not rec.patched


@pytest.mark.parametrize("nodes", [3, 5, 7])
def test_one_replica_per_node_on_a_larger_cluster(monkeypatch, nodes) -> None:
    """#1718 — every node runs its own CoreDNS, so the kube-dns Service can keep
    each node's lookups local (ensure_kube_dns_node_local). Capped at 2, the node
    without a replica sent half its lookups to a lost node's pod until that node
    read NotReady, and the stalls held the Redis failover to 77 s."""
    rec = _Recorder(200, _deploy(2, _STOCK_TOLERATIONS + _FAST_TOLERATIONS,
                                 _REQUIRED_SPREAD), nodes=nodes)
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.ensure_coredns_ha()

    assert (changed, err) == (True, None)
    assert rec.patch_body["spec"]["replicas"] == nodes


def test_two_replicas_on_three_nodes_is_not_converged(monkeypatch) -> None:
    """The pre-#1718 shape on a three-node cluster is scaled, not left alone."""
    rec = _Recorder(
        200, _deploy(2, _STOCK_TOLERATIONS + _FAST_TOLERATIONS, _REQUIRED_SPREAD), nodes=3
    )
    monkeypatch.setattr(k8s_api, "_request", rec)

    assert k8s_api.ensure_coredns_ha() == (True, None)
    assert rec.patch_body["spec"]["replicas"] == 3


# ── Feasibility gate ────────────────────────────────────────────────────────

def test_template_change_deferred_while_a_node_is_down(monkeypatch) -> None:
    """Two registered nodes but only one schedulable: patching the template to
    the HA shape now would author exactly the #750 deadlock. Defer — not an
    error, and retried on the next heartbeat."""
    rec = _Recorder(200, _deploy(1, _STOCK_TOLERATIONS), nodes=2, schedulable=1)
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.ensure_coredns_ha()

    assert (changed, err) == (False, None)
    assert not rec.patched


def test_scale_up_with_correct_template_is_not_deferred(monkeypatch) -> None:
    """A pure replica change creates no new ReplicaSet, so it cannot deadlock:
    the extra pod just sits Pending until the peer is back."""
    rec = _Recorder(
        200,
        _deploy(1, _STOCK_TOLERATIONS, _REQUIRED_SPREAD),
        nodes=2,
        schedulable=1,
    )
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.ensure_coredns_ha()

    assert (changed, err) == (True, None)
    assert rec.patch_body["spec"]["replicas"] == 2


# ── Convergence: the patch must settle, in one round ────────────────────────

def _apply(deploy_json: str, patch_body: dict) -> str:
    """Apply the reconciler's merge-patch to a fake deployment, the way the
    apiserver would, so a test can feed the result straight back in."""
    dep = json.loads(deploy_json)
    tmpl = dep["spec"]["template"]["spec"]
    patch_spec = patch_body["spec"]
    dep["spec"]["replicas"] = patch_spec["replicas"]
    patch_tmpl = patch_spec["template"]["spec"]
    tmpl["tolerations"] = patch_tmpl["tolerations"]
    merged = k8s_api._merge_patch(tmpl.get("affinity"), patch_tmpl["affinity"])
    if patch_tmpl["affinity"] is None or merged is None:
        tmpl.pop("affinity", None)
    else:
        tmpl["affinity"] = merged
    return json.dumps(dep)


@pytest.mark.parametrize(
    "nodes,deployment",
    [
        # Fresh install on a real cluster.
        (2, _deploy(1, _STOCK_TOLERATIONS)),
        # The #750 deadlock, on one node.
        (1, _deploy(2, _STOCK_TOLERATIONS + _FAST_TOLERATIONS, _REQUIRED_SPREAD)),
        # Sibling scheduling constraints we must not delete.
        (1, _deploy(2, _STOCK_TOLERATIONS + _FAST_TOLERATIONS, {
            "nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {}},
            **_REQUIRED_SPREAD,
        })),
        (2, _deploy(1, _STOCK_TOLERATIONS, {
            "nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {}},
        })),
        # A pre-#633 build's preferred spread.
        (2, _deploy(2, _STOCK_TOLERATIONS + _FAST_TOLERATIONS, _PREFERRED_SPREAD)),
        # Someone hand-edited the eviction delay.
        (2, _deploy(2, _STOCK_TOLERATIONS + [
            {"key": "node.kubernetes.io/unreachable", "operator": "Exists",
             "effect": "NoExecute", "tolerationSeconds": 25},
            {"key": "node.kubernetes.io/not-ready", "operator": "Exists",
             "effect": "NoExecute", "tolerationSeconds": 25},
        ], _REQUIRED_SPREAD)),
    ],
)
def test_one_patch_reaches_a_fixed_point(monkeypatch, nodes, deployment) -> None:
    """Patch, feed the result back, and the reconciler must report converged.

    This is the patch-storm guard. The reconciler runs on every 30 s heartbeat,
    so any state where it patches, the apiserver accepts, and it still says
    "not converged" is an endless rollout — far worse than the deadlock #750
    fixed. Each case below is one that a looser convergence check could get
    wrong.
    """
    first = _Recorder(200, deployment, nodes=nodes)
    monkeypatch.setattr(k8s_api, "_request", first)
    changed, err = k8s_api.ensure_coredns_ha()
    assert (changed, err) == (True, None)

    settled = _Recorder(200, _apply(deployment, first.patch_body), nodes=nodes)
    monkeypatch.setattr(k8s_api, "_request", settled)

    assert k8s_api.ensure_coredns_ha() == (False, None)
    assert not settled.patched


def test_hand_edited_eviction_delay_is_normalised(monkeypatch) -> None:
    """A 25 s fast-evict toleration is not the shape we ship (#1753: none is).

    Convergence is "the template equals what we would send", not "it looks
    close enough" — and the loose version of that check was what let a
    template satisfy it while still differing from the canonical body, so the
    resulting pod-template rewrite skipped the deadlock gate entirely.
    """
    near_miss = _STOCK_TOLERATIONS + [
        {"key": "node.kubernetes.io/unreachable", "operator": "Exists",
         "effect": "NoExecute", "tolerationSeconds": 25},
        {"key": "node.kubernetes.io/not-ready", "operator": "Exists",
         "effect": "NoExecute", "tolerationSeconds": 25},
    ]
    rec = _Recorder(200, _deploy(2, near_miss, _REQUIRED_SPREAD), nodes=2)
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.ensure_coredns_ha()

    assert (changed, err) == (True, None)
    assert rec.patch_body["spec"]["template"]["spec"]["tolerations"] == _STOCK_TOLERATIONS


# ── Error paths ─────────────────────────────────────────────────────────────

def test_missing_deployment_reports(monkeypatch) -> None:
    rec = _Recorder(404, "not found", nodes=1)
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.ensure_coredns_ha()

    assert changed is False
    assert err is not None and "404" in err
    assert not rec.patched


def test_unreadable_node_list_defers_rather_than_guessing(monkeypatch) -> None:
    """Without a node count there is no way to know which target applies, and
    guessing the single-node one would scale a real cluster's DNS down."""
    rec = _Recorder(200, _deploy(1, _STOCK_TOLERATIONS), nodes_status=403)
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.ensure_coredns_ha()

    assert changed is False
    assert err is not None and "node count" in err
    assert not rec.patched


def test_transport_error_on_the_node_list_is_caught(monkeypatch) -> None:
    """``_request`` builds its connection (and reads the CA) outside the try
    that converts transport errors, so a bare OSError can reach us. It must
    not escape into the heartbeat loop."""

    def boom(method, path, body=None, content_type=None, timeout=None):
        raise OSError("ca.crt: permission denied")

    monkeypatch.setattr(k8s_api, "_request", boom)

    changed, err = k8s_api.ensure_coredns_ha()

    assert changed is False
    assert err is not None and "permission denied" in err


def test_zero_nodes_is_treated_as_a_bad_read(monkeypatch) -> None:
    rec = _Recorder(200, _deploy(2, _STOCK_TOLERATIONS), nodes=0)
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.ensure_coredns_ha()

    assert changed is False
    assert err is not None and "no nodes" in err
    assert not rec.patched


def test_count_nodes_ignores_cordoned_and_notready_for_schedulable(monkeypatch) -> None:
    """``registered`` counts Node objects (flap-free, survives NotReady);
    ``ready_and_schedulable`` is the stricter count the feasibility gate uses."""
    listing = json.dumps({"items": [
        {"spec": {}, "status": {"conditions": [{"type": "Ready", "status": "True"}]}},
        {"spec": {"unschedulable": True},
         "status": {"conditions": [{"type": "Ready", "status": "True"}]}},
        {"spec": {}, "status": {"conditions": [{"type": "Ready", "status": "False"}]}},
    ]})
    monkeypatch.setattr(
        k8s_api,
        "_request",
        lambda method, path, body=None, content_type=None, timeout=None: (200, listing),
    )

    assert k8s_api.count_nodes() == (3, 1, None)
