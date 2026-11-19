"""#2240: ensure_cnpg_operator_spread keeps the CNPG operator's two
replicas on different nodes once the cluster has three.

The operator IS Postgres failover: while it is gone nothing promotes a new
primary. #590 gave it two replicas, 20 s fast-evict tolerations and a
PREFERRED hostname anti-affinity, and firstboot installs it on the seed while
the seed is the only node, so both replicas start there. Preferred
anti-affinity is IgnoredDuringExecution and Kubernetes never rebalances
running pods, so they stay on the seed as members join: a seven-node cluster
lost both at once when the seed was killed, and the failover waited for their
rescheduling. ``ensure_coredns_ha`` (#633) is the same lesson for CoreDNS.

A REQUIRED rule cannot be the chart's default: on one node the second replica
could never schedule. And the operator rolls with two replicas, a surge of
one and none unavailable, so a pod-template change needs a THIRD eligible
node for its surge pod while the old pods still hold two (the #750 deadlock
otherwise). So the supervisor adds the required term once three nodes are
registered, defers the rollout while fewer than three are schedulable, and
removes the term again below three.

These tests pin that, the exact patch (a JSON merge-patch that adds or
deletes only the required term, so the chart's own preferred term and every
other field stay as Helm rendered them), the selector against the chart's
own term, the RBAC grant, and that kubeapi errors surface.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from spatium_supervisor import k8s_api

_NODES_PATH = "/api/v1/nodes"
_OPERATOR_PATH = "/apis/apps/v1/namespaces/spatium/deployments/spatium-bootstrap-cloudnative-pg"

_TERM = {
    "topologyKey": "kubernetes.io/hostname",
    "labelSelector": {"matchLabels": {"app.kubernetes.io/name": "cloudnative-pg"}},
}

# What charts/spatiumddi-appliance/values.yaml renders (#590).
_CHART_PREFERRED = {
    "podAntiAffinity": {
        "preferredDuringSchedulingIgnoredDuringExecution": [
            {"weight": 100, "podAffinityTerm": dict(_TERM)},
        ]
    }
}


def _with_required(term: dict | None = None) -> dict:
    aff = json.loads(json.dumps(_CHART_PREFERRED))
    aff["podAntiAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"] = [
        term if term is not None else dict(_TERM)
    ]
    return aff


def _deploy(affinity: dict | None) -> str:
    tmpl_spec: dict = {"containers": [{"name": "manager"}]}
    if affinity is not None:
        tmpl_spec["affinity"] = affinity
    return json.dumps({"spec": {"replicas": 2, "template": {"spec": tmpl_spec}}})


class _Recorder:
    """Fake ``_request``: the node list, the operator Deployment GET, PATCH."""

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
        self.calls: list[tuple[str, str, bytes | None, str | None]] = []

    def _node_list(self) -> str:
        items = []
        for i in range(self._nodes):
            ready = "True" if i < self._schedulable else "False"
            items.append(
                {
                    "metadata": {"name": f"n{i}"},
                    "spec": {},
                    "status": {"conditions": [{"type": "Ready", "status": ready}]},
                }
            )
        return json.dumps({"items": items})

    def __call__(self, method, path, body=None, content_type=None, timeout=None):
        self.calls.append((method, path, body, content_type))
        if method == "GET" and path == _NODES_PATH:
            if self._nodes_status != 200:
                return (self._nodes_status, "forbidden")
            return (200, self._node_list())
        if method == "GET":
            assert path == _OPERATOR_PATH
            return self._get
        return (self._patch_status, "{}")

    @property
    def patches(self) -> list[tuple[str, dict, str | None]]:
        return [
            (path, json.loads(body), ctype)
            for method, path, body, ctype in self.calls
            if method == "PATCH" and body is not None
        ]


def _run(monkeypatch, rec: _Recorder) -> tuple[bool, str | None]:
    monkeypatch.setattr(k8s_api, "_request", rec)
    return k8s_api.ensure_cnpg_operator_spread()


# ── Below three nodes: the chart's preferred rule is the target ─────────────


@pytest.mark.parametrize("nodes", [1, 2])
def test_below_three_nodes_the_chart_template_is_left_alone(monkeypatch, nodes) -> None:
    """One node: a required rule could never place the second replica. Two
    nodes: the surge pod of the rollout a template change starts would find
    no free node while the old pods hold both (#750). Either way, no patch."""
    rec = _Recorder(200, _deploy(_CHART_PREFERRED), nodes=nodes)
    assert _run(monkeypatch, rec) == (False, None)
    assert rec.patches == []


# ── Three nodes and more: the required term is added ────────────────────────


@pytest.mark.parametrize("nodes", [3, 5, 7])
def test_three_or_more_nodes_get_the_required_spread(monkeypatch, nodes) -> None:
    rec = _Recorder(200, _deploy(_CHART_PREFERRED), nodes=nodes)
    assert _run(monkeypatch, rec) == (True, None)
    [(path, body, ctype)] = rec.patches
    assert path == _OPERATOR_PATH
    assert ctype == "application/merge-patch+json"
    # Only the required term travels: a merge-patch leaves the chart's
    # preferred term, the tolerations and every other field as Helm rendered
    # them, so a later helm upgrade has nothing of its own to revert.
    assert body == {
        "spec": {
            "template": {
                "spec": {
                    "affinity": {
                        "podAntiAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [_TERM]}
                    }
                }
            }
        }
    }


def test_an_operator_template_with_no_affinity_still_gets_the_term(monkeypatch) -> None:
    rec = _Recorder(200, _deploy(None), nodes=3)
    assert _run(monkeypatch, rec) == (True, None)
    [(_path, body, _ctype)] = rec.patches
    aff = body["spec"]["template"]["spec"]["affinity"]
    assert aff == {"podAntiAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [_TERM]}}


def test_an_already_spread_template_is_converged(monkeypatch) -> None:
    """Reconciled every seed heartbeat: the converged state writes nothing,
    so there is no pod-template change and no rollout."""
    rec = _Recorder(200, _deploy(_with_required()), nodes=3)
    assert _run(monkeypatch, rec) == (False, None)
    assert rec.patches == []


def test_the_rollout_is_deferred_while_a_node_is_down(monkeypatch) -> None:
    """Three registered but two Ready: the surge pod has no free node, so
    the change waits for the next heartbeat instead of authoring a stuck
    rollout. Not an error: nothing is wrong."""
    rec = _Recorder(200, _deploy(_CHART_PREFERRED), nodes=3, schedulable=2)
    assert _run(monkeypatch, rec) == (False, None)
    assert rec.patches == []


def test_a_term_that_is_not_ours_is_replaced(monkeypatch) -> None:
    """The reconciler owns the required term outright, as ``ensure_coredns_ha``
    owns its template: a hand-edited or stale term is "not what we send"."""
    foreign = {"topologyKey": "topology.kubernetes.io/zone", "labelSelector": {}}
    rec = _Recorder(200, _deploy(_with_required(foreign)), nodes=3)
    assert _run(monkeypatch, rec) == (True, None)
    [(_path, body, _ctype)] = rec.patches
    terms = body["spec"]["template"]["spec"]["affinity"]["podAntiAffinity"][
        "requiredDuringSchedulingIgnoredDuringExecution"
    ]
    assert terms == [_TERM]


# ── The cluster shrinks: the term is removed, never deferred ────────────────


@pytest.mark.parametrize("nodes,schedulable", [(2, 2), (2, 1), (1, 1)])
def test_the_term_is_removed_below_three_nodes(monkeypatch, nodes, schedulable) -> None:
    """``null`` deletes the key under a JSON merge-patch, back to the chart's
    own template. Never deferred: a preferred-only rollout can always place
    its surge pod, so removing the term cannot deadlock anything."""
    rec = _Recorder(200, _deploy(_with_required()), nodes=nodes, schedulable=schedulable)
    assert _run(monkeypatch, rec) == (True, None)
    [(_path, body, _ctype)] = rec.patches
    assert body == {
        "spec": {
            "template": {
                "spec": {
                    "affinity": {
                        "podAntiAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": None}
                    }
                }
            }
        }
    }


# ── No operator, and errors ─────────────────────────────────────────────────


def test_no_operator_deployment_is_a_no_op(monkeypatch) -> None:
    """A 404 is an appliance whose bootstrap chart runs no operator; there is
    nothing to spread and nothing wrong."""
    rec = _Recorder(404, '{"kind":"Status","code":404}', nodes=3)
    assert _run(monkeypatch, rec) == (False, None)
    assert rec.patches == []


def test_kubeapi_errors_surface(monkeypatch) -> None:
    changed, err = _run(monkeypatch, _Recorder(500, "boom", nodes=3))
    assert changed is False and err is not None and "500" in err

    changed, err = _run(monkeypatch, _Recorder(200, _deploy(None), nodes=3, nodes_status=403))
    assert changed is False and err is not None and "node count unavailable" in err

    changed, err = _run(monkeypatch, _Recorder(200, _deploy(_CHART_PREFERRED), 422, nodes=3))
    assert changed is False and err is not None and "422" in err

    changed, err = _run(monkeypatch, _Recorder(200, "not json", nodes=3))
    assert changed is False and err is not None


def test_no_nodes_is_not_trusted(monkeypatch) -> None:
    """A cluster we run inside has at least one Node; zero is a bad read, and
    acting on it would turn the bad read into a template change."""
    rec = _Recorder(200, _deploy(_with_required()), nodes=0)
    changed, err = _run(monkeypatch, rec)
    assert changed is False and err is not None
    assert rec.patches == []


# ── The term matches the chart, and the supervisor may send it ─────────────


def _repo_file(rel: str) -> Path:
    """Walk up to the repo root. RAISES rather than skipping, like
    ``test_helmchartconfig_noop._firstboot``: a cross-tree test that quietly
    skips reports a clean pass while checking nothing."""
    for parent in Path(__file__).resolve().parents:
        candidate = parent / rel
        if candidate.is_file():
            return candidate
    raise AssertionError(f"could not find {rel} above {__file__}")


def test_the_required_term_selects_what_the_charts_own_term_selects() -> None:
    """The operator pods carry the labels the chart's nameOverride renders
    (#277). If that ever changed, a required term with a stale selector would
    match no pod and spread nothing; pin it to the chart's own preferred
    term."""
    values = yaml.safe_load(_repo_file("charts/spatiumddi-appliance/values.yaml").read_text())
    [preferred] = values["cnpg"]["affinity"]["podAntiAffinity"][
        "preferredDuringSchedulingIgnoredDuringExecution"
    ]
    assert preferred["podAffinityTerm"] == k8s_api._CNPG_OPERATOR_SPREAD_TERM
    assert k8s_api._CNPG_OPERATOR_SPREAD_TERM == _TERM
    # The Deployment the reconciler reads is the one the chart renders: the
    # spatium-bootstrap release, the subchart's nameOverride.
    assert values["cnpg"]["nameOverride"] == "cloudnative-pg"
    assert k8s_api._CNPG_OPERATOR_PATH == _OPERATOR_PATH
    assert values["cnpg"]["replicaCount"] == 2


def test_the_supervisor_may_read_and_patch_only_the_operator_deployment() -> None:
    """Without get + patch the GET 403s every heartbeat and nothing spreads
    (the #272 CNPG lesson); the grant is pinned to the one Deployment."""
    text = _repo_file("charts/spatiumddi-appliance/templates/supervisor-rbac.yaml").read_text()
    role = text[text.index("name: spatium-supervisor-cnpg") :]
    role = role[: role.index("kind: RoleBinding")]
    assert '- apiGroups: ["apps"]' in role
    assert 'resources: ["deployments"]' in role
    assert 'resourceNames: ["spatium-bootstrap-cloudnative-pg"]' in role
    rule = role[role.index('resourceNames: ["spatium-bootstrap-cloudnative-pg"]') :]
    assert 'verbs: ["get", "patch"]' in rule.splitlines()[1]
