"""#2450 — the first promotion changes the frontend's replica count and nothing else.

The supervisor re-renders the control plane's overrides on every promote and
demote (``apply_control_plane_overrides``). On a multi-node appliance the
frontend runs on the host network, binds the node's ports 80 and 443, and
retires an old pod before it starts a new one. Anything those overrides change
in its pod template at the first promotion therefore rolls the seed's only
frontend pod, and the seed refuses connections on both ports until the
replacement has bound them, while the browser that drives the promotion is on
it.

The chart keeps the frontend's pod template the same at any replica count on
the host network (``.github/scripts/chart-template-stable.py`` in
``charts-render-check.sh``). This pins the supervisor's half: between one
control-plane node and three, the frontend's overrides differ in ``replicas``
alone, so the chart is handed nothing else that could change the template.
"""

from __future__ import annotations

import json

import yaml

from spatium_supervisor import k8s_api


class _Kube:
    """A kubeapi stand-in that keeps the spatium-control HelmChartConfig the
    supervisor writes (the shape test_cnpg_instances_rendered.py's uses)."""

    def __init__(self) -> None:
        self.config: str | None = None

    def __call__(self, method, path, body=None, content_type=None):
        if "/helmchartconfigs" in path:
            if method == "GET":
                if self.config is None:
                    return 404, b""
                return 200, json.dumps({"spec": {"valuesContent": self.config}}).encode()
            self.config = json.loads(body)["spec"]["valuesContent"]
            return (201 if method == "POST" else 200), b"{}"
        if "/helmcharts/" in path:
            return 200, json.dumps({"spec": {"valuesContent": ""}}).encode()
        return 404, b""


def _frontend(monkeypatch, cp_size: int, kube: _Kube) -> dict:
    monkeypatch.setattr(k8s_api, "_request", kube)
    ok, err = k8s_api.apply_control_plane_overrides(
        cp_size, "192.0.2.10", web_ui_allowed_cidrs=["192.0.2.0/24"], mem_total_mib=8192
    )
    assert (ok, err) == (True, None)
    return dict((yaml.safe_load(kube.config or "") or {})["frontend"])


def test_the_first_promotion_changes_the_frontends_replicas_and_nothing_else(
    monkeypatch,
) -> None:
    kube = _Kube()
    one = _frontend(monkeypatch, 1, kube)
    three = _frontend(monkeypatch, 3, kube)   # the same HelmChartConfig, promoted

    assert (one.pop("replicas"), three.pop("replicas")) == (1, 3)
    assert one == three
    # What the chart gate renders the frontend with is what the supervisor
    # writes: hard anti-affinity on every size (the chart adds the host network
    # from firstboot's values), so the template the chart renders is the same.
    assert one["podAntiAffinity"] == "hard"


def test_a_demote_back_to_one_node_changes_only_the_replicas_too(monkeypatch) -> None:
    kube = _Kube()
    three = _frontend(monkeypatch, 3, kube)
    one = _frontend(monkeypatch, 1, kube)

    assert (three.pop("replicas"), one.pop("replicas")) == (3, 1)
    assert one == three
