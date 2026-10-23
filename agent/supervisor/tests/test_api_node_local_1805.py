"""The appliance keeps each node's api callers on its own api pod (#1805).

The api Service's ``trafficDistribution: PreferSameNode`` is what keeps a
surviving node's heartbeat off a lost node's api pod. It belongs to the
appliance, not to the umbrella chart: there every control-plane node runs one
api pod (``replicas`` = control-plane size, hard anti-affinity), while on a
BYO-Kubernetes cluster it would pin each node's callers to whichever api pod
shares their node. So the chart's default is ``""`` (no field) and the
appliance sets the value in both places its control chart takes values from:

* firstboot's ``_render_control_helmchart``: the seed's ``spatium-control``
  HelmChart, a fresh install's only values (a joined member renders nothing);
* ``apply_control_plane_overrides``: the ``spatium-control`` HelmChartConfig
  the seed supervisor merges on every heartbeat. helm-controller merges it over
  the HelmChart, so it is what a multi-node cluster, and an appliance upgraded
  from a build that predates the value, ends up with.

``test_helmchartconfig_noop`` keeps the two equal on a fresh install (#1005).
"""

from __future__ import annotations

import pytest

from spatium_supervisor import k8s_api

from .test_helmchartconfig_noop import (
    _Kube,
    _owned,
    _render_firstboot_control_values,
    _yaml,
)

WANT = "PreferSameNode"


def _api_traffic_distribution(values: dict) -> object:
    return ((values.get("api") or {}).get("service") or {}).get("trafficDistribution")


@pytest.mark.parametrize("cp_size", [1, 3, 5])
def test_the_supervisor_writes_it_at_every_size(cp_size: int) -> None:
    """Every size, single node included: one api pod makes it inert, and a
    merge cannot remove a key, so it is never left to depend on the size."""
    assert _api_traffic_distribution(_owned(cp_size)) == WANT


def test_firstboot_renders_it() -> None:
    assert _api_traffic_distribution(_render_firstboot_control_values()) == WANT


def test_a_three_node_cluster_from_an_older_build_ends_with_it(monkeypatch) -> None:
    """The upgrade shape: the seed's HelmChart and the HelmChartConfig were
    both written before the value existed. The supervisor's merge must add
    it, so the EFFECTIVE values (``deep_merge(chart, config)``, what helm
    renders) carry it, and keep what it does not own (the chart bump's
    ``image.tag``)."""
    chart = _render_firstboot_control_values()
    chart["api"].pop("service", None)
    config = _owned(3)
    config["api"].pop("service", None)
    config["image"] = {"tag": "2026.10.16-1"}
    kube = _Kube(chart=_yaml(chart), config=_yaml(config))
    monkeypatch.setattr(k8s_api, "_request", kube)

    ok, err = k8s_api.apply_control_plane_overrides(3, "", web_ui_allowed_cidrs=[])

    assert (ok, err) == (True, None)
    written = kube.written_values
    assert _api_traffic_distribution(written) == WANT
    assert written["image"] == {"tag": "2026.10.16-1"}
    assert written["api"]["replicas"] == 3
    effective = k8s_api._deep_merge(chart, written)
    assert _api_traffic_distribution(effective) == WANT


def test_an_operator_key_beside_it_survives(monkeypatch) -> None:
    """``api.service`` is a mapping the operator may also write to (#2024):
    the supervisor owns ``trafficDistribution`` in it, nothing else. Same
    older-build shape as above, with an operator's key already there."""
    chart = _render_firstboot_control_values()
    chart["api"].pop("service", None)
    config = _owned(3)
    config["api"]["service"] = {"type": "NodePort"}
    kube = _Kube(chart=_yaml(chart), config=_yaml(config))
    monkeypatch.setattr(k8s_api, "_request", kube)

    ok, err = k8s_api.apply_control_plane_overrides(3, "", web_ui_allowed_cidrs=[])

    assert (ok, err) == (True, None)
    assert kube.written_values["api"]["service"] == {
        "type": "NodePort",
        "trafficDistribution": WANT,
    }
