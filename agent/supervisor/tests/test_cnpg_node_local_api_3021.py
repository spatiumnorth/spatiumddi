"""The appliance's CNPG instances reach the API server on their own node (#3021).

Each CNPG instance manager keeps one long-lived connection to the API server.
Through the ``kubernetes`` Service it lands on any control-plane node's API
server, and when that node was the one lost, the primary lost the API: its
liveness probe's isolation check then failed on the replica it could not reach
either, and kubelet restarted a primary that had lost nothing it needed. On the
appliance every control-plane node is a k3s server, so the instance pods take
the API server from their own node (``postgresql.cnpg.nodeLocalApiServer``).

The chart's default is off (a BYO-Kubernetes node may serve no API on its own
address), so the appliance sets the value in both places its control chart
takes values from, as #1805 does for the api Service:

* firstboot's ``_render_control_helmchart``: the seed's ``spatium-control``
  HelmChart, a fresh install's only values;
* ``apply_control_plane_overrides``: the ``spatium-control`` HelmChartConfig the
  seed supervisor merges on every heartbeat, which is what a grown cluster, and
  an appliance upgraded from a build that predates the value, ends up with.

``test_helmchartconfig_noop`` keeps the two equal on a fresh install (#1005).
The chart's own rendering of the value is checked by
``.github/scripts/chart-cnpg-node-local-api.py`` in the render gate.
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


def _node_local(values: dict) -> dict:
    cnpg = (values.get("postgresql") or {}).get("cnpg") or {}
    return cnpg.get("nodeLocalApiServer") or {}


@pytest.mark.parametrize("cp_size", [1, 3, 5])
def test_the_supervisor_writes_it_at_every_size(cp_size: int) -> None:
    """Every size, single node included: on one node its own API server is
    the only one, and a merge cannot remove a key, so a promotion never has
    to add it (which would roll the instances mid-promotion)."""
    assert _node_local(_owned(cp_size)).get("enabled") is True


def test_firstboot_renders_it() -> None:
    assert _node_local(_render_firstboot_control_values()).get("enabled") is True


def test_a_three_node_cluster_from_an_older_build_ends_with_it(monkeypatch) -> None:
    """The upgrade shape: the seed's HelmChart and the HelmChartConfig were
    both written before the value existed. The supervisor's merge must add
    it, so the EFFECTIVE values (``deep_merge(chart, config)``, what helm
    renders) carry it, and keep what it does not own (the chart bump's
    ``image.tag``) and the instance count it already wrote."""
    chart = _render_firstboot_control_values()
    chart["postgresql"]["cnpg"].pop("nodeLocalApiServer", None)
    config = _owned(3)
    config["postgresql"]["cnpg"].pop("nodeLocalApiServer", None)
    config["image"] = {"tag": "2026.10.28-1"}
    kube = _Kube(chart=_yaml(chart), config=_yaml(config))
    monkeypatch.setattr(k8s_api, "_request", kube)

    ok, err = k8s_api.apply_control_plane_overrides(3, "", web_ui_allowed_cidrs=[])

    assert (ok, err) == (True, None)
    written = kube.written_values
    assert _node_local(written).get("enabled") is True
    assert written["image"] == {"tag": "2026.10.28-1"}
    assert written["postgresql"]["cnpg"]["instances"] == 3
    effective = k8s_api._deep_merge(chart, written)
    assert _node_local(effective).get("enabled") is True


def test_an_operator_port_beside_it_survives(monkeypatch) -> None:
    """The supervisor owns ``enabled`` in the mapping, nothing else: an
    operator who serves the API on another port keeps it. Same older-build
    shape as above, with the operator's key already there."""
    chart = _render_firstboot_control_values()
    chart["postgresql"]["cnpg"].pop("nodeLocalApiServer", None)
    config = _owned(3)
    config["postgresql"]["cnpg"]["nodeLocalApiServer"] = {"port": 7443}
    kube = _Kube(chart=_yaml(chart), config=_yaml(config))
    monkeypatch.setattr(k8s_api, "_request", kube)

    ok, err = k8s_api.apply_control_plane_overrides(3, "", web_ui_allowed_cidrs=[])

    assert (ok, err) == (True, None)
    assert kube.written_values["postgresql"]["cnpg"]["nodeLocalApiServer"] == {
        "port": 7443,
        "enabled": True,
    }
