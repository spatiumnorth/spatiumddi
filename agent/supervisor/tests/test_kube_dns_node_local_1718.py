"""#1718 — once a cluster has a second node, each node resolves through its own
CoreDNS replica: the kube-dns Service carries ``trafficDistribution:
PreferSameNode``.

A lost node's CoreDNS pod stays a ready kube-dns endpoint until the node reads
NotReady (about 40 s). Load-balanced across every replica, half of each other
node's lookups went to it and stalled for the resolver's whole timeout: every
surviving Redis sentinel resolved its peers into TILT, the failover took 77 s,
and the supervisors' own heartbeats failed with EAI_AGAIN. With one replica per
node (ensure_coredns_ha) and node-local routing, a lost node takes only its own
pods' DNS with it.
"""

from __future__ import annotations

import json

import pytest

from spatium_supervisor import k8s_api

_NODES_PATH = "/api/v1/nodes"
_SVC_PATH = "/api/v1/namespaces/kube-system/services/kube-dns"


class _Recorder:
    def __init__(self, traffic: str | None = None, *, nodes: int = 3, get_status: int = 200,
                 patch_status: int = 200, nodes_status: int = 200):
        self.traffic = traffic
        self.nodes = nodes
        self.get_status = get_status
        self.patch_status = patch_status
        self.nodes_status = nodes_status
        self.calls: list[tuple[str, str, bytes | None, str | None]] = []

    def __call__(self, method, path, body=None, content_type=None, timeout=None):
        self.calls.append((method, path, body, content_type))
        if method == "GET" and path == _NODES_PATH:
            if self.nodes_status != 200:
                return (self.nodes_status, "forbidden")
            items = [{"metadata": {"name": f"n{i}"}, "spec": {},
                      "status": {"conditions": [{"type": "Ready", "status": "True"}]}}
                     for i in range(self.nodes)]
            return (200, json.dumps({"items": items}))
        assert path == _SVC_PATH, path
        if method == "GET":
            if self.get_status != 200:
                return (self.get_status, "not found")
            spec = {"clusterIP": "10.43.0.10"}
            if self.traffic is not None:
                spec["trafficDistribution"] = self.traffic
            return (200, json.dumps({"metadata": {"name": "kube-dns"}, "spec": spec}))
        return (self.patch_status, "{}")

    @property
    def patches(self) -> list[dict]:
        return [json.loads(b) for m, _, b, _ in self.calls if m == "PATCH"]


@pytest.mark.parametrize("nodes", [2, 3, 7])
def test_a_real_cluster_gets_node_local_dns(monkeypatch, nodes) -> None:
    rec = _Recorder(None, nodes=nodes)
    monkeypatch.setattr(k8s_api, "_request", rec)

    assert k8s_api.ensure_kube_dns_node_local() == (True, None)
    assert rec.patches == [{"spec": {"trafficDistribution": "PreferSameNode"}}]
    assert [ct for m, _, _, ct in rec.calls if m == "PATCH"] == ["application/merge-patch+json"]


def test_converged_cluster_is_left_alone(monkeypatch) -> None:
    rec = _Recorder("PreferSameNode", nodes=3)
    monkeypatch.setattr(k8s_api, "_request", rec)

    assert k8s_api.ensure_kube_dns_node_local() == (False, None)
    assert rec.patches == []


def test_single_node_stock_service_is_left_alone(monkeypatch) -> None:
    """#750's rule: on one node the stock manifest is the target, so a fresh
    install patches nothing."""
    rec = _Recorder(None, nodes=1)
    monkeypatch.setattr(k8s_api, "_request", rec)

    assert k8s_api.ensure_kube_dns_node_local() == (False, None)
    assert rec.patches == []


def test_single_node_is_put_back_to_stock(monkeypatch) -> None:
    """A cluster shrunk back to one node drops the field (``null`` deletes it
    under a merge-patch)."""
    rec = _Recorder("PreferSameNode", nodes=1)
    monkeypatch.setattr(k8s_api, "_request", rec)

    assert k8s_api.ensure_kube_dns_node_local() == (True, None)
    assert rec.patches == [{"spec": {"trafficDistribution": None}}]


def test_another_distribution_is_replaced(monkeypatch) -> None:
    rec = _Recorder("PreferClose", nodes=3)
    monkeypatch.setattr(k8s_api, "_request", rec)

    assert k8s_api.ensure_kube_dns_node_local() == (True, None)
    assert rec.patches == [{"spec": {"trafficDistribution": "PreferSameNode"}}]


def test_one_patch_reaches_a_fixed_point(monkeypatch) -> None:
    first = _Recorder(None, nodes=3)
    monkeypatch.setattr(k8s_api, "_request", first)
    assert k8s_api.ensure_kube_dns_node_local() == (True, None)

    settled = _Recorder(first.patches[0]["spec"]["trafficDistribution"], nodes=3)
    monkeypatch.setattr(k8s_api, "_request", settled)
    assert k8s_api.ensure_kube_dns_node_local() == (False, None)
    assert settled.patches == []


def test_unreadable_node_list_defers(monkeypatch) -> None:
    rec = _Recorder(None, nodes_status=403)
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.ensure_kube_dns_node_local()
    assert changed is False and err is not None and "node count" in err
    assert rec.patches == []


def test_missing_service_reports(monkeypatch) -> None:
    rec = _Recorder(None, get_status=404)
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.ensure_kube_dns_node_local()
    assert changed is False and err is not None and "404" in err
    assert rec.patches == []


def test_refused_patch_reports(monkeypatch) -> None:
    """An apiserver that does not know the value answers 422; the heartbeat logs
    it and carries on."""
    rec = _Recorder(None, patch_status=422)
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.ensure_kube_dns_node_local()
    assert changed is False and err is not None and "422" in err


def test_transport_error_is_caught(monkeypatch) -> None:
    def boom(method, path, body=None, content_type=None, timeout=None):
        raise OSError("ca.crt: permission denied")

    monkeypatch.setattr(k8s_api, "_request", boom)

    changed, err = k8s_api.ensure_kube_dns_node_local()
    assert changed is False and err is not None and "permission denied" in err
