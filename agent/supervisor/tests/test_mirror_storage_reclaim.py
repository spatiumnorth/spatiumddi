"""#1541 — the slot-image mirror's claim is reclaimed off an evicted node.

The #1659 walk: after a 3 -> 1 demote the mirror sat Pending for good, its
local-path volume pinned to a node that no longer existed. The seed's
eviction reclaimed Redis's and Postgres's claims and not the mirror's. And
unlike those, nothing re-creates the mirror's claim once it is deleted — it
is a plain Helm-owned PVC, not a volumeClaimTemplate or a CNPG instance
claim — so the reclaim keeps a manifest and re-creates the claim once the
old one has finished terminating.
"""

from __future__ import annotations

import inspect
import json

from spatium_supervisor import heartbeat, k8s_api

NS = "/api/v1/namespaces/spatium"
CLAIM = "spatium-control-spatiumddi-slot-image-mirror-data"
DEAD, SEED = "ddipg-member-2", "ddipg-seed"


def _mirror_claim(node: str, *, terminating: bool = False) -> dict:
    meta: dict = {
        "name": CLAIM,
        "namespace": "spatium",
        "uid": "abc",
        "resourceVersion": "42",
        "labels": {
            "app.kubernetes.io/component": "slot-image-mirror",
            "app.kubernetes.io/managed-by": "Helm",
        },
        "annotations": {
            "helm.sh/resource-policy": "keep",
            "meta.helm.sh/release-name": "spatium-control",
            "meta.helm.sh/release-namespace": "spatium",
            "volume.kubernetes.io/selected-node": node,
            "pv.kubernetes.io/bind-completed": "yes",
            "volume.kubernetes.io/storage-provisioner": "rancher.io/local-path",
        },
        "finalizers": ["kubernetes.io/pvc-protection"],
    }
    if terminating:
        meta["deletionTimestamp"] = "2026-10-11T00:00:00Z"
    return {
        "metadata": meta,
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "resources": {"requests": {"storage": "20Gi"}},
            "storageClassName": "local-path",
            "volumeMode": "Filesystem",
            "volumeName": "pvc-1234",
        },
        "status": {"phase": "Bound"},
    }


def _pv(node: str) -> dict:
    return {
        "spec": {
            "nodeAffinity": {
                "required": {
                    "nodeSelectorTerms": [
                        {
                            "matchExpressions": [
                                {
                                    "key": "kubernetes.io/hostname",
                                    "operator": "In",
                                    "values": [node],
                                }
                            ]
                        }
                    ]
                }
            }
        }
    }


class _Kube:
    """A scripted kubeapi: one PVC list, one PV, the mirror's pods, and the
    claim's create / get answers."""

    def __init__(
        self,
        claims: list[dict],
        pv_node: str,
        *,
        post_status: int = 201,
        get_claim: tuple[int, dict | None] = (404, None),
    ) -> None:
        self.claims = claims
        self.pv_node = pv_node
        self.post_status = post_status
        self.get_claim = get_claim
        self.calls: list[tuple[str, str]] = []
        self.posted: list[dict] = []

    def __call__(self, method, path, body=None, content_type=None, timeout=10.0):
        self.calls.append((method, path))
        if method == "GET" and path == f"{NS}/persistentvolumeclaims":
            return 200, json.dumps({"items": self.claims}).encode()
        if method == "GET" and path.startswith("/api/v1/persistentvolumes/"):
            return 200, json.dumps(_pv(self.pv_node)).encode()
        if method == "GET" and path.startswith(f"{NS}/pods"):
            assert "slot-image-mirror" in path
            return (
                200,
                json.dumps(
                    {
                        "items": [
                            {
                                "metadata": {"name": "mirror-abc", "namespace": "spatium"},
                                "status": {"phase": "Pending"},
                            },
                        ]
                    }
                ).encode(),
            )
        if method == "GET" and path == f"{NS}/persistentvolumeclaims/{CLAIM}":
            status, doc = self.get_claim
            return status, json.dumps(doc or {}).encode()
        if method == "POST":
            self.posted.append(json.loads(body))
            return self.post_status, b"{}"
        return 200, b"{}"

    @property
    def deleted(self) -> list[str]:
        return [p for m, p in self.calls if m == "DELETE"]


def test_the_stranded_claim_and_its_pod_are_deleted_and_owed(monkeypatch) -> None:
    kube = _Kube([_mirror_claim(DEAD)], DEAD)
    monkeypatch.setattr(k8s_api, "_request", kube)

    owed, err = k8s_api.reclaim_stranded_mirror_storage(DEAD)

    assert err is None and list(owed) == [CLAIM]
    assert kube.deleted == [
        f"{NS}/persistentvolumeclaims/{CLAIM}",
        f"{NS}/pods/mirror-abc",
    ]
    manifest = owed[CLAIM]
    # A NEW claim: Helm still owns it, it asks for the same storage, and it
    # carries nothing that binds it to the old volume or the gone node.
    assert manifest["metadata"]["name"] == CLAIM
    assert manifest["metadata"]["annotations"] == {
        "helm.sh/resource-policy": "keep",
        "meta.helm.sh/release-name": "spatium-control",
        "meta.helm.sh/release-namespace": "spatium",
    }
    assert manifest["metadata"]["labels"]["app.kubernetes.io/managed-by"] == "Helm"
    for gone in ("uid", "resourceVersion", "finalizers", "deletionTimestamp"):
        assert gone not in manifest["metadata"]
    assert "volumeName" not in manifest["spec"]
    assert "status" not in manifest
    assert manifest["spec"]["resources"] == {"requests": {"storage": "20Gi"}}
    assert manifest["spec"]["storageClassName"] == "local-path"


def test_a_claim_on_a_live_node_is_left_alone(monkeypatch) -> None:
    kube = _Kube([_mirror_claim(SEED)], SEED)
    monkeypatch.setattr(k8s_api, "_request", kube)

    owed, err = k8s_api.reclaim_stranded_mirror_storage(DEAD)

    assert (owed, err) == ({}, None)
    assert kube.deleted == []


def test_the_pv_affinity_decides_not_the_annotation(monkeypatch) -> None:
    """The scheduler's annotation can name a node the volume is not on; the
    bound PV's node affinity is what the scheduler enforces."""
    kube = _Kube([_mirror_claim(DEAD)], SEED)
    monkeypatch.setattr(k8s_api, "_request", kube)

    owed, err = k8s_api.reclaim_stranded_mirror_storage(DEAD)

    assert (owed, err) == ({}, None)


def test_other_claims_are_never_touched(monkeypatch) -> None:
    redis = _mirror_claim(DEAD)
    redis["metadata"]["name"] = "data-spatium-control-spatiumddi-redis-2"
    kube = _Kube([redis], DEAD)
    monkeypatch.setattr(k8s_api, "_request", kube)

    owed, _ = k8s_api.reclaim_stranded_mirror_storage(DEAD)

    assert owed == {} and kube.deleted == []


def test_the_owed_claim_is_created(monkeypatch) -> None:
    manifest = {"metadata": {"name": CLAIM}, "spec": {}}
    kube = _Kube([], DEAD, post_status=201)
    monkeypatch.setattr(k8s_api, "_request", kube)

    created, still, err = k8s_api.recreate_reclaimed_claims({CLAIM: manifest})

    assert (created, still, err) == ([CLAIM], {}, None)
    assert kube.posted == [manifest]


def test_a_claim_still_terminating_stays_owed(monkeypatch) -> None:
    """409 while pvc-protection holds the old claim: retried next tick, and
    the mirror's pod is deleted again in case one was re-created on the old
    claim in between."""
    manifest = {"metadata": {"name": CLAIM}, "spec": {}}
    kube = _Kube([], DEAD, post_status=409, get_claim=(200, _mirror_claim(DEAD, terminating=True)))
    monkeypatch.setattr(k8s_api, "_request", kube)

    created, still, err = k8s_api.recreate_reclaimed_claims({CLAIM: manifest})

    assert (created, still, err) == ([], {CLAIM: manifest}, None)
    assert f"{NS}/pods/mirror-abc" in kube.deleted


def test_a_claim_somebody_else_recreated_is_settled(monkeypatch) -> None:
    """409 on a claim that is NOT terminating: a Helm upgrade put it back
    already, which is the outcome wanted, so nothing is owed."""
    manifest = {"metadata": {"name": CLAIM}, "spec": {}}
    fresh = _mirror_claim(SEED)
    kube = _Kube([], DEAD, post_status=409, get_claim=(200, fresh))
    monkeypatch.setattr(k8s_api, "_request", kube)

    created, still, err = k8s_api.recreate_reclaimed_claims({CLAIM: manifest})

    assert (created, still, err) == ([], {}, None)


def test_the_seed_eviction_reclaims_and_recreates_the_mirror_claim() -> None:
    """Structural: ``heartbeat_once`` reclaims the mirror's claim right after
    the Node DELETE (where Redis's was reclaimed until #2404 moved it to a
    sweep on every seed tick), and drives the owed claims every tick."""
    src = inspect.getsource(heartbeat.heartbeat_once)
    deleted = src.index("k8s_api.delete_node(")
    mirror = src.index("k8s_api.reclaim_stranded_mirror_storage(")
    recreate = src.index("k8s_api.recreate_reclaimed_claims(")
    assert deleted < mirror < recreate
    assert "_mirror_claims_owed.update(owed)" in src
