"""#590 — reclaim_stranded_redis_storage frees node-affine Redis PVCs.

Evicting a dead node strands every local-path PVC provisioned on it (the
PV is node-affine), so the StatefulSet's replacement pod sits Pending
forever and the missing replica's sentinel silently drops the failover
quorum. These tests pin the contract: reclaim exactly the Redis claims
annotated with the deleted node (PVC first, then the Pending consumer
pod so the StatefulSet recreates both), never touch CNPG's claims or
other nodes' claims, and surface kubeapi errors instead of guessing.

#2404: the reclaim used to run on one tick only, the one whose Node DELETE
succeeded, and nothing looked again, so an error answer then, or a Node removed
any other way, left the claim stranded for good. The cases
below the line pin the level-triggered sweep that replaced it: every seed tick,
one cheap read while Redis is whole, the names evicted this tick authoritative,
and a claim whose node is still a Node never touched.
"""

from __future__ import annotations

import json
import types
import uuid

import httpx
import pytest
import structlog
from structlog.testing import capture_logs

from spatium_supervisor import appliance_state, heartbeat, k8s_api


class _Recorder:
    """Stand-in for k8s_api._request that scripts the PVC-list GET and
    records every follow-up DELETE."""

    def __init__(self, get_status: int, get_body: str, delete_status: int = 200):
        self._get = (get_status, get_body)
        self._delete_status = delete_status
        self.calls: list[tuple[str, str]] = []

    def __call__(self, method, path, body=None, content_type=None):
        self.calls.append((method, path))
        if method == "GET":
            return self._get
        return (self._delete_status, "{}")

    @property
    def deleted(self) -> list[str]:
        return [p for m, p in self.calls if m == "DELETE"]


def _pvc(name: str, node: str | None) -> dict:
    meta: dict = {"name": name}
    if node is not None:
        meta["annotations"] = {"volume.kubernetes.io/selected-node": node}
    return {"metadata": meta}


def _pvc_list(*items: dict) -> str:
    return json.dumps({"items": list(items)})


def test_reclaims_redis_pvc_and_pending_pod_on_dead_node(monkeypatch) -> None:
    rec = _Recorder(200, _pvc_list(
        _pvc("data-spatium-control-spatiumddi-redis-2", "ddipg-member-2"),
        _pvc("data-spatium-control-spatiumddi-redis-0", "ddipg-seed"),
    ))
    monkeypatch.setattr(k8s_api, "_request", rec)

    reclaimed, err = k8s_api.reclaim_stranded_redis_storage("ddipg-member-2")

    assert (reclaimed, err) == (["data-spatium-control-spatiumddi-redis-2"], None)
    # PVC first (pvc-protection holds it until its pod is gone), then the pod.
    assert rec.deleted == [
        "/api/v1/namespaces/spatium/persistentvolumeclaims/data-spatium-control-spatiumddi-redis-2",
        "/api/v1/namespaces/spatium/pods/spatium-control-spatiumddi-redis-2",
    ]


def test_never_touches_cnpg_or_other_nodes(monkeypatch) -> None:
    # CNPG deletes + recreates its own instance PVCs; reclaiming one out
    # from under the operator would fight its reconcile. And claims on
    # LIVE nodes are healthy — only the deleted node's are stranded.
    rec = _Recorder(200, _pvc_list(
        _pvc("spatium-control-spatiumddi-postgresql-2", "ddipg-member-2"),
        _pvc("data-spatium-control-spatiumddi-redis-1", "ddipg-member-1"),
    ))
    monkeypatch.setattr(k8s_api, "_request", rec)

    reclaimed, err = k8s_api.reclaim_stranded_redis_storage("ddipg-member-2")

    assert (reclaimed, err) == ([], None)
    assert rec.deleted == []


def test_unannotated_pvc_is_left_alone(monkeypatch) -> None:
    # No selected-node annotation = not a WaitForFirstConsumer local-path
    # claim (or not yet scheduled) — there is nothing node-affine to free.
    rec = _Recorder(200, _pvc_list(
        _pvc("data-spatium-control-spatiumddi-redis-2", None),
    ))
    monkeypatch.setattr(k8s_api, "_request", rec)

    reclaimed, err = k8s_api.reclaim_stranded_redis_storage("ddipg-member-2")

    assert (reclaimed, err) == ([], None)
    assert rec.deleted == []


def test_list_failure_reports_instead_of_guessing(monkeypatch) -> None:
    rec = _Recorder(500, "boom")
    monkeypatch.setattr(k8s_api, "_request", rec)

    reclaimed, err = k8s_api.reclaim_stranded_redis_storage("ddipg-member-2")

    assert reclaimed == []
    assert err is not None and "500" in err
    assert rec.deleted == []


# ---------------------------------------------------------------------------
# #2404: the reclaim is level-triggered.
#
# On a fresh three-node cluster (2026-10-22) a dead member was replaced and its
# Redis replica's claim stayed Bound to the dead member's volume: 37 minutes
# later the replica was still Pending on "didn't match PersistentVolume's node
# affinity" and Redis ran two of three, while the same drill on another cluster
# of the same build reclaimed it on the eviction tick. The world below is that
# walk's: redis-0 on the seed, redis-1 on member-1, redis-2's claim on the dead
# member-2, and member-3 the replacement.
# ---------------------------------------------------------------------------

NS = "/api/v1/namespaces/spatium"
PVC_PATH = f"{NS}/persistentvolumeclaims"
POD_PATH = f"{NS}/pods"
PENDING_PATH = f"{POD_PATH}?fieldSelector=status.phase%3DPending"
NODES_PATH = "/api/v1/nodes"
REDIS = "spatium-control-spatiumddi-redis"
R2 = f"data-{REDIS}-2"
DEAD = "ddipg-member-2"
LIVE = ("ddipg-seed", "ddipg-member-1", "ddipg-member-3")
# What freeing redis-2 deletes, in order: the claim, then its Pending pod.
FREED = [f"{PVC_PATH}/{R2}", f"{POD_PATH}/{REDIS}-2"]


class _Kube:
    """A scripted kubeapi keyed by path. A GET answers from ``gets``: a list is
    one answer per call, its last answer repeating, and a path not scripted is
    a 404. A DELETE answers 200 unless ``deletes`` says otherwise. Every call is
    recorded in order."""

    def __init__(self, gets: dict, deletes: dict[str, int] | None = None) -> None:
        self._gets = {p: list(a) if isinstance(a, list) else [a] for p, a in gets.items()}
        self._deletes = deletes or {}
        self.calls: list[tuple[str, str]] = []

    def __call__(self, method, path, body=None, content_type=None, timeout=None):
        self.calls.append((method, path))
        if method == "DELETE":
            return self._deletes.get(path, 200), b"{}"
        answers = self._gets.get(path)
        if method != "GET" or not answers:
            return 404, b"{}"
        status, payload = answers.pop(0) if len(answers) > 1 else answers[0]
        raw = payload if isinstance(payload, str) else json.dumps(payload)
        return status, raw.encode()

    @property
    def reads(self) -> list[str]:
        return [p for m, p in self.calls if m == "GET"]

    @property
    def deleted(self) -> list[str]:
        return [p for m, p in self.calls if m == "DELETE"]


def _redis_claim(
    ordinal: int, volume: str, *, selected: str | None = None, terminating: bool = False
) -> dict:
    meta: dict = {"name": f"data-{REDIS}-{ordinal}"}
    if selected:
        meta["annotations"] = {"volume.kubernetes.io/selected-node": selected}
    if terminating:
        meta["deletionTimestamp"] = "2026-10-22T04:21:00Z"
    return {"metadata": meta, "spec": {"volumeName": volume}}


def _pv(host: str) -> dict:
    term = {"key": "kubernetes.io/hostname", "operator": "In", "values": [host]}
    return {
        "spec": {"nodeAffinity": {"required": {"nodeSelectorTerms": [{"matchExpressions": [term]}]}}}
    }


def _node(name: str, *, ready: bool = True) -> dict:
    cond = {"type": "Ready", "status": "True" if ready else "False"}
    return {"metadata": {"name": name}, "status": {"conditions": [cond]}}


def _pending_pod(name: str, claim: str) -> dict:
    volume = {"name": "data", "persistentVolumeClaim": {"claimName": claim}}
    return {"metadata": {"name": name}, "spec": {"volumes": [volume]}, "status": {"phase": "Pending"}}


_WALK_CLAIMS = (
    _redis_claim(0, "pv-r0", selected="ddipg-seed"),
    _redis_claim(1, "pv-r1", selected="ddipg-member-1"),
    _redis_claim(2, "pv-r2", selected=DEAD),
)
_WALK_PVS = {"pv-r0": "ddipg-seed", "pv-r1": "ddipg-member-1", "pv-r2": DEAD}
_REDIS_2_PENDING = (_pending_pod(f"{REDIS}-2", R2),)


def _walk(*, nodes=LIVE, pending=_REDIS_2_PENDING, claims=_WALK_CLAIMS, pvs=None) -> dict:
    """The fresh-cluster walk after the replace, as GET answers by path."""
    gets: dict = {
        PENDING_PATH: (200, {"items": list(pending)}),
        NODES_PATH: (200, {"items": [n if isinstance(n, dict) else _node(n) for n in nodes]}),
        PVC_PATH: (200, {"items": list(claims)}),
    }
    for volume, host in (_WALK_PVS if pvs is None else pvs).items():
        gets[f"/api/v1/persistentvolumes/{volume}"] = (200, _pv(host))
    return gets


def test_a_claim_whose_node_is_gone_is_reclaimed_on_any_tick(monkeypatch) -> None:
    # Nothing was evicted this tick (the supervisor restarted since, or the
    # eviction tick's reclaim failed, or the Node went another way). redis-2's
    # pod is Pending on the dead node's volume, so the sweep reads the Nodes.
    kube = _Kube(_walk())
    monkeypatch.setattr(k8s_api, "_request", kube)

    out = k8s_api.reclaim_stranded_redis_storage()

    assert tuple(out) == ([R2], None)
    assert kube.deleted == FREED
    assert out.sources == {R2: "pv"}
    assert out.nodes == [DEAD]


@pytest.mark.parametrize("ready", [True, False], ids=["ready", "not-ready"])
def test_a_claim_whose_node_is_still_a_node_is_never_touched(monkeypatch, ready) -> None:
    # NotReady is not gone: member-2 is still registered (powered off and not
    # evicted yet, or back), and it can return with its data. Its replica's pod
    # waits Pending on the volume's affinity meanwhile, which opens the sweep.
    kube = _Kube(_walk(nodes=(*LIVE, _node(DEAD, ready=ready))))
    monkeypatch.setattr(k8s_api, "_request", kube)

    assert tuple(k8s_api.reclaim_stranded_redis_storage()) == ([], None)
    assert kube.deleted == []


_MIRROR = "spatium-control-spatiumddi-slot-image-mirror"


@pytest.mark.parametrize(
    "pending",
    [(), (_pending_pod(f"{_MIRROR}-0", f"{_MIRROR}-data"),)],
    ids=["no-pending-pod", "another-components-pending-pod"],
)
def test_the_healthy_steady_state_is_one_read(monkeypatch, pending) -> None:
    # Every seed tick pays this: one list of the namespace's Pending pods,
    # empty while Redis is whole. Nodes, claims and volumes are read only
    # while a pod that mounts a Redis claim is waiting to be scheduled.
    kube = _Kube(_walk(pending=pending))
    monkeypatch.setattr(k8s_api, "_request", kube)

    assert tuple(k8s_api.reclaim_stranded_redis_storage()) == ([], None)
    assert kube.reads == [PENDING_PATH]
    assert kube.deleted == []


def test_the_eviction_tick_reclaims_without_reading_the_nodes(monkeypatch) -> None:
    # The Node DELETE is milliseconds old and the name can still be listed.
    # The names the caller evicted are authoritative (as for Postgres, #1058),
    # so the claim goes at once, as #590's did, with no Node read.
    kube = _Kube(_walk(nodes=(*LIVE, DEAD), pending=()))
    monkeypatch.setattr(k8s_api, "_request", kube)

    out = k8s_api.reclaim_stranded_redis_storage({DEAD})

    assert tuple(out) == ([R2], None)
    assert kube.deleted == FREED
    assert NODES_PATH not in kube.reads and PENDING_PATH not in kube.reads


@pytest.mark.parametrize("evicted", [(), DEAD], ids=["any-tick", "eviction-tick"])
def test_the_volume_decides_not_the_annotation(monkeypatch, evicted) -> None:
    # #590 matched the scheduler's selected-node annotation against the name it
    # was given. The bound PV's node affinity is what the scheduler enforces, so
    # it decides, as it does for Postgres and the mirror (_pvc_pinned_hostnames).
    claims = (
        _redis_claim(1, "pv-r1", selected="ddipg-member-1"),
        _redis_claim(2, "pv-r2", selected="ddipg-member-3"),  # pv-r2 is on member-2
    )
    kube = _Kube(_walk(claims=claims))
    monkeypatch.setattr(k8s_api, "_request", kube)

    assert tuple(k8s_api.reclaim_stranded_redis_storage(evicted)) == ([R2], None)
    assert kube.deleted == FREED


def test_a_claim_whose_volume_is_on_a_live_node_is_left_alone(monkeypatch) -> None:
    # The reverse: the annotation names the evicted node, the volume is on
    # member-3. The claim is not stranded; deleting it would lose a replica.
    claims = (_redis_claim(2, "pv-r2", selected=DEAD),)
    kube = _Kube(_walk(claims=claims, pvs={"pv-r2": "ddipg-member-3"}))
    monkeypatch.setattr(k8s_api, "_request", kube)

    assert tuple(k8s_api.reclaim_stranded_redis_storage(DEAD)) == ([], None)
    assert kube.deleted == []


def test_a_name_the_backend_sends_as_stored_still_matches(monkeypatch) -> None:
    # #1757: k3s registers the host's name lowercased, and an old backend may
    # send it as stored. delete_node lowercases it; the reclaim now does too.
    kube = _Kube(_walk(pending=()))
    monkeypatch.setattr(k8s_api, "_request", kube)

    assert tuple(k8s_api.reclaim_stranded_redis_storage("DDIPG-Member-2.")) == ([R2], None)
    assert kube.deleted == FREED


def test_a_claim_already_deleted_is_not_reclaimed_again(monkeypatch) -> None:
    # Deleted on an earlier tick and held by pvc-protection until its pod is
    # gone: no second claim DELETE and no second "reclaimed", but the pod
    # DELETE is retried, because the first one may have been refused.
    claims = (*_WALK_CLAIMS[:2], _redis_claim(2, "pv-r2", selected=DEAD, terminating=True))
    kube = _Kube(_walk(claims=claims))
    monkeypatch.setattr(k8s_api, "_request", kube)

    out = k8s_api.reclaim_stranded_redis_storage(DEAD)

    assert tuple(out) == ([], None)
    assert out.terminating == [R2]
    assert kube.deleted == [f"{POD_PATH}/{REDIS}-2"]


def test_a_refused_pod_delete_is_an_error_with_the_claim_still_counted(monkeypatch) -> None:
    # #590 dropped the pod DELETE's answer. A refusal now surfaces, so the
    # heartbeat keeps the node owed and the next tick retries the pod.
    kube = _Kube(_walk(), deletes={f"{POD_PATH}/{REDIS}-2": 500})
    monkeypatch.setattr(k8s_api, "_request", kube)

    out = k8s_api.reclaim_stranded_redis_storage(DEAD)

    assert out.reclaimed == [R2]
    assert out.error is not None and "500" in out.error and f"pod {REDIS}-2" in out.error


def test_a_volume_read_that_fails_is_an_error_not_a_guess(monkeypatch) -> None:
    # The supervisor's grant on persistentvolumes is ``get`` (#1058); a 403 or
    # a 5xx there is a fault to report, never a reason to fall back on the
    # annotation. Only a PV that does not exist (404) falls back.
    gets = _walk()
    gets["/api/v1/persistentvolumes/pv-r2"] = (403, "forbidden")
    kube = _Kube(gets)
    monkeypatch.setattr(k8s_api, "_request", kube)

    out = k8s_api.reclaim_stranded_redis_storage(DEAD)

    assert out.reclaimed == []
    assert out.error is not None and "403" in out.error and R2 in out.error
    assert kube.deleted == []


@pytest.mark.parametrize("path", [PENDING_PATH, NODES_PATH, PVC_PATH])
def test_a_read_that_fails_is_reported_and_frees_nothing(monkeypatch, path) -> None:
    # An unreadable Node list never reads as "every node is gone".
    gets = _walk()
    gets[path] = (500, "boom")
    kube = _Kube(gets)
    monkeypatch.setattr(k8s_api, "_request", kube)

    out = k8s_api.reclaim_stranded_redis_storage()

    assert out.reclaimed == []
    assert out.error is not None and "500" in out.error
    assert kube.deleted == []


# --- the seed's heartbeat, tick by tick --------------------------------------


@pytest.fixture
def seed_tick(monkeypatch, tmp_path):
    """``tick(body_out)`` runs one ``heartbeat_once`` as the seed of a formed
    cluster whose backend answers ``body_out``, and returns the events it
    logged. Everything the control-plane block calls besides the Node DELETE
    and the Redis reclaim is stubbed; the kubeapi is whatever the test puts on
    ``k8s_api._request``. Module state starts empty, as after a restart."""
    monkeypatch.setattr(appliance_state, "collect", dict)
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "docker")
    monkeypatch.setattr(appliance_state, "detect_appliance_variant", lambda: "control-plane")
    monkeypatch.setattr(appliance_state, "read_firewall_state", dict)
    for name in [n for n in dir(appliance_state) if n.startswith("maybe_fire_")]:
        monkeypatch.setattr(appliance_state, name, lambda *a, **k: False)
    for name in (
        "clear_fleet_upgrade_marker",
        "reset_cluster_join_attempts",
        "mark_cluster_join_state_consumed",
    ):
        monkeypatch.setattr(appliance_state, name, lambda *a, **k: None)
    monkeypatch.setattr(heartbeat, "probe_port_conflicts", dict)
    monkeypatch.setattr(heartbeat, "_capabilities_payload", dict)
    monkeypatch.setattr(heartbeat, "_effective_control_plane_url", lambda cfg: "http://cp.invalid")
    monkeypatch.setattr(heartbeat, "load_cert", lambda d: None)
    monkeypatch.setattr(heartbeat, "record_shared_chart_hold", lambda *a, **k: None)
    scale = types.SimpleNamespace(
        current=3, ready=3, reported=3, scaled=False, deferred="", error=None,
        spec_after=lambda size: size,
    )
    monkeypatch.setattr(k8s_api, "patch_cnpg_instances", lambda *a, **k: scale)
    monkeypatch.setattr(k8s_api, "sizing_memory_mib", lambda *a, **k: None)
    for name in (
        "apply_control_plane_overrides",
        "apply_metallb_overrides",
        "apply_dataplane_vip_overrides",
        "ensure_coredns_ha",
    ):
        monkeypatch.setattr(k8s_api, name, lambda *a, **k: (False, None))
    monkeypatch.setattr(k8s_api, "reclaim_stranded_mirror_storage", lambda *a, **k: ({}, None))
    monkeypatch.setattr(
        k8s_api, "reclaim_stranded_postgres_storage", lambda **k: k8s_api.PostgresReclaim()
    )
    monkeypatch.setattr(
        heartbeat, "_etcd_evictions", types.SimpleNamespace(tick=lambda asked, wanted=(): ([], {}))
    )
    for name in (
        "_nodes_deleted",
        "_evicted_pending",
        "_stranded_pending",
        "_redis_stranded_pending",
        "_redis_failures_logged",
    ):
        monkeypatch.setattr(heartbeat, name, set())
    monkeypatch.setattr(heartbeat, "_evict_reasons", {})
    monkeypatch.setattr(heartbeat, "_mirror_claims_owed", {})
    monkeypatch.setattr(heartbeat, "_replace_hold", heartbeat._ReplaceHold())
    monkeypatch.setattr(heartbeat, "_demote_shrink", heartbeat._DemoteShrink())
    cfg = types.SimpleNamespace(heartbeat_interval_seconds=0, state_dir=tmp_path)

    def tick(body_out: dict) -> list[dict]:
        def backend(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=body_out)

        with (
            capture_logs() as logs,
            httpx.Client(transport=httpx.MockTransport(backend)) as client,
        ):
            heartbeat.heartbeat_once(
                cfg, uuid.uuid4(), "tok", None, client, structlog.get_logger()  # type: ignore[arg-type]
            )
        return logs

    return tick


def _said(logs: list[dict], what: str) -> list[dict]:
    return [e for e in logs if e["event"] == f"supervisor.heartbeat.{what}"]


# The backend asking the seed to evict member-2 for a dead-node Replace.
_REPLACE_MEMBER_2 = {
    "control_plane_size": 2,
    "evict_node_names": [DEAD],
    "replace_node_names": [DEAD],
}
# The backend after the eviction settled: nothing left to evict.
_SETTLED = {"control_plane_size": 3}


def test_the_eviction_tick_still_reclaims_at_once(seed_tick, monkeypatch) -> None:
    kube = _Kube(_walk(nodes=(*LIVE, DEAD), pending=()))
    monkeypatch.setattr(k8s_api, "_request", kube)

    logs = seed_tick(_REPLACE_MEMBER_2)

    assert kube.deleted == [f"/api/v1/nodes/{DEAD}", *FREED]
    assert [e["pvcs"] for e in _said(logs, "redis_storage_reclaimed")] == [[R2]]
    assert not _said(logs, "redis_storage_reclaim_failed")


def test_a_reclaim_that_failed_on_the_eviction_tick_is_retried(seed_tick, monkeypatch) -> None:
    # The claim list read fails on the eviction tick (the apiserver is slow
    # right after a member's hard loss). #590 logged it and never asked again:
    # the next tick skips a name already deleted.
    gets = _walk(pending=())
    gets[PVC_PATH] = [(503, "etcdserver: request timed out"), gets[PVC_PATH]]
    kube = _Kube(gets)
    monkeypatch.setattr(k8s_api, "_request", kube)

    first = seed_tick(_REPLACE_MEMBER_2)
    second = seed_tick(_REPLACE_MEMBER_2)  # the backend has not settled it yet

    assert kube.deleted == [f"/api/v1/nodes/{DEAD}", *FREED]
    assert len(_said(first, "redis_storage_reclaim_failed")) == 1
    assert [e["pvcs"] for e in _said(second, "redis_storage_reclaimed")] == [[R2]]


def test_a_restarted_supervisor_frees_a_claim_it_never_reclaimed(seed_tick, monkeypatch) -> None:
    # The Node is gone and the backend has settled the eviction, so no tick
    # will name member-2 again, and this supervisor (fresh state, as after a
    # restart) never saw it. redis-2's pod is Pending on the dead volume.
    kube = _Kube(_walk())
    monkeypatch.setattr(k8s_api, "_request", kube)

    logs = seed_tick(_SETTLED)

    assert kube.deleted == FREED
    assert [e["pvcs"] for e in _said(logs, "redis_storage_reclaimed")] == [[R2]]


def test_a_healthy_seed_tick_costs_one_read_and_logs_nothing(seed_tick, monkeypatch) -> None:
    kube = _Kube(_walk(pending=()))
    monkeypatch.setattr(k8s_api, "_request", kube)
    # The sweep's own calls, apart from what else the heartbeat reads on a
    # seed tick (that is other features' cost, and changes with them).
    sweeps: list[tuple[set, list]] = []
    sweep = k8s_api.reclaim_stranded_redis_storage

    def recorded(evicted_nodes=(), *args, **kwargs):
        start = len(kube.calls)
        try:
            return sweep(evicted_nodes, *args, **kwargs)
        finally:
            sweeps.append((set(evicted_nodes), kube.calls[start:]))

    monkeypatch.setattr(k8s_api, "reclaim_stranded_redis_storage", recorded)

    logs = seed_tick(_SETTLED)

    # One sweep, nothing forced, and its cost is one list of Pending pods.
    assert sweeps == [(set(), [("GET", PENDING_PATH)])]
    assert not [e for e in logs if "redis_storage" in e["event"]]


def test_a_failure_that_repeats_is_logged_once(seed_tick, monkeypatch) -> None:
    # Three ticks of the same 503, one of a 500, then an answer: one line per
    # kind of failure, not one per tick, and the reclaim once it answers.
    gets = _walk(pending=())
    ok = gets[PVC_PATH]
    gets[PVC_PATH] = [(503, "etcdserver: request timed out")] * 3 + [(500, "boom"), ok]
    kube = _Kube(gets)
    monkeypatch.setattr(k8s_api, "_request", kube)

    logs = [event for _ in range(5) for event in seed_tick(_REPLACE_MEMBER_2)]

    failed = [e["error"] for e in _said(logs, "redis_storage_reclaim_failed")]
    assert len(failed) == 2 and "503" in failed[0] and "500" in failed[1]
    assert [e["pvcs"] for e in _said(logs, "redis_storage_reclaimed")] == [[R2]]
    assert kube.deleted[-2:] == FREED


# ---------------------------------------------------------------------------
# Review of #2433, point 1: a name a failed sweep left owed is not this tick's
# eviction. It can outlive a run of failed sweeps, and its node can rejoin under
# the same hostname meanwhile, its Redis replica running on the claim again.
# Only the Node list can say the name is still gone.
# ---------------------------------------------------------------------------

MEMBER_4 = "ddipg-member-4"


def test_a_node_back_under_an_owed_name_keeps_its_claim_and_pod(seed_tick, monkeypatch) -> None:
    # The eviction tick's claim list fails, so member-2 is owed. By the next
    # tick member-2 is back under the same hostname and redis-2 runs there on
    # its claim (no Redis pod is Pending). Handed back as evicted, the owed
    # name cost it the claim and the running pod, for a replica resync.
    gets = _walk(nodes=(*LIVE, DEAD), pending=())
    gets[PVC_PATH] = [(503, "etcdserver: request timed out"), gets[PVC_PATH]]
    kube = _Kube(gets)
    monkeypatch.setattr(k8s_api, "_request", kube)

    first = seed_tick(_REPLACE_MEMBER_2)
    second = seed_tick(_SETTLED)

    assert len(_said(first, "redis_storage_reclaim_failed")) == 1
    assert kube.deleted == [f"/api/v1/nodes/{DEAD}"]
    assert not _said(second, "redis_storage_reclaimed")
    assert heartbeat._redis_stranded_pending == set()  # back, so owed no more


@pytest.mark.parametrize("ready", [True, False], ids=["ready", "not-ready"])
def test_an_owed_name_the_node_list_has_again_is_left_alone(monkeypatch, ready) -> None:
    # Listed again is not gone, Ready or not, as on the sweep.
    kube = _Kube(_walk(nodes=(*LIVE, _node(DEAD, ready=ready)), pending=()))
    monkeypatch.setattr(k8s_api, "_request", kube)

    out = k8s_api.reclaim_stranded_redis_storage(owed_nodes=[DEAD])

    assert tuple(out) == ([], None)
    assert kube.deleted == []


def test_an_owed_name_still_missing_from_the_node_list_is_reclaimed(monkeypatch) -> None:
    # Still gone: freed at once on one Node read, without waiting for its pod
    # to show Pending, and matched as delete_node sends it (#1757).
    kube = _Kube(_walk(pending=()))
    monkeypatch.setattr(k8s_api, "_request", kube)

    out = k8s_api.reclaim_stranded_redis_storage(owed_nodes=["DDIPG-Member-2."])

    assert tuple(out) == ([R2], None)
    assert kube.deleted == FREED
    assert kube.reads.count(NODES_PATH) == 1 and PENDING_PATH not in kube.reads


def test_an_owed_name_is_not_reclaimed_on_a_node_list_that_fails(monkeypatch) -> None:
    # An unreadable Node list says nothing about the owed node: it stays owed.
    gets = _walk(pending=())
    gets[NODES_PATH] = (500, "boom")
    kube = _Kube(gets)
    monkeypatch.setattr(k8s_api, "_request", kube)

    out = k8s_api.reclaim_stranded_redis_storage(owed_nodes=[DEAD])

    assert out.reclaimed == []
    assert out.error is not None and "500" in out.error
    assert kube.deleted == []


def test_this_ticks_eviction_stays_authoritative_beside_an_owed_name(monkeypatch) -> None:
    # member-2 was evicted this tick and is still listed (its DELETE is
    # milliseconds old); member-4, owed from an earlier tick, is back with
    # redis-3 on it. The Node read the owed name costs decides member-4 only.
    claims = (*_WALK_CLAIMS, _redis_claim(3, "pv-r3", selected=MEMBER_4))
    kube = _Kube(
        _walk(
            nodes=(*LIVE, DEAD, MEMBER_4),
            pending=(),
            claims=claims,
            pvs={**_WALK_PVS, "pv-r3": MEMBER_4},
        )
    )
    monkeypatch.setattr(k8s_api, "_request", kube)

    out = k8s_api.reclaim_stranded_redis_storage({DEAD}, owed_nodes=[MEMBER_4])

    assert tuple(out) == ([R2], None)
    assert kube.deleted == FREED
