"""Tests for the Cluster health snapshot service + endpoint (#402).

The gather reads nodes + pods cluster-wide and the kubelet Summary API via
the api pod's ServiceAccount. Here we monkeypatch the three ``k8s`` helpers
with realistic kubeapi-shaped fixtures and assert the rollup (KPIs, per-node
live usage, workload health, top pods) + the degraded paths (no Summary-API
grant → no live usage; nodes 403 → available=false; SA missing → 503).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.services.appliance import cluster_health

_HEALTH_URL = "/api/v1/appliance/cluster/health"


# ── kube-shaped fixtures ────────────────────────────────────────────────────


def _node(name: str = "ddi1", *, ready: bool = True, cpu: str = "4", mem: str = "8Gi") -> dict:
    return {
        "metadata": {
            "name": name,
            "creationTimestamp": "2026-06-12T19:00:00Z",
            "labels": {
                "node-role.kubernetes.io/control-plane": "true",
                "node-role.kubernetes.io/etcd": "true",
            },
        },
        "spec": {"unschedulable": False},
        "status": {
            "conditions": [
                {"type": "Ready", "status": "True" if ready else "False"},
                {"type": "MemoryPressure", "status": "False"},
                {"type": "DiskPressure", "status": "False"},
            ],
            "addresses": [{"type": "InternalIP", "address": "192.168.0.199"}],
            "nodeInfo": {
                "kubeletVersion": "v1.36.4+k3s1",
                "osImage": "Debian GNU/Linux 13 (trixie)",
                "kernelVersion": "6.12.90",
                "containerRuntimeVersion": "containerd://2.2.5-k3s2",
                "architecture": "amd64",
            },
            "capacity": {"cpu": cpu, "memory": mem, "pods": "110"},
        },
    }


def _pod(
    name: str,
    *,
    ns: str = "spatium",
    comp: str = "api",
    node: str = "ddi1",
    phase: str = "Running",
    ready: bool = True,
    restarts: int = 0,
    owner: str = "ReplicaSet",
    waiting: str | None = None,
) -> dict:
    state: dict = (
        {"running": {}} if ready else {"waiting": {"reason": waiting or "ContainerCreating"}}
    )
    return {
        "metadata": {
            "name": name,
            "namespace": ns,
            "creationTimestamp": "2026-06-12T19:00:00Z",
            "labels": {"app.kubernetes.io/component": comp},
            "ownerReferences": [{"kind": owner}],
        },
        "spec": {"nodeName": node},
        "status": {
            "phase": phase,
            "podIP": "10.42.0.5",
            "containerStatuses": [
                {"ready": ready, "restartCount": restarts, "state": state},
            ],
        },
    }


def _summary(node: str = "ddi1") -> dict:
    return {
        "node": {
            "nodeName": node,
            "cpu": {"usageNanoCores": 800_000_000},  # 0.8 cores
            "memory": {"workingSetBytes": 2 * 1024**3, "availableBytes": 6 * 1024**3},
            "fs": {"usedBytes": 5 * 1024**3, "capacityBytes": 20 * 1024**3},
        },
        "pods": [
            {
                "podRef": {
                    "namespace": "spatium",
                    "name": "spatium-control-spatiumddi-api-x",
                },
                "cpu": {"usageNanoCores": 500_000_000},
                "memory": {"workingSetBytes": 400 * 1024**2},
            },
            {
                "podRef": {
                    "namespace": "spatium",
                    "name": "spatium-control-spatiumddi-worker-y",
                },
                "cpu": {"usageNanoCores": 120_000_000},
                "memory": {"workingSetBytes": 250 * 1024**2},
            },
        ],
    }


def _patch_kube(monkeypatch, *, node_status=200, summary_status=200, nodes=1) -> None:
    pods = [
        _pod("spatium-control-spatiumddi-api-x", comp="api"),
        _pod("spatium-control-spatiumddi-worker-y", comp="worker"),
        _pod(
            "helm-install-spatium-bootstrap-z",
            ns="kube-system",
            comp="helm-install",
            phase="Succeeded",
            ready=False,
            owner="Job",
        ),
    ]
    monkeypatch.setattr(
        "app.services.appliance.k8s.list_nodes",
        lambda label_selector=None: (
            node_status,
            [_node(f"ddi{i + 1}") for i in range(nodes)] if node_status == 200 else [],
        ),
    )
    monkeypatch.setattr(
        "app.services.appliance.k8s.list_all_pods",
        lambda: (200, pods),
    )
    monkeypatch.setattr(
        "app.services.appliance.k8s.get_node_stats_summary",
        # #983 Phase 2 item 6 — the caller now hands over the node IP so the
        # direct kubelet transport can be tried before the apiserver proxy.
        lambda name, node_ip=None: (
            summary_status,
            _summary(name) if summary_status == 200 else None,
            "direct",
        ),
    )


# ── service-level ───────────────────────────────────────────────────────────


def test_get_cluster_health_rollup(monkeypatch) -> None:
    _patch_kube(monkeypatch)
    snap = cluster_health.get_cluster_health()

    assert snap["available"] is True
    assert snap["nodes_total"] == 1
    assert snap["nodes_ready"] == 1
    assert snap["control_plane_nodes"] == 1
    assert snap["is_ha"] is False
    assert snap["metrics_available"] is True
    assert snap["kubelet_version"] == "v1.36.4+k3s1"

    # Live per-node usage flowed through from the kubelet summary.
    node = snap["nodes"][0]
    assert node["cpu_usage_cores"] == pytest.approx(0.8)
    assert node["cpu_capacity_cores"] == pytest.approx(4.0)
    assert node["memory_working_set_bytes"] == 2 * 1024**3
    assert node["fs_capacity_bytes"] == 20 * 1024**3
    assert "control-plane" in node["roles"]

    # Cluster aggregate.
    assert snap["cpu_usage_cores"] == pytest.approx(0.8)
    assert snap["cpu_capacity_cores"] == pytest.approx(4.0)

    # Workload rollup: api + worker present + healthy; the Completed Job pod
    # is excluded (not counted as "down").
    comps = {w["component"]: w for w in snap["workloads"]}
    assert comps["api"]["status"] == "healthy"
    assert comps["worker"]["status"] == "healthy"
    assert "helm-install" not in comps

    # Top pods by CPU — api (0.5) ahead of worker (0.12).
    assert snap["top_pods_cpu"][0]["component"] == "api"
    assert snap["top_pods_cpu"][0]["cpu_usage_cores"] == pytest.approx(0.5)


def _rollup_with(monkeypatch, pods: list[dict]) -> dict[str, dict]:
    _patch_kube(monkeypatch)
    monkeypatch.setattr("app.services.appliance.k8s.list_all_pods", lambda: (200, pods))
    return {w["component"]: w for w in cluster_health.get_cluster_health()["workloads"]}


def test_a_running_join_job_is_not_a_ready_database_instance(monkeypatch) -> None:
    """#1213: while CNPG bootstraps a replica, its running ``-join`` Job pod
    read as a third ready database pod, so the rollup said 3/3 healthy while
    CNPG reported two instances. Job pods are not serving instances."""
    comps = _rollup_with(
        monkeypatch,
        [
            _pod("postgresql-1", comp="database", owner="Cluster"),
            _pod("postgresql-2", comp="database", owner="Cluster"),
            _pod("postgresql-3-join-abcde", comp="database", owner="Job"),
        ],
    )
    db = comps["database"]
    assert (db["ready"], db["total"]) == (2, 2)
    assert db["status"] == "degraded"
    # The row says why it is degraded at 2/2.
    assert db["jobs_running"] == 1


def test_the_database_reads_healthy_once_the_join_job_is_done(monkeypatch) -> None:
    comps = _rollup_with(
        monkeypatch,
        [
            _pod("postgresql-1", comp="database", owner="Cluster"),
            _pod("postgresql-2", comp="database", owner="Cluster"),
            _pod("postgresql-3", comp="database", owner="Cluster"),
            _pod(
                "postgresql-3-join-abcde",
                comp="database",
                owner="Job",
                phase="Succeeded",
                ready=False,
            ),
        ],
    )
    db = comps["database"]
    assert (db["ready"], db["total"], db["status"]) == (3, 3, "healthy")
    assert db["jobs_running"] == 0


def test_a_component_made_only_of_jobs_is_not_a_workload(monkeypatch) -> None:
    comps = _rollup_with(
        monkeypatch,
        [
            _pod("spatium-control-spatiumddi-api-x", comp="api"),
            _pod("helm-install-spatium-control-q", comp="helm-install", owner="Job"),
        ],
    )
    assert "helm-install" not in comps
    assert comps["api"]["status"] == "healthy"


def test_cluster_health_degrades_without_kubelet_proxy(monkeypatch) -> None:
    # Neither Summary-API grant → 403 → no live usage, but
    # the node inventory + workload rollup still render.
    _patch_kube(monkeypatch, summary_status=403)
    snap = cluster_health.get_cluster_health()
    assert snap["available"] is True
    assert snap["metrics_available"] is False
    assert snap["cpu_usage_cores"] is None
    assert snap["nodes"][0]["cpu_usage_cores"] is None
    # Capacity (from the Node object) is still known even without live usage.
    assert snap["nodes"][0]["cpu_capacity_cores"] == pytest.approx(4.0)
    assert snap["nodes_total"] == 1


def test_cluster_health_unavailable_when_nodes_forbidden(monkeypatch) -> None:
    _patch_kube(monkeypatch, node_status=403)
    snap = cluster_health.get_cluster_health()
    assert snap["available"] is False
    assert "RBAC" in (snap["detail"] or "") or "ServiceAccount" in (snap["detail"] or "")


def test_quantity_parsers() -> None:
    assert cluster_health._cpu_cores("4") == pytest.approx(4.0)
    assert cluster_health._cpu_cores("500m") == pytest.approx(0.5)
    assert cluster_health._cpu_cores("250000000n") == pytest.approx(0.25)
    assert cluster_health._cpu_cores(None) is None
    assert cluster_health._mem_bytes("8Gi") == 8 * 1024**3
    assert cluster_health._mem_bytes("8113280Ki") == 8113280 * 1024
    assert cluster_health._mem_bytes("2000M") == 2_000_000_000
    assert cluster_health._mem_bytes(None) is None


# ── endpoint-level ──────────────────────────────────────────────────────────


async def _superadmin(db: AsyncSession) -> User:
    u = User(
        username=f"sa-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@x.com",
        display_name="SA",
        hashed_password=hash_password("OldPass123!"),
        auth_source="local",
        is_active=True,
        is_superadmin=True,
        force_password_change=False,
        password_changed_at=datetime.now(UTC),
    )
    db.add(u)
    await db.flush()
    await db.commit()
    return u


def _bearer(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def test_health_endpoint_returns_snapshot(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
) -> None:
    _patch_kube(monkeypatch)
    admin = await _superadmin(db_session)
    r = await client.get(_HEALTH_URL, headers=_bearer(admin))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["available"] is True
    assert body["nodes_total"] == 1
    assert body["metrics_available"] is True
    assert body["nodes"][0]["cpu_usage_cores"] == pytest.approx(0.8)


async def test_health_endpoint_503_when_sa_missing(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
) -> None:
    # No monkeypatch of the SA volume → list_nodes raises KubeapiUnavailable.
    def _boom(label_selector=None):
        from app.services.appliance.k8s import KubeapiUnavailableError

        raise KubeapiUnavailableError("ServiceAccount not mounted; kubeapi unreachable")

    monkeypatch.setattr("app.services.appliance.k8s.list_nodes", _boom)
    admin = await _superadmin(db_session)
    r = await client.get(_HEALTH_URL, headers=_bearer(admin))
    assert r.status_code == 503, r.text


async def test_health_endpoint_requires_auth(client: AsyncClient) -> None:
    r = await client.get(_HEALTH_URL)
    assert r.status_code == 401, r.text


async def test_health_endpoint_merges_host_partitions(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
) -> None:
    """#402 — host partitions the supervisor reports inside its cluster_health
    JSONB are merged onto the matching node (hostname == kube node name)."""
    import hashlib
    import os

    from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance

    _patch_kube(monkeypatch)  # kube node is "ddi1"
    der = os.urandom(32)
    db_session.add(
        Appliance(
            id=uuid.uuid4(),
            hostname="ddi1",
            public_key_der=der,
            public_key_fingerprint=hashlib.sha256(der).hexdigest(),
            state=APPLIANCE_STATE_APPROVED,
            deployment_kind="appliance",
            appliance_variant="control-plane",
            session_token_hash="deadbeef",
            cluster_health={
                "kubeapi_ready": True,
                "host_disk_partitions": [
                    {
                        "mount": "/",
                        "label": "OS (root slot)",
                        "total_bytes": 8_000_000_000,
                        "used_bytes": 3_000_000_000,
                    },
                    {
                        "mount": "/var",
                        "label": "Data",
                        "total_bytes": 15_000_000_000,
                        "used_bytes": 9_800_000_000,
                    },
                    {
                        "mount": "/boot/efi",
                        "label": "ESP",
                        "total_bytes": 536_000_000,
                        "used_bytes": 12_000_000,
                    },
                ],
            },
        )
    )
    admin = await _superadmin(db_session)
    await db_session.commit()

    r = await client.get(_HEALTH_URL, headers=_bearer(admin))
    assert r.status_code == 200, r.text
    node = r.json()["nodes"][0]
    assert node["name"] == "ddi1"
    assert {p["mount"] for p in node["host_disk_partitions"]} == {
        "/",
        "/var",
        "/boot/efi",
    }
    root = next(p for p in node["host_disk_partitions"] if p["mount"] == "/")
    assert root["label"] == "OS (root slot)"
    assert root["total_bytes"] == 8_000_000_000


@pytest.mark.asyncio
async def test_host_storage_merged_with_derived_findings(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#999 Part A — md / multipath state rides the same cluster_health
    JSONB as the #402 partitions, and the node carries the CLASSIFIED
    verdict, not just the raw reading.

    The verdict is derived server-side on purpose: the browser would
    otherwise need its own copy of "severity comes from redundancy
    remaining, not from the state string", and a drifted copy shows a
    green chip over a red alert.
    """
    import hashlib
    import os

    from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance

    _patch_kube(monkeypatch)  # kube node is "ddi1"
    der = os.urandom(32)
    db_session.add(
        Appliance(
            id=uuid.uuid4(),
            hostname="ddi1",
            public_key_der=der,
            public_key_fingerprint=hashlib.sha256(der).hexdigest(),
            state=APPLIANCE_STATE_APPROVED,
            deployment_kind="appliance",
            appliance_variant="control-plane",
            session_token_hash="deadbeef",
            cluster_health={
                "kubeapi_ready": True,
                "storage": {
                    "md_supported": True,
                    "md_arrays": [
                        {
                            "name": "md0",
                            "level": "raid1",
                            # The kernel says clean; the collector says
                            # degraded, because one member is gone.
                            "state": "degraded",
                            "array_state": "clean",
                            "members_expected": 2,
                            "members_in_sync": 1,
                            "members_faulty": 1,
                            "spares": 0,
                            "redundancy_remaining": 0,
                            "min_working_members": 1,
                            "size_bytes": 1000203804160,
                            "members": [
                                {"device": "sda1", "state": "in_sync", "slot": 0},
                                {"device": "sdb1", "state": "faulty", "slot": None},
                            ],
                        }
                    ],
                    "multipath_maps": [],
                },
            },
        )
    )
    admin = await _superadmin(db_session)
    await db_session.commit()

    r = await client.get(_HEALTH_URL, headers=_bearer(admin))
    assert r.status_code == 200, r.text
    node = r.json()["nodes"][0]
    storage = node["host_storage"]
    assert storage["md_supported"] is True
    assert storage["md_arrays"][0]["array_state"] == "clean"
    assert storage["md_arrays"][0]["state"] == "degraded"
    assert storage["worst_severity"] == "critical"
    assert len(storage["findings"]) == 1
    assert "no redundancy remains" in storage["findings"][0]["detail"]


@pytest.mark.asyncio
async def test_host_storage_null_when_supervisor_never_reported(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A supervisor too old to collect storage leaves ``host_storage``
    null — UNKNOWN, which the node card renders as nothing at all rather
    than as an empty (and therefore reassuring) snapshot."""
    import hashlib
    import os

    from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance

    _patch_kube(monkeypatch)
    der = os.urandom(32)
    db_session.add(
        Appliance(
            id=uuid.uuid4(),
            hostname="ddi1",
            public_key_der=der,
            public_key_fingerprint=hashlib.sha256(der).hexdigest(),
            state=APPLIANCE_STATE_APPROVED,
            deployment_kind="appliance",
            appliance_variant="control-plane",
            session_token_hash="deadbeef",
            cluster_health={"kubeapi_ready": True},
        )
    )
    admin = await _superadmin(db_session)
    await db_session.commit()

    r = await client.get(_HEALTH_URL, headers=_bearer(admin))
    assert r.status_code == 200, r.text
    assert r.json()["nodes"][0]["host_storage"] is None


# ── PSI (#983 Phase 2 item 7) ───────────────────────────────────────────────
#
# The whole point of these is the null/zero distinction. A kubelet below 1.36
# reports no PSI at all; a 1.36 kubelet on an idle node reports 0.0. Those are
# opposite facts — "we don't know" versus "nothing is stalling" — and every
# surface downstream (the node card, the alert matcher, the copilot tool)
# branches on it, so flattening one into the other here would be invisible and
# wrong everywhere at once.


def _psi(some: float, full: float = 0.0) -> dict:
    return {
        "some": {"total": 1, "avg10": some, "avg60": some, "avg300": some},
        "full": {"total": 1, "avg10": full, "avg60": full, "avg300": full},
    }


def test_psi_absent_parses_to_none_not_zero() -> None:
    """The pre-1.36 shape — no ``psi`` key anywhere."""
    stats = cluster_health._parse_node_stats(_summary())
    assert stats["psi_cpu"] is None
    assert stats["psi_memory"] is None
    assert stats["psi_io"] is None


def test_psi_zero_is_reported_as_zero() -> None:
    """A 1.36 kubelet on an idle node. Must NOT come back as None."""
    summary = _summary()
    summary["node"]["cpu"]["psi"] = _psi(0.0)
    stats = cluster_health._parse_node_stats(summary)
    assert stats["psi_cpu"] is not None
    assert stats["psi_cpu"]["some"]["avg300"] == 0.0


def test_psi_parsed_for_cpu_memory_and_io() -> None:
    summary = _summary()
    summary["node"]["cpu"]["psi"] = _psi(12.5)
    summary["node"]["memory"]["psi"] = _psi(3.25, full=1.5)
    summary["node"]["io"] = {"psi": _psi(0.75)}
    stats = cluster_health._parse_node_stats(summary)
    assert stats["psi_cpu"]["some"]["avg10"] == 12.5
    assert stats["psi_memory"]["full"]["avg300"] == 1.5
    assert stats["psi_io"]["some"]["avg60"] == 0.75


def test_psi_partial_window_set_keeps_what_it_has() -> None:
    """Tolerate a kubelet that reports fewer windows than we expect rather
    than discarding the reading — this is an unversioned wire shape."""
    summary = _summary()
    summary["node"]["cpu"]["psi"] = {"some": {"avg10": 4.0}}
    stats = cluster_health._parse_node_stats(summary)
    assert stats["psi_cpu"]["some"] == {"avg10": 4.0}
    assert stats["psi_cpu"].get("full") is None


@pytest.mark.parametrize("junk", [None, [], "psi", {}, {"some": "nope"}, {"some": {}}])
def test_psi_junk_is_none(junk) -> None:
    """An unusable block must not become a half-populated reading."""
    assert cluster_health._parse_psi(junk) is None


def test_psi_reaches_the_node_row(monkeypatch) -> None:
    def _with_psi(node: str = "ddi1") -> dict:
        s = _summary(node)
        s["node"]["cpu"]["psi"] = _psi(41.0)
        return s

    _patch_kube(monkeypatch)
    monkeypatch.setattr(
        "app.services.appliance.k8s.get_node_stats_summary",
        lambda name, node_ip=None: (200, _with_psi(name), "direct"),
    )
    snap = cluster_health.get_cluster_health()
    assert snap["nodes"][0]["psi_cpu"]["some"]["avg300"] == 41.0
    assert snap["nodes"][0]["psi_memory"] is None


def test_node_ip_is_handed_to_the_summary_fetch(monkeypatch) -> None:
    """Item 6's plumbing: without the IP the direct kubelet transport can
    never be tried and the broad ``nodes/proxy`` grant can never be retired."""
    seen: list[tuple[str, str | None]] = []

    def _capture(name, node_ip=None):
        seen.append((name, node_ip))
        return 200, _summary(name), "direct"

    _patch_kube(monkeypatch)
    monkeypatch.setattr("app.services.appliance.k8s.get_node_stats_summary", _capture)
    cluster_health.get_cluster_health()
    assert seen and seen[0][1] == "192.168.0.199"


# ── kubelet transport report (#983 Phase 2 item 6) ──────────────────────────


def _patch_transport(monkeypatch, per_node: dict[str, str], reasons=None) -> None:
    _patch_kube(monkeypatch)
    monkeypatch.setattr(
        "app.services.appliance.k8s.get_node_stats_summary",
        lambda name, node_ip=None: (200, _summary(name), per_node.get(name, "direct")),
    )
    monkeypatch.setattr("app.services.appliance.k8s.kubelet_block_reasons", lambda: reasons or {})


def test_transport_all_direct_is_the_go_ahead(monkeypatch) -> None:
    _patch_transport(monkeypatch, {"ddi1": "direct"})
    t = cluster_health.get_cluster_health()["kubelet_transport"]
    assert t["all_direct"] is True
    assert (t["direct_nodes"], t["proxy_nodes"]) == (1, 0)
    assert t["by_node"] == {"ddi1": "direct"}


def test_transport_reports_per_node_not_last_wins(monkeypatch) -> None:
    """One value would report whichever node was processed last — reading
    'direct' while another node was quietly served by the proxy, which is the
    exact wrong answer to 'can I drop the broad grant?'."""
    _patch_kube(monkeypatch, nodes=2)
    per = {"ddi1": "direct", "ddi2": "proxy"}
    monkeypatch.setattr(
        "app.services.appliance.k8s.get_node_stats_summary",
        lambda name, node_ip=None: (200, _summary(name), per[name]),
    )
    monkeypatch.setattr(
        "app.services.appliance.k8s.kubelet_block_reasons",
        lambda: {"192.168.0.199": "kubelet returned HTTP 403 (nodes/stats grant?)"},
    )
    t = cluster_health.get_cluster_health()["kubelet_transport"]
    assert t["all_direct"] is False
    assert (t["direct_nodes"], t["proxy_nodes"]) == (1, 1)
    assert t["by_node"] == per


def test_transport_reasons_are_keyed_by_node_name(monkeypatch) -> None:
    """k8s.py tracks blocks by IP because that is what it connects to; the
    report has to name nodes or an operator cannot act on it."""
    _patch_transport(monkeypatch, {"ddi1": "proxy"}, reasons={"192.168.0.199": "bad CA"})
    t = cluster_health.get_cluster_health()["kubelet_transport"]
    assert t["blocked_reasons"] == {"ddi1": "bad CA"}


def test_transport_all_direct_is_false_when_nothing_was_probed(monkeypatch) -> None:
    """Measuring nothing must never read as 'safe to drop the grant'."""
    assert (
        cluster_health.cluster_unavailable("kubeapi down")["kubelet_transport"]["all_direct"]
        is False
    )


# ── #1083 — the kube snapshot survives a database that is failing over ─────


class _DeadDB:
    """A session whose every query times out — what a checkout looks like
    while CNPG promotes a new primary (asyncpg's connect timeout, raised bare)."""

    async def execute(self, *_args, **_kwargs):
        raise TimeoutError("connect timed out")

    async def rollback(self):
        return None


async def test_health_endpoint_keeps_the_kube_snapshot_when_the_db_fails(monkeypatch) -> None:
    """During a CNPG failover the host-state decoration cannot be read; the
    nodes/pods answer that came from kubeapi must still be served, with every
    node's ``host_storage`` left as "not reported" (None)."""
    from app.api.v1.appliance import cluster as cluster_router

    _patch_kube(monkeypatch)
    out = await cluster_router.cluster_health(db=_DeadDB())  # type: ignore[arg-type]
    assert out.available is True
    assert out.nodes_total == 1 and out.nodes_ready == 1
    assert out.nodes[0].host_storage is None
    assert out.nodes[0].host_disk_partitions == []


async def test_host_state_merge_failure_is_logged_not_raised(monkeypatch) -> None:
    from app.api.v1.appliance import cluster as cluster_router

    events: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        cluster_router.logger,
        "warning",
        lambda event, **kw: events.append((event, kw)),
    )
    snap = {"available": True, "nodes": [{"name": "ddi1", "host_storage": None}]}
    await cluster_router._merge_host_state_best_effort(_DeadDB(), snap)  # type: ignore[arg-type]
    assert snap["nodes"][0]["host_storage"] is None
    assert events and events[0][0] == "cluster_health_host_state_unavailable"
    assert events[0][1]["error_class"] == "TimeoutError"
