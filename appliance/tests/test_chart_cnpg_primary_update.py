"""#2831: a replicated CNPG Cluster updates its primary by switchover.

On a formed three-node appliance, a spec change that rolls the Postgres
instances (a resources or parameter change, on an upgrade, a resize or a
promote) reaches the primary last. Under CloudNativePG's default
``primaryUpdateMethod: restart`` the operator deletes the primary's pod while
it still serves, and the instance manager's smart shutdown turns every new
connection away for the whole ``smartShutdownTimeout`` (180 s), because the
services' pooled sessions never end: measured from a client on a nested
three-node rig, 204 s in which nothing new reached the database. ``switchover``
promotes an updated replica first, and the same change costs seconds.

The guard is ``.github/scripts/chart-cnpg-recovery.py`` in the Charts job
(helm renders, no pytest), so its new rule is pinned here with negative
controls, the way ``test_chart_pod_posture.py`` pins its gate: a guard that
fails open ships the defect green.

``k8s/ha/postgres-cluster.yaml``, the plain-Kubernetes Cluster with its own
CloudNativePG 1.24 pin, is no chart render, so that guard never reads it: the
last test here holds it to the same method.

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_chart_cnpg_primary_update.py -v
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent.parent
SCRIPT = ROOT / ".github" / "scripts" / "chart-cnpg-recovery.py"
UMBRELLA = ROOT / "charts" / "spatiumddi"


def _cluster(instances: int, method: str | None) -> str:
    line = f"\n  primaryUpdateMethod: {method}" if method is not None else ""
    # The smart-shutdown bound (#2878) is the same script's other rule; these
    # Clusters meet it, so each test here reads the #2831 rule alone.
    return textwrap.dedent(
        f"""\
        apiVersion: postgresql.cnpg.io/v1
        kind: Cluster
        metadata:
          name: x-spatiumddi-postgresql
        spec:
          instances: {instances}{{line}}
          smartShutdownTimeout: 15
          storage:
            size: 8Gi
          postgresql:
            parameters:
              max_slot_wal_keep_size: 3GB
              wal_keep_size: 2GB
        """
    ).replace("{line}", line)


def _run(manifest: str, tmp_path: Path) -> subprocess.CompletedProcess:
    path = tmp_path / "render.yaml"
    path.write_text(manifest, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--require-cluster", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_a_replicated_cluster_that_switches_over_passes(tmp_path: Path) -> None:
    res = _run(_cluster(3, "switchover"), tmp_path)
    assert res.returncode == 0, res.stderr


def test_a_replicated_cluster_left_on_cnpgs_default_fails(tmp_path: Path) -> None:
    res = _run(_cluster(3, None), tmp_path)
    assert res.returncode == 1
    assert "#2831" in res.stderr and "unset" in res.stderr


def test_a_replicated_cluster_restarting_its_primary_fails(tmp_path: Path) -> None:
    for count in (2, 3, 5):
        res = _run(_cluster(count, "restart"), tmp_path)
        assert res.returncode == 1, count
        assert "#2831" in res.stderr and f"{count} instances" in res.stderr


def test_one_instance_is_not_held_to_a_switchover(tmp_path: Path) -> None:
    # No replica to promote: CNPG restarts a single instance in place under
    # either method, and the chart leaves the field out there.
    for method in (None, "restart"):
        res = _run(_cluster(1, method), tmp_path)
        assert res.returncode == 0, (method, res.stderr)


def test_the_wal_guard_still_runs_beside_it(tmp_path: Path) -> None:
    # The #2831 check comes first, so an early return in the #2317 one cannot
    # hide it, and the #2317 one still fails a render on its own.
    bad = _cluster(3, "restart").replace("max_slot_wal_keep_size: 3GB", "max_slot_wal_keep_size: -1")
    res = _run(bad, tmp_path)
    assert res.returncode == 1
    assert "#2831" in res.stderr and "#2317" in res.stderr


def test_the_chart_defaults_to_switchover_for_replicated_clusters() -> None:
    values = yaml.safe_load((UMBRELLA / "values.yaml").read_text(encoding="utf-8"))
    assert values["postgresql"]["cnpg"]["primaryUpdateMethod"] == "switchover"
    template = (UMBRELLA / "templates" / "cnpg-cluster.yaml").read_text(encoding="utf-8")
    assert "if gt (int .Values.postgresql.cnpg.instances) 1" in template
    assert "primaryUpdateMethod: {{ .Values.postgresql.cnpg.primaryUpdateMethod" in template


def test_the_plain_kubernetes_ha_cluster_switches_over_too() -> None:
    # The plain-Kubernetes HA Cluster (k8s/README.md) has three instances
    # too, so a rolling update must hand the primary to an updated replica
    # rather than restart it under its clients.
    path = ROOT / "k8s" / "ha" / "postgres-cluster.yaml"
    docs = [doc for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")) if doc]
    clusters = [doc for doc in docs if doc.get("kind") == "Cluster"]
    assert len(clusters) == 1, [doc.get("kind") for doc in docs]
    spec = clusters[0]["spec"]
    assert int(spec["instances"]) > 1
    assert spec.get("primaryUpdateMethod") == "switchover", spec.get("primaryUpdateMethod")
