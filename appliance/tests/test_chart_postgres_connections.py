"""#2955: the chart's Postgres holds the connections its pools can open.

``.github/scripts/chart-postgres-connections.py`` runs in the Charts job (helm
renders, no pytest), so its rules are pinned here with negative controls: a
guard that fails open ships the defect green. Two rules: the api / worker /
beat pools fit ``max_connections``, and (``--check-memory``) the Postgres memory
limit holds that many busy backends, the appliance's #2156 rule. The memory
rule shares its constants with the supervisor (``k8s_api``), held below.

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_chart_postgres_connections.py -v
"""

from __future__ import annotations

import re
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
SCRIPT = ROOT / ".github" / "scripts" / "chart-postgres-connections.py"
K8S_API = ROOT / "agent" / "supervisor" / "spatium_supervisor" / "k8s_api.py"
HELPERS = ROOT / "charts" / "spatiumddi" / "templates" / "_helpers.tpl"


def _render(max_connections: int, memory: str, max_replicas: int = 10) -> str:
    return textwrap.dedent(f"""\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: x-api
          labels: {{app.kubernetes.io/component: api}}
        spec:
          replicas: 2
          template:
            spec:
              containers: [{{name: api}}]
        ---
        apiVersion: autoscaling/v2
        kind: HorizontalPodAutoscaler
        metadata: {{name: x-api}}
        spec:
          scaleTargetRef: {{kind: Deployment, name: x-api}}
          maxReplicas: {max_replicas}
        ---
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: x-worker
          labels: {{app.kubernetes.io/component: worker}}
        spec:
          replicas: 2
          template:
            spec:
              containers: [{{name: worker, args: [--concurrency=4]}}]
        ---
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: x-beat
          labels: {{app.kubernetes.io/component: beat}}
        spec:
          template:
            spec:
              containers: [{{name: beat}}]
        ---
        apiVersion: postgresql.cnpg.io/v1
        kind: Cluster
        metadata: {{name: x-postgresql}}
        spec:
          instances: 3
          postgresql:
            parameters:
              max_connections: "{max_connections}"
              shared_buffers: 256MB
          resources:
            limits: {{memory: {memory}}}
        """)


def _run(manifest: str, tmp_path: Path, *flags: str) -> subprocess.CompletedProcess:
    path = tmp_path / "render.yaml"
    path.write_text(manifest, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--require", *flags, str(path)],
        capture_output=True,
        text=True,
        check=False,
    )


# 10 x (30 + 3) + 2 x (4 x 3 + 1) + 3 beat + 3 superuser-reserved.
_POOLS = 330 + 26 + 3 + 3
# 256 + 256 + 371 x (14 + 1).
_NEED_MIB = 256 + 256 + 371 * 15


def test_the_chart_defaults_pass(tmp_path: Path) -> None:
    res = _run(_render(371, f"{_NEED_MIB}Mi"), tmp_path, "--check-memory")
    assert res.returncode == 0, res.stderr


def test_max_connections_below_the_pools_fails(tmp_path: Path) -> None:
    res = _run(_render(_POOLS - 1, "64Gi"), tmp_path)
    assert res.returncode == 1
    assert f"can open {_POOLS} connections, but max_connections is {_POOLS - 1}" in res.stderr


def test_the_hpa_maximum_is_what_counts(tmp_path: Path) -> None:
    res = _run(_render(371, "64Gi", max_replicas=11), tmp_path)
    assert res.returncode == 1
    assert "api 11 pod(s)" in res.stderr


def test_a_memory_limit_short_of_the_connections_fails(tmp_path: Path) -> None:
    res = _run(_render(371, f"{_NEED_MIB - 1}Mi"), tmp_path, "--check-memory")
    assert res.returncode == 1
    assert f"need {_NEED_MIB}Mi" in res.stderr
    # ...and the chart's old 1Gi is far short of it.
    res = _run(_render(371, "1Gi"), tmp_path, "--check-memory")
    assert "the Postgres memory limit is 1024Mi" in res.stderr


def test_memory_is_checked_only_when_asked(tmp_path: Path) -> None:
    assert _run(_render(371, "1Gi"), tmp_path).returncode == 0


def test_a_render_without_a_database_is_skipped_but_require_refuses_it(tmp_path: Path) -> None:
    manifest = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n"
    res = _run(manifest, tmp_path)
    assert res.returncode == 1
    assert "no render carried" in res.stderr


def _const(text: str, name: str) -> int:
    m = re.search(rf"^{name}\s*=\s*(\d+)", text, re.MULTILINE)
    assert m, name
    return int(m.group(1))


def test_the_rule_is_the_appliances() -> None:
    """The guard, the chart helper and the supervisor share one rule: a drift
    in one of them would size the chart and the appliance differently."""
    guard = SCRIPT.read_text(encoding="utf-8")
    sup = K8S_API.read_text(encoding="utf-8")
    helpers = HELPERS.read_text(encoding="utf-8")
    assert _const(guard, "BACKEND_MIB") == _const(sup, "_PG_BACKEND_BASE_MIB")
    assert _const(guard, "FIXED_MIB") == _const(sup, "_PG_FIXED_MIB")
    assert _const(guard, "HOOKS") == _const(sup, "_HOOK_DB_CONN_PER_PROCESS")
    assert _const(guard, "WORKER_SLACK") == _const(sup, "_WORKER_DB_CONN_SLACK")
    backend = _const(sup, "_PG_BACKEND_BASE_MIB")
    fixed = _const(sup, "_PG_FIXED_MIB")
    reserve = _const(sup, "_PG_CONN_RESERVE")
    assert f"add $sb {fixed} (mul $conns (add {backend} (div (add $sb 511) 512)))" in helpers
    assert f"add $api $worker 3 $senders {reserve}" in helpers
