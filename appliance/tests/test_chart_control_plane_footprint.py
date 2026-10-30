"""The #3110 sizing gate actually fails when it should.

``.github/scripts/chart-control-plane-footprint.py`` refuses a render whose api
autoscaler aims below what one api pod was measured to use, or whose api
memory request or limit is below that use (with the sizing guide's headroom
on the limit). Before #3110 the chart aimed memory at 80 % of a
256Mi request, about 205 MiB, while one idle api process holds about 305 MiB,
so every default install with a metrics-server ran 10 api replicas at rest.
The Charts job runs the script over the default render
(``.github/scripts/charts-render-check.sh``); its rules are pinned here
because ``appliance/tests`` is the hermetic pytest job with PyYAML that runs
on every PR.

Every passing case is paired with a case that must FAIL. The fixtures are the
api and worker as the umbrella chart renders them at its defaults, before
#3110 and after it.

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_chart_control_plane_footprint.py -v
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

SCRIPT = (
    Path(__file__).parent.parent.parent / ".github" / "scripts" / "chart-control-plane-footprint.py"
)

NOW = {"cpu": "200m", "memory": "512Mi"}, {"cpu": "1000m", "memory": "1Gi"}
BEFORE = {"cpu": "100m", "memory": "256Mi"}, {"cpu": "1000m", "memory": "512Mi"}


def _deployment(component: str, requests: dict | None, limits: dict | None) -> str:
    res = ""
    for key, vals in (("requests", requests), ("limits", limits)):
        if vals:
            body = "".join(f"\n                  {k}: {v}" for k, v in vals.items())
            res += f"\n                {key}:{body}"
    resources = f"\n              resources:{res}" if res else ""
    return f"""
    ---
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: rel-spatiumddi-{component}
      labels:
        app.kubernetes.io/component: {component}
    spec:
      template:
        spec:
          containers:
            - name: {component}
              image: ghcr.io/spatiumnorth/spatiumddi-api:test{resources}
    """


def _hpa(
    cpu: int | None = 70, memory: int | None = None, target: str = "rel-spatiumddi-api"
) -> str:
    metrics = ""
    for name, pct in (("cpu", cpu), ("memory", memory)):
        if pct is not None:
            metrics += f"""
        - type: Resource
          resource:
            name: {name}
            target:
              type: Utilization
              averageUtilization: {pct}"""
    return f"""
    ---
    apiVersion: autoscaling/v2
    kind: HorizontalPodAutoscaler
    metadata:
      name: rel-spatiumddi-api
    spec:
      scaleTargetRef:
        apiVersion: apps/v1
        kind: Deployment
        name: {target}
      minReplicas: 2
      maxReplicas: 10
      metrics:{metrics}
    """


def _api(sizing=NOW) -> str:
    return _deployment("api", *sizing)


def _worker(limit: str | None = "2Gi") -> str:
    return _deployment(
        "worker", {"cpu": "200m", "memory": "256Mi"}, {"memory": limit} if limit else None
    )


def _run(manifest: str, tmp_path: Path, *flags: str) -> subprocess.CompletedProcess:
    f = tmp_path / "render.yaml"
    f.write_text(textwrap.dedent(manifest))
    return subprocess.run(
        [sys.executable, str(SCRIPT), *flags, str(f)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_script_exists() -> None:
    assert SCRIPT.is_file(), f"{SCRIPT} missing: the Charts job calls it by path"


def test_the_charts_defaults_pass(tmp_path: Path) -> None:
    r = _run(_api() + _hpa() + _worker(), tmp_path, "--require", "--expect-metrics", "cpu")
    assert r.returncode == 0, r.stderr
    assert "the default sizing holds its measured use (1 render(s))" in r.stdout


def test_the_charts_pre_3110_defaults_fail_on_every_rule(tmp_path: Path) -> None:
    """The render that shipped: memory at 80 % of 256Mi, CPU at 70 % of 100m
    and a 512Mi api limit."""
    r = _run(_api(BEFORE) + _hpa(memory=80) + _worker("1Gi"), tmp_path, "--expect-metrics", "cpu")
    assert r.returncode == 1
    for line in (
        "the api's memory request is 256Mi, below the 373 MiB",
        "the api's memory limit is 512Mi, below 704 MiB",
        "aims CPU at 70 % of 100m = 70m, below the 100m",
        "aims memory at 80 % of 256Mi = 205 MiB, below the 373 MiB",
        "scales on ['cpu', 'memory'], expected ['cpu']",
    ):
        assert line in r.stderr, line
    assert r.stderr.count("(#3110") == 5


def test_an_opt_in_memory_target_passes_only_above_the_working_set(tmp_path: Path) -> None:
    r = _run(_api() + _hpa(memory=80) + _worker(), tmp_path, "--expect-metrics", "cpu,memory")
    assert r.returncode == 0, r.stderr
    r = _run(_api() + _hpa(memory=70) + _worker(), tmp_path)
    assert r.returncode == 1
    assert "aims memory at 70 % of 512Mi = 358 MiB, below the 373 MiB" in r.stderr


def test_a_target_with_no_request_to_share_is_refused(tmp_path: Path) -> None:
    """A Utilization target needs a request; without one the autoscaler
    cannot compute it, and the guard must not read that as a pass."""
    api = _deployment("api", None, {"cpu": "1000m", "memory": "1Gi"})
    r = _run(api + _hpa(cpu=70, memory=80) + _worker(), tmp_path)
    assert r.returncode == 1
    assert "aims CPU at 70 % of no request" in r.stderr
    assert "aims memory at 80 % of no request" in r.stderr
    assert "the api's memory request is unset" in r.stderr


def test_an_autoscaler_on_another_workload_is_not_the_apis(tmp_path: Path) -> None:
    r = _run(_api() + _hpa(memory=50, target="rel-spatiumddi-other") + _worker(), tmp_path)
    assert r.returncode == 0, r.stderr


def test_quantities_compare_across_units(tmp_path: Path) -> None:
    sizing = {"cpu": "0.2", "memory": "0.5Gi"}, {"cpu": "1", "memory": "1073741824"}
    r = _run(_api(sizing) + _hpa() + _worker("2048Mi"), tmp_path)
    assert r.returncode == 0, r.stderr


def test_require_fails_on_a_render_with_no_api(tmp_path: Path) -> None:
    r = _run(_worker(), tmp_path)
    assert r.returncode == 0, r.stderr
    r = _run(_worker(), tmp_path, "--require")
    assert r.returncode == 1
    assert "no render carried the api Deployment" in r.stderr


def test_expect_metrics_fails_when_the_autoscaler_is_gone(tmp_path: Path) -> None:
    r = _run(_api() + _worker(), tmp_path, "--expect-metrics", "cpu")
    assert r.returncode == 1
    assert "the api autoscaler scales on nothing, expected ['cpu']" in r.stderr
