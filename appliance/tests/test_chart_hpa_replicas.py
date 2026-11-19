"""The #3111 gate actually fails when it should.

``.github/scripts/chart-hpa-replicas.py`` refuses a render in which a workload
that a HorizontalPodAutoscaler scales also renders ``spec.replicas``. Under
Helm 4's server-side apply helm then owns the field the autoscaler writes
through the ``scale`` subresource, and once the autoscaler has moved the count
every ``helm upgrade`` of the release fails on ``.spec.replicas``. The Charts
job runs the script over every render (``.github/scripts/charts-render-check.sh``);
its rules are pinned here because ``appliance/tests`` is the hermetic pytest
job with PyYAML that runs on every PR.

Every passing case is paired with a case that must FAIL. The fixtures are the
api Deployment and autoscaler as the umbrella chart renders them: the default
render before #3111 (``replicas: 2`` beside the autoscaler), the same render
after it, and the appliance's (autoscaler off, ``replicas`` set by the
supervisor's control-plane size).

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_chart_hpa_replicas.py -v
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

SCRIPT = Path(__file__).parent.parent.parent / ".github" / "scripts" / "chart-hpa-replicas.py"


def _api(replicas: int | None) -> str:
    line = "" if replicas is None else f"\n      replicas: {replicas}"
    return f"""
    ---
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: rel-spatiumddi-api
      labels:
        app.kubernetes.io/component: api
    spec:{line}
      selector:
        matchLabels:
          app.kubernetes.io/component: api
      template:
        spec:
          containers:
            - name: api
              image: ghcr.io/spatiumnorth/spatiumddi-api:test
    """


def _hpa(target: str = "rel-spatiumddi-api", kind: str = "Deployment") -> str:
    return f"""
    ---
    apiVersion: autoscaling/v2
    kind: HorizontalPodAutoscaler
    metadata:
      name: rel-spatiumddi-api
    spec:
      scaleTargetRef:
        apiVersion: apps/v1
        kind: {kind}
        name: {target}
      minReplicas: 2
      maxReplicas: 10
    """


def _run(
    manifest: str, tmp_path: Path, *flags: str, name: str = "render.yaml"
) -> subprocess.CompletedProcess:
    f = tmp_path / name
    f.write_text(textwrap.dedent(manifest))
    return subprocess.run(
        [sys.executable, str(SCRIPT), *flags, str(f)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_script_exists() -> None:
    assert SCRIPT.is_file(), f"{SCRIPT} missing: the Charts job calls it by path"


def test_an_autoscaled_deployment_without_replicas_passes(tmp_path: Path) -> None:
    r = _run(_api(None) + _hpa(), tmp_path, "--require")
    assert r.returncode == 0, r.stderr
    assert "autoscaled workloads render no spec.replicas (1 checked)" in r.stdout


def test_the_charts_pre_3111_default_render_fails(tmp_path: Path) -> None:
    """The render that shipped: ``replicas: 2`` beside the autoscaler."""
    r = _run(_api(2) + _hpa(), tmp_path)
    assert r.returncode == 1
    assert "Deployment 'rel-spatiumddi-api' renders spec.replicas: 2" in r.stderr
    assert "HorizontalPodAutoscaler 'rel-spatiumddi-api' scales it" in r.stderr
    assert "(#3111)" in r.stderr


def test_an_autoscaler_whose_target_is_not_in_the_render_is_refused(tmp_path: Path) -> None:
    """Fail closed: a renamed Deployment, or a target kind the guard does not
    read, must not pass every render unchecked."""
    r = _run(_api(2) + _hpa(target="rel-spatiumddi-api-renamed"), tmp_path)
    assert r.returncode == 1
    assert "scales Deployment 'rel-spatiumddi-api-renamed', which is not in the render" in r.stderr
    r = _run(_api(2) + _hpa(kind="Rollout"), tmp_path)
    assert r.returncode == 1
    assert "scales Rollout 'rel-spatiumddi-api', which is not in the render" in r.stderr


def test_require_fails_on_a_render_with_no_autoscaler(tmp_path: Path) -> None:
    r = _run(_api(2), tmp_path)
    assert r.returncode == 0, r.stderr
    r = _run(_api(2), tmp_path, "--require")
    assert r.returncode == 1
    assert "no workload scaled by a HorizontalPodAutoscaler was checked" in r.stderr


def test_the_appliance_render_keeps_its_replicas(tmp_path: Path) -> None:
    """The appliance turns the autoscaler off and sizes ``api.replicas`` to its
    control plane: helm must keep rendering the count there."""
    r = _run(_api(3), tmp_path, "--replicas", "api=3")
    assert r.returncode == 0, r.stderr


def test_the_replicas_control_fails_on_each_wrong_render(tmp_path: Path) -> None:
    r = _run(_api(None), tmp_path, "--replicas", "api=3")
    assert r.returncode == 1
    assert "renders spec.replicas unset, expected 3" in r.stderr
    r = _run(_api(1), tmp_path, "--replicas", "api=3")
    assert r.returncode == 1
    assert "renders spec.replicas 1, expected 3" in r.stderr
    r = _run(_api(None) + _hpa(), tmp_path, "--replicas", "api=3")
    assert r.returncode == 1
    assert "is scaled by a HorizontalPodAutoscaler; this render must carry none" in r.stderr
    r = _run(
        _api(3).replace("component: api", "component: worker"), tmp_path, "--replicas", "api=3"
    )
    assert r.returncode == 1
    assert "no Deployment with component 'api' in the render" in r.stderr


def test_one_bad_render_among_several_fails_the_run(tmp_path: Path) -> None:
    good = tmp_path / "good.yaml"
    good.write_text(textwrap.dedent(_api(None) + _hpa()))
    bad = tmp_path / "bad.yaml"
    bad.write_text(textwrap.dedent(_api(2) + _hpa()))
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--require", str(good), str(bad)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 1
    assert f"{bad}: Deployment 'rel-spatiumddi-api' renders spec.replicas: 2" in r.stderr
    assert str(good) not in r.stderr
