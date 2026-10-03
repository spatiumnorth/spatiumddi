"""The #1174 slot-image mirror gate actually fails when it should.

``.github/scripts/chart-slot-image-mirror.py`` refuses a render in which the
slot-image mirror gets a lower memory or CPU limit than the api container whose
image it runs. The Charts job runs it over every render of the umbrella chart
(``.github/scripts/charts-render-check.sh``). It lives here, beside the #983
posture gate's tests, because ``appliance/tests`` is the hermetic pytest job
with PyYAML that runs on every PR.

Every passing case is paired with a case that must FAIL. The fixtures are the
renders read on 2026-10-03: the chart's defaults before #1174 (api
``1000m/512Mi``, mirror ``500m/256Mi``) and an appliance whose supervisor sized
the api to 2949Mi on a three-node control plane.

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_chart_slot_image_mirror.py -v
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import textwrap
from pathlib import Path

SCRIPT = (
    Path(__file__).parent.parent.parent / ".github" / "scripts" / "chart-slot-image-mirror.py"
)


def _deployment(component: str, container: str, limits: dict[str, str] | None) -> str:
    resources = ""
    if limits is not None:
        lines = "".join(f"\n                  {k}: {v}" for k, v in limits.items())
        resources = f"\n              resources:\n                limits:{lines}"
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
            - name: {container}
              image: ghcr.io/spatiumnorth/spatiumddi-api:test{resources}
    """


def _api(memory: str = "512Mi", cpu: str = "1000m") -> str:
    return _deployment("api", "api", {"cpu": cpu, "memory": memory})


def _mirror(memory: str = "512Mi", cpu: str = "1000m") -> str:
    return _deployment("slot-image-mirror", "slot-image-mirror", {"cpu": cpu, "memory": memory})


def _run(manifest: str, tmp_path: Path, name: str = "render.yaml") -> subprocess.CompletedProcess:
    f = tmp_path / name
    f.write_text(textwrap.dedent(manifest))
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(f)],
        capture_output=True,
        text=True,
        check=False,
    )


def _module():
    spec = importlib.util.spec_from_file_location("chart_slot_image_mirror", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_script_exists() -> None:
    assert SCRIPT.is_file(), f"{SCRIPT} missing: the Charts job calls it by path"


def test_a_mirror_sized_like_the_api_passes(tmp_path: Path) -> None:
    r = _run(_api() + _mirror(), tmp_path)
    assert r.returncode == 0, r.stderr
    assert "slot-image mirror at or above the api in 1 render(s)" in r.stdout


def test_the_charts_pre_1174_defaults_fail_on_memory_and_cpu(tmp_path: Path) -> None:
    """The render that shipped: api 1000m/512Mi, mirror 500m/256Mi."""
    r = _run(_api() + _mirror(memory="256Mi", cpu="500m"), tmp_path)
    assert r.returncode == 1
    assert (
        "Deployment/rel-spatiumddi-slot-image-mirror container slot-image-mirror: "
        "limits.memory 256Mi is below the api's 512Mi (Deployment/rel-spatiumddi-api)"
    ) in r.stderr
    assert "limits.cpu 500m is below the api's 1000m" in r.stderr
    assert "2 slot-image mirror shortfall(s)" in r.stderr


def test_the_appliance_sizing_must_reach_the_mirror(tmp_path: Path) -> None:
    """The supervisor sizes the api from the node's RAM (2949Mi on a 3-node
    rig). A mirror left at the chart's own number is below it, which is the
    gap #1174 describes; a mirror that follows the api passes."""
    r = _run(_api(memory="2949Mi", cpu="1") + _mirror(memory="512Mi", cpu="1"), tmp_path)
    assert r.returncode == 1
    assert "limits.memory 512Mi is below the api's 2949Mi" in r.stderr
    assert "limits.cpu" not in r.stderr
    r = _run(_api(memory="2949Mi", cpu="1") + _mirror(memory="2949Mi", cpu="1000m"), tmp_path)
    assert r.returncode == 0, r.stderr


def test_more_than_the_api_and_no_limit_at_all_both_pass(tmp_path: Path) -> None:
    r = _run(_api() + _mirror(memory="2Gi", cpu="2"), tmp_path)
    assert r.returncode == 0, r.stderr
    unbounded = _deployment("slot-image-mirror", "slot-image-mirror", None)
    r = _run(_api() + unbounded, tmp_path)
    assert r.returncode == 0, r.stderr


def test_a_render_without_the_mirror_passes_and_says_so(tmp_path: Path) -> None:
    r = _run(_api(), tmp_path)
    assert r.returncode == 0, r.stderr
    assert "no slot-image mirror rendered" in r.stdout


def test_a_mirror_with_no_api_to_compare_is_refused(tmp_path: Path) -> None:
    """Fail closed: if the api's labels or container name ever change, the gate
    must say it lost its reference rather than pass every render."""
    r = _run(_mirror(memory="256Mi"), tmp_path)
    assert r.returncode == 1
    assert "no api container" in r.stderr and "refusing rather than passing" in r.stderr


def test_one_bad_render_among_several_fails_the_run(tmp_path: Path) -> None:
    good = tmp_path / "good.yaml"
    good.write_text(textwrap.dedent(_api() + _mirror()))
    bad = tmp_path / "bad.yaml"
    bad.write_text(textwrap.dedent(_api() + _mirror(memory="256Mi")))
    r = subprocess.run(
        [sys.executable, str(SCRIPT), str(good), str(bad)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 1
    assert f"{bad}: Deployment/rel-spatiumddi-slot-image-mirror" in r.stderr
    assert str(good) not in r.stderr


def test_quantities_compare_across_units() -> None:
    mod = _module()
    assert mod.memory_bytes("1Gi") == mod.memory_bytes("1024Mi") == 2**30
    assert mod.memory_bytes("512Mi") < mod.memory_bytes("1G") < mod.memory_bytes("1Gi")
    assert mod.memory_bytes("2949Mi") == 2949 * 2**20
    assert mod.memory_bytes("lots") is None and mod.memory_bytes(None) is None
    assert mod.cpu_millicores("1") == mod.cpu_millicores("1000m") == 1000
    assert mod.cpu_millicores("0.5") == mod.cpu_millicores("500m") == 500
    assert mod.cpu_millicores("1Gi") is None
