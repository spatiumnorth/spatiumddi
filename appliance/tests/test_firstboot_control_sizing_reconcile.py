"""firstboot brings an existing spatium-control HelmChartConfig's sizing up to date (#1210).

helm-controller merges the HelmChartConfig on top of the HelmChart, and the Config
survives a slot upgrade.  After an upgrade from a release that sized the control
plane differently, the first helm upgrade of the new release therefore rolled api
and worker out under the OLD limits, and the supervisor's first heartbeat then
rewrote the Config: a second spatium-control revision, a second migrate Job and a
second rollout.

``reconcile_control_sizing`` runs while the new HelmChart is still ``.deferred`` and
rewrites the Config's sizing keys to the values that HelmChart carries.  These tests
drive the real function under ``sh`` (dash on the appliance) against a stub ``k3s``
and a real rendered-looking manifest, and assert on what is PATCHED.

HOW TO RUN: python3 -m pytest appliance/tests/test_firstboot_control_sizing_reconcile.py -v
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import textwrap
from pathlib import Path

import yaml

SCRIPT = (
    Path(__file__).parent.parent / "mkosi.extra" / "usr" / "local" / "bin" / "spatiumddi-firstboot"
)
SHELL = shutil.which("dash") or "sh"

STUB_K3S = r"""#!/bin/sh
S="$STUB"
echo "$*" >> "$S/calls.log"
[ "$1" = kubectl ] && shift
args="$*"
case "$args" in
  *"get helmchartconfig spatium-control"*)
    [ -f "$S/apierr" ] && { echo refused >&2; exit 1; }
    [ -f "$S/config" ] && cat "$S/config"
    exit 0 ;;
  *"patch helmchartconfig spatium-control --type merge -p "*)
    printf '%s' "${args#*-p }" > "$S/patched"
    [ -f "$S/patch_fails" ] && exit 1
    exit 0 ;;
esac
echo "stub k3s: unexpected: $*" >&2
exit 3
"""

# What _render_control_helmchart emits for an 8 GiB node under #1115's budget.
CHART_VALUES = textwrap.dedent(
    """\
    image:
      tag: "2026.10.02-1"
    api:
      resources:
        limits:
          memory: "3072Mi"
    worker:
      concurrency: 2
      resources:
        limits:
          memory: "1536Mi"
    postgresql:
      resources:
        requests:
          memory: "256Mi"
        limits:
          memory: "1536Mi"
      cnpg:
        parameters:
          shared_buffers: "384MB"
    """
)


def _manifest(values: str = CHART_VALUES) -> str:
    body = textwrap.indent(values, "    ")
    return (
        "apiVersion: helm.cattle.io/v1\nkind: HelmChart\nmetadata:\n  name: spatium-control\n"
        "  namespace: kube-system\nspec:\n  chartContent: QUJD\n  valuesContent: |\n" + body
    )


def _extract(name: str) -> str:
    lines = SCRIPT.read_text(encoding="utf-8").splitlines()
    i = lines.index(f"{name}() {{")
    j = next(k for k in range(i + 1, len(lines)) if lines[k] == "}")
    return "\n".join(lines[i : j + 1])


def _run(tmp_path: Path, config: dict | None, *, manifest: str | None = None,
         apierr: bool = False, patch_fails: bool = False):
    stub = tmp_path / "stub"
    stub.mkdir(parents=True)
    k3s = tmp_path / "k3s"
    k3s.write_text(STUB_K3S)
    k3s.chmod(0o755)
    if config is not None:
        (stub / "config").write_text(yaml.safe_dump(config, sort_keys=True))
    for flag, on in (("apierr", apierr), ("patch_fails", patch_fails)):
        if on:
            (stub / flag).touch()
    control = tmp_path / "spatium-control.yaml"
    if manifest is not None:
        Path(f"{control}.deferred").write_text(manifest)
    body = _extract("reconcile_control_sizing").replace("/usr/local/bin/k3s", str(k3s))
    script = f'set -eu\nCONTROL_MANIFEST="{control}"\n{body}\nreconcile_control_sizing\necho rc=$?\n'
    proc = subprocess.run([SHELL, "-c", script], env={**os.environ, "STUB": str(stub)},
                          capture_output=True, text=True, check=False)
    patched = (stub / "patched").read_text() if (stub / "patched").exists() else None
    new_values = None
    if patched:
        new_values = yaml.safe_load(json.loads(patched)["spec"]["valuesContent"])
    return proc, patched, new_values


# The Config the 2026.09.04-1 supervisor wrote on a 8 GiB node (fractions of MemTotal).
def _old_config() -> dict:
    return {
        "api": {
            "replicas": 1,
            "resources": {"limits": {"memory": "4096Mi"}},
        },
        "worker": {"replicas": 1, "resources": {"limits": {"memory": "2048Mi"}}},
        "frontend": {"controlPlaneVIP": ""},
        "image": {"tag": "2026.09.04-1"},
    }


def test_old_sizing_in_the_config_is_brought_up_to_the_charts(tmp_path: Path) -> None:
    proc, patched, new = _run(tmp_path, _old_config(), manifest=_manifest())
    assert proc.returncode == 0, proc.stderr
    assert patched is not None, "the old sizing would outrank the new HelmChart"
    assert new["api"]["resources"]["limits"]["memory"] == "3072Mi"
    assert new["worker"]["resources"]["limits"]["memory"] == "1536Mi"
    # Only keys the Config already carried: nothing is added, nothing else is touched.
    assert "postgresql" not in new and "concurrency" not in new["worker"]
    assert new["api"]["replicas"] == 1 and new["image"] == {"tag": "2026.09.04-1"}
    assert new["frontend"] == {"controlPlaneVIP": ""}


def test_an_up_to_date_config_is_not_written(tmp_path: Path) -> None:
    cfg = yaml.safe_load(CHART_VALUES)
    cfg.pop("image")
    proc, patched, _ = _run(tmp_path, cfg, manifest=_manifest())
    assert proc.returncode == 0, proc.stderr
    # A Config write is itself a helm revision, so a no-op boot must write nothing.
    assert patched is None


def test_the_written_document_is_dumped_the_way_the_supervisor_dumps_it(tmp_path: Path) -> None:
    _, patched, new = _run(tmp_path, _old_config(), manifest=_manifest())
    body = json.loads(patched)["spec"]["valuesContent"]
    assert body == yaml.safe_dump(new, sort_keys=True, default_flow_style=False)


def test_no_config_yet_writes_nothing(tmp_path: Path) -> None:
    proc, patched, _ = _run(tmp_path, None, manifest=_manifest())
    assert proc.returncode == 0 and patched is None


def test_no_deferred_manifest_touches_nothing(tmp_path: Path) -> None:
    proc, patched, _ = _run(tmp_path, _old_config(), manifest=None)
    assert proc.returncode == 0 and patched is None
    assert not (tmp_path / "stub" / "calls.log").exists()


def test_a_manifest_without_sizing_leaves_the_config_alone(tmp_path: Path) -> None:
    # MemTotal unreadable at render time: firstboot emits no sizing, and the
    # Config's numbers must not be replaced by nothing.
    _, patched, _ = _run(tmp_path, _old_config(), manifest=_manifest('image:\n  tag: "x"\n'))
    assert patched is None


def test_an_unreadable_apiserver_or_a_refused_patch_never_fails(tmp_path: Path) -> None:
    proc, patched, _ = _run(tmp_path / "a", _old_config(), manifest=_manifest(), apierr=True)
    assert proc.stdout.strip().endswith("rc=0") and patched is None
    assert "WARN: could not read" in proc.stderr
    proc, _, _ = _run(tmp_path / "b", _old_config(), manifest=_manifest(), patch_fails=True)
    assert proc.stdout.strip().endswith("rc=0")
    assert "WARN: could not reconcile" in proc.stderr


def test_it_runs_before_the_control_chart_is_released() -> None:
    src = SCRIPT.read_text(encoding="utf-8")
    body = _extract("place_deferred_control_manifest")
    assert body.index("reconcile_control_sizing") < body.index("release_control_manifest")
    assert src.index("reconcile_control_sizing() {") < src.index("place_deferred_control_manifest() {")
