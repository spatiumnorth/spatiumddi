"""firstboot brings an existing spatium-control HelmChartConfig's sizing up to date (#1210).

helm-controller merges the HelmChartConfig on top of the HelmChart, and the Config
survives a slot upgrade.  After an upgrade from a release that sized the control
plane differently, the first helm upgrade of the new release therefore rolled api
and worker out under the OLD limits, and the supervisor's first heartbeat then
rewrote the Config: a second spatium-control revision, a second migrate Job and a
second rollout.

``control_sizing_patch`` computes, while the new HelmChart is still ``.deferred``, the
Config's sizing keys at the values that HelmChart carries, and
``apply_control_sizing_patch`` writes them as soon as k3s has applied the released
HelmChart -- so helm-controller runs ONE job carrying the new image and the new
sizing.  (Patched before the release, the Config change re-runs the PREVIOUS
release's HelmChart instead: measured against k3s v1.36.4, that is a rollout on the
old image followed by a second one.)  These tests drive the real functions under
``sh`` (dash on the appliance) against a stub ``k3s`` and a real rendered-looking
manifest, and assert on what is PATCHED and when.

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
  *"get helmchart spatium-control"*)
    # The deploy controller applies the released manifest after a few polls.
    n=$(cat "$S/polls" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$S/polls"
    if [ -f "$S/live" ] && [ "$n" -ge "$(cat "$S/live_after" 2>/dev/null || echo 1)" ]; then
      cat "$S/live"
    else
      cat "$S/stale" 2>/dev/null
    fi
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
         apierr: bool = False, patch_fails: bool = False, live_after: int | None = 3):
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
    deferred = Path(f"{control}.deferred")
    if manifest is not None:
        deferred.write_text(manifest)
        # Before the release the live HelmChart is the previous release's.
        (stub / "stale").write_text('image:\n  tag: "2026.09.04-1"\n')
        if live_after is not None:
            values = yaml.safe_load_all(manifest)
            live = next(d for d in values if d.get("kind") == "HelmChart")
            (stub / "live").write_text(live["spec"]["valuesContent"])
            (stub / "live_after").write_text(str(live_after))
    body = "\n".join(
        _extract(n) for n in ("control_sizing_patch", "apply_control_sizing_patch")
    ).replace("/usr/local/bin/k3s", str(k3s))
    script = (
        f'set -eu\nCONTROL_MANIFEST="{control}"\n{body}\n'
        f'p=$(control_sizing_patch "{deferred}")\n'
        f'apply_control_sizing_patch "{deferred}" "$p"\necho rc=$?\n'
    )
    env = {**os.environ, "STUB": str(stub), "CONTROL_SIZING_WAIT_STEP": "0",
           "CONTROL_SIZING_WAIT_TICKS": "8"}
    proc = subprocess.run([SHELL, "-c", script], env=env,
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


def test_cpu_limits_in_the_config_follow_the_chart_2240(tmp_path: Path) -> None:
    """#2240's CPU limits are reconciled like the memory: a Config that carries
    them (a supervisor sized them under an older formula) takes the HelmChart's;
    one that does not carry them gets none added (the HelmChart's own then apply,
    and the supervisor's #1005 guard finds them already rendered)."""
    chart = yaml.safe_load(CHART_VALUES)
    chart["api"]["resources"]["limits"]["cpu"] = "2000m"
    chart["postgresql"]["resources"]["limits"]["cpu"] = "4000m"
    values = yaml.safe_dump(chart, sort_keys=False)
    cfg = yaml.safe_load(CHART_VALUES)
    cfg.pop("image")
    cfg["api"]["resources"]["limits"]["cpu"] = "1000m"
    cfg["postgresql"]["resources"]["limits"]["cpu"] = "1000m"
    proc, patched, new = _run(tmp_path / "a", cfg, manifest=_manifest(values))
    assert proc.returncode == 0, proc.stderr
    assert patched is not None
    assert new["api"]["resources"]["limits"] == {"memory": "3072Mi", "cpu": "2000m"}
    assert new["postgresql"]["resources"]["limits"] == {"memory": "1536Mi", "cpu": "4000m"}

    without = yaml.safe_load(CHART_VALUES)
    without.pop("image")
    _, patched, _ = _run(tmp_path / "b", without, manifest=_manifest(values))
    assert patched is None


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


def test_the_patch_waits_for_the_released_helmchart(tmp_path: Path) -> None:
    proc, patched, _ = _run(tmp_path, _old_config(), manifest=_manifest(), live_after=3)
    assert patched is not None, proc.stderr
    calls = (tmp_path / "stub" / "calls.log").read_text().splitlines()
    polls = [i for i, c in enumerate(calls) if "get helmchart spatium-control" in c]
    patch = next(i for i, c in enumerate(calls) if "patch helmchartconfig" in c)
    # Patched while the previous release's HelmChart is live, the Config change
    # would re-run THAT chart: a rollout on the old image, then a second one.
    assert len(polls) == 3 and polls[-1] < patch
    assert "was not seen applied" not in proc.stderr


def test_a_helmchart_never_seen_applied_is_still_reconciled(tmp_path: Path) -> None:
    proc, patched, _ = _run(tmp_path, _old_config(), manifest=_manifest(), live_after=None)
    assert proc.stdout.strip().endswith("rc=0")
    assert patched is not None
    assert "was not seen applied" in proc.stderr


def test_nothing_to_patch_does_not_wait(tmp_path: Path) -> None:
    cfg = yaml.safe_load(CHART_VALUES)
    cfg.pop("image")
    _run(tmp_path, cfg, manifest=_manifest(), live_after=None)
    calls = (tmp_path / "stub" / "calls.log").read_text()
    assert "get helmchart spatium-control" not in calls


def test_it_is_written_right_behind_the_released_chart() -> None:
    src = SCRIPT.read_text(encoding="utf-8")
    body = _extract("release_control_manifest")
    mv = body.index('mv -f "$deferred" "$CONTROL_MANIFEST"')
    # Computed from the final bytes (after any priority-class strip), before
    # the release; written after it.
    assert body.index("_strip_control_priority_class") < body.index("control_sizing_patch")
    assert body.index("control_sizing_patch") < mv < body.index("apply_control_sizing_patch")
    # And no longer before the webhook wait, when the old HelmChart is live.
    assert "sizing" not in _extract("place_deferred_control_manifest")
    assert src.index("apply_control_sizing_patch() {") < src.index("release_control_manifest() {")


def test_a_seed_reboot_leaves_the_supervisors_cluster_sized_postgres_limit_2156(
    tmp_path: Path,
) -> None:
    """#2156 — the supervisor sizes the Postgres limit for the cluster's node
    count, and this script renders one node. firstboot re-renders the HelmChart
    on every boot, so reconciling the limit would bring a nine-node cluster's
    4363Mi down to the one-node 2479Mi on each seed reboot, and the next
    heartbeat back up: two CloudNativePG rolling restarts per reboot."""
    chart = yaml.safe_load(CHART_VALUES)
    chart["postgresql"]["resources"]["limits"]["memory"] = "2479Mi"
    cfg = yaml.safe_load(CHART_VALUES)
    cfg.pop("image")
    cfg["postgresql"]["resources"]["limits"]["memory"] = "4363Mi"
    _, patched, _ = _run(tmp_path / "a", cfg, manifest=_manifest(yaml.safe_dump(chart)))
    assert patched is None

    # The keys that do not depend on the node count are still reconciled
    # around it, and the limit rides along untouched.
    cfg["api"]["resources"]["limits"]["memory"] = "1024Mi"
    proc, patched, new = _run(tmp_path / "b", cfg, manifest=_manifest(yaml.safe_dump(chart)))
    assert proc.returncode == 0, proc.stderr
    assert patched is not None
    assert new["api"]["resources"]["limits"]["memory"] == "3072Mi"
    assert new["postgresql"]["resources"]["limits"]["memory"] == "4363Mi"
