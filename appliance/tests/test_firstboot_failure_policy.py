"""firstboot never lets helm-controller UNINSTALL the control release (#1299).

A k3s HelmChart's ``failurePolicy: reinstall`` (the CRD default) uninstalls a
failed release and installs it again, and ``helm uninstall`` keeps only what the
release's LAST stored revision annotates ``helm.sh/resource-policy: keep``. After
a slot rollback to a release older than #1044, the forward boot re-ran the
HelmChart the old release had left (its chart: no ``keep`` on the app Secret)
before firstboot placed its own; that upgrade failed, the reinstall deleted the
Secret, and the install minted a new SECRET_KEY.

The control release now retries instead. The policy that counts is the
HelmChartConfig's: it overrides the HelmChart's, and the CRD defaults it to
``reinstall``. It also survives a rollback (the supervisor and the api only
merge-patch its valuesContent), so it governs the job helm-controller re-runs for
a stale HelmChart too. ``pin_control_failure_policy`` sets it on every boot,
before the control chart is placed; ``_render_control_helmchart`` sets the same
on the HelmChart (test_secret_key_survives_reinstall.py).

These tests drive the real function against a stub ``k3s`` that plays the
apiserver, under ``sh`` (dash on the appliance and on the CI runner):

  * no control chart on this node (a joined member) -> nothing is touched;
  * an apiserver that does not answer -> a WARN, nothing written, never fatal;
  * the HelmChartConfig absent -> created carrying only the policy;
  * present without the policy (the supervisor's), or with another one -> patched;
  * already ``retry`` -> nothing written;
  * a create that raced the supervisor's -> patched instead;
  * a patch that fails -> a WARN, never fatal.

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_firstboot_failure_policy.py -v
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import yaml

SCRIPT = (
    Path(__file__).parent.parent
    / "mkosi.extra"
    / "usr"
    / "local"
    / "bin"
    / "spatiumddi-firstboot"
)
FUNC = "pin_control_failure_policy"
SHELL = shutil.which("dash") or "sh"

# The stub apiserver. ``hcc`` holds the HelmChartConfig's failurePolicy (an empty
# file = present without one; absent file = no HelmChartConfig); ``apierr`` = the
# apiserver is down; ``create_conflict`` = the supervisor created it first;
# ``patch_fails`` = the patch is refused.
STUB_K3S = r"""#!/bin/sh
S="$STUB"
echo "$*" >> "$S/calls.log"
[ "$1" = kubectl ] && shift
args="$*"
case "$args" in
  "--request-timeout=10s -n kube-system get helmchartconfig spatium-control --ignore-not-found -o jsonpath={.metadata.name}/{.spec.failurePolicy}")
    if [ -f "$S/apierr" ]; then
      echo "The connection to the server 127.0.0.1:6443 was refused" >&2; exit 1
    fi
    [ -f "$S/hcc" ] && printf 'spatium-control/%s' "$(cat "$S/hcc")"
    exit 0 ;;
  "--request-timeout=10s create -f -")
    cat > "$S/created.yaml"
    if [ -f "$S/create_conflict" ]; then
      echo 'Error from server (AlreadyExists): helmchartconfigs.helm.cattle.io "spatium-control" already exists' >&2
      exit 1
    fi
    exit 0 ;;
  "--request-timeout=10s -n kube-system patch helmchartconfig spatium-control --type merge -p "*)
    printf '%s' "${args#*-p }" > "$S/patched"
    [ -f "$S/patch_fails" ] && exit 1
    exit 0 ;;
esac
echo "stub k3s: unexpected: $args" >&2
exit 3
"""


def _extract_function(name: str) -> str:
    """The shell source of a top-level ``name() { ... }`` (closing brace at column 0)."""
    lines = SCRIPT.read_text(encoding="utf-8").splitlines()
    opener = f"{name}() {{"
    for i, line in enumerate(lines):
        if line == opener:
            break
    else:  # pragma: no cover - the assert below is the real reporter
        raise AssertionError(f"{name}() not found in {SCRIPT} (renamed?)")
    for j in range(i + 1, len(lines)):
        if lines[j] == "}":
            return "\n".join(lines[i : j + 1])
    raise AssertionError(f"{name}() has no closing brace at column 0")


def _run(tmp_path: Path, *, hcc: str | None = None, apierr: bool = False,
         create_conflict: bool = False, patch_fails: bool = False,
         manifest: str | None = "deferred"):
    stub = tmp_path / "stub"
    stub.mkdir()
    k3s = tmp_path / "k3s"
    k3s.write_text(STUB_K3S)
    k3s.chmod(0o755)
    if hcc is not None:
        (stub / "hcc").write_text(hcc)
    for flag, on in (("apierr", apierr), ("create_conflict", create_conflict),
                     ("patch_fails", patch_fails)):
        if on:
            (stub / flag).touch()
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    control = manifests / "spatium-control.yaml"
    if manifest == "deferred":
        Path(f"{control}.deferred").write_text("# deferred\n")
    elif manifest == "placed":
        control.write_text("# placed\n")
    body = _extract_function(FUNC).replace("/usr/local/bin/k3s", str(k3s))
    script = (
        f'. "{SCRIPT}"\n'                       # the lib half (returns before the boot body)
        "set -eu\n"                             # firstboot's own mode: the function must hold
        f'CONTROL_MANIFEST="{control}"\n'
        f"{body}\n{FUNC}\necho rc=$?\n"
    )
    proc = subprocess.run(
        [SHELL, "-c", script],
        env={**os.environ, "SPATIUM_FIRSTBOOT_LIB": "1", "STUB": str(stub)},
        capture_output=True, text=True, check=False,
    )
    log = stub / "calls.log"
    calls = log.read_text().splitlines() if log.exists() else []
    created = (stub / "created.yaml").read_text() if (stub / "created.yaml").exists() else None
    patched = (stub / "patched").read_text() if (stub / "patched").exists() else None
    return proc, calls, created, patched


def _gets(calls: list[str]) -> int:
    return sum(1 for c in calls if " get helmchartconfig spatium-control " in c)


def test_absent_it_is_created_carrying_only_the_policy(tmp_path: Path) -> None:
    proc, calls, created, patched = _run(tmp_path, hcc=None)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().endswith("rc=0")
    doc = yaml.safe_load(created)
    assert doc == {"apiVersion": "helm.cattle.io/v1", "kind": "HelmChartConfig",
                   "metadata": {"name": "spatium-control", "namespace": "kube-system"},
                   "spec": {"failurePolicy": "retry"}}
    # nothing but the policy: the supervisor owns valuesContent and merges it in later
    assert "valuesContent" not in created
    assert patched is None
    assert "(created)" in proc.stdout


def test_the_supervisors_config_without_a_policy_is_patched(tmp_path: Path) -> None:
    proc, calls, created, patched = _run(tmp_path, hcc="")
    assert proc.returncode == 0, proc.stderr
    assert created is None
    assert patched == '{"spec":{"failurePolicy":"retry"}}'


def test_another_policy_is_overwritten(tmp_path: Path) -> None:
    proc, calls, created, patched = _run(tmp_path, hcc="reinstall")
    assert proc.returncode == 0, proc.stderr
    assert patched == '{"spec":{"failurePolicy":"retry"}}'
    assert "(was 'reinstall')" in proc.stdout


def test_already_retry_writes_nothing(tmp_path: Path) -> None:
    proc, calls, created, patched = _run(tmp_path, hcc="retry")
    assert proc.returncode == 0, proc.stderr
    assert calls and _gets(calls) == len(calls) == 1
    assert created is None and patched is None


def test_a_create_that_raced_the_supervisor_is_patched(tmp_path: Path) -> None:
    proc, calls, created, patched = _run(tmp_path, hcc=None, create_conflict=True)
    assert proc.returncode == 0, proc.stderr
    assert created is not None
    assert patched == '{"spec":{"failurePolicy":"retry"}}'


def test_an_apiserver_that_does_not_answer_writes_nothing_and_never_fails(tmp_path: Path) -> None:
    proc, calls, created, patched = _run(tmp_path, apierr=True)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().endswith("rc=0")
    assert "WARN: could not read HelmChartConfig" in proc.stderr
    assert created is None and patched is None and len(calls) == 1


def test_a_refused_patch_warns_and_never_fails(tmp_path: Path) -> None:
    proc, calls, created, patched = _run(tmp_path, hcc="", patch_fails=True)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().endswith("rc=0")
    assert "WARN: could not pin failurePolicy" in proc.stderr


def test_a_node_without_the_control_chart_is_untouched(tmp_path: Path) -> None:
    proc, calls, created, patched = _run(tmp_path, manifest=None)
    assert proc.returncode == 0, proc.stderr
    assert calls == []


def test_an_already_placed_control_chart_counts_as_carrying_it(tmp_path: Path) -> None:
    proc, calls, _, _ = _run(tmp_path, hcc="retry", manifest="placed")
    assert proc.returncode == 0, proc.stderr
    assert _gets(calls) == 1


def test_the_policy_is_pinned_before_this_boots_control_chart_is_placed() -> None:
    """The pin is the readiness path's first act: before the TLS Secret, the class
    re-assert and the control chart's placement, i.e. before this boot's own
    HelmChart replaces the stale one and its job runs."""
    src = SCRIPT.read_text(encoding="utf-8")
    ready = src.index('if [ "$ready" = 1 ]; then')
    body = src[ready:]
    calls = [m.group(0) for m in re.finditer(
        r"^\s+(pin_control_failure_policy|place_deferred_tls_manifest|"
        r"reassert_control_plane_class|place_deferred_control_manifest)\b", body, re.M)]
    names = [c.strip() for c in calls]
    assert names[:4] == ["pin_control_failure_policy", "place_deferred_tls_manifest",
                         "reassert_control_plane_class", "place_deferred_control_manifest"], names
    # defined before the boot body that calls it (a shell function must exist when called)
    assert src.index(f"{FUNC}() {{") < ready
