"""A cluster Rolling Upgrade's hold holds the control chart, not only its values (#2865).

The hold (``backend/app/services/upgrades/shared_tags.py``) pins the image tags
and the control chart's ``applianceVersion`` in two HelmChartConfigs until
every node runs the target, so that the seed's boot onto its new slot does not
roll the control plane mid-run. A HelmChartConfig holds values, not the chart:
the seed's firstboot rendered the control chart from its NEW slot and released
it, and a release whose chart changed the api, worker or beat pod template
rolled them on the held image, with the worker that drives the run (seen live:
the worker rolled 12 minutes before the run moved the tags).

``release_control_manifest`` now keeps that chart back as
``spatium-control.yaml.held`` while a run's hold is on, and
``spatium-control-release`` releases it through the same gate once nothing
pins the control chart any more: the control plane rolls once, on the new
chart, the new tag and the new version together. These tests drive the real
functions and the real runner against a stub ``k3s`` that plays the apiserver
and a stub ``systemctl``:

  * the gate: a run's hold parks the chart and starts the runner; no hold,
    chart_bump's lone image.tag pin, a hold on this boot's own tag, an
    apiserver that did not answer, or a runner that could not be started all
    release it as before #2865;
  * the runner: it waits through the hold and a half-done flip, releases
    through the gate (the PriorityClass guard and the sizing read run at that
    release, not at the park), keeps waiting when a new run's Start pins the
    chart again, never takes an unanswered apiserver for a hold that ended,
    and releases nothing on a joined member.

Runs under ``sh`` (dash on the appliance and on the CI runner) so a bashism
fails here rather than on a boot.

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_firstboot_control_chart_hold.py -v
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

APPLIANCE = Path(__file__).parent.parent
BIN = APPLIANCE / "mkosi.extra" / "usr" / "local" / "bin"
SCRIPT = BIN / "spatiumddi-firstboot"
RUNNER = BIN / "spatium-control-release"
UNIT = APPLIANCE / "mkosi.extra" / "etc" / "systemd" / "system" / "spatiumddi-control-release.service"
MANIFESTS_LINE = "K3S_MANIFESTS_DIR=/var/lib/rancher/k3s/server/manifests"
SHELL = shutil.which("dash") or "sh"

# The gate and the helpers it calls: below firstboot's guards, so taken by name.
GATE = ("_strip_control_priority_class", "control_sizing_patch", "apply_control_sizing_patch",
        "control_hold_state", "control_helm_job_active", "release_control_manifest")


def _extract(body: str, name: str) -> str:
    """The shell source of a top-level ``name() {`` to its closing brace in column 0."""
    lines = body.splitlines()
    i = lines.index(f"{name}() {{")
    j = next(k for k in range(i + 1, len(lines)) if lines[k] == "}")
    return "\n".join(lines[i : j + 1])


OLD = "2026.10.27-1"  # the release the run upgrades from: the hold's tag
NEW = "2026.10.28-1"  # this boot's slot: the chart firstboot renders

# The stub apiserver. ``states`` holds what the two HelmChartConfigs read as,
# one ``kubectl get -o json`` answer per line, the Nth read answering line N
# and every read after the last answering the last (``APIERR`` = the apiserver
# did not answer). ``jobs`` does the same for ``.status.active`` of
# spatium-control's install Job (absent = no Job). The PriorityClass is
# present, and spatium-control carries no sizing values, so the gate's #983 and
# #1210 halves pass through.
STUB_K3S = r"""#!/bin/sh
S="$STUB"
echo "$*" >> "$S/calls.log"
[ "$1" = kubectl ] && shift
args="$*"
case "$args" in
  *"get helmchartconfig spatium-bootstrap spatium-control "*)
    n=$(cat "$S/reads" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$S/reads"
    total=$(grep -c '' "$S/states")
    [ "$n" -le "$total" ] || n=$total
    state=$(sed -n "${n}p" "$S/states")
    if [ "$state" = APIERR ]; then
      echo "The connection to the server 127.0.0.1:6443 was refused" >&2; exit 1
    fi
    printf '%s\n' "$state"; exit 0 ;;
  *"get job helm-install-spatium-control "*)
    [ -f "$S/jobs" ] || exit 0
    n=$(cat "$S/jreads" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$S/jreads"
    total=$(grep -c '' "$S/jobs")
    [ "$n" -le "$total" ] || n=$total
    active=$(sed -n "${n}p" "$S/jobs")
    if [ "$active" = APIERR ]; then
      echo "The connection to the server 127.0.0.1:6443 was refused" >&2; exit 1
    fi
    printf '%s' "$active"; exit 0 ;;
  *"get helmchartconfig spatium-control --ignore-not-found -o jsonpath="*)
    exit 0 ;;
  "get priorityclass spatium-control-plane"*)
    exit 0 ;;
esac
echo "stub k3s: unexpected: $args" >&2
exit 3
"""

STUB_SYSTEMCTL = r"""#!/bin/sh
echo "$*" >> "$STUB/systemctl.log"
exit "$(cat "$STUB/systemctl.rc" 2>/dev/null || echo 0)"
"""


def _hcc(name: str, values: dict) -> dict:
    return {
        "apiVersion": "helm.cattle.io/v1",
        "kind": "HelmChartConfig",
        "metadata": {"name": name, "namespace": "kube-system"},
        "spec": {"valuesContent": yaml.safe_dump(values)},
    }


def _configs(bootstrap: str | None = None, control: str | None = None,
             version: str | None = None) -> str:
    """The two HelmChartConfigs as ``kubectl get -o json`` lists them. The
    supervisor's own keys stay on spatium-control whatever the hold does."""
    items = []
    if bootstrap is not None:
        items.append(_hcc("spatium-bootstrap", {"global": {"imageTag": bootstrap}}))
    control_values: dict = {"worker": {"concurrency": 2}}
    if control is not None:
        control_values["image"] = {"tag": control}
    if version is not None:
        control_values["applianceVersion"] = version
    items.append(_hcc("spatium-control", control_values))
    return json.dumps({"apiVersion": "v1", "kind": "List", "items": items,
                       "metadata": {"resourceVersion": ""}})


HOLD = _configs(OLD, OLD, OLD)  # a run's hold: shared_tags.ensure_hold
HALF = _configs(None, OLD, OLD)  # the flip half done: the bootstrap pin is off
FREE = _configs()  # the flip done, or the hold released


def _manifest(tag: str = NEW, version: str = NEW) -> str:
    """The control chart as _render_control_helmchart lays it out."""
    return (
        "apiVersion: helm.cattle.io/v1\n"
        "kind: HelmChart\n"
        "metadata:\n"
        "  name: spatium-control\n"
        "  namespace: kube-system\n"
        "spec:\n"
        "  chartContent: Y2hhcnQ=\n"
        "  targetNamespace: spatium\n"
        "  failurePolicy: retry\n"
        "  valuesContent: |\n"
        "    image:\n"
        f'      tag: "{tag}"\n'
        "      pullPolicy: IfNotPresent\n"
        f'    applianceVersion: "{version}"\n'
    )


class Node:
    """One node's manifests dir, stubs and a firstboot whose k3s and manifests
    dir are the stubs'."""

    def __init__(self, tmp_path: Path, states: list[str], *, systemctl_rc: int = 0,
                 member: bool = False, jobs: list[str] | None = None,
                 job_wait_polls: int = 30) -> None:
        self.stub = tmp_path / "stub"
        self.stub.mkdir()
        (self.stub / "states").write_text("\n".join(states) + "\n")
        if jobs is not None:
            (self.stub / "jobs").write_text("\n".join(jobs) + "\n")
        (self.stub / "systemctl.rc").write_text(str(systemctl_rc))
        bindir = tmp_path / "bin"
        bindir.mkdir()
        k3s = bindir / "k3s"
        k3s.write_text(STUB_K3S)
        systemctl = bindir / "systemctl"
        systemctl.write_text(STUB_SYSTEMCTL)
        for stub in (k3s, systemctl):
            stub.chmod(0o755)
        self.manifests = tmp_path / "manifests"
        self.manifests.mkdir()
        self.control = self.manifests / "spatium-control.yaml"
        self.deferred = self.manifests / "spatium-control.yaml.deferred"
        self.held = self.manifests / "spatium-control.yaml.held"
        dropin = tmp_path / "spatium-cluster.yaml"
        if member:
            dropin.write_text("server: https://10.0.0.1:6443\n")
        body = SCRIPT.read_text(encoding="utf-8")
        assert MANIFESTS_LINE in body, "K3S_MANIFESTS_DIR moved: update this harness"
        body = body.replace(MANIFESTS_LINE, f"K3S_MANIFESTS_DIR={self.manifests}")
        self.firstboot = tmp_path / "spatiumddi-firstboot"
        self.firstboot.write_text(body.replace("/usr/local/bin/k3s", str(k3s)))
        self.env = {
            **os.environ,
            # python3 with PyYAML, as on the appliance: the test's own interpreter
            "PATH": os.pathsep.join([str(bindir), str(Path(sys.executable).parent),
                                     os.environ.get("PATH", "")]),
            "STUB": str(self.stub),
            "SPATIUM_K3S_JOIN_DROPIN": str(dropin),
            "SPATIUM_FIRSTBOOT": str(self.firstboot),
            "SPATIUM_CONTROL_RELEASE_POLL_S": "0",
            "SPATIUM_CONTROL_RELEASE_JOB_WAIT_POLLS": str(job_wait_polls),
        }

    def gate(self) -> subprocess.CompletedProcess:
        """firstboot's release of this boot's chart, as place_deferred_control_manifest calls it."""
        body = self.firstboot.read_text(encoding="utf-8")
        defs = "\n".join(_extract(body, fn) for fn in GATE)
        return subprocess.run(
            [SHELL, "-c", f'. "{self.firstboot}"\n{defs}\nrelease_control_manifest\n'],
            env={**self.env, "SPATIUM_FIRSTBOOT_LIB": "1"},
            capture_output=True, text=True, check=False, timeout=60,
        )

    def runner(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            [SHELL, str(RUNNER)], env=self.env,
            capture_output=True, text=True, check=False, timeout=60,
        )

    def calls(self) -> list[str]:
        log = self.stub / "calls.log"
        return log.read_text().splitlines() if log.exists() else []

    def started(self) -> list[str]:
        log = self.stub / "systemctl.log"
        return log.read_text().splitlines() if log.exists() else []


def _is_pair_read(call: str) -> bool:
    return "get helmchartconfig spatium-bootstrap spatium-control " in call


def _is_job_read(call: str) -> bool:
    return "get job helm-install-spatium-control " in call


LIVE = "# the release the cluster runs\n"


# ── the gate: firstboot's release_control_manifest ──────────────────────────


def test_a_runs_hold_parks_the_chart_and_starts_the_runner(tmp_path: Path) -> None:
    node = Node(tmp_path, [HOLD])
    node.control.write_text(LIVE)
    node.deferred.write_text(_manifest())
    proc = node.gate()
    assert proc.returncode == 0, proc.stderr
    assert node.control.read_text() == LIVE  # the control plane is not touched
    assert node.held.read_text() == _manifest()
    assert not node.deferred.exists()
    assert oct(node.held.stat().st_mode & 0o777) == "0o600"
    assert node.started() == ["start --no-block spatiumddi-control-release.service"]
    assert f"holds the control plane at {OLD}" in proc.stdout
    # parked, not released: neither the #983 guard nor the #1210 sizing read ran
    assert [c for c in node.calls() if not _is_pair_read(c)] == []


def test_a_later_boot_of_the_same_run_replaces_the_held_chart(tmp_path: Path) -> None:
    node = Node(tmp_path, [HOLD])
    node.held.write_text("# an earlier boot's chart\n")
    node.deferred.write_text(_manifest())
    proc = node.gate()
    assert proc.returncode == 0, proc.stderr
    assert node.held.read_text() == _manifest()
    assert not node.control.exists()
    assert len(node.started()) == 1


@pytest.mark.parametrize(
    "configs",
    [
        pytest.param(FREE, id="no-pins"),
        pytest.param("", id="no-configs-at-all"),
        pytest.param(json.dumps({"apiVersion": "v1", "kind": "List", "items": []}), id="empty-list"),
        # chart_bump.py writes spatium-control's image.tag alone, to the new tag
        pytest.param(_configs(None, NEW, None), id="chart-bump-pin"),
        pytest.param(_configs(None, OLD, None), id="control-pin-alone"),
        pytest.param(_configs(OLD, None, None), id="bootstrap-pin-alone"),
        pytest.param(_configs(OLD, "2026.10.26-1", OLD), id="pins-that-differ"),
        # a node booted back into the held version runs the chart the cluster runs
        pytest.param(_configs(NEW, NEW, NEW), id="held-at-this-boots-own-tag"),
        pytest.param(json.dumps(_hcc("spatium-control", {"image": {"tag": NEW}})), id="one-bare-object"),
    ],
)
def test_no_runs_hold_releases_as_before(tmp_path: Path, configs: str) -> None:
    node = Node(tmp_path, [configs])
    node.deferred.write_text(_manifest())
    proc = node.gate()
    assert proc.returncode == 0, proc.stderr
    assert node.control.read_text() == _manifest()
    assert not node.deferred.exists() and not node.held.exists()
    assert node.started() == []


@pytest.mark.parametrize("configs", ["APIERR", "{not json"])
def test_a_hold_that_cannot_be_read_is_no_hold(tmp_path: Path, configs: str) -> None:
    """Fail open, as before #2865: at worst the mid-run roll this prevents, never
    a control chart that is not released at all."""
    node = Node(tmp_path, [configs])
    node.deferred.write_text(_manifest())
    proc = node.gate()
    assert proc.returncode == 0, proc.stderr
    assert node.control.read_text() == _manifest()
    assert node.started() == []


def test_a_runner_that_cannot_be_started_releases_now(tmp_path: Path) -> None:
    node = Node(tmp_path, [HOLD], systemctl_rc=1)
    node.deferred.write_text(_manifest())
    proc = node.gate()
    assert proc.returncode == 0, proc.stderr
    assert node.control.read_text() == _manifest()
    assert not node.held.exists()
    assert "releasing the held control chart now" in proc.stderr


def test_a_held_chart_from_an_earlier_boot_is_superseded_by_a_release(tmp_path: Path) -> None:
    node = Node(tmp_path, [FREE])
    node.held.write_text("# an earlier boot's chart\n")
    node.deferred.write_text(_manifest())
    proc = node.gate()
    assert proc.returncode == 0, proc.stderr
    assert node.control.read_text() == _manifest()
    assert not node.held.exists()


# ── the runner: spatium-control-release ─────────────────────────────────────


def test_the_runner_releases_once_the_flip_has_taken_every_pin_off(tmp_path: Path) -> None:
    """The flip takes the bootstrap pin off first and the control pins in a
    later write: the chart waits for the second, so it is one helm revision."""
    node = Node(tmp_path, [HOLD, HOLD, HALF, FREE])
    node.control.write_text(LIVE)
    node.held.write_text(_manifest())
    proc = node.runner()
    assert proc.returncode == 0, proc.stderr
    assert node.control.read_text() == _manifest()
    assert not node.held.exists()
    calls = node.calls()
    pair_reads = [i for i, c in enumerate(calls) if _is_pair_read(c)]
    job_reads = [i for i, c in enumerate(calls) if _is_job_read(c)]
    # the runner's reads (hold, hold, half, free, free), then the gate's own;
    # the second free read asks after helm-controller's Job (there is none)
    assert len(pair_reads) == 6
    assert len(job_reads) == 1 and pair_reads[4] < job_reads[0] < pair_reads[5]
    # the PriorityClass guard and the sizing read run at the release, after it
    others = [i for i, c in enumerate(calls) if not _is_pair_read(c) and not _is_job_read(c)]
    assert others and min(others) > pair_reads[-1]
    assert f"waiting for the Rolling Upgrade's hold to end (held {OLD})" in proc.stdout
    assert "the Rolling Upgrade's hold has ended" in proc.stdout
    assert node.started() == []


def test_a_new_runs_start_keeps_the_chart_held(tmp_path: Path) -> None:
    """A failed run's hold released by the beat, then a new run's Start before
    the runner's release: the gate reads the hold again and keeps the chart."""
    node = Node(tmp_path, [FREE, FREE, HOLD, HOLD, FREE, FREE, FREE])
    node.control.write_text(LIVE)
    node.held.write_text(_manifest())
    proc = node.runner()
    assert proc.returncode == 0, proc.stderr
    assert node.started() == ["start --no-block spatiumddi-control-release.service"]
    assert proc.stdout.count("the Rolling Upgrade's hold has ended") == 2
    assert proc.stdout.count("releasing ") == 2
    assert node.control.read_text() == _manifest()
    assert not node.held.exists()


def test_an_apiserver_that_did_not_answer_is_not_a_hold_that_ended(tmp_path: Path) -> None:
    node = Node(tmp_path, [HOLD, "APIERR", "APIERR", FREE])
    node.held.write_text(_manifest())
    proc = node.runner()
    assert proc.returncode == 0, proc.stderr
    assert "(unknown)" in proc.stdout
    released = [i for i, line in enumerate(proc.stdout.splitlines()) if "hold has ended" in line]
    unknown = [i for i, line in enumerate(proc.stdout.splitlines()) if "(unknown)" in line]
    assert len(released) == 1 and unknown[-1] < released[0]
    assert node.control.read_text() == _manifest()


def test_an_applianceversion_pin_alone_still_holds(tmp_path: Path) -> None:
    """#2176's pin is the control chart's too: the chart waits for it."""
    node = Node(tmp_path, [_configs(None, None, OLD), FREE])
    node.held.write_text(_manifest())
    proc = node.runner()
    assert proc.returncode == 0, proc.stderr
    assert f"(held {OLD})" in proc.stdout
    assert node.control.read_text() == _manifest()


def test_the_release_waits_for_helm_controllers_run_of_the_unpinned_values(tmp_path: Path) -> None:
    """Removing the pins starts helm-controller's Job for spatium-control: the
    held chart goes in once that Job has ended, not under it."""
    node = Node(tmp_path, [HOLD, FREE], jobs=["1", "1", ""])
    node.held.write_text(_manifest())
    proc = node.runner()
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.count("waiting for helm-controller's run of spatium-control to end") == 1
    calls = node.calls()
    job_reads = [i for i, c in enumerate(calls) if _is_job_read(c)]
    assert len(job_reads) == 3
    released = [i for i, c in enumerate(calls) if "get priorityclass" in c]
    assert released and released[0] > job_reads[-1]
    assert node.control.read_text() == _manifest()


@pytest.mark.parametrize("jobs", [["1"], ["APIERR"]], ids=["job-never-ends", "job-unreadable"])
def test_the_wait_for_helm_controller_is_bounded(tmp_path: Path, jobs: list[str]) -> None:
    """A Job that does not end, or cannot be read, delays the release for
    JOB_WAIT_POLLS polls at most: the chart is never held for it."""
    node = Node(tmp_path, [FREE], jobs=jobs, job_wait_polls=4)
    node.held.write_text(_manifest())
    proc = node.runner()
    assert proc.returncode == 0, proc.stderr
    job_reads = [c for c in node.calls() if _is_job_read(c)]
    assert len(job_reads) == (3 if jobs == ["1"] else 1)
    assert node.control.read_text() == _manifest()
    assert not node.held.exists()


def test_a_joined_member_releases_nothing(tmp_path: Path) -> None:
    """#590: a joined member's control chart is the seed's."""
    node = Node(tmp_path, [FREE], member=True)
    node.held.write_text(_manifest())
    proc = node.runner()
    assert proc.returncode == 0, proc.stderr
    assert node.held.exists() and not node.control.exists()
    assert node.calls() == []


def test_the_runner_with_nothing_held_exits(tmp_path: Path) -> None:
    node = Node(tmp_path, [HOLD])
    proc = node.runner()
    assert proc.returncode == 0, proc.stderr
    assert node.calls() == []
    assert "no control chart held back" in proc.stdout


# ── shape ───────────────────────────────────────────────────────────────────


def _definitions(body: str) -> dict[str, str]:
    """Each top-level ``name() {`` to its first ``}`` in column 0, comments dropped."""
    lines = body.splitlines()
    out = {}
    for i, line in enumerate(lines):
        m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\(\) \{", line)
        if m:
            j = next((k for k in range(i, len(lines)) if lines[k] == "}"), i)
            out[m.group(1)] = "\n".join(ln for ln in lines[i : j + 1] if not ln.lstrip().startswith("#"))
    return out


def test_the_runner_takes_every_definition_the_gate_needs() -> None:
    """spatium-control-release sources firstboot's LIB half for the globals and
    node_is_cluster_member, and takes the gate and every helper it calls (they
    sit below the SPATIUM_FIRSTBOOT_RENDER_ONLY guard) from the file itself."""
    body = SCRIPT.read_text(encoding="utf-8")
    guard = body.index('\nif [ "${SPATIUM_FIRSTBOOT_LIB:-}" = "1" ]; then\n')
    for name in ("CONTROL_MANIFEST=", "CONTROL_MANIFEST_HELD=", "CONTROL_RELEASE_UNIT=",
                 "node_is_cluster_member() {"):
        assert body.index(f"\n{name}") < guard, name
    runner = RUNNER.read_text(encoding="utf-8")
    m = re.search(r"\nfor fn in (.*?); do\n", runner, re.S)
    assert m, "the runner's list of firstboot definitions moved: update this test"
    taken = set(m.group(1).replace("\\\n", " ").split())
    defs = _definitions(body)
    above = set(_definitions(body[:guard]))
    for fn in taken:
        assert body.splitlines().count(f"{fn}() {{") == 1, f"{fn}() is not defined exactly once"
    # every firstboot function the runner's own code names, and every one those
    # reach, transitively, is taken or in the LIB half
    code = "\n".join(ln for ln in runner.replace(m.group(0), "\n").splitlines()
                     if not ln.lstrip().startswith("#"))
    named = [fn for fn in defs if re.search(rf"(?<![\w-]){re.escape(fn)}(?![\w-])", code)]
    assert {"control_hold_state", "control_helm_job_active", "release_control_manifest",
            "node_is_cluster_member"} <= set(named), named
    need, todo = set(), list(named)
    while todo:
        fn = todo.pop()
        need.add(fn)
        for other in defs:
            if other not in need and re.search(rf"(?<![\w-]){re.escape(other)}(?![\w-])", defs[fn]):
                todo.append(other)
    assert need - above <= taken, sorted(need - above - taken)


def test_the_unit_is_started_by_firstboot_only_and_runs_the_runner() -> None:
    unit = UNIT.read_text(encoding="utf-8")
    body = SCRIPT.read_text(encoding="utf-8")
    assert "[Install]" not in re.sub(r"(?m)^#.*$", "", unit)
    assert "ExecStart=/usr/local/bin/spatium-control-release\n" in unit
    assert "ConditionPathExists=/var/lib/rancher/k3s/server/manifests/spatium-control.yaml.held\n" in unit
    assert 'CONTROL_MANIFEST="$K3S_MANIFESTS_DIR/spatium-control.yaml"' in body
    assert 'CONTROL_MANIFEST_HELD="${CONTROL_MANIFEST}.held"' in body
    assert f"CONTROL_RELEASE_UNIT={UNIT.name}\n" in body
    assert RUNNER.read_text(encoding="utf-8").startswith("#!/bin/sh\n")
