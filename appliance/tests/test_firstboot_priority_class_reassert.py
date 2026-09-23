"""firstboot puts ``spatium-control-plane`` back before it releases the control chart (#1123).

``release_control_manifest`` degrades the CONTROL chart when the class is
absent: a pod naming a PriorityClass that does not exist is refused by the
apiserver, so the chart is released unranked and the Web UI is left up to
diagnose with. That covered the control chart and nothing else. The same class
is named by ``spatium-bootstrap``'s own workloads — the CloudNativePG operator
and the supervisor DaemonSet — so on a boot where the operator's pods had to be
re-created (a cluster node loss evicts them within ~20 s), its ReplicaSet was
refused, the CNPG webhook had no endpoints, the unranked control chart's
``Cluster`` apply was refused by that webhook, and helm-controller's
``reinstall`` policy uninstalled and reinstalled spatium-control forever. The
UI answered 503 until the class was put back by hand.

The class is spatium-bootstrap's own object, so firstboot now makes that
release re-create it — by re-running its helm-install Job, the lever
``spatiumddi-helm-stuck-recover`` already pulls — and then re-queues the
controllers the apiserver refused while it was gone. These tests drive the real
function against a stub ``k3s`` that plays the apiserver, so every guard is
exercised as a shell run, not reasoned about:

  * the class present, or an apiserver that did not answer → nothing is touched;
  * spatium-bootstrap not ``deployed`` → nothing is re-run and nothing is
    logged (every first boot is this case: the release is still installing);
  * a bootstrap install Job that has not completed — running, retrying a
    failed or interrupted upgrade, just created, gone → it is left to
    helm-controller (only a completed Job is re-run);
  * the class not back within the bound → a WARN and the old degraded path;
  * a joined member, or a node with no control chart → the function is inert.

It runs under ``sh`` (dash on the appliance and on the CI runner) so a bashism
fails here rather than on a boot.

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_firstboot_priority_class_reassert.py -v
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).parent.parent
    / "mkosi.extra"
    / "usr"
    / "local"
    / "bin"
    / "spatiumddi-firstboot"
)
FUNC = "reassert_control_plane_class"
SHELL = shutil.which("dash") or "sh"

# The stub apiserver. State lives in files under $STUB (so one run can change
# it mid-flight): ``class`` present, ``apierr`` = the apiserver is down,
# ``deployed`` = spatium-bootstrap's release secret says deployed, ``job.<field>``
# = that ``.status`` field of its install Job (``job.absent`` = no Job at all),
# ``rerun_after`` = how many class polls after the Job is deleted until the
# re-run has re-created the class (absent = never).
STUB_K3S = r"""#!/bin/sh
S="$STUB"
echo "$*" >> "$S/calls.log"
[ "$1" = kubectl ] && shift
args="$*"
case "$args" in
  "get priorityclass spatium-control-plane"*)
    if [ -f "$S/apierr" ]; then
      echo "The connection to the server 127.0.0.1:6443 was refused" >&2; exit 1
    fi
    if [ -f "$S/rerun" ] && [ -f "$S/rerun_after" ]; then
      n=$(cat "$S/polls" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$S/polls"
      [ "$n" -ge "$(cat "$S/rerun_after")" ] && touch "$S/class"
    fi
    if [ -f "$S/class" ]; then
      echo "priorityclass.scheduling.k8s.io/spatium-control-plane"; exit 0
    fi
    echo 'Error from server (NotFound): priorityclasses.scheduling.k8s.io "spatium-control-plane" not found' >&2
    exit 1 ;;
  "-n spatium get secret -l owner=helm,name=spatium-bootstrap,status=deployed"*)
    [ -f "$S/deployed" ] && echo "secret/sh.helm.release.v1.spatium-bootstrap.v1"
    exit 0 ;;
  "-n kube-system get job helm-install-spatium-bootstrap"*)
    if [ -f "$S/job.absent" ]; then
      echo 'Error from server (NotFound): jobs.batch "helm-install-spatium-bootstrap" not found' >&2
      exit 1
    fi
    for f in succeeded active failed; do
      case "$args" in *"{.status.$f}"*) [ -f "$S/job.$f" ] && cat "$S/job.$f" ;; esac
    done
    exit 0 ;;
  "-n kube-system delete job helm-install-spatium-bootstrap"*)
    touch "$S/rerun"; exit 0 ;;
  "-n spatium annotate"*)
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


# The install Job's ``.status`` in each state a test puts it in — what the
# apiserver answers field by field (a count of 0 is omitted, so "new" has none).
JOB_STATUS = {
    "complete": {"succeeded": "1"},
    "running": {"active": "1"},
    "retrying": {"failed": "2"},  # between two failed attempts: no pod is active
    "new": {},  # just created; its pod not counted yet
}


def _run(tmp_path: Path, *, cls: bool = False, apierr: bool = False, deployed: bool = True,
         job: str = "complete", rerun_after: int | None = 2, member: bool = False,
         manifest: str | None = "deferred") -> tuple[subprocess.CompletedProcess, list[str]]:
    stub = tmp_path / "stub"
    stub.mkdir()
    k3s = tmp_path / "k3s"
    k3s.write_text(STUB_K3S)
    k3s.chmod(0o755)
    for flag, on in (("class", cls), ("apierr", apierr), ("deployed", deployed)):
        if on:
            (stub / flag).touch()
    if job == "absent":
        (stub / "job.absent").touch()
    else:
        for field, value in JOB_STATUS[job].items():
            (stub / f"job.{field}").write_text(value)
    if rerun_after is not None:
        (stub / "rerun_after").write_text(str(rerun_after))
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    control = manifests / "spatium-control.yaml"
    if manifest == "deferred":
        Path(f"{control}.deferred").write_text("# deferred\n")
    elif manifest == "placed":
        control.write_text("# placed\n")
    dropin = tmp_path / "spatium-cluster.yaml"
    if member:
        dropin.write_text("server: https://10.0.0.1:6443\n")
    body = _extract_function(FUNC).replace("/usr/local/bin/k3s", str(k3s))
    script = (
        f'. "{SCRIPT}"\n'                       # the lib half: node_is_cluster_member & co.
        f'CONTROL_MANIFEST="{control}"\n'
        "sleep() { :; }\n"                      # the bound is counted in polls, not waited out
        f"{body}\n{FUNC}\n"
    )
    proc = subprocess.run(
        [SHELL, "-c", script],
        env={**os.environ, "SPATIUM_FIRSTBOOT_LIB": "1", "SPATIUM_K3S_JOIN_DROPIN": str(dropin),
             "STUB": str(stub)},
        capture_output=True,
        text=True,
        check=False,
    )
    log = stub / "calls.log"
    calls = log.read_text().splitlines() if log.exists() else []
    return proc, calls


def _deleted(calls: list[str]) -> bool:
    return any("delete job helm-install-spatium-bootstrap" in c for c in calls)


def _nudged(calls: list[str]) -> bool:
    return any("annotate replicasets,statefulsets,daemonsets --all" in c for c in calls)


def test_the_class_present_touches_nothing(tmp_path: Path) -> None:
    proc, calls = _run(tmp_path, cls=True)
    assert proc.returncode == 0, proc.stderr
    assert calls == ["kubectl get priorityclass spatium-control-plane -o name"]


def test_an_apiserver_that_did_not_answer_proves_nothing(tmp_path: Path) -> None:
    """Only an explicit NotFound means the class is gone. A refused connection
    re-running the bootstrap release would be acting on a guess."""
    proc, calls = _run(tmp_path, apierr=True)
    assert proc.returncode == 0, proc.stderr
    assert not _deleted(calls) and not _nudged(calls)
    assert len(calls) == 1


def test_a_bootstrap_release_that_is_not_deployed_is_left_alone_quietly(tmp_path: Path) -> None:
    """Every FIRST boot is this case — the release is still installing and
    creates the class itself during the webhook wait. Nothing is re-run and
    nothing is said: a WARN here read as a false alarm on every install (seen
    on the first QA build of this fix), and release_control_manifest already
    speaks if the class is still missing when the chart is released. (A
    failed or interrupted UPGRADE still has a deployed revision — see the
    install-Job test below for that case.)"""
    proc, calls = _run(tmp_path, deployed=False)
    assert proc.returncode == 0, proc.stderr
    assert not _deleted(calls) and not _nudged(calls)
    assert proc.stdout == "" and proc.stderr == ""


def test_the_class_absent_reruns_bootstrap_then_nudges(tmp_path: Path) -> None:
    proc, calls = _run(tmp_path, rerun_after=3)
    assert proc.returncode == 0, proc.stderr
    assert _deleted(calls)
    assert _nudged(calls)
    # The order is the point: the release re-run first, then the wait for the
    # class, and nothing re-queued until the poll that found it.
    delete = next(i for i, c in enumerate(calls) if "delete job" in c)
    polls = [i for i, c in enumerate(calls)
             if c == "kubectl get priorityclass spatium-control-plane"]
    nudge = next(i for i, c in enumerate(calls) if "annotate" in c)
    assert len(polls) == 3
    assert delete < polls[0] and polls[-1] < nudge
    assert "re-running the spatium-bootstrap release" in proc.stdout
    assert "re-created by spatium-bootstrap" in proc.stdout


def test_a_running_bootstrap_job_is_not_deleted(tmp_path: Path) -> None:
    """Deleting a live helm run leaves the release pending-upgrade. The running
    Job re-creates the class on its own; the function only waits for it."""
    proc, calls = _run(tmp_path, job="running", rerun_after=None)
    # nothing re-runs, so the class never appears: the bound is reached
    assert proc.returncode == 0, proc.stderr
    assert not _deleted(calls)
    assert not _nudged(calls)
    assert "has not completed" in proc.stdout
    assert "within 3 min" in proc.stderr


@pytest.mark.parametrize("job", ["retrying", "new", "absent"])
def test_only_a_completed_bootstrap_job_is_rerun(tmp_path: Path, job: str) -> None:
    """The release check cannot see a failed or interrupted upgrade: Helm keeps
    the previous revision ``deployed`` until the next one SUCCEEDS (it records
    the new one ``pending-upgrade``, then ``failed``), while klipper-helm acts
    on the latest. So a Job retrying that upgrade — between attempts it has no
    active pod — would be deleted by a "not running" test, and its re-run would
    fire the reinstall policy in the middle of a boot. The same test would
    delete a Job helm-controller had only just created for a changed chart.
    Only a COMPLETED Job is re-run; anything else is helm-controller's own run
    (and helm-stuck-recover's), and the function only waits, saying so."""
    proc, calls = _run(tmp_path, job=job, rerun_after=None)
    assert proc.returncode == 0, proc.stderr
    assert not _deleted(calls)
    assert not _nudged(calls)
    assert "has not completed" in proc.stdout
    assert "re-running" not in proc.stdout
    assert "within 3 min" in proc.stderr


def test_a_class_that_never_comes_back_falls_through(tmp_path: Path) -> None:
    """Bounded and never fatal: the unranked release that follows is the
    fallback, exactly as before #1123."""
    proc, calls = _run(tmp_path, rerun_after=None)
    assert proc.returncode == 0, proc.stderr
    assert _deleted(calls)
    assert not _nudged(calls)
    polls = [c for c in calls if c == "kubectl get priorityclass spatium-control-plane"]
    assert len(polls) == 36
    assert "within 3 min" in proc.stderr


@pytest.mark.parametrize("member,manifest", [(True, "deferred"), (False, None)])
def test_inert_where_this_node_releases_nothing(tmp_path: Path, member: bool,
                                                 manifest: str | None) -> None:
    """A joined member's releases are the seed's (#590), and an appliance /
    application node has no control chart to protect."""
    proc, calls = _run(tmp_path, member=member, manifest=manifest)
    assert proc.returncode == 0, proc.stderr
    assert calls == []


def test_it_also_runs_when_the_control_chart_was_already_released(tmp_path: Path) -> None:
    """The host-migrate failure path releases before readyz; the class can
    still be put back afterwards, and the unranked chart then installs."""
    proc, calls = _run(tmp_path, manifest="placed")
    assert proc.returncode == 0, proc.stderr
    assert _deleted(calls) and _nudged(calls)


def test_it_runs_between_the_tls_placement_and_the_control_release() -> None:
    """After the namespace exists (the TLS placement waits for it), and before
    the CNPG-webhook wait — the webhook cannot come up while the operator's
    pods are refused, so the class has to be back first."""
    body = SCRIPT.read_text(encoding="utf-8")
    ready = body[body.index('if [ "$ready" = 1 ]; then'):]
    ready = ready[: ready.index("\nfi\n")]
    tls = ready.index("place_deferred_tls_manifest")
    reassert = ready.index(FUNC)
    control = ready.index("place_deferred_control_manifest")
    assert tls < reassert < control
