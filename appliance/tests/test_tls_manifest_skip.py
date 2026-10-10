"""k3s no longer puts the first-boot Web UI certificate back when it starts (#1215).

k3s re-applies every manifest in ``server/manifests`` each time it starts.
``spatium-appliance-tls.yaml`` holds the self-signed certificate firstboot
minted on the seed's first boot, so every k3s start on the seed wrote that
certificate back over the one the api had deployed into the
``spatium-appliance-tls`` Secret: an uploaded, CSR-signed or ACME one. On a
single node the api does not restart with k3s (``KillMode=process`` keeps the
pods), so the revert stayed until the api next restarted; on any node the api's
write-back then rolled every frontend pod (#1282).

The manifest's one job is to create the Secret. The api never creates it (its
RBAC has no create, by design) and adopts whatever it finds there, so once
the Secret exists a ``.skip`` beside the manifest tells k3s to leave it alone.
k3s keeps the Addon and the Secret as they are; deleting the manifest instead
would make k3s delete the Secret with it. Three places carry the marker, and
these tests drive each of them as a shell run:

  * firstboot writes it on every boot once the Secret exists, and creates the
    Secret from the manifest if a marker ever stands in front of a missing one
    (k3s never applies a skipped manifest);
  * ``spatium-tls-manifest-skip`` (a k3s.service ExecStartPre) writes it before
    k3s starts on a seed that finished its first boot on an earlier boot: the
    first boot of a slot upgraded from a build without the fix, which would
    otherwise revert the certificate once more before firstboot got there;
  * a cluster leave drops it, because the datastore it starts k3s on is new
    and holds no Secret for the marker to protect.

The shell runs use ``dash`` where the script is ``sh`` (as on the appliance),
so a bashism fails here rather than on a boot.

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_tls_manifest_skip.py -v

No k3s, no appliance required.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

BIN = Path(__file__).parent.parent / "mkosi.extra" / "usr" / "local" / "bin"
FIRSTBOOT = BIN / "spatiumddi-firstboot"
RUNNER = BIN / "spatium-tls-manifest-skip"
CLUSTER_JOIN = BIN / "spatium-cluster-join"
UNIT = Path(__file__).parent.parent / "mkosi.extra" / "etc" / "systemd" / "system" / "k3s.service"
FUNC = "skip_tls_manifest_reapply"
SHELL = shutil.which("dash") or "sh"
MANIFEST = "spatium-appliance-tls.yaml"
LEAVE_CONFIRM = "SPATIUMDDI-CLUSTER-LEAVE-CONFIRM-V1"

# The stub apiserver for firstboot's function. State lives in files under
# $STUB: ``secret`` = the Secret exists, ``apierr`` = the apiserver is down,
# ``appears_after`` = the poll at which k3s's addon deployer has created it,
# ``create_fails`` = ``kubectl create`` is refused.
STUB_K3S = r"""#!/bin/sh
S="$STUB"
echo "$*" >> "$S/calls.log"
[ "$1" = kubectl ] && shift
case "$*" in
  "-n spatium get secret spatium-appliance-tls -o name")
    if [ -f "$S/apierr" ]; then
      echo "The connection to the server 127.0.0.1:6443 was refused" >&2; exit 1
    fi
    n=$(cat "$S/polls" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$S/polls"
    if [ -f "$S/appears_after" ] && [ "$n" -ge "$(cat "$S/appears_after")" ]; then
      touch "$S/secret"
    fi
    if [ -f "$S/secret" ]; then echo "secret/spatium-appliance-tls"; exit 0; fi
    echo 'Error from server (NotFound): secrets "spatium-appliance-tls" not found' >&2
    exit 1 ;;
  "create -f "*)
    if [ -f "$S/create_fails" ]; then echo "error: refused" >&2; exit 1; fi
    touch "$S/secret"; exit 0 ;;
esac
echo "stub k3s: unexpected: $*" >&2
exit 3
"""


def _extract_function(name: str) -> str:
    """The shell source of a top-level ``name() { ... }`` (closing brace at column 0)."""
    lines = FIRSTBOOT.read_text(encoding="utf-8").splitlines()
    opener = f"{name}() {{"
    for i, line in enumerate(lines):
        if line == opener:
            break
    else:  # pragma: no cover - the assert below is the real reporter
        raise AssertionError(f"{name}() not found in {FIRSTBOOT} (renamed?)")
    for j in range(i + 1, len(lines)):
        if lines[j] == "}":
            return "\n".join(lines[i : j + 1])
    raise AssertionError(f"{name}() has no closing brace at column 0")


def _firstboot(tmp_path: Path, *, secret: bool = True, apierr: bool = False,
               appears_after: int | None = None, create_fails: bool = False,
               manifest: str | None = "placed", skip: bool = False,
               member: bool = False) -> tuple[subprocess.CompletedProcess, list[str], Path]:
    stub = tmp_path / "stub"
    stub.mkdir()
    k3s = tmp_path / "k3s"
    k3s.write_text(STUB_K3S)
    k3s.chmod(0o755)
    for flag, on in (("secret", secret), ("apierr", apierr), ("create_fails", create_fails)):
        if on:
            (stub / flag).touch()
    if appears_after is not None:
        (stub / "appears_after").write_text(str(appears_after))
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    tls = manifests / MANIFEST
    if manifest == "placed":
        tls.write_text("kind: Secret\n")
    elif manifest == "deferred":
        Path(f"{tls}.deferred").write_text("kind: Secret\n")
    if skip:
        Path(f"{tls}.skip").touch()
    dropin = tmp_path / "spatium-cluster.yaml"
    if member:
        dropin.write_text("server: https://10.0.0.1:6443\n")
    body = _extract_function(FUNC).replace("/usr/local/bin/k3s", str(k3s))
    script = (
        f'. "{FIRSTBOOT}"\n'                    # the lib half: node_is_cluster_member & co.
        f'TLS_CERT_MANIFEST="{tls}"\n'
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
    return proc, calls, Path(f"{tls}.skip")


GET = "kubectl -n spatium get secret spatium-appliance-tls -o name"


def _created(calls: list[str]) -> bool:
    return any(c.startswith("kubectl create -f ") for c in calls)


# ── firstboot ────────────────────────────────────────────────────────────────


def test_an_existing_secret_gets_the_marker(tmp_path: Path) -> None:
    proc, calls, skip = _firstboot(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert skip.exists()
    assert calls == [GET]
    assert "#1215" in proc.stdout


def test_the_marker_waits_for_k3s_to_create_the_secret(tmp_path: Path) -> None:
    """A first boot: k3s's addon deployer applies the placed manifest on its
    next scan. Skipped before that, it would never be applied at all."""
    proc, calls, skip = _firstboot(tmp_path, secret=False, appears_after=3)
    assert proc.returncode == 0, proc.stderr
    assert skip.exists()
    assert calls == [GET] * 3
    assert not _created(calls)


def test_a_secret_k3s_has_not_created_is_left_to_k3s(tmp_path: Path) -> None:
    """Bounded and never fatal: no marker, so k3s still applies the manifest,
    exactly as before #1215. Nothing creates the Secret behind k3s's back."""
    proc, calls, skip = _firstboot(tmp_path, secret=False)
    assert proc.returncode == 0, proc.stderr
    assert not skip.exists()
    assert calls == [GET] * 24
    assert not _created(calls)
    assert "WARN" in proc.stderr


def test_an_apiserver_that_does_not_answer_proves_nothing(tmp_path: Path) -> None:
    """Only a Secret read back counts as existing, and only an explicit
    NotFound as missing. A refused connection is neither."""
    proc, calls, skip = _firstboot(tmp_path, apierr=True)
    assert proc.returncode == 0, proc.stderr
    assert not skip.exists()
    assert not _created(calls)
    assert len(calls) == 24
    assert "WARN" in proc.stderr


def test_an_apiserver_that_does_not_answer_creates_nothing(tmp_path: Path) -> None:
    proc, calls, skip = _firstboot(tmp_path, apierr=True, skip=True)
    assert proc.returncode == 0, proc.stderr
    assert skip.exists()
    assert not _created(calls)


def test_a_marker_with_no_secret_behind_it_creates_the_secret(tmp_path: Path) -> None:
    """k3s never applies a skipped manifest, so waiting for it would be waiting
    for nothing and the Web UI would have no certificate. Create the Secret
    from the manifest, as k3s's next start used to, and keep the marker."""
    proc, calls, skip = _firstboot(tmp_path, secret=False, skip=True)
    assert proc.returncode == 0, proc.stderr
    assert calls[0] == GET
    assert calls[1] == f"kubectl create -f {tmp_path / 'manifests' / MANIFEST}"
    assert len(calls) == 2
    assert skip.exists()
    assert "missing" in proc.stderr


def test_a_refused_create_is_retried_then_left(tmp_path: Path) -> None:
    proc, calls, skip = _firstboot(tmp_path, secret=False, skip=True, create_fails=True)
    assert proc.returncode == 0, proc.stderr
    assert sum(1 for c in calls if c.startswith("kubectl create -f ")) == 24
    assert "WARN" in proc.stderr


def test_an_existing_marker_is_left_as_it_is(tmp_path: Path) -> None:
    proc, calls, skip = _firstboot(tmp_path, skip=True)
    assert proc.returncode == 0, proc.stderr
    assert skip.exists()
    assert calls == [GET]
    assert proc.stdout == "" and proc.stderr == ""


@pytest.mark.parametrize("member,manifest", [(True, "placed"), (False, "deferred"), (False, None)])
def test_inert_where_this_node_owns_no_placed_manifest(tmp_path: Path, member: bool,
                                                      manifest: str | None) -> None:
    """A joined member's Secret is the seed's (#590); a staged manifest has not
    been handed to k3s yet (#994)."""
    proc, calls, skip = _firstboot(tmp_path, member=member, manifest=manifest)
    assert proc.returncode == 0, proc.stderr
    assert calls == []
    assert not skip.exists()


def test_it_runs_on_the_ready_path_after_both_placements() -> None:
    """After the TLS manifest is placed and after the control chart's webhook
    wait, by when k3s applied the TLS manifest long ago on a first boot, and
    before the slot commit, which can end the run."""
    body = FIRSTBOOT.read_text(encoding="utf-8")
    ready = body[body.index('if [ "$ready" = 1 ]; then'):]
    ready = ready[: ready.index("\nfi\n")]
    tls = ready.index("place_deferred_tls_manifest")
    control = ready.index("place_deferred_control_manifest")
    skip = ready.index(f"\n    {FUNC}\n")
    commit = ready.index("slot_images_allow_commit")
    assert tls < control < skip < commit


# ── spatium-tls-manifest-skip (k3s.service ExecStartPre) ─────────────────────

BOOTED = 1_760_000_000


def _runner(tmp_path: Path, *, manifest: bool = True, skip: bool = False,
            stamp: str | None = "earlier", datastore: bool = True,
            btime: bool = True) -> tuple[subprocess.CompletedProcess, Path]:
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    tls = manifests / MANIFEST
    if manifest:
        tls.write_text("kind: Secret\n")
    marker = Path(f"{tls}.skip")
    if skip:
        marker.touch()
    db = tmp_path / "db"
    if datastore:
        db.mkdir()
    proc_stat = tmp_path / "stat"
    proc_stat.write_text(
        "cpu  10 0 10 100 0 0 0 0 0 0\n"
        + (f"btime {BOOTED}\n" if btime else "")
        + "processes 100\n"
    )
    done = tmp_path / "firstboot.done"
    if stamp is not None:
        done.write_text("2026-10-01T00:00:00+00:00\n")
        at = BOOTED - 3600 if stamp == "earlier" else BOOTED + 60
        os.utime(done, (at, at))
    proc = subprocess.run(
        [SHELL, str(RUNNER)],
        env={**os.environ,
             "SPATIUM_K3S_MANIFESTS_DIR": str(manifests),
             "SPATIUM_K3S_DB_DIR": str(db),
             "SPATIUM_FIRSTBOOT_STAMP": str(done),
             "SPATIUM_PROC_STAT": str(proc_stat)},
        capture_output=True,
        text=True,
        check=False,
    )
    return proc, marker


def test_an_upgraded_seed_is_skipped_before_k3s_starts(tmp_path: Path) -> None:
    """The first boot of a slot upgraded from a build without the fix: the
    seed finished its first boot long ago, so the Secret is in the datastore
    and holds the api's certificate. Skip the manifest before k3s applies it."""
    proc, marker = _runner(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert marker.exists()
    assert "#1215" in proc.stdout


@pytest.mark.parametrize(
    "case,kwargs",
    [
        # a joined member (the seed owns the Secret), or a first boot before
        # firstboot placed the staged manifest
        ("no placed manifest", {"manifest": False}),
        # k3s's first start on a fresh install: no boot has finished firstboot
        ("no first boot finished", {"stamp": None}),
        # a k3s restart during a first boot: the manifest may have been placed
        # moments ago and not applied yet
        ("first boot finished on this boot", {"stamp": "this-boot"}),
        # the fresh datastore a cluster leave starts k3s on (spatium-cluster-join)
        ("no datastore", {"datastore": False}),
        # no boot time to compare with: every doubt leaves the manifest to k3s
        ("no boot time", {"btime": False}),
    ],
)
def test_every_doubt_leaves_the_manifest_to_k3s(tmp_path: Path, case: str, kwargs: dict) -> None:
    """A marker on a datastore that does not hold the Secret would leave the
    Web UI with no certificate. The cost of not writing one is the behaviour
    before #1215 for one more start."""
    proc, marker = _runner(tmp_path, **kwargs)
    assert proc.returncode == 0, (case, proc.stderr)
    assert not marker.exists(), case


def test_an_existing_marker_is_not_touched(tmp_path: Path) -> None:
    proc, marker = _runner(tmp_path, skip=True)
    assert proc.returncode == 0, proc.stderr
    assert marker.exists()
    assert proc.stdout == ""


def test_k3s_runs_it_before_it_starts() -> None:
    """In the main unit, which a slot upgrade carries (a drop-in would be left
    behind), ahead of ExecStart, and never able to stop k3s from starting."""
    lines = [ln.strip() for ln in UNIT.read_text().splitlines()]
    pre = "ExecStartPre=-/usr/local/bin/spatium-tls-manifest-skip"
    assert pre in lines
    assert lines.index(pre) < lines.index("ExecStart=/usr/local/bin/k3s server")


# ── spatium-cluster-join ─────────────────────────────────────────────────────


def test_a_leave_starts_k3s_with_the_manifest_unskipped(tmp_path: Path) -> None:
    """The seed's manifests come back from aside with the marker firstboot put
    beside the TLS manifest, but the datastore the leave starts k3s on is new
    and holds no Secret. The leave drops the marker, and the ExecStartPre at
    that start does not put it back."""
    server = tmp_path / "k3s" / "server"
    manifests = server / "manifests"
    manifests.mkdir(parents=True)
    (server / "db" / "etcd").mkdir(parents=True)        # the cluster's datastore
    agent = tmp_path / "k3s" / "agent"
    (agent / "images").mkdir(parents=True)
    release_state = tmp_path / "release-state"
    aside = release_state / "manifests-joined-aside"
    aside.mkdir(parents=True)
    for name in (MANIFEST, f"{MANIFEST}.skip", "spatium-bootstrap.yaml"):
        (aside / name).write_text("# aside\n")
    (release_state / "cluster-leave-pending").write_text(f"{LEAVE_CONFIRM}\n")
    config = tmp_path / "config.yaml"
    config.write_text("server: https://10.0.0.1:6443\ntoken: x\n")
    (tmp_path / "log").mkdir()
    done = tmp_path / "firstboot.done"
    done.write_text("2026-10-01T00:00:00+00:00\n")
    os.utime(done, (BOOTED - 3600, BOOTED - 3600))
    proc_stat = tmp_path / "stat"
    proc_stat.write_text(f"btime {BOOTED}\n")
    started = tmp_path / "k3s-started-with"
    stubs = (
        # systemd runs the ExecStartPre lines, then k3s: record what k3s sees
        "systemctl() {\n"
        '  if [ "$1" = start ]; then\n'
        f'    {SHELL} "{RUNNER}"\n'
        f'    ls -a "$K3S_SERVER_DIR/manifests" > "{started}"\n'
        "  fi\n"
        "  return 0\n"
        "}\n"
        "wait_ready() { return 0; }\n"
        "clean_k3s_runtime() { :; }\n"
    )
    proc = subprocess.run(
        ["bash", "-c", f'source "{CLUSTER_JOIN}"\n{stubs}do_leave'],
        env={**os.environ,
             "SPATIUM_CLUSTER_JOIN_LIB": "1",
             "SPATIUM_RELEASE_STATE": str(release_state),
             "SPATIUM_K3S_SERVER_DIR": str(server),
             "SPATIUM_K3S_AGENT_DIR": str(agent),
             "SPATIUM_K3S_NODE_PASSWORD": str(tmp_path / "node" / "password"),
             "SPATIUM_K3S_KUBECONFIG": str(tmp_path / "k3s.yaml"),
             "SPATIUM_K3S_CONFIG": str(config),
             "SPATIUM_K3S_DROPIN_DIR": str(tmp_path / "config.yaml.d"),
             "SPATIUM_LOG_DIR": str(tmp_path / "log"),
             "SPATIUM_FLANNEL_SUBNET_ENV": str(tmp_path / "flannel" / "subnet.env"),
             "SPATIUM_CNI_NETWORKS_DIR": str(tmp_path / "cni" / "networks"),
             # the ExecStartPre, pointed at the same tree
             "SPATIUM_K3S_MANIFESTS_DIR": str(manifests),
             "SPATIUM_K3S_DB_DIR": str(server / "db"),
             "SPATIUM_FIRSTBOOT_STAMP": str(done),
             "SPATIUM_PROC_STAT": str(proc_stat)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    seen = started.read_text().split()
    assert MANIFEST in seen and "spatium-bootstrap.yaml" in seen
    assert f"{MANIFEST}.skip" not in seen
    assert not (manifests / f"{MANIFEST}.skip").exists()


def test_a_failed_join_keeps_the_marker() -> None:
    """Its rollback restores the node's own datastore, which still holds the
    Secret, together with the manifests and their marker. Only the leave,
    which starts a new datastore, may drop it."""
    body = CLUSTER_JOIN.read_text(encoding="utf-8")
    join = body[body.index("do_join() {"):body.index("do_leave() {")]
    leave = body[body.index("do_leave() {"):]
    leave = leave[: leave.index("\n}\n")]
    assert f'rm -f "$K3S_MANIFESTS/{MANIFEST}.skip"' not in join
    restore = leave.index('mv -f "$MANIFESTS_ASIDE"/*.yaml* "$K3S_MANIFESTS/"')
    drop = leave.index(f'rm -f "$K3S_MANIFESTS/{MANIFEST}.skip"')
    start = leave.index("systemctl start k3s")
    assert restore < drop < start
