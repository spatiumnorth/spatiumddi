"""firstboot moves the role chart onto the booted slot's tag (#3919).

The role release (the supervisor's ``spatiumddi-appliance`` HelmChart) lives in
the datastore, so after a slot upgrade it still carries the previous release's
``global.imageTag`` and chart; k3s starts the role pods from it, and the new
supervisor's first apply, minutes later, rolled them a second time.
``reconcile_role_chart_tag`` writes the booted slot's tag and chart as soon as
k3s answers. These tests drive the real function against a stub ``k3s``.

HOW TO RUN:
    python3 -m pytest appliance/tests/test_firstboot_role_chart_tag.py -v
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from pathlib import Path

import yaml

SCRIPT = (
    Path(__file__).parent.parent / "mkosi.extra" / "usr" / "local" / "bin" / "spatiumddi-firstboot"
)
FUNC = "reconcile_role_chart_tag"
SHELL = shutil.which("dash") or "sh"

STUB_K3S = r"""#!/bin/sh
S="$STUB"
[ "$1" = kubectl ] && shift
args="$*"
echo "$args" >> "$S/calls.log"
case "$args" in
  "--request-timeout=10s get nodes -o name")
    [ -f "$S/apierr" ] && exit 1
    cat "$S/nodes"; exit 0 ;;
  "--request-timeout=10s -n kube-system get helmchart spatiumddi-appliance "*)
    [ -f "$S/apierr" ] && exit 1
    [ -f "$S/values" ] && cat "$S/values"; exit 0 ;;
  "--request-timeout=30s -n kube-system patch helmchart spatiumddi-appliance --type merge --patch-file "*)
    cp "${args##* }" "$S/patched.json"
    [ -f "$S/patch_fails" ] && exit 1
    exit 0 ;;
esac
echo "stub k3s: unexpected: $args" >&2
exit 3
"""

LIVE = {
    "global": {"imageTag": "OLD", "imagePullPolicy": "Never"},
    "dhcpKea": {"enabled": True, "agentKey": "k"},
}


def _extract_function(name: str) -> str:
    lines = SCRIPT.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        if line == f"{name}() {{":
            break
    else:
        raise AssertionError(f"{name}() not found")
    for j in range(i + 1, len(lines)):
        if lines[j] == "}":
            return "\n".join(lines[i : j + 1])
    raise AssertionError("no closing brace")


def _run(tmp_path, *, hold=False, nodes=1, values=LIVE, apierr=False, patch_fails=False, tag="NEW"):
    stub = tmp_path / "stub"
    stub.mkdir()
    k3s = tmp_path / "k3s"
    k3s.write_text(STUB_K3S)
    k3s.chmod(0o755)
    (stub / "nodes").write_text("".join(f"node/n{i}\n" for i in range(nodes)))
    if values is not None:
        (stub / "values").write_text(yaml.safe_dump(values, default_flow_style=False, sort_keys=False))
    for flag, on in (("apierr", apierr), ("patch_fails", patch_fails)):
        if on:
            (stub / flag).touch()
    chart = tmp_path / "chart.tgz"
    chart.write_bytes(b"\x1f\x8bchart-bytes")
    state = tmp_path / "state"
    state.mkdir()
    if hold:
        (state / "shared-chart-hold").write_text("{}")
    body = _extract_function(FUNC).replace("/usr/local/bin/k3s", str(k3s))
    script = (
        f'. "{SCRIPT}"\nset -eu\n'
        f'CHART_TGZ="{chart}"\nSPATIUMDDI_VERSION="{tag}"\n'
        f"{body}\n{FUNC}\necho rc=$?\n"
    )
    proc = subprocess.run(
        [SHELL, "-c", script],
        env={
            **os.environ,
            "SPATIUM_FIRSTBOOT_LIB": "1",
            "STUB": str(stub),
            "SUPERVISOR_STATE_DIR": str(state),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    pj = stub / "patched.json"
    patched = json.loads(pj.read_text()) if pj.exists() else None
    return proc, patched, chart


def test_old_tag_is_replaced_and_chart_follows(tmp_path):
    proc, patched, chart = _run(tmp_path)
    assert "rc=0" in proc.stdout, proc.stderr
    assert patched is not None
    values = yaml.safe_load(patched["spec"]["valuesContent"])
    assert values["global"]["imageTag"] == "NEW"
    assert values["dhcpKea"] == LIVE["dhcpKea"]  # supervisor-owned keys untouched
    assert base64.b64decode(patched["spec"]["chartContent"]) == chart.read_bytes()
    # byte-identical to the supervisor's own dump, so its later apply is a no-op
    want = dict(LIVE, **{"global": dict(LIVE["global"], imageTag="NEW")})
    assert patched["spec"]["valuesContent"] == yaml.safe_dump(
        want, default_flow_style=False, sort_keys=False
    )


def test_rollback_writes_the_older_tag(tmp_path):
    proc, patched, _ = _run(tmp_path, values=dict(LIVE, **{"global": {"imageTag": "NEW"}}), tag="OLD")
    assert yaml.safe_load(patched["spec"]["valuesContent"])["global"]["imageTag"] == "OLD"


def test_already_on_tag_writes_nothing(tmp_path):
    proc, patched, _ = _run(tmp_path, tag="OLD")
    assert "rc=0" in proc.stdout and patched is None


def test_cluster_is_left_to_the_supervisor(tmp_path):
    proc, patched, _ = _run(tmp_path, nodes=3)
    assert "rc=0" in proc.stdout and patched is None


def test_recorded_rolling_upgrade_hold_is_respected(tmp_path):
    proc, patched, _ = _run(tmp_path, hold=True)
    assert "rc=0" in proc.stdout and patched is None


def test_no_helmchart_yet_first_install(tmp_path):
    proc, patched, _ = _run(tmp_path, values=None)
    assert "rc=0" in proc.stdout and patched is None


def test_apiserver_down_is_never_fatal(tmp_path):
    proc, patched, _ = _run(tmp_path, apierr=True)
    assert "rc=0" in proc.stdout and patched is None and "WARN" in proc.stderr


def test_patch_failure_is_never_fatal(tmp_path):
    proc, _, _ = _run(tmp_path, patch_fails=True)
    assert "rc=0" in proc.stdout and "WARN" in proc.stderr


def test_wired_in_ahead_of_the_bootstrap_release():
    text = SCRIPT.read_text(encoding="utf-8")
    call = text.index("    reconcile_role_chart_tag || true\n")
    assert call < text.index("    release_bootstrap_manifest || true\n    trap - EXIT TERM")
