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
  "--request-timeout=10s -n spatium get daemonset "*)
    ds=$(echo "$args" | awk '{print $6}')
    # kubectl's default: managedFields are omitted unless asked for.
    [ -f "$S/ds_$ds.json" ] || exit 0
    case "$args" in
      *--show-managed-fields*) cat "$S/ds_$ds.json" ;;
      *) python3 -c '
import json, sys
d = json.load(sys.stdin)
d.get("metadata", {}).pop("managedFields", None)
print(json.dumps(d))' < "$S/ds_$ds.json" ;;
    esac
    exit 0 ;;
  "--request-timeout=10s -n spatium patch daemonset "*" --type json -p "*)
    ds=$(echo "$args" | awk '{print $6}')
    printf '%s' "${args#* --type json -p }" > "$S/jsonpatch_$ds.json"
    [ -f "$S/release_fails" ] && exit 1
    exit 0 ;;
  "--request-timeout=30s -n spatium patch daemonset "*)
    ds=$(echo "$args" | awk '{print $6}')
    cp "${args##* }" "$S/patched_ds_$ds.json"
    echo "ds $ds" >> "$S/order.log"
    [ -f "$S/ds_patch_fails" ] && exit 1
    exit 0 ;;
  "--request-timeout=30s -n kube-system patch helmchart spatiumddi-appliance --type merge --patch-file "*)
    cp "${args##* }" "$S/patched.json"
    echo chart >> "$S/order.log"
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


def _run(tmp_path, *, release_fails=False, daemonsets=None, ds_patch_fails=False, hold=False, nodes=1, values=LIVE, apierr=False, patch_fails=False, tag="NEW"):
    stub = tmp_path / "stub"
    stub.mkdir()
    k3s = tmp_path / "k3s"
    k3s.write_text(STUB_K3S)
    k3s.chmod(0o755)
    (stub / "nodes").write_text("".join(f"node/n{i}\n" for i in range(nodes)))
    if values is not None:
        (stub / "values").write_text(yaml.safe_dump(values, default_flow_style=False, sort_keys=False))
    for name, ds in (daemonsets or {}).items():
        (stub / f"ds_{name}.json").write_text(json.dumps(ds))
    for flag, on in (
        ("apierr", apierr),
        ("patch_fails", patch_fails),
        ("ds_patch_fails", ds_patch_fails),
        ("release_fails", release_fails),
    ):
        if on:
            (stub / flag).touch()
    chart = tmp_path / "chart.tgz"
    chart.write_bytes(b"\x1f\x8bchart-bytes")
    state = tmp_path / "state"
    state.mkdir()
    if hold:
        (state / "shared-chart-hold").write_text("{}")
    body = "\n".join(
        _extract_function(f)
        for f in ("release_preroll_ownership", "preroll_role_daemonsets", FUNC)
    ).replace("/usr/local/bin/k3s", str(k3s))
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


def _ds(*images, init=()):
    spec = {"containers": [{"name": f"c{i}", "image": im} for i, im in enumerate(images)]}
    if init:
        spec["initContainers"] = [{"name": f"i{i}", "image": im} for i, im in enumerate(init)]
    return {"spec": {"template": {"spec": spec}}}


def _order(tmp_path):
    return (tmp_path / "stub" / "order.log").read_text().split()


def test_role_daemonsets_move_to_the_new_tag_before_the_chart(tmp_path):
    ds = {
        "dhcp-kea": _ds("reg/kea:OLD"),
        "dns-bind9": _ds("reg/bind:OLD", "reg/sidecar:pinned", init=["reg/init:OLD"]),
    }
    proc, patched, _ = _run(tmp_path, daemonsets=ds)
    assert "rc=0" in proc.stdout, proc.stderr
    stub = tmp_path / "stub"
    kea = json.loads((stub / "patched_ds_dhcp-kea.json").read_text())
    assert kea == {"spec": {"template": {"spec": {"containers": [{"name": "c0", "image": "reg/kea:NEW"}]}}}}
    bind = json.loads((stub / "patched_ds_dns-bind9.json").read_text())["spec"]["template"]["spec"]
    assert bind["containers"] == [{"name": "c0", "image": "reg/bind:NEW"}]  # pinned one untouched
    assert bind["initContainers"] == [{"name": "i0", "image": "reg/init:NEW"}]
    assert not (stub / "patched_ds_dns-powerdns.json").exists()
    # the template moves first, then the chart write that follows
    assert _order(tmp_path)[-1] == "chart" and "ds" in _order(tmp_path)[:-1]
    assert patched is not None


def test_daemonset_already_on_the_tag_is_not_patched(tmp_path):
    _, _, _ = _run(tmp_path, daemonsets={"dhcp-kea": _ds("reg/kea:NEW")})
    assert not (tmp_path / "stub" / "patched_ds_dhcp-kea.json").exists()


def test_no_daemonset_patch_when_the_chart_is_left_alone(tmp_path):
    # cluster / hold / first install: the DaemonSets stay with the supervisor
    ds = {"dhcp-kea": _ds("reg/kea:OLD")}
    for kw in ({"nodes": 3}, {"hold": True}):
        sub = tmp_path / ("c" if "nodes" in kw else "h")
        sub.mkdir()
        _run(sub, daemonsets=ds, **kw)
        assert not (sub / "stub" / "patched_ds_dhcp-kea.json").exists()


def test_daemonset_patch_failure_still_writes_the_chart(tmp_path):
    proc, patched, _ = _run(
        tmp_path, daemonsets={"dhcp-kea": _ds("reg/kea:OLD")}, ds_patch_fails=True
    )
    assert "rc=0" in proc.stdout and "WARN" in proc.stderr and patched is not None


def test_early_call_before_the_readyz_wait():
    text = SCRIPT.read_text(encoding="utf-8")
    early = text.index("get --raw=/livez")
    assert text.index('echo "Waiting for k3s /readyz') < early < text.index("\nready=0\n")
    assert "reconcile_role_chart_tag || true" in text[early : early + 200]


FM = "spatium-firstboot-preroll"


def _managed(*managers):
    return [
        {"manager": m, "operation": op, "apiVersion": "apps/v1", "fieldsType": "FieldsV1"}
        for m, op in managers
    ]


def _apply_json_patch(doc, ops):
    """The two RFC 6902 ops the release uses, as the apiserver applies them."""
    for op in ops:
        *parents, last = op["path"].strip("/").split("/")
        node = doc
        for part in parents:
            node = node[int(part)] if isinstance(node, list) else node[part]
        key = int(last) if isinstance(node, list) else last
        if op["op"] == "test":
            assert node[key] == op["value"]
        else:
            assert op["op"] == "remove"
            del node[key]


def test_preroll_patch_uses_its_own_field_manager(tmp_path):
    _run(tmp_path, daemonsets={"dhcp-kea": _ds("reg/kea:OLD")})
    calls = (tmp_path / "stub" / "calls.log").read_text().splitlines()
    patch = [c for c in calls if "patch daemonset dhcp-kea --field-manager" in c]
    assert patch and f"--field-manager={FM}" in patch[0] and "--type strategic" in patch[0]


def test_preroll_ownership_is_released_so_helm_can_apply_other_images(tmp_path):
    ds = _ds("reg/kea:OLD")
    ds["metadata"] = {
        "managedFields": _managed(
            ("helm", "Apply"),
            ("kube-controller-manager", "Update"),
            (FM, "Update"),
            ("kubectl-patch", "Update"),  # an operator's own, never ours to drop
        )
    }
    proc, _, _ = _run(tmp_path, daemonsets={"dhcp-kea": ds})
    assert "rc=0" in proc.stdout, proc.stderr
    ops = json.loads((tmp_path / "stub" / "jsonpatch_dhcp-kea.json").read_text())
    live = json.loads(json.dumps(ds))
    _apply_json_patch(live, ops)
    left = [e["manager"] for e in live["metadata"]["managedFields"]]
    assert left == ["helm", "kube-controller-manager", "kubectl-patch"]


def test_release_removes_every_entry_highest_index_first(tmp_path):
    ds = _ds("reg/kea:OLD")
    ds["metadata"] = {
        "managedFields": _managed((FM, "Update"), ("helm", "Apply"), (FM, "Update"))
    }
    _run(tmp_path, daemonsets={"dhcp-kea": ds})
    live = json.loads(json.dumps(ds))
    _apply_json_patch(
        live, json.loads((tmp_path / "stub" / "jsonpatch_dhcp-kea.json").read_text())
    )
    assert [e["manager"] for e in live["metadata"]["managedFields"]] == ["helm"]


def test_no_release_patch_when_we_own_nothing_or_release_fails(tmp_path):
    ds = _ds("reg/kea:OLD")
    ds["metadata"] = {"managedFields": _managed(("helm", "Apply"))}
    _run(tmp_path, daemonsets={"dhcp-kea": ds})
    assert not (tmp_path / "stub" / "jsonpatch_dhcp-kea.json").exists()
    sub = tmp_path / "f"
    sub.mkdir()
    ds["metadata"] = {"managedFields": _managed((FM, "Update"))}
    proc, patched, _ = _run(sub, daemonsets={"dhcp-kea": ds}, release_fails=True)
    assert "rc=0" in proc.stdout and "WARN" in proc.stderr and patched is not None


def test_no_managed_fields_or_no_entry_of_ours_is_reported_not_silent(tmp_path):
    ds = _ds("reg/kea:OLD")
    proc, _, _ = _run(tmp_path, daemonsets={"dhcp-kea": ds})
    assert "rc=0" in proc.stdout and "no managedFields" in proc.stderr
    sub = tmp_path / "g"
    sub.mkdir()
    ds["metadata"] = {"managedFields": _managed(("helm", "Apply"))}
    proc, _, _ = _run(sub, daemonsets={"dhcp-kea": ds})
    assert "rc=0" in proc.stdout and f"no managedFields entry for {FM}" in proc.stderr
