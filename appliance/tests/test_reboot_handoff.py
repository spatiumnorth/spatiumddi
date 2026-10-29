"""A Fleet reboot hands the PostgreSQL primary off before the node goes (#2849).

The kubelet's graceful node shutdown (#1976) stops CloudNativePG's primary
with the node's other pods, and CNPG fails over only once it has stopped,
while the node itself shuts down. On a QA cluster the API through the other
nodes failed for 24 to 69 s, and still for up to 44 s with the primary's
shutdown bounded to 15 s (#2878).

spatiumddi-reboot-agent now runs spatium-reboot-handoff --before-reboot
before ``systemctl reboot``: when this node holds a Cluster's current primary
and CNPG can switch over, it cordons the node (marked with an annotation) and
waits, bounded, until CNPG has switched the primary over to another node and
the -rw Service lists it, and then until the old primary runs again as a ready
standby: CNPG finishes demoting it only once it reaches the new primary through
that Service, and on a QA cluster a reboot issued at that moment stopped it in
the middle (it came back through crash recovery, stack walk dev-8d394e6).
spatiumddi-reboot-handoff.service runs --at-boot and
uncordons the node only when that annotation is on it, by a JSON patch that
tests the annotation and carries no resourceVersion, tried again until its
budget is spent: at boot k3s writes the Node for seconds, and on a QA rig
three merge patches carrying the resourceVersion they had read all lost to
those writes. These tests keep the unit and the agent's wiring honest and run
the real runner against a stub kubectl: when it cordons and when it must not,
what it waits for, that it never holds the reboot past its budget, and that it
uncordons only its own cordon, whatever else writes the Node meanwhile.

    python3 -m pytest appliance/tests/test_reboot_handoff.py -v

No k3s, no appliance required.
"""

from __future__ import annotations

import configparser
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
EXTRA = REPO / "appliance" / "mkosi.extra"
UNIT_DIR = EXTRA / "etc" / "systemd" / "system"
UNIT = UNIT_DIR / "spatiumddi-reboot-handoff.service"
K3S_UNIT = UNIT_DIR / "k3s.service"
SCRIPT = EXTRA / "usr" / "local" / "bin" / "spatium-reboot-handoff"
AGENT = EXTRA / "usr" / "local" / "bin" / "spatiumddi-reboot-agent"
POSTINST = REPO / "appliance" / "mkosi.postinst"

pytestmark = pytest.mark.skipif(not UNIT.is_file(), reason="appliance tree not present")

NODE = "ddipg-seed"
OTHER = "ddipg-member-1"
THIRD = "ddipg-member-2"
NS = "spatium"
CL = "spatium-control-spatiumddi-postgresql"
ANN = "spatium.io/reboot-cordoned"

# A stand-in for `k3s kubectl`, served from a JSON state file: readyz (fails
# while api_down_polls > 0), the Clusters, instance pods by label selector,
# EndpointSlices by service name, the Node, and a merge or JSON patch of the
# Node applied as the apiserver applies it: to the Node as it is when the patch
# lands, a merge patch failing when the resourceVersion it carries is no longer
# the Node's, a JSON patch failing, and changing nothing, when one of its
# operations does not hold. Before the next `other_writes` patches someone else
# (k3s, its supervisor, the kubelet) writes the Node; the next
# `failing_patches` fail as `patch_error`; `lost_answers` land but answer as a
# timeout. `switch` plays CNPG: once the Node is unschedulable and the Cluster
# has been read `after_gets` times, the primary moves to `to`; the -rw slice
# follows after `slice_after_gets` reads. The old primary's postgres container
# starts again (CNPG demotes it) after `restart_after_gets` reads, not ready,
# and is ready again (a standby) after `ready_after_gets`; until it starts
# again, its pod reads as it did before the switch.
FAKE_KUBECTL = r'''
import json, os, sys, time
ANN = "spatium.io/reboot-cordoned"
path = os.environ["FAKE_KUBECTL_STATE"]
st = json.load(open(path))
args = [a for a in sys.argv[1:] if not a.startswith("--request-timeout")]
st.setdefault("calls", []).append(args)
def save():
    json.dump(st, open(path, "w"))
def out(obj):
    save()
    print(json.dumps(obj))
    sys.exit(0)
def err(msg):
    save()
    print(msg, file=sys.stderr)
    sys.exit(1)
def match(labels, sel):
    return all((labels or {}).get(k) == v for k, v in (p.split("=", 1) for p in sel.split(",")))
def postgres_of(name):
    for p in st["pods"]:
        if p["metadata"]["name"] == name:
            for c in p.setdefault("status", {}).setdefault("containerStatuses", []):
                if c.get("name") == "postgres":
                    return c
    return None
def play_cnpg():
    sw = st.get("switch")
    if not sw or not (st["node"] or {}).get("spec", {}).get("unschedulable"):
        return
    st["cluster_gets"] = st.get("cluster_gets", 0) + 1
    n = st["cluster_gets"]
    if n >= sw["after_gets"] and not sw.get("done"):
        sw["done"] = True
        sw["from"] = st["clusters"][0]["status"]["currentPrimary"]
        for c in st["clusters"]:
            c["status"]["currentPrimary"] = c["status"]["targetPrimary"] = sw["to"]
        for p in st["pods"]:
            role = "primary" if p["metadata"]["name"] == sw["to"] else "replica"
            p["metadata"]["labels"]["cnpg.io/instanceRole"] = role
    if n >= sw.get("slice_after_gets", sw["after_gets"]) and sw.get("done"):
        node_of = {p["metadata"]["name"]: p["spec"]["nodeName"] for p in st["pods"]}
        for s in st["slices"]:
            s["endpoints"] = [{"targetRef": {"kind": "Pod", "name": sw["to"]},
                               "nodeName": node_of[sw["to"]], "conditions": {"ready": True}}]
    old = postgres_of(sw.get("from") or "")
    if old is not None and n >= sw.get("restart_after_gets", sw["after_gets"]) \
            and not sw.get("restarted"):
        sw["restarted"] = True
        old["ready"] = False
        old["state"] = {"running": {"startedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                                 time.gmtime())}}
    if old is not None and sw.get("restarted") and n >= sw.get(
            "ready_after_gets", sw.get("slice_after_gets", sw["after_gets"])):
        old["ready"] = True
if args[:2] == ["get", "--raw=/readyz"]:
    if st.get("api_down_polls", 0) > 0:
        st["api_down_polls"] -= 1
        err("The connection to the server 127.0.0.1:6443 was refused")
    save()
    print("ok")
    sys.exit(0)
if args[0] == "get":
    if args[-2:] == ["-o", "json"]:
        args = args[:-2]
    kind = args[1]
    ns = args[args.index("-n") + 1] if "-n" in args else None
    sel = args[args.index("-l") + 1] if "-l" in args else None
    if kind == "clusters.postgresql.cnpg.io":
        if st.get("no_crd"):
            err('error: the server doesn\'t have a resource type "clusters"')
        if "--all-namespaces" in args:
            out({"items": st["clusters"]})
        play_cnpg()
        for c in st["clusters"]:
            if (c["metadata"]["namespace"], c["metadata"]["name"]) == (ns, args[4]):
                out(c)
        err('Error from server (NotFound): clusters.postgresql.cnpg.io "%s" not found' % args[4])
    if kind == "pods":
        out({"items": [p for p in st["pods"] if p["metadata"]["namespace"] == ns
                       and match(p["metadata"].get("labels"), sel)]})
    if kind == "endpointslices.discovery.k8s.io":
        out({"items": [s for s in st["slices"] if s["metadata"]["namespace"] == ns
                       and match(s["metadata"].get("labels"), sel)]})
    if kind == "node":
        if st["node"] is None or st["node"]["metadata"]["name"] != args[2]:
            err('Error from server (NotFound): nodes "%s" not found' % args[2])
        out(st["node"])
def bump(node):
    node["metadata"]["resourceVersion"] = str(int(node["metadata"]["resourceVersion"]) + 1)
def json_patch(doc, ops):
    doc = json.loads(json.dumps(doc))
    for op in ops:
        *parents, key = [p.replace("~1", "/").replace("~0", "~")
                         for p in op["path"].lstrip("/").split("/")]
        cur = doc
        for p in parents:
            if not isinstance(cur, dict) or p not in cur:
                raise ValueError("missing path: %s" % op["path"])
            cur = cur[p]
        if op["op"] == "test":
            if cur.get(key) != op["value"]:
                raise ValueError("testing value %s failed" % op["path"])
        elif op["op"] == "remove":
            if key not in cur:
                raise ValueError("unable to remove nonexistent key %s" % op["path"])
            del cur[key]
        elif op["op"] == "replace":
            if key not in cur:
                raise ValueError("replace: doc is missing key %s" % op["path"])
            cur[key] = op["value"]
        elif op["op"] == "add":
            cur[key] = op["value"]
        else:
            raise ValueError("unexpected op %s" % op["op"])
    return doc
if args[:2] == ["patch", "node"]:
    ptype = next(a for a in args if a.startswith("--type=")).split("=", 1)[1]
    body = json.loads(args[args.index("-p") + 1])
    st.setdefault("patches", []).append(body)
    st.setdefault("patch_types", []).append(ptype)
    node = st["node"]
    if node is None:
        err('Error from server (NotFound): nodes "%s" not found' % args[2])
    if st.get("other_writes", 0) > 0:
        st["other_writes"] -= 1
        node["metadata"].setdefault("labels", {})["k3s.io/written"] = node["metadata"]["resourceVersion"]
        bump(node)
    if st.get("cordon_before_patch"):
        st["cordon_before_patch"] = False
        node["spec"]["unschedulable"] = True
        bump(node)
    if st.get("drop_mark_before_patch"):
        st["drop_mark_before_patch"] = False
        node["metadata"]["annotations"].pop(ANN, None)
        bump(node)
    if st.get("restamp_before_patch"):
        node["metadata"]["annotations"][ANN] = st.pop("restamp_before_patch")
        bump(node)
    if st.get("failing_patches", 0) > 0:
        st["failing_patches"] -= 1
        err(st.get("patch_error") or "Error from server (InternalError): Internal error "
            "occurred: etcdserver: request timed out")
    if ptype == "merge":
        want = (body.get("metadata") or {}).get("resourceVersion")
        if want and want != node["metadata"]["resourceVersion"]:
            err('Error from server (Conflict): Operation cannot be fulfilled on nodes "%s": the '
                'object has been modified; please apply your changes to the latest version '
                'and try again' % args[2])
        anns = node["metadata"].setdefault("annotations", {})
        for k, v in ((body.get("metadata") or {}).get("annotations") or {}).items():
            if v is None:
                anns.pop(k, None)
            else:
                anns[k] = v
        for k, v in (body.get("spec") or {}).items():
            node.setdefault("spec", {})[k] = v
    elif ptype == "json":
        try:
            node = st["node"] = json_patch(node, body)
        except ValueError as ex:
            st.setdefault("refused", []).append(str(ex))
            # k3s v1.36.5's kubectl, word for word, for a test that fails
            err("The request is invalid: the server rejected our request due to an error "
                "in our request")
    else:
        err("fake kubectl: unexpected patch type %s" % ptype)
    if node["spec"].get("unschedulable") is False:
        del node["spec"]["unschedulable"]  # omitempty, as the apiserver stores it
    bump(node)
    if st.get("lost_answers", 0) > 0:
        st["lost_answers"] -= 1
        err("Unable to connect to the server: net/http: request canceled (Client.Timeout "
            "exceeded while awaiting headers)")
    out(node)
save()
print("fake kubectl: unexpected call %r" % (args,), file=sys.stderr)
sys.exit(2)
'''


def _cluster(primary: str = f"{CL}-1", *, target: str | None = None, instances: int = 3,
             ready: int = 3) -> dict:
    return {
        "metadata": {"namespace": NS, "name": CL},
        "spec": {"instances": instances},
        "status": {"currentPrimary": primary, "targetPrimary": target or primary,
                   "readyInstances": ready},
    }


#: When the instances' postgres containers last started: long before any handoff.
LONG_AGO = "2026-10-27T00:00:00Z"


def _ipod(n: int, node: str, role: str, *, started: str | None = LONG_AGO,
          ready: bool = True) -> dict:
    """An instance pod; its postgres container running since `started` (not
    running when None), ready or not."""
    state = {"running": {"startedAt": started}} if started else {"waiting": {"reason": "x"}}
    return {
        "metadata": {"namespace": NS, "name": f"{CL}-{n}",
                     "labels": {"cnpg.io/cluster": CL, "cnpg.io/podRole": "instance",
                                "cnpg.io/instanceRole": role}},
        "spec": {"nodeName": node},
        "status": {
            "initContainerStatuses": [{"name": "bootstrap-controller", "ready": True,
                                       "state": {"terminated": {"exitCode": 0}}}],
            "containerStatuses": [{"name": "postgres", "ready": ready, "state": state}],
        },
    }


def _ep(pod: str, node: str, ready: bool | None = True) -> dict:
    ep: dict = {"targetRef": {"kind": "Pod", "name": pod}, "nodeName": node}
    if ready is not None:
        ep["conditions"] = {"ready": ready}
    return ep


def _slice(*eps: dict) -> dict:
    return {"metadata": {"namespace": NS, "name": f"{CL}-rw-x7k2p",
                         "labels": {"kubernetes.io/service-name": f"{CL}-rw"}},
            "endpoints": list(eps)}


def _node(*, unschedulable: bool = False, ours: bool = False) -> dict:
    node: dict = {"metadata": {"name": NODE, "resourceVersion": "100", "annotations": {}},
                  "spec": {}}
    if unschedulable:
        node["spec"]["unschedulable"] = True
    if ours:
        node["metadata"]["annotations"][ANN] = "2026-10-27T15:40:00Z"
    return node


# The seed holds the primary of a healthy three-instance Cluster.
PODS = [_ipod(1, NODE, "primary"), _ipod(2, OTHER, "replica"), _ipod(3, THIRD, "replica")]
SLICES = [_slice(_ep(f"{CL}-1", NODE))]


def _module():
    """The runner as a module, loaded without writing bytecode next to it (it
    lives in mkosi.extra, which the image build copies)."""
    loader = importlib.machinery.SourceFileLoader("spatium_reboot_handoff", str(SCRIPT))
    spec = importlib.util.spec_from_loader("spatium_reboot_handoff", loader)
    mod = importlib.util.module_from_spec(spec)
    was, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = was
    return mod


def _run(tmp_path: Path, argv: tuple, *, clusters: list | None = None,
         pods: list | None = None, slices: list | None = None, node: dict | None = None,
         no_node: bool = False, wait_s: float = 5.0, short_wait_s: float = 1.0,
         handoff_s: float = 5.0, cordon_s: float = 5.0,
         **state) -> tuple[subprocess.CompletedProcess, dict]:
    fake = tmp_path / "fake_kubectl.py"
    fake.write_text(FAKE_KUBECTL)
    state_file = tmp_path / "kubectl.json"
    state_file.write_text(json.dumps({
        "clusters": [_cluster()] if clusters is None else clusters,
        "pods": PODS if pods is None else pods,
        "slices": SLICES if slices is None else slices,
        "node": None if no_node else (_node() if node is None else node),
        **state,
    }))
    env = {
        **os.environ,
        "SPATIUM_KUBECTL": f'"{sys.executable}" "{fake}"',
        "SPATIUM_KUBECONFIG": str(tmp_path / "k3s.yaml"),
        "SPATIUM_NODE_NAME": NODE,
        "SPATIUM_API_WAIT_S": str(wait_s),
        "SPATIUM_API_WAIT_SHORT_S": str(short_wait_s),
        "SPATIUM_API_POLL_S": "0.05",
        "SPATIUM_HANDOFF_WAIT_S": str(handoff_s),
        "SPATIUM_HANDOFF_POLL_S": "0.05",
        "SPATIUM_CORDON_WAIT_S": str(cordon_s),
        "SPATIUM_RETRY_FIRST_S": "0.05",
        "SPATIUM_RETRY_MAX_S": "0.1",
        "FAKE_KUBECTL_STATE": str(state_file),
    }
    res = subprocess.run([sys.executable, str(SCRIPT), *argv], env=env, capture_output=True,
                         text=True, check=False, timeout=120)
    return res, json.loads(state_file.read_text())


def _unit(path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    parser.read_string(path.read_text())
    return parser


# ---- the unit and the agent's wiring ----------------------------------------------


def test_unit_runs_after_k3s_and_never_pulls_it_in() -> None:
    unit = _unit(UNIT)["Unit"]
    assert "k3s.service" in unit.get("After", "").split()
    for key in ("Wants", "Requires", "BindsTo", "Upholds", "PartOf", "Requisite"):
        assert "k3s.service" not in unit.get(key, "").split(), (
            f"{key}=k3s.service would start k3s whenever this unit starts (#1723)"
        )


def test_unit_never_holds_the_boot() -> None:
    service = _unit(UNIT)["Service"]
    # exec: started once the runner is exec'd; it waits for the API itself.
    assert service.get("Type") == "exec"
    assert service.get("ExecStart") == "/usr/local/bin/spatium-reboot-handoff --at-boot"
    assert "Before" not in _unit(UNIT)["Unit"]


def test_unit_runs_where_k3s_runs() -> None:
    mine = {k: v for k, v in _unit(UNIT)["Unit"].items() if k.startswith("Condition")}
    k3s = {k: v for k, v in _unit(K3S_UNIT)["Unit"].items() if k.startswith("Condition")}
    assert mine == k3s


def test_the_image_enables_the_unit_and_makes_the_runner_executable() -> None:
    text = POSTINST.read_text()
    assert "spatiumddi-reboot-handoff.service \\" in text
    assert 'chmod 0755 "$BUILDROOT/usr/local/bin/spatium-reboot-handoff"' in text
    assert 'chmod 0644 "$BUILDROOT/etc/systemd/system/spatiumddi-reboot-handoff.service"' in text


def test_the_agent_delegates_to_the_power_action_wrapper() -> None:
    """#3008 — one implementation: the wrapper owns the handoff, the cancel
    trap, the marker and the undo; the agent keeps its trigger semantics and
    runs none of those itself."""
    lines = [ln.strip() for ln in AGENT.read_text().splitlines()
             if ln.strip() and not ln.strip().startswith("#")]
    text = "\n".join(lines)
    assert '"$POWER_ACTION" reboot' in text
    assert "--before-reboot" not in text and "--undo" not in text
    assert "systemctl reboot" not in text.replace("spatium-power-action reboot", "")
    assert 'mv -f "$TRIGGER" "${TRIGGER}.done"' in text
    mv = next(i for i, ln in enumerate(lines) if ln.startswith('mv -f "$TRIGGER"'))
    call = next(i for i, ln in enumerate(lines) if '"$POWER_ACTION" reboot' in ln)
    assert mv < call


def _agent_run(tmp_path: Path, *, wrapper_rc: int):
    import os
    import subprocess
    wrapper = tmp_path / "wrapper"
    wrapper.write_text(f'#!/bin/bash\necho "wrapper $*" >> {tmp_path}/calls\nexit {wrapper_rc}\n')
    wrapper.chmod(0o755)
    src = AGENT.read_text()
    state = tmp_path / "state"
    state.mkdir()
    (state / "reboot-pending-fleet").write_text("stamp-1\n")
    src = (src.replace("/var/lib/spatiumddi/release-state", str(state))
              .replace("/var/log/spatiumddi", str(tmp_path / "log"))
              .replace("GRACE_SECONDS=5", "GRACE_SECONDS=0"))
    script = tmp_path / "agent"
    script.write_text(src)
    script.chmod(0o755)
    proc = subprocess.run([str(script)], env={**os.environ, "SPATIUM_POWER_ACTION": str(wrapper)},
                          capture_output=True, text=True, timeout=30)
    return proc, state


def test_the_agent_renames_the_trigger_and_runs_the_wrapper(tmp_path: Path) -> None:
    proc, state = _agent_run(tmp_path, wrapper_rc=0)
    assert proc.returncode == 0
    assert (tmp_path / "calls").read_text().splitlines() == ["wrapper reboot"]
    assert not (state / "reboot-pending-fleet").exists()
    assert (state / "reboot-pending-fleet.done").exists()


def test_the_agent_fails_when_the_wrapper_does(tmp_path: Path) -> None:
    proc, _ = _agent_run(tmp_path, wrapper_rc=1)
    assert proc.returncode == 1


# ---- pure: what CNPG would do, and when the handoff is done ------------------------


@pytest.mark.parametrize(("cluster", "pods", "says"), [
    (_cluster(instances=1, ready=1), PODS[:1], "a single instance"),
    (_cluster(ready=2), PODS, "2 of its 3 instances ready"),
    (_cluster(target=f"{CL}-2"), PODS, "under way"),
    (_cluster(), [PODS[0], _ipod(2, NODE, "replica"), PODS[2]], "only 1 of its instances"),
])
def test_it_never_cordons_when_cnpg_would_not_switch_over(cluster, pods, says) -> None:
    assert says in _module().switch_blocker(cluster, pods, NODE)


def test_a_healthy_cluster_can_switch_over() -> None:
    assert _module().switch_blocker(_cluster(), PODS, NODE) == ""


def test_the_primary_held_here_is_the_clusters_current_primary_on_this_node() -> None:
    mod = _module()
    assert mod.primary_here(_cluster(), PODS, NODE) == f"{CL}-1"
    assert mod.primary_here(_cluster(), PODS, OTHER) == ""
    assert mod.primary_here(_cluster(primary=""), PODS, NODE) == ""


@pytest.mark.parametrize(("cluster", "roles", "slices", "done", "says"), [
    (_cluster(target=f"{CL}-2"), ("primary", "replica"), [_ep(f"{CL}-1", NODE)], False,
     "switching over"),
    (_cluster(), ("primary", "replica"), [_ep(f"{CL}-1", NODE)], False, "still the primary here"),
    (_cluster(f"{CL}-2"), ("replica", "replica"), [_ep(f"{CL}-1", NODE)], False,
     "not labelled primary"),
    (_cluster(f"{CL}-2"), ("replica", "primary"), [_ep(f"{CL}-1", NODE)], False,
     "does not list"),
    (_cluster(f"{CL}-2"), ("replica", "primary"), [_ep(f"{CL}-2", OTHER, ready=False)], False,
     "does not list"),
    (_cluster(f"{CL}-2"), ("replica", "primary"), [_ep(f"{CL}-2", OTHER), _ep(f"{CL}-1", NODE)],
     False, f"still lists {CL}-1"),
    (_cluster(f"{CL}-2"), ("replica", "primary"), [_ep(f"{CL}-2", OTHER)], True, OTHER),
    # an unset ready condition reads as ready, as kube-proxy reads it
    (_cluster(f"{CL}-2"), ("replica", "primary"), [_ep(f"{CL}-2", OTHER, ready=None)], True,
     OTHER),
])
def test_the_handoff_is_done_once_the_rw_service_lists_the_new_primary_only(
        cluster, roles, slices, done, says) -> None:
    pods = [_ipod(1, NODE, roles[0]), _ipod(2, OTHER, roles[1]), _ipod(3, THIRD, "replica")]
    ok, what = _module().handed_off(cluster, pods, [_slice(*slices)], NODE)
    assert ok is done
    assert says in what


# The handoff began at 06:22:46Z; CNPG restarted the old primary's container to
# demote it at 06:23:01Z (stack walk dev-8d394e6, turn 3).
SINCE = 1793168566.75  # 2026-10-28T06:22:46.75Z
AFTER = "2026-10-28T06:23:01Z"


@pytest.mark.parametrize(("old", "done", "says"), [
    # the API still shows the container that ran as the primary: it is not a
    # standby yet, however ready it reads
    (_ipod(1, NODE, "replica", started=LONG_AGO, ready=True), False, "not started again"),
    (_ipod(1, NODE, "replica", started="2026-10-28T06:22:45Z", ready=True), False,
     "not started again"),
    # started again for the demotion, PostgreSQL not up as a standby yet
    (_ipod(1, NODE, "replica", started=AFTER, ready=False), False, "not ready"),
    (_ipod(1, NODE, "replica", started=None, ready=False), False, "not running"),
    (_ipod(1, NODE, "replica", started=AFTER, ready=True), True, "ready standby"),
    # the same second as the handoff's start still counts: the kubelet's times
    # are whole seconds
    (_ipod(1, NODE, "replica", started="2026-10-28T06:22:46Z", ready=True), True,
     "ready standby"),
    # nothing of it on this node for the reboot to stop
    (_ipod(1, OTHER, "replica", started=LONG_AGO, ready=False), True, "does not run here"),
    (None, True, "not listed"),
])
def test_the_old_primary_is_demoted_once_it_runs_again_as_a_ready_standby(
        old, done, says) -> None:
    pods = [_ipod(2, OTHER, "primary"), _ipod(3, THIRD, "replica")]
    if old is not None:
        pods.insert(0, old)
    ok, what = _module().demoted(pods, f"{CL}-1", NODE, SINCE)
    assert ok is done
    assert says in what


# ---- --before-reboot -----------------------------------------------------------------


def test_it_cordons_with_its_annotation_and_waits_for_the_switchover(tmp_path: Path) -> None:
    res, st = _run(tmp_path, ("--before-reboot",),
                   switch={"after_gets": 3, "slice_after_gets": 5, "to": f"{CL}-2"})
    assert res.returncode == 0, res.stderr
    first = st["patches"][0]
    assert first["spec"] == {"unschedulable": True}
    assert ANN in first["metadata"]["annotations"]
    assert first["metadata"]["resourceVersion"] == "100"
    assert st["patch_types"] == ["merge"]
    assert len(st["patches"]) == 1
    assert st["node"]["spec"]["unschedulable"] is True
    assert f"the primary moved from {CL}-1 to {CL}-2 on {OTHER}" in res.stdout
    # it waited for the -rw slice, not only for the Cluster's status
    assert st["cluster_gets"] >= 5


def test_it_reboots_only_once_the_old_primary_runs_again_as_a_ready_standby(
        tmp_path: Path) -> None:
    # The -rw Service lists the new primary at the 5th read; the old primary's
    # container starts again (its demotion) at the 6th and is ready at the 9th.
    # CNPG lets the old primary finish its demotion only once it reaches the
    # new one through the -rw Service, so a reboot at the 5th read would stop
    # it in the middle (#2849, stack walk dev-8d394e6 turn 3).
    res, st = _run(tmp_path, ("--before-reboot",),
                   switch={"after_gets": 3, "slice_after_gets": 5, "restart_after_gets": 6,
                           "ready_after_gets": 9, "to": f"{CL}-2"})
    assert res.returncode == 0, res.stderr
    out = res.stdout
    moved = out.index(f"the primary moved from {CL}-1 to {CL}-2 on {OTHER}")
    standby = out.index(f"{CL}-1 is a ready standby again")
    assert moved < standby
    assert st["cluster_gets"] >= 9
    assert "rebooting anyway" not in out
    # a whole read of the Cluster, its pods and its -rw slice each time
    pods_reads = [c for c in st["calls"] if c[:2] == ["get", "pods"] and "-n" in c]
    assert len(pods_reads) >= 9


def test_a_stale_ready_read_of_the_old_primary_is_not_taken_for_its_demotion(
        tmp_path: Path) -> None:
    # The pod still reads as the container that ran as the primary (ready)
    # after the -rw Service moved: the handoff waits for the container that
    # started since it began.
    res, st = _run(tmp_path, ("--before-reboot",),
                   switch={"after_gets": 2, "slice_after_gets": 3, "restart_after_gets": 7,
                           "ready_after_gets": 8, "to": f"{CL}-2"})
    assert res.returncode == 0, res.stderr
    assert f"{CL}-1 is a ready standby again" in res.stdout
    assert st["cluster_gets"] >= 8


def test_an_old_primary_never_ready_again_holds_the_reboot_no_longer_than_the_budget(
        tmp_path: Path) -> None:
    started = time.monotonic()
    res, _ = _run(tmp_path, ("--before-reboot",), handoff_s=1.0,
                  switch={"after_gets": 1, "slice_after_gets": 2, "restart_after_gets": 2,
                          "ready_after_gets": 10_000, "to": f"{CL}-2"})
    took = time.monotonic() - started
    assert res.returncode == 0, res.stderr
    assert "the primary moved" in res.stdout
    assert f"{CL}-1 did not run again as a ready standby within" in res.stdout
    assert f"{CL}-1 is not ready yet" in res.stdout
    assert "rebooting anyway" in res.stdout
    assert took < 15


def test_a_node_without_the_primary_is_never_cordoned(tmp_path: Path) -> None:
    pods = [_ipod(1, OTHER, "primary"), _ipod(2, NODE, "replica"), _ipod(3, THIRD, "replica")]
    res, st = _run(tmp_path, ("--before-reboot",), pods=pods)
    assert res.returncode == 0
    assert "patches" not in st
    assert "no CNPG primary to hand off" in res.stdout


def test_a_cluster_cnpg_would_not_switch_over_is_left_and_nothing_cordoned(
        tmp_path: Path) -> None:
    res, st = _run(tmp_path, ("--before-reboot",), clusters=[_cluster(ready=2)])
    assert res.returncode == 0
    assert "patches" not in st
    assert "2 of its 3 instances ready" in res.stdout


def test_a_node_already_unschedulable_is_left_as_it_is_and_not_marked(tmp_path: Path) -> None:
    res, st = _run(tmp_path, ("--before-reboot",), node=_node(unschedulable=True),
                   switch={"after_gets": 1, "to": f"{CL}-2"})
    assert res.returncode == 0
    assert "patches" not in st
    assert ANN not in st["node"]["metadata"]["annotations"]
    assert "left as it is, not marked" in res.stdout
    assert "the primary moved" in res.stdout


def test_it_never_holds_the_reboot_past_its_budget(tmp_path: Path) -> None:
    started = time.monotonic()
    res, st = _run(tmp_path, ("--before-reboot",), handoff_s=0.5)
    took = time.monotonic() - started
    assert res.returncode == 0
    assert "did not move within" in res.stdout
    assert "rebooting anyway" in res.stdout
    assert took < 15


def test_with_no_api_it_hands_nothing_off_and_exits_0(tmp_path: Path) -> None:
    res, st = _run(tmp_path, ("--before-reboot",), api_down_polls=10_000, short_wait_s=0.3)
    assert res.returncode == 0
    assert "patches" not in st
    assert "no API within" in res.stdout


def test_without_cloudnativepg_it_hands_nothing_off(tmp_path: Path) -> None:
    res, st = _run(tmp_path, ("--before-reboot",), no_crd=True)
    assert res.returncode == 0
    assert "patches" not in st
    assert "could not list the CNPG Clusters" in res.stdout


def test_a_node_written_meanwhile_is_read_again(tmp_path: Path) -> None:
    res, st = _run(tmp_path, ("--before-reboot",), other_writes=1,
                   switch={"after_gets": 1, "to": f"{CL}-2"})
    assert res.returncode == 0
    assert len(st["patches"]) == 2
    assert st["patches"][1]["metadata"]["resourceVersion"] == "101"
    assert st["node"]["spec"]["unschedulable"] is True
    assert ANN in st["node"]["metadata"]["annotations"]


def test_the_cordon_keeps_trying_after_a_pause_while_the_node_keeps_changing(
        tmp_path: Path) -> None:
    res, st = _run(tmp_path, ("--before-reboot",), other_writes=6,
                   switch={"after_gets": 1, "to": f"{CL}-2"})
    assert res.returncode == 0
    assert len(st["patches"]) == 7
    assert st["node"]["spec"]["unschedulable"] is True
    assert ANN in st["node"]["metadata"]["annotations"]
    assert "not cordoned yet" in res.stdout
    assert "the primary moved" in res.stdout


def test_a_cordon_set_by_someone_else_meanwhile_is_never_taken_for_the_handoffs(
        tmp_path: Path) -> None:
    # an operator cordons between the read and the patch: the resourceVersion
    # the patch carries fails it, and the read after it finds a cordon not ours
    res, st = _run(tmp_path, ("--before-reboot",), cordon_before_patch=True,
                   switch={"after_gets": 1, "to": f"{CL}-2"})
    assert res.returncode == 0
    assert len(st["patches"]) == 1
    assert st["node"]["spec"]["unschedulable"] is True
    assert ANN not in st["node"]["metadata"]["annotations"]
    assert "left as it is, not marked" in res.stdout


def test_a_cordon_that_never_lands_holds_the_reboot_no_longer_than_its_budget(
        tmp_path: Path) -> None:
    started = time.monotonic()
    res, st = _run(tmp_path, ("--before-reboot",), failing_patches=10_000, cordon_s=0.5)
    took = time.monotonic() - started
    assert res.returncode == 0
    assert len(st["patches"]) >= 2
    assert not st["node"]["spec"].get("unschedulable")
    assert "could not cordon it" in res.stdout
    assert "nothing handed off" in res.stdout
    assert took < 15


# ---- --at-boot and --undo ---------------------------------------------------------------


def test_at_boot_it_uncordons_the_node_its_handoff_cordoned(tmp_path: Path) -> None:
    res, st = _run(tmp_path, ("--at-boot",), node=_node(unschedulable=True, ours=True))
    assert res.returncode == 0
    # a JSON patch that holds only while the mark is the one read, and that
    # carries no resourceVersion (the body kubectl sent to k3s v1.36.5 on a QA
    # rig, #2849)
    assert st["patch_types"] == ["json"]
    assert st["patches"] == [[
        {"op": "test", "path": "/metadata/annotations/spatium.io~1reboot-cordoned",
         "value": "2026-10-27T15:40:00Z"},
        {"op": "remove", "path": "/metadata/annotations/spatium.io~1reboot-cordoned"},
        {"op": "add", "path": "/spec/unschedulable", "value": False},
    ]]
    assert not st["node"]["spec"].get("unschedulable")
    assert ANN not in st["node"]["metadata"]["annotations"]
    assert f"uncordoned {NODE}, cordoned by the handoff of 2026-10-27T15:40:00Z" in res.stdout


def test_at_boot_k3s_writing_the_node_never_fails_the_uncordon(tmp_path: Path) -> None:
    # #2849: after a reboot k3s and its supervisor wrote the Node's labels,
    # annotations and status within seconds of the API answering, and three
    # merge patches carrying the resourceVersion they had read all lost to
    # those writes: the node stayed cordoned, its PostgreSQL instance Pending.
    res, st = _run(tmp_path, ("--at-boot",), node=_node(unschedulable=True, ours=True),
                   other_writes=50)
    assert res.returncode == 0
    assert len(st["patches"]) == 1
    assert not st["node"]["spec"].get("unschedulable")
    assert ANN not in st["node"]["metadata"]["annotations"]
    assert f"uncordoned {NODE}" in res.stdout


def test_at_boot_an_api_not_taking_writes_yet_is_tried_again(tmp_path: Path) -> None:
    res, st = _run(tmp_path, ("--at-boot",), node=_node(unschedulable=True, ours=True),
                   failing_patches=3)
    assert res.returncode == 0
    assert len(st["patches"]) == 4
    assert res.stdout.count("not uncordoned yet (Error from server (InternalError)") == 3
    assert not st["node"]["spec"].get("unschedulable")
    assert ANN not in st["node"]["metadata"]["annotations"]
    assert f"uncordoned {NODE}" in res.stdout


def test_at_boot_it_gives_up_at_its_budget_and_leaves_the_mark_for_the_next_boot(
        tmp_path: Path) -> None:
    started = time.monotonic()
    res, st = _run(tmp_path, ("--at-boot",), node=_node(unschedulable=True, ours=True),
                   failing_patches=10_000, wait_s=0.5)
    took = time.monotonic() - started
    assert res.returncode == 0
    assert len(st["patches"]) >= 2
    assert st["node"]["spec"]["unschedulable"] is True
    assert ANN in st["node"]["metadata"]["annotations"]
    assert "could not uncordon it within" in res.stdout
    assert "the next boot looks again" in res.stdout
    assert took < 15


def test_at_boot_a_patch_whose_answer_was_lost_reads_as_uncordoned(tmp_path: Path) -> None:
    res, st = _run(tmp_path, ("--at-boot",), node=_node(unschedulable=True, ours=True),
                   lost_answers=1)
    assert res.returncode == 0
    assert len(st["patches"]) == 1
    assert not st["node"]["spec"].get("unschedulable")
    assert f"uncordoned {NODE}" in res.stdout


def test_at_boot_a_mark_restamped_meanwhile_is_read_again(tmp_path: Path) -> None:
    res, st = _run(tmp_path, ("--at-boot",), node=_node(unschedulable=True, ours=True),
                   restamp_before_patch="2026-10-27T15:41:00Z")
    assert res.returncode == 0
    assert [p[0]["value"] for p in st["patches"]] == ["2026-10-27T15:40:00Z",
                                                     "2026-10-27T15:41:00Z"]
    assert not st["node"]["spec"].get("unschedulable")
    assert "cordoned by the handoff of 2026-10-27T15:41:00Z" in res.stdout


def test_at_boot_a_mark_taken_off_meanwhile_leaves_the_cordon_as_it_is(
        tmp_path: Path) -> None:
    # someone took the cordon over between the read and the patch: the patch
    # changes nothing, and the read after it finds no mark
    res, st = _run(tmp_path, ("--at-boot",), node=_node(unschedulable=True, ours=True),
                   drop_mark_before_patch=True)
    assert res.returncode == 0
    assert len(st["patches"]) == 1
    assert st["node"]["spec"]["unschedulable"] is True
    assert "no handoff cordon on it: nothing to do" in res.stdout


def test_at_boot_a_mark_left_on_a_node_uncordoned_while_it_was_down_is_dropped(
        tmp_path: Path) -> None:
    res, st = _run(tmp_path, ("--at-boot",), node=_node(ours=True))
    assert res.returncode == 0
    assert len(st["patches"]) == 1
    assert ANN not in st["node"]["metadata"]["annotations"]
    assert not st["node"]["spec"].get("unschedulable")


def test_at_a_first_boot_a_node_not_registered_yet_has_nothing_to_undo(
        tmp_path: Path) -> None:
    res, st = _run(tmp_path, ("--at-boot",), no_node=True)
    assert res.returncode == 0
    assert "patches" not in st
    assert f"{NODE}: no Node of this name registered yet" in res.stdout
    assert "could not" not in res.stdout


def test_at_boot_an_operators_cordon_stays(tmp_path: Path) -> None:
    res, st = _run(tmp_path, ("--at-boot",), node=_node(unschedulable=True))
    assert res.returncode == 0
    assert "patches" not in st
    assert st["node"]["spec"]["unschedulable"] is True


def test_at_boot_it_waits_for_the_api(tmp_path: Path) -> None:
    res, st = _run(tmp_path, ("--at-boot",), node=_node(unschedulable=True, ours=True),
                   api_down_polls=3)
    assert res.returncode == 0
    assert not st["node"]["spec"].get("unschedulable")
    assert ANN not in st["node"]["metadata"]["annotations"]


def test_at_boot_it_never_fails_the_boot_when_the_api_never_answers(tmp_path: Path) -> None:
    res, st = _run(tmp_path, ("--at-boot",), node=_node(unschedulable=True, ours=True),
                   api_down_polls=10_000, wait_s=0.3)
    assert res.returncode == 0
    assert "patches" not in st
    assert "the next boot looks again" in res.stdout


def test_undo_releases_the_cordon_of_a_reboot_that_did_not_happen(tmp_path: Path) -> None:
    res, st = _run(tmp_path, ("--undo",), node=_node(unschedulable=True, ours=True))
    assert res.returncode == 0
    assert not st["node"]["spec"].get("unschedulable")
    assert ANN not in st["node"]["metadata"]["annotations"]


def test_unknown_arguments_do_nothing(tmp_path: Path) -> None:
    res, st = _run(tmp_path, ("--now",))
    assert res.returncode == 0
    assert "patches" not in st
    assert "unknown arguments" in res.stdout
