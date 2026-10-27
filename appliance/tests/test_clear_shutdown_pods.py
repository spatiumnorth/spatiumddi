"""The pods a node's shutdown ended are deleted when the node is back (#1976).

The kubelet's graceful node shutdown (test_kubelet_graceful_shutdown.py)
ends every pod of the node before a reboot goes on. Each one is left
terminal (Succeeded when its containers exited 0, Failed otherwise) with
the condition DisruptionTarget, reason TerminationByKubelet, and its
controller replaces it. The DaemonSet and StatefulSet controllers delete
the old pod, CloudNativePG re-creates its own, but a ReplicaSet never
deletes a terminal pod, and the pod GC keeps them until there are 12,500.
So every reboot left the node's Deployment pods listed as Completed beside
their replacements (a single node's api, worker and frontend pods, three a
reboot), and anything listing pods without reading their phase counted
them.

spatiumddi-clear-shutdown-pods.service runs spatium-clear-shutdown-pods at
each boot, after k3s. These tests keep its unit honest (ordered after k3s,
never pulling it in, never holding the boot) and run the real runner
against a stub kubectl: what it deletes, what it never touches, and that it
never fails the boot.

The same unit's ExecStop runs it with --at-shutdown (#2848). The kubelet
releases its shutdown lock once the node's pods have stopped, before every
final status of theirs has reached the API, and k3s then stops: a pod whose
last write was lost stays Ready (a Service endpoint) until the node is back,
because the node controller marks a node's pods NotReady only when the node
stops reporting Ready, and this one reported NotReady when its shutdown
began. Systemd stops the unit after that lock and before k3s; the runner
marks NotReady each pod of the node the API still reads Ready, only while
the system is stopping, within a budget, never failing the shutdown.

    python3 -m pytest appliance/tests/test_clear_shutdown_pods.py -v

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
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
EXTRA = REPO / "appliance" / "mkosi.extra"
UNIT_DIR = EXTRA / "etc" / "systemd" / "system"
UNIT = UNIT_DIR / "spatiumddi-clear-shutdown-pods.service"
K3S_UNIT = UNIT_DIR / "k3s.service"
SCRIPT = EXTRA / "usr" / "local" / "bin" / "spatium-clear-shutdown-pods"

pytestmark = pytest.mark.skipif(not UNIT.is_file(), reason="appliance tree not present")

NODE = "ddipg-seed"
# The kubelet's own words (k8s pkg/kubelet/nodeshutdown, nodeShutdownMessage),
# as a 10-25 QA rig read them on every pod its reboots left.
SHUTDOWN_MSG = "Pod was terminated in response to imminent node shutdown."
# What the eviction manager writes for a node-pressure eviction: the same
# condition reason, its own message.
EVICTION_MSG = "The node was low on resource: memory. Threshold quantity: 100Mi, available: 9Mi."

# A stand-in for `k3s kubectl`: the three calls the runner makes, served from a
# JSON state file. `get --raw=/readyz` fails while api_down_polls > 0; `get
# pods` lists the state's pods bound to the field selector's node, as the
# apiserver does; `delete --raw <path> -f -` reads DeleteOptions from stdin and
# answers as the apiserver does: 404 for a missing pod, 409 when the UID
# precondition does not match, else removes it.
FAKE_KUBECTL = r'''
import json, os, sys
path = os.environ["FAKE_KUBECTL_STATE"]
st = json.load(open(path))
args = sys.argv[1:]
st.setdefault("calls", []).append(args)
def save():
    json.dump(st, open(path, "w"))
if "--raw=/readyz" in args:
    if st.get("api_down_polls", 0) > 0:
        st["api_down_polls"] -= 1
        save()
        print("The connection to the server 127.0.0.1:6443 was refused", file=sys.stderr)
        sys.exit(1)
    save()
    print("ok")
    sys.exit(0)
if args[1:3] == ["get", "pods"]:
    node = args[args.index("--field-selector") + 1].split("=", 1)[1]
    save()
    if st.get("list_fails"):
        print("The connection to the server 127.0.0.1:6443 was refused", file=sys.stderr)
        sys.exit(1)
    print(json.dumps({"kind": "PodList", "items": [p for p in st["pods"]
                      if p["spec"].get("nodeName") == node]}))
    sys.exit(0)
if args[1:3] == ["delete", "--raw"]:
    url = args[3]
    body = json.loads(sys.stdin.read())
    st.setdefault("deletes", []).append({"path": url, "body": body})
    ns, name = url.split("/")[4], url.split("/")[6]
    key = ns + "/" + name
    if key in st.get("gone_before_delete", []):
        st["pods"] = [p for p in st["pods"] if (p["metadata"]["namespace"], p["metadata"]["name"]) != (ns, name)]
    if key in st.get("replaced_before_delete", {}):
        for p in st["pods"]:
            if (p["metadata"]["namespace"], p["metadata"]["name"]) == (ns, name):
                p["metadata"]["uid"] = st["replaced_before_delete"][key]
                p["status"] = {"phase": "Running"}
    pod = next((p for p in st["pods"] if (p["metadata"]["namespace"], p["metadata"]["name"]) == (ns, name)), None)
    if pod is None:
        save()
        print('Error from server (NotFound): pods "%s" not found' % name, file=sys.stderr)
        sys.exit(1)
    want = body.get("preconditions", {}).get("uid")
    if want and want != pod["metadata"]["uid"]:
        save()
        print('Error from server (Conflict): Operation cannot be fulfilled on Pod "%s": '
              'Precondition failed: UID in precondition: %s, UID in object meta: %s'
              % (name, want, pod["metadata"]["uid"]), file=sys.stderr)
        sys.exit(1)
    st["pods"] = [p for p in st["pods"] if p is not pod]
    save()
    print(json.dumps({"kind": "Pod", "metadata": pod["metadata"]}))
    sys.exit(0)
if args[1:3] == ["replace", "--raw"]:
    url = args[3]
    body = json.loads(sys.stdin.read())
    st.setdefault("replaces", []).append({"path": url, "body": body})
    if st.get("hang_replace_s"):
        save()
        import time
        time.sleep(st["hang_replace_s"])
        sys.exit(1)
    ns, name = url.split("/")[4], url.split("/")[6]
    pod = next((p for p in st["pods"] if (p["metadata"]["namespace"], p["metadata"]["name"]) == (ns, name)), None)
    if pod is None:
        save()
        print('Error from server (NotFound): pods "%s" not found' % name, file=sys.stderr)
        sys.exit(1)
    key = ns + "/" + name
    if key in st.get("written_before_replace", {}):
        # the kubelet's own write lands between the list and this update
        pod["status"] = st["written_before_replace"].pop(key)
        pod["metadata"]["resourceVersion"] = str(int(pod["metadata"]["resourceVersion"]) + 1)
    if body["metadata"].get("resourceVersion") != pod["metadata"]["resourceVersion"]:
        save()
        print('Error from server (Conflict): Operation cannot be fulfilled on pods "%s": the '
              'object has been modified; please apply your changes to the latest version and '
              'try again' % name, file=sys.stderr)
        sys.exit(1)
    pod["status"] = body["status"]
    pod["metadata"]["resourceVersion"] = str(int(pod["metadata"]["resourceVersion"]) + 1)
    save()
    print(json.dumps(pod))
    sys.exit(0)
save()
print("fake kubectl: unexpected call %r" % (args,), file=sys.stderr)
sys.exit(2)
'''

# A stand-in for `systemctl is-system-running`: prints FAKE_SYSTEM_STATE and,
# as systemctl does, exits non-zero for every state but "running".
FAKE_SYSTEMCTL = r'''
import os, sys
state = os.environ.get("FAKE_SYSTEM_STATE", "running")
print(state)
sys.exit(0 if state == "running" else 1)
'''


def _pod(name: str, *, ns: str = "spatium", node: str = NODE, phase: str = "Succeeded",
         owner: str | None = "ReplicaSet", cond: dict | None = None, deleting: bool = False,
         uid: str | None = None) -> dict:
    meta: dict = {"namespace": ns, "name": name, "uid": uid or f"uid-{name}"}
    if owner:
        meta["ownerReferences"] = [
            {"kind": owner, "name": name.rsplit("-", 1)[0], "controller": True}
        ]
    if deleting:
        meta["deletionTimestamp"] = "2026-10-25T22:30:40Z"
    conditions = [{"type": "Ready", "status": "False"}]
    if cond is not None:
        conditions.append(cond)
    return {
        "metadata": meta,
        "spec": {"nodeName": node},
        "status": {"phase": phase, "conditions": conditions},
    }


def _shutdown(**over: str) -> dict:
    cond = {
        "type": "DisruptionTarget",
        "status": "True",
        "reason": "TerminationByKubelet",
        "message": SHUTDOWN_MSG,
        "lastTransitionTime": "2026-10-25T22:30:33Z",
    }
    cond.update(over)
    return cond


# What a single node lists after one graceful reboot, plus everything that
# looks like it and must stay.
LEFT = [
    _pod("spatium-control-spatiumddi-api-64554b86fc-7dgmg", cond=_shutdown()),
    _pod("spatium-control-spatiumddi-worker-56b5b4d58f-pcml8", phase="Failed", cond=_shutdown()),
    _pod("coredns-84f99c5dfc-74kg4", ns="kube-system", cond=_shutdown()),
]
STAYS = [
    # its replacement
    _pod("spatium-control-spatiumddi-api-64554b86fc-xsd2b", phase="Running"),
    # a Job's history: completed, no shutdown in it
    _pod("helm-install-spatium-control-brr7r", ns="kube-system", owner="Job"),
    # a node-pressure eviction: same reason, the eviction manager's message
    _pod("spatium-control-spatiumddi-worker-56b5b4d58f-ev1ct", phase="Failed",
         cond=_shutdown(message=EVICTION_MSG)),
    # another node's (each node clears its own when it is back)
    _pod("coredns-84f99c5dfc-p247j", ns="kube-system", node="ddipg-member-1", cond=_shutdown()),
    # controllers that delete their own terminal pods
    _pod("dns-bind9-cr4nt", owner="DaemonSet", cond=_shutdown()),
    _pod("spatium-control-spatiumddi-redis-2", owner="StatefulSet", phase="Failed",
         cond=_shutdown()),
    _pod("spatium-control-spatiumddi-postgresql-1", owner="Cluster", phase="Failed",
         cond=_shutdown()),
    # no controller: nothing replaced it, its record is all there is
    _pod("debug-shell", owner=None, cond=_shutdown()),
    # already being deleted
    _pod("spatium-control-spatiumddi-frontend-676c9d5975-fk4xf", cond=_shutdown(),
         deleting=True),
    # a condition that is not the kubelet's shutdown
    _pod("spatium-control-spatiumddi-frontend-676c9d5975-mqjc7", cond=_shutdown(status="False")),
    _pod("spatium-control-spatiumddi-frontend-676c9d5975-x8pvs",
         cond=_shutdown(reason="DeletionByTaintManager")),
]


def _module():
    """The runner as a module, loaded without writing bytecode next to it (it
    lives in mkosi.extra, which the image build copies)."""
    loader = importlib.machinery.SourceFileLoader("spatium_clear_shutdown_pods", str(SCRIPT))
    spec = importlib.util.spec_from_loader("spatium_clear_shutdown_pods", loader)
    mod = importlib.util.module_from_spec(spec)
    was, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = was
    return mod


def _run(tmp_path: Path, pods: list[dict], *, wait_s: float = 5.0, argv: tuple = (),
         system: str = "running", budget_s: float = 10.0,
         **state) -> tuple[subprocess.CompletedProcess, dict]:
    fake = tmp_path / "fake_kubectl.py"
    fake.write_text(FAKE_KUBECTL)
    fake_systemctl = tmp_path / "fake_systemctl.py"
    fake_systemctl.write_text(FAKE_SYSTEMCTL)
    state_file = tmp_path / "kubectl.json"
    state_file.write_text(json.dumps({"pods": pods, **state}))
    env = {
        **os.environ,
        "SPATIUM_KUBECTL": f'"{sys.executable}" "{fake}"',
        "SPATIUM_KUBECONFIG": str(tmp_path / "k3s.yaml"),
        "SPATIUM_SYSTEMCTL": f'"{sys.executable}" "{fake_systemctl}"',
        "SPATIUM_NODE_NAME": NODE,
        "SPATIUM_API_WAIT_S": str(wait_s),
        "SPATIUM_API_POLL_S": "0.05",
        "SPATIUM_SHUTDOWN_BUDGET_S": str(budget_s),
        "FAKE_KUBECTL_STATE": str(state_file),
        "FAKE_SYSTEM_STATE": system,
    }
    res = subprocess.run([sys.executable, str(SCRIPT), *argv], env=env, capture_output=True,
                         text=True, check=False, timeout=120)
    return res, json.loads(state_file.read_text())


def _names(pods: list[dict]) -> set[str]:
    return {p["metadata"]["name"] for p in pods}


def _unit(path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    parser.read_string(path.read_text())
    return parser


# ---- the unit ---------------------------------------------------------------


def test_unit_runs_after_k3s_and_never_pulls_it_in() -> None:
    unit = _unit(UNIT)["Unit"]
    assert "k3s.service" in unit.get("After", "").split()
    for key in ("Wants", "Requires", "BindsTo", "Upholds", "PartOf", "Requisite"):
        assert "k3s.service" not in unit.get(key, "").split(), (
            f"{key}=k3s.service would start k3s whenever this unit starts (#1723)"
        )


def test_unit_never_holds_the_boot() -> None:
    """A oneshot holds multi-user.target (and `systemctl is-system-running`
    at `starting`) for as long as it waits for the API."""
    service = _unit(UNIT)["Service"]
    assert service.get("Type") == "exec"
    assert service.get("ExecStart") == "/usr/local/bin/spatium-clear-shutdown-pods"
    assert os.access(SCRIPT, os.X_OK), "the runner must be executable (lint_appliance_runners)"


def test_unit_runs_where_k3s_runs() -> None:
    def conditions(path: Path) -> set[tuple[str, str]]:
        return {
            (ln.split("=", 1)[0], ln.split("=", 1)[1])
            for ln in (raw.strip() for raw in path.read_text().splitlines())
            if ln.startswith("Condition")
        }

    assert conditions(UNIT) == conditions(K3S_UNIT)
    assert _unit(UNIT)["Install"].get("WantedBy") == "multi-user.target"


def test_unit_marks_the_nodes_pods_at_shutdown_before_k3s_stops() -> None:
    """Systemd runs ExecStop only for a unit that is still active, and stops
    units in the reverse of their start order: RemainAfterExit keeps the unit
    active after the boot run exits, and After=k3s.service stops it before k3s,
    while the local API still answers (#2848). It must never hold the shutdown
    much past its own budget."""
    unit = _unit(UNIT)
    service = unit["Service"]
    assert service.get("RemainAfterExit") == "yes"
    assert service.get("ExecStop") == "/usr/local/bin/spatium-clear-shutdown-pods --at-shutdown"
    assert "k3s.service" in unit["Unit"].get("After", "").split()
    assert unit["Unit"].get("DefaultDependencies", "yes") != "no", (
        "default dependencies are what stop the unit at shutdown"
    )
    mod = _module()
    assert mod.SHUTDOWN_BUDGET_S + 5 <= int(service.get("TimeoutStopSec", "0")) <= 30


# ---- what it deletes ----------------------------------------------------------


def test_it_selects_the_pods_a_shutdown_left_and_nothing_else() -> None:
    mod = _module()
    assert _names(mod.leftovers(LEFT + STAYS, NODE)) == _names(LEFT)


def test_the_kubelets_shutdown_message_is_what_it_matches() -> None:
    mod = _module()
    assert mod.shutdown_condition(_pod("a", cond=_shutdown())) is not None
    assert mod.shutdown_condition(_pod("b", cond=_shutdown(message=EVICTION_MSG))) is None


def test_the_node_is_the_lower_cased_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    """k3s registers the Node under the hostname, lower-cased; the appliance
    sets neither node-name nor with-node-id."""
    mod = _module()
    monkeypatch.delenv("SPATIUM_NODE_NAME", raising=False)
    monkeypatch.setattr(mod.socket, "gethostname", lambda: "DDIPG-Seed")
    assert mod.node_name() == "ddipg-seed"


def test_it_deletes_each_leftover_by_its_uid(tmp_path: Path) -> None:
    res, st = _run(tmp_path, LEFT + STAYS)
    assert res.returncode == 0, res.stderr
    deleted = {d["path"]: d["body"] for d in st["deletes"]}
    assert deleted == {
        f"/api/v1/namespaces/{p['metadata']['namespace']}/pods/{p['metadata']['name']}": {
            "kind": "DeleteOptions",
            "apiVersion": "v1",
            "preconditions": {"uid": p["metadata"]["uid"]},
        }
        for p in LEFT
    }
    assert _names(st["pods"]) == _names(STAYS)
    assert "3 pod(s) a shutdown left: 3 deleted" in res.stdout, res.stdout


def test_a_new_pod_under_the_same_name_is_left_alone(tmp_path: Path) -> None:
    """A controller that re-uses names could create a new pod under the old
    one's name between the list and the delete: the UID precondition fails
    and the new pod stays."""
    api = LEFT[0]["metadata"]
    key = f"{api['namespace']}/{api['name']}"
    res, st = _run(tmp_path, LEFT + STAYS, replaced_before_delete={key: "uid-new"})
    assert res.returncode == 0, res.stderr
    assert any(p["metadata"]["uid"] == "uid-new" for p in st["pods"])
    assert "left alone, a newer pod has its name" in res.stdout, res.stdout
    assert "2 deleted, 1 replaced" in res.stdout, res.stdout


def test_a_pod_already_gone_is_not_an_error(tmp_path: Path) -> None:
    worker = LEFT[1]["metadata"]
    res, st = _run(tmp_path, LEFT, gone_before_delete=[f"{worker['namespace']}/{worker['name']}"])
    assert res.returncode == 0, res.stderr
    assert st["pods"] == []
    assert "already gone" in res.stdout and "2 deleted, 1 gone" in res.stdout, res.stdout


def test_it_waits_for_the_api(tmp_path: Path) -> None:
    res, st = _run(tmp_path, LEFT, api_down_polls=3)
    assert res.returncode == 0, res.stderr
    readyz = [c for c in st["calls"] if "--raw=/readyz" in c]
    assert len(readyz) == 4
    assert st["pods"] == []


def test_it_never_fails_the_boot_when_the_api_never_answers(tmp_path: Path) -> None:
    res, st = _run(tmp_path, LEFT, wait_s=0.3, api_down_polls=10_000)
    assert res.returncode == 0, res.stderr
    assert "deletes" not in st and len(st["pods"]) == len(LEFT)
    assert "nothing deleted" in res.stdout, res.stdout


def test_a_clean_boot_deletes_nothing(tmp_path: Path) -> None:
    res, st = _run(tmp_path, STAYS)
    assert res.returncode == 0, res.stderr
    assert "deletes" not in st
    assert "was left by a shutdown" in res.stdout, res.stdout


# ---- what it marks at shutdown (#2848) -----------------------------------------


def _live(name: str, *, ns: str = "spatium", node: str = NODE, ready: str = "True",
          owner: str | None = "ReplicaSet", phase: str = "Running", rv: str = "100",
          deleting: bool = False) -> dict:
    """A pod as the API lists it while its node shuts down: Ready as the kubelet
    last wrote it."""
    pod = _pod(name, ns=ns, node=node, phase=phase, owner=owner, deleting=deleting)
    pod["metadata"]["resourceVersion"] = rv
    pod["status"]["conditions"] = [
        {"type": "PodScheduled", "status": "True"},
        {"type": "ContainersReady", "status": ready},
        {"type": "Ready", "status": ready, "lastTransitionTime": "2026-10-26T11:58:01Z"},
    ]
    return pod


# What a member listed after its kubelet released the shutdown lock: the last
# group's CoreDNS pod and a killed primary still Ready (2 of 6 reboots of a
# 10-26 QA rig), the rest written NotReady in time, and another node's pods.
STALE = [
    _live("coredns-84f99c5dfc-wsgqz", ns="kube-system"),
    _live("spatium-control-spatiumddi-postgresql-2", owner="Cluster", deleting=True),
]
CURRENT = [
    _live("spatium-control-spatiumddi-api-64554b86fc-7dgmg", ready="False", phase="Succeeded"),
    _live("dns-bind9-cr4nt", owner="DaemonSet", ready="False", phase="Failed"),
    _live("coredns-84f99c5dfc-p247j", ns="kube-system", node="ddipg-member-1"),
    _live("spatium-control-spatiumddi-api-64554b86fc-xsd2b", node="ddipg-member-1"),
]


def _ready(pod: dict) -> dict:
    return next(c for c in pod["status"]["conditions"] if c["type"] == "Ready")


def test_at_shutdown_it_marks_what_still_reads_ready_and_nothing_else(tmp_path: Path) -> None:
    res, st = _run(tmp_path, STALE + CURRENT, argv=("--at-shutdown",), system="stopping")
    assert res.returncode == 0, res.stderr
    paths = [r["path"] for r in st["replaces"]]
    assert paths == [
        f"/api/v1/namespaces/{p['metadata']['namespace']}/pods/{p['metadata']['name']}/status"
        for p in STALE
    ]
    for r, pod in zip(st["replaces"], STALE):
        # the listed object, its resourceVersion the precondition, only Ready changed
        assert r["body"]["metadata"]["resourceVersion"] == pod["metadata"]["resourceVersion"]
        assert r["body"]["kind"] == "Pod" and r["body"]["apiVersion"] == "v1"
        cond = _ready(r["body"])
        assert (cond["status"], cond["reason"]) == ("False", "NodeShutdown")
        assert cond["lastTransitionTime"] != _ready(pod)["lastTransitionTime"]
        others = [c for c in r["body"]["status"]["conditions"] if c["type"] != "Ready"]
        assert others == [c for c in pod["status"]["conditions"] if c["type"] != "Ready"]
    by_name = {p["metadata"]["name"]: p for p in st["pods"]}
    assert all(_ready(by_name[p["metadata"]["name"]])["status"] == "False" for p in STALE)
    assert _ready(by_name["coredns-84f99c5dfc-p247j"])["status"] == "True"
    assert "deletes" not in st
    assert "marked NotReady: kube-system/coredns-84f99c5dfc-wsgqz" in res.stdout, res.stdout
    assert "terminating" in res.stdout
    assert "2 pod(s) still Ready in the API: 2 marked" in res.stdout, res.stdout


def test_at_shutdown_it_does_nothing_unless_the_system_is_stopping(tmp_path: Path) -> None:
    """`systemctl stop` or a restart of the unit on a running node must not
    mark a live node's pods."""
    res, st = _run(tmp_path, STALE + CURRENT, argv=("--at-shutdown",), system="running")
    assert res.returncode == 0, res.stderr
    assert "calls" not in st
    assert "the system is running, not stopping: nothing marked" in res.stdout, res.stdout


def test_a_status_the_kubelet_wrote_meanwhile_is_read_again(tmp_path: Path) -> None:
    """The kubelet's own write can land between the list and the update: the
    update's precondition fails, the pod is read again and marked only if it
    still reads Ready."""
    dns, pg = (f"{p['metadata']['namespace']}/{p['metadata']['name']}" for p in STALE)
    written = {
        dns: {"phase": "Succeeded", "conditions": [{"type": "Ready", "status": "False"}]},
        pg: STALE[1]["status"],  # a write that left it Ready
    }
    res, st = _run(tmp_path, STALE + CURRENT, argv=("--at-shutdown",), system="stopping",
                   written_before_replace=written)
    assert res.returncode == 0, res.stderr
    names = [r["path"].split("/")[6] for r in st["replaces"]]
    assert names == ["coredns-84f99c5dfc-wsgqz", "spatium-control-spatiumddi-postgresql-2",
                     "spatium-control-spatiumddi-postgresql-2"]
    by_name = {p["metadata"]["name"]: p for p in st["pods"]}
    assert _ready(by_name["coredns-84f99c5dfc-wsgqz"]).get("reason") is None
    assert _ready(by_name["spatium-control-spatiumddi-postgresql-2"])["status"] == "False"
    assert "2 pod(s) still Ready in the API: 1 changed, 1 marked" in res.stdout, res.stdout


def test_at_shutdown_it_never_holds_the_shutdown(tmp_path: Path) -> None:
    """An API that never answers costs the budget at most, and exits 0."""
    import time

    t0 = time.monotonic()
    res, st = _run(tmp_path, STALE, argv=("--at-shutdown",), system="stopping",
                   budget_s=1.0, hang_replace_s=30)
    assert res.returncode == 0, res.stderr
    assert time.monotonic() - t0 < 15
    assert len(st["replaces"]) == 1
    assert "1 failed, 1 unreached" in res.stdout, res.stdout


def test_at_shutdown_with_no_api_it_marks_nothing_and_exits_0(tmp_path: Path) -> None:
    res, st = _run(tmp_path, STALE, argv=("--at-shutdown",), system="stopping", list_fails=True)
    assert res.returncode == 0, res.stderr
    assert "replaces" not in st
    assert "could not list the pods of ddipg-seed" in res.stdout, res.stdout


def test_unknown_arguments_do_nothing(tmp_path: Path) -> None:
    res, st = _run(tmp_path, STALE + LEFT, argv=("--now",), system="stopping")
    assert res.returncode == 0, res.stderr
    assert "calls" not in st and "unknown arguments" in res.stdout
