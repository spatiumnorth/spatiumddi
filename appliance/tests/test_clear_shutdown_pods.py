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
save()
print("fake kubectl: unexpected call %r" % (args,), file=sys.stderr)
sys.exit(2)
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


def _run(tmp_path: Path, pods: list[dict], *, wait_s: float = 5.0,
         **state) -> tuple[subprocess.CompletedProcess, dict]:
    fake = tmp_path / "fake_kubectl.py"
    fake.write_text(FAKE_KUBECTL)
    state_file = tmp_path / "kubectl.json"
    state_file.write_text(json.dumps({"pods": pods, **state}))
    env = {
        **os.environ,
        "SPATIUM_KUBECTL": f'"{sys.executable}" "{fake}"',
        "SPATIUM_KUBECONFIG": str(tmp_path / "k3s.yaml"),
        "SPATIUM_NODE_NAME": NODE,
        "SPATIUM_API_WAIT_S": str(wait_s),
        "SPATIUM_API_POLL_S": "0.05",
        "FAKE_KUBECTL_STATE": str(state_file),
    }
    res = subprocess.run([sys.executable, str(SCRIPT)], env=env, capture_output=True,
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
