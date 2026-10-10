"""spatium-etcd-evict --leave-self: a demoted member leaves etcd before it wipes
itself (#1541).

A demoted node used to reset itself to a fresh single-node seed without leaving
etcd, so the seed kept its seat as a voter nobody would ever answer for. From
three members the only demote allowed takes both non-seed members, and the seed
lost quorum. etcd removes a member only while it has quorum, so the removal has
to happen while this node still votes, and only a survivor can say it is done.

These tests run the real runner against fake etcd answers: one for this node's
own k3s, one for the survivor the node joined.

    python3 -m pytest appliance/tests/test_etcd_leave_self.py -v
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPT = (
    Path(__file__).parent.parent / "mkosi.extra" / "usr" / "local" / "bin" / "spatium-etcd-evict"
)

# `list <store>` prints the store's members as k3s's /db/info does; `remove <id>`
# drops the member from BOTH stores (one cluster, seen from two nodes) unless
# told to refuse.
FAKE = r"""
import json, os, sys
if sys.argv[1] == "list":
    st = json.load(open(sys.argv[2]))
    if st.get("unreadable"):
        print("curl: (7) Failed to connect"); sys.exit(7)
    print(json.dumps({"members": st["members"]}))
else:
    mid = int(sys.argv[2])
    log = os.environ["FAKE_LOG"]
    open(log, "a").write(f"remove {mid}\n")
    if os.environ.get("FAKE_REFUSE"):
        print("grpc-status 9: etcdserver: unhealthy cluster"); sys.exit(1)
    for store in (os.environ["FAKE_LOCAL"], os.environ["FAKE_SURVIVOR"]):
        st = json.load(open(store))
        if not st.get("frozen"):
            st["members"] = [m for m in st["members"] if m["ID"] != mid]
        json.dump(st, open(store, "w"))
"""

SEED = {"ID": 8674559146448320794, "name": "ddipg-seed-964d1931"}
ME = {"ID": 12000000000000000002, "name": "ddipg-member-1-7f072fd9"}
OTHER = {"ID": 18446744073709551557, "name": "ddipg-member-2-7d1c4ad1"}


def _run(
    tmp_path: Path,
    *,
    joined: bool = True,
    survivor_frozen: bool = False,
    survivor_down: bool = False,
    refuse: bool = False,
    local_unreadable: bool = False,
) -> tuple[int, list[str], bool, str]:
    k3s = tmp_path / "k3s-server"
    (k3s / "db" / "etcd").mkdir(parents=True)
    (k3s / "db" / "etcd" / "config").write_text(f"name: {ME['name']}\n")
    dropin = tmp_path / "config.yaml.d"
    dropin.mkdir()
    if joined:
        (dropin / "spatium-cluster.yaml").write_text(
            "server: https://192.168.122.245:6443\ntoken: K10::server:x\n"
        )
    members = [SEED, ME, OTHER]
    local = tmp_path / "local.json"
    local.write_text(json.dumps({"members": members, "unreadable": local_unreadable}))
    survivor = tmp_path / "survivor.json"
    survivor.write_text(
        json.dumps({"members": members, "frozen": survivor_frozen, "unreadable": survivor_down})
    )
    fake = tmp_path / "fake.py"
    fake.write_text(FAKE)
    stopped = tmp_path / "k3s-stopped"
    removals = tmp_path / "removals"
    env = {
        **os.environ,
        "SPATIUM_LOG_DIR": str(tmp_path / "log"),
        "SPATIUM_K3S_SERVER_DIR": str(k3s),
        "SPATIUM_K3S_DROPIN_DIR": str(dropin),
        "SPATIUM_NODE_NAME": "ddipg-member-1",
        "SPATIUM_ETCD_MEMBERS_CMD": f'"{sys.executable}" "{fake}" list "{local}"',
        "SPATIUM_ETCD_SURVIVOR_MEMBERS_CMD": f'"{sys.executable}" "{fake}" list "{survivor}"',
        "SPATIUM_ETCD_REMOVE_CMD": f'"{sys.executable}" "{fake}" remove "$1"',
        "SPATIUM_STOP_K3S_CMD": f'touch "{stopped}"',
        "SPATIUM_LEAVE_CONFIRM_S": "1",
        "SPATIUM_LEAVE_POLL_S": "0.2",
        "FAKE_LOCAL": str(local),
        "FAKE_SURVIVOR": str(survivor),
        "FAKE_LOG": str(removals),
        "FAKE_REFUSE": "1" if refuse else "",
    }
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--leave-self"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    log = (tmp_path / "log" / "etcd-evict.log").read_text() if (tmp_path / "log").exists() else ""
    done = removals.read_text().split() if removals.exists() else []
    return r.returncode, done, stopped.exists(), log


def test_removes_only_its_own_member_then_stops_k3s_and_confirms(tmp_path: Path) -> None:
    rc, removed, stopped, log = _run(tmp_path)
    assert rc == 0, log
    assert removed == ["remove", str(ME["ID"])]
    assert stopped
    assert "no longer lists" in log


def test_a_node_that_joined_nobody_has_nothing_to_remove(tmp_path: Path) -> None:
    rc, removed, stopped, _ = _run(tmp_path, joined=False)
    assert rc == 2
    assert removed == []
    assert not stopped


def test_unconfirmed_removal_is_a_failure(tmp_path: Path) -> None:
    # The survivor answers and still lists the member: the caller must not wipe.
    rc, _, stopped, log = _run(tmp_path, survivor_frozen=True)
    assert rc == 1
    assert stopped
    assert "did not confirm" in log


def test_an_unreachable_survivor_does_not_refuse_an_accepted_removal(tmp_path: Path) -> None:
    """etcd accepted the removal, so the member is gone. Refusing because the
    survivor could not be asked restarted k3s, which rejoined the node as a
    new member and left the control plane on two voters (ddi-pg, #1659)."""
    rc, removed, stopped, log = _run(tmp_path, survivor_down=True)
    assert rc == 0, log
    assert removed == ["remove", str(ME["ID"])]
    assert stopped
    assert "could not be reached" in log


def test_a_refused_removal_leaves_k3s_running(tmp_path: Path) -> None:
    rc, _, stopped, log = _run(tmp_path, refuse=True)
    assert rc == 1
    assert not stopped
    assert "could not remove" in log


def test_an_unreadable_own_list_removes_nothing(tmp_path: Path) -> None:
    rc, removed, stopped, _ = _run(tmp_path, local_unreadable=True)
    assert rc == 1
    assert removed == []
    assert not stopped
