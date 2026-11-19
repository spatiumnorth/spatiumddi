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

import pytest

SCRIPT = (
    Path(__file__).parent.parent / "mkosi.extra" / "usr" / "local" / "bin" / "spatium-etcd-evict"
)

# `list <store>` prints the store's members as k3s's /db/info does; `remove <id>`
# drops the member from BOTH stores (one cluster, seen from two nodes) unless
# told to refuse. FAKE_ANSWER is an error etcd answers after that, and
# FAKE_NOT_APPLIED keeps the removal from happening behind it. FAKE_TOMBSTONE is
# the file k3s writes when a peer tells its etcd that this member was removed.
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
    if os.environ.get("FAKE_LEAD"):
        st = json.load(open(os.environ["FAKE_LEAD"]))
        st["removed_under"].append(st["leader"])
        json.dump(st, open(os.environ["FAKE_LEAD"], "w"))
    if os.environ.get("FAKE_REFUSE"):
        print("grpc-status 9: etcdserver: unhealthy cluster"); sys.exit(1)
    if not os.environ.get("FAKE_NOT_APPLIED"):
        for store in (os.environ["FAKE_LOCAL"], os.environ["FAKE_SURVIVOR"]):
            st = json.load(open(store))
            if not st.get("frozen"):
                st["members"] = [m for m in st["members"] if m["ID"] != mid]
            json.dump(st, open(store, "w"))
        if os.environ.get("FAKE_TOMBSTONE"):
            open(os.environ["FAKE_TOMBSTONE"], "w").close()
    if os.environ.get("FAKE_ANSWER"):
        print(os.environ["FAKE_ANSWER"]); sys.exit(1)
"""

# curl itself, for the answers that are curl's own exit code. It reads the frame
# remove_frame() pipes in (the member ID is a varint after the 5-byte gRPC header
# and field 1's tag), hands the removal to FAKE's `remove`, and exits
# FAKE_CURL_EXIT with curl's message on stderr.
FAKE_CURL = r"""
import os, subprocess, sys
frame, mid = sys.stdin.buffer.read(), 0
for i, b in enumerate(frame[6:]):
    mid |= (b & 0x7F) << (7 * i)
    if not b & 0x80:
        break
subprocess.run([sys.executable, os.environ["FAKE"], "remove", str(mid)], check=True)
sys.stderr.write(os.environ["FAKE_CURL_ERROR"] + "\n")
sys.exit(int(os.environ["FAKE_CURL_EXIT"]))
"""

# This node's etcd answering MoveLeader (#2874), with the member to hand the lead
# to as $1. FAKE_LEAD holds the leader's ID (0 while an election runs) and writes
# the etcd_server_has_leader gauge the metrics file serves. Only the leader takes
# the call, and it hands the lead over unless it is "stuck". A running election
# ends at the next call, won by "winner". FAKE's `remove` notes who led then.
FAKE_MOVE = r"""
import json, os, sys
path = os.environ["FAKE_LEAD"]
st = json.load(open(path))
target = int(sys.argv[1])
if not st["leader"] and st["calls"]:
    st["leader"] = st["winner"]
if st["leader"] != st["me"]:
    answer = "grpc-status 9: etcdserver: not leader"
elif st["stuck"]:
    answer = "grpc-status 14: etcdserver: request timed out, leader transfer took too long"
else:
    answer = ""
    st["leader"] = target
st["calls"].append([target, answer])
json.dump(st, open(path, "w"))
if st["metrics"]:
    open(st["metrics"], "w").write(f"etcd_server_has_leader {1 if st['leader'] else 0}\n")
if answer:
    print(answer); sys.exit(1)
"""

SEED = {
    "ID": 8674559146448320794,
    "name": "ddipg-seed-964d1931",
    "peerURLs": ["https://192.168.122.245:2380"],
}
ME = {
    "ID": 12000000000000000002,
    "name": "ddipg-member-1-7f072fd9",
    "peerURLs": ["https://192.168.122.161:2380"],
}
OTHER = {
    "ID": 18446744073709551557,
    "name": "ddipg-member-2-7d1c4ad1",
    "peerURLs": ["https://192.168.122.134:2380"],
}
LEADS = {"seed": SEED["ID"], "me": ME["ID"], "other": OTHER["ID"], "": 0}
NOT_LEADER = "grpc-status 9: etcdserver: not leader"

# What MemberRemove answered when a member removed itself and its etcd shut down
# first (#2394): etcd's ErrStopped, after the change was proposed.
SERVER_STOPPED = "grpc-status 14: etcdserver: server stopped"


def _run(
    tmp_path: Path,
    *,
    joined: bool = True,
    survivor_frozen: bool = False,
    survivor_down: bool = False,
    refuse: bool = False,
    local_unreadable: bool = False,
    answer: str = "",
    applied: bool = True,
    tombstone: bool = False,
    curl: tuple[int, str] | None = None,
    lead: str = "seed",
    winner: str = "seed",
    stuck: bool = False,
    gauge: bool = True,
    server: str = "https://192.168.122.245:6443",
) -> tuple[int, list[str], bool, str]:
    """`lead` names the member whose etcd leads when the leave starts ("" while an
    election runs, which `winner` wins); `stuck` keeps this node's etcd from
    handing the lead over; `gauge` False makes etcd's metrics unreadable. What
    MoveLeader was asked and who led at each removal: _lead(tmp_path)."""
    k3s = tmp_path / "k3s-server"
    (k3s / "db" / "etcd").mkdir(parents=True)
    (k3s / "db" / "etcd" / "config").write_text(f"name: {ME['name']}\n")
    dropin = tmp_path / "config.yaml.d"
    dropin.mkdir()
    if joined:
        (dropin / "spatium-cluster.yaml").write_text(f"server: {server}\ntoken: K10::server:x\n")
    metrics = tmp_path / "metrics"
    if gauge:
        metrics.write_text(f"etcd_server_has_leader {1 if LEADS[lead] else 0}\n")
    lead_state = tmp_path / "lead.json"
    lead_state.write_text(
        json.dumps(
            {
                "leader": LEADS[lead],
                "winner": LEADS[winner],
                "me": ME["ID"],
                "stuck": stuck,
                "metrics": str(metrics) if gauge else "",
                "calls": [],
                "removed_under": [],
            }
        )
    )
    move = tmp_path / "fake_move.py"
    move.write_text(FAKE_MOVE)
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
        "SPATIUM_ETCD_MOVE_LEADER_CMD": f'"{sys.executable}" "{move}" "$1"',
        "SPATIUM_ETCD_METRICS_URL": metrics.as_uri(),
        "SPATIUM_LEAVE_CONFIRM_S": "1",
        "SPATIUM_LEAD_HANDOFF_S": "1",
        "SPATIUM_LEAVE_POLL_S": "0.2",
        "FAKE_LEAD": str(lead_state),
        "FAKE_LOCAL": str(local),
        "FAKE_SURVIVOR": str(survivor),
        "FAKE_LOG": str(removals),
        "FAKE_REFUSE": "1" if refuse else "",
        "FAKE_ANSWER": answer,
        "FAKE_NOT_APPLIED": "" if applied else "1",
        "FAKE_TOMBSTONE": str(k3s / "db" / "etcd" / "tombstone") if tombstone else "",
    }
    if curl is not None:
        # The runner's own curl call, with `curl` (exit code, message) its answer.
        fake_curl = tmp_path / "fake_curl.py"
        fake_curl.write_text(FAKE_CURL)
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        (bin_dir / "curl").write_text(f'#!/bin/sh\nexec "{sys.executable}" "{fake_curl}" "$@"\n')
        (bin_dir / "curl").chmod(0o755)
        del env["SPATIUM_ETCD_REMOVE_CMD"]
        env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
        env["FAKE"] = str(fake)
        env["FAKE_CURL_EXIT"] = str(curl[0])
        env["FAKE_CURL_ERROR"] = f"curl: ({curl[0]}) {curl[1]}"
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


def _lead(tmp_path: Path) -> dict:
    """What the fake etcd saw: `calls` ([member asked to lead, answer] per
    MoveLeader) and `removed_under` (who led at each removal, 0 for nobody)."""
    return json.loads((tmp_path / "lead.json").read_text())


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


# ---- an error answer for this node's own member (#2394) --------------------------
#
# The member removes itself through its own etcd. A peer that has applied the
# removal rejects this etcd's traffic, k3s writes its tombstone and closes etcd,
# and the MemberRemove call, still waiting for this node to apply the change,
# answers `server stopped`. The member is gone; the answer says nothing either way.


def test_a_removal_answered_server_stopped_goes_on_once_the_survivor_confirms(
    tmp_path: Path,
) -> None:
    rc, removed, stopped, log = _run(tmp_path, answer=SERVER_STOPPED)
    assert rc == 0, log
    assert removed == ["remove", str(ME["ID"])]
    assert stopped
    assert "server stopped" in log
    assert "no longer lists" in log


@pytest.mark.parametrize(
    "answer",
    [
        # grpc_error(): no gRPC status at all, so etcd never took the call.
        "no grpc-status in etcd's answer (HTTP 415)",
        # etcd's strict reconfiguration check, which refuses before proposing.
        "grpc-status 9: etcdserver: re-configuration failed due to not enough started members",
        "grpc-status 14: etcdserver: unhealthy cluster",
    ],
)
def test_an_answer_given_before_anything_was_proposed_still_refuses_at_once(
    tmp_path: Path, answer: str
) -> None:
    rc, removed, stopped, log = _run(tmp_path, answer=answer, applied=False)
    assert rc == 1
    assert removed == ["remove", str(ME["ID"])]
    assert not stopped
    assert "could not remove" in log


@pytest.mark.parametrize("tombstone", [False, True])
def test_an_error_answer_is_refused_while_the_survivor_still_lists_the_member(
    tmp_path: Path, tombstone: bool
) -> None:
    """A survivor that answers is the verdict: the leave is refused, k3s was
    stopped, and the caller starts it again. A tombstone does not overrule it."""
    rc, _, stopped, log = _run(
        tmp_path, answer=SERVER_STOPPED, survivor_frozen=True, tombstone=tombstone
    )
    assert rc == 1
    assert stopped
    assert "did not confirm" in log


def test_an_error_answer_with_no_survivor_and_no_tombstone_is_refused(tmp_path: Path) -> None:
    """Nothing shows the member gone. Wiping a node whose member may still vote is
    the #1541 harm, which can cost the seed its quorum; refusing costs this node a
    rejoin. The runner cannot tell this from a removal that applied and left no
    trace, so it refuses both."""
    rc, _, stopped, log = _run(
        tmp_path, answer=SERVER_STOPPED, applied=False, survivor_down=True
    )
    assert rc == 1
    assert stopped
    assert "not wiping" in log


def test_an_error_answer_with_no_survivor_goes_on_when_k3s_left_its_tombstone(
    tmp_path: Path,
) -> None:
    """k3s writes db/etcd/tombstone only when a peer rejects this etcd because it
    has applied the member's removal: a committed removal, whatever the call
    answered."""
    rc, removed, stopped, log = _run(
        tmp_path, answer=SERVER_STOPPED, survivor_down=True, tombstone=True
    )
    assert rc == 0, log
    assert removed == ["remove", str(ME["ID"])]
    assert stopped
    assert "tombstone" in log


# ---- a curl that failed (#2394) ---------------------------------------------------
#
# Without SPATIUM_ETCD_REMOVE_CMD the runner sends the removal with curl, and a
# failed curl answers with its exit code. curl raises some exits only while it
# connects, before it sends anything, so etcd never saw the call. Every other
# exit can come after the call was sent, when etcd may have applied it.

# The runner's CURL_NEVER_SENT, each with a message of the kind curl prints.
NEVER_SENT = {
    6: "Could not resolve host: etcd",
    7: "Failed to connect to 127.0.0.1 port 2379: Connection refused",
    35: "TLS connect error: unexpected eof while reading",
    58: "could not load PEM client certificate",
    60: "SSL certificate problem: certificate has expired",
    77: "error setting certificate file",
}
MAY_HAVE_BEEN_SENT = {
    16: "Error in the HTTP2 framing layer",
    28: "Operation timed out after 15002 milliseconds with 0 bytes received",
    52: "Empty reply from server",
    55: "Failed sending data to the peer",
    56: "Recv failure: Connection reset by peer",
    92: "HTTP/2 stream 1 was not closed cleanly: INTERNAL_ERROR (err 2)",
}


@pytest.mark.parametrize("code", sorted(NEVER_SENT))
def test_a_curl_that_never_sent_the_removal_refuses_at_once_with_k3s_running(
    tmp_path: Path, code: int
) -> None:
    """etcd never saw the call, so the member still votes. Stopping k3s here
    would take a voter away while it still counts, and two demotes at once
    could briefly cost a three-node cluster its quorum."""
    rc, removed, stopped, log = _run(tmp_path, curl=(code, NEVER_SENT[code]), applied=False)
    assert rc == 1, log
    assert removed == ["remove", str(ME["ID"])]
    assert not stopped, log
    assert (
        f"could not remove this node's etcd member {ME['ID']} {ME['name']}: curl exit {code}:"
        in log
    )


@pytest.mark.parametrize("code", sorted(MAY_HAVE_BEEN_SENT))
def test_a_curl_that_failed_after_sending_the_removal_still_asks_the_survivor(
    tmp_path: Path, code: int
) -> None:
    """etcd may have applied the removal, as it did here: k3s is stopped and the
    survivor decides, as after `server stopped`."""
    rc, removed, stopped, log = _run(tmp_path, curl=(code, MAY_HAVE_BEEN_SENT[code]))
    assert rc == 0, log
    assert removed == ["remove", str(ME["ID"])]
    assert stopped
    assert f"curl exit {code}:" in log
    assert "no longer lists" in log


# ---- the etcd lead (#2874) ---------------------------------------------------------
#
# A leader that removes itself leaves the cluster without one until an election
# timeout. With both members of three leaving at once, the other member's removal
# waited through that election, won it, and committed at once with itself as the
# leader: the seed, alone and still leaderless, lost its controller-manager lease,
# k3s exited, and it came back counting the removed member as a voter for good.


def test_a_leader_hands_the_lead_to_the_seed_before_it_removes_itself(tmp_path: Path) -> None:
    rc, removed, stopped, log = _run(tmp_path, lead="me")
    assert rc == 0, log
    assert removed == ["remove", str(ME["ID"])]
    assert stopped
    lead = _lead(tmp_path)
    assert lead["calls"] == [[SEED["ID"], ""]]
    assert lead["removed_under"] == [SEED["ID"]]
    assert f"handed the etcd lead to {SEED['ID']} {SEED['name']}" in log


@pytest.mark.parametrize("leader", ["seed", "other"])
def test_a_follower_has_no_lead_to_hand_off(tmp_path: Path, leader: str) -> None:
    rc, removed, stopped, log = _run(tmp_path, lead=leader)
    assert rc == 0, log
    assert removed == ["remove", str(ME["ID"])]
    assert stopped
    lead = _lead(tmp_path)
    assert lead["calls"] == [[SEED["ID"], NOT_LEADER]]
    assert lead["removed_under"] == [LEADS[leader]]
    assert "handed the etcd lead" not in log


def test_the_lead_goes_to_the_member_on_the_host_this_node_joined(tmp_path: Path) -> None:
    """The survivor is found by the join's ``server:`` host, not by list order."""
    rc, _, _, log = _run(tmp_path, lead="me", server="https://192.168.122.134:6443")
    assert rc == 0, log
    lead = _lead(tmp_path)
    assert lead["calls"] == [[OTHER["ID"], ""]]
    assert lead["removed_under"] == [OTHER["ID"]]


@pytest.mark.parametrize("winner", ["seed", "me"])
def test_with_no_leader_the_removal_waits_for_the_election(tmp_path: Path, winner: str) -> None:
    """Proposed into an election, the removal would commit at once if this node
    won it, with this node the leader. It waits for a leader instead, and hands
    the lead to the seed if this node won."""
    rc, removed, stopped, log = _run(tmp_path, lead="", winner=winner)
    assert rc == 0, log
    assert removed == ["remove", str(ME["ID"])]
    assert stopped
    lead = _lead(tmp_path)
    assert lead["calls"][0] == [SEED["ID"], NOT_LEADER]
    assert lead["calls"][-1] == [SEED["ID"], "" if winner == "me" else NOT_LEADER]
    assert lead["removed_under"] == [SEED["ID"]]


def test_a_leader_that_cannot_hand_off_keeps_its_member_and_k3s(tmp_path: Path) -> None:
    rc, removed, stopped, log = _run(tmp_path, lead="me", stuck=True)
    assert rc == 1
    assert removed == []
    assert not stopped
    assert "leader transfer took too long" in log
    assert "not removing its member" in log


def test_an_unreadable_leader_gauge_does_not_hold_the_leave(tmp_path: Path) -> None:
    """Without the gauge the runner cannot tell an election from another member's
    lead, and goes on as before the hand-off existed."""
    rc, removed, stopped, log = _run(tmp_path, lead="", gauge=False)
    assert rc == 0, log
    assert removed == ["remove", str(ME["ID"])]
    assert stopped
    assert _lead(tmp_path)["calls"] == [[SEED["ID"], NOT_LEADER]]
