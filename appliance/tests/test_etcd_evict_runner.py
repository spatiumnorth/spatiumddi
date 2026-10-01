"""spatium-etcd-evict removes the etcd member of a node Fleet → Replace evicts,
on the seed, and nothing else (#1284).

k3s removes a server's etcd member only through its k8s Node. A node that became
an etcd voter before its Node registered has none, so the seed's Node delete
(a 404) left the dead voter in place for good. These tests run the real runner
against a fake etcd (SPATIUM_ETCD_MEMBERS_CMD / SPATIUM_ETCD_REMOVE_CMD) and a
temp release-state dir: what it removes, what it never touches, what it reports,
and the gRPC frame it sends.

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_etcd_evict_runner.py -v

No etcd, no k3s required.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

SCRIPT = (
    Path(__file__).parent.parent / "mkosi.extra" / "usr" / "local" / "bin" / "spatium-etcd-evict"
)
CONFIRM = "SPATIUMDDI-ETCD-EVICT-CONFIRM-V1"

# A stand-in for the two etcd calls: `list` prints k3s's /db/info body (member
# IDs as bare uint64 numbers, as k3s serves them); `remove <id>` drops the
# member, or fails the way etcd refuses when told to.
FAKE_ETCD = r'''
import json, os, sys
store = os.environ["FAKE_ETCD_STATE"]
st = json.load(open(store))
if sys.argv[1] == "list":
    if st.get("unreadable"):
        print("curl: (7) Failed to connect to 127.0.0.1 port 6443"); sys.exit(7)
    if st.get("next_request"):
        # the supervisor writes its next request while the runner is working
        open(os.environ["FAKE_TRIGGER"], "w").write(st.pop("next_request"))
        json.dump(st, open(store, "w"))
    print(json.dumps({"members": st["members"]}))
else:
    mid = int(sys.argv[2])
    st.setdefault("removed", []).append(mid)
    json.dump(st, open(store, "w"))
    if mid in st.get("refuse", []):
        print("grpc-status 14: etcdserver: unhealthy cluster"); sys.exit(1)
    st["members"] = [m for m in st["members"] if m["ID"] != mid]
    json.dump(st, open(store, "w"))
'''


def _m(mid: int, name: str, ip: str, learner: bool = False) -> dict:
    m: dict = {"ID": mid, "name": name, "peerURLs": [f"https://{ip}:2380"]}
    if name:
        m["clientURLs"] = [f"https://{ip}:2379"]
    if learner:
        m["isLearner"] = True
    return m


SEED = _m(8674559146448320794, "ddipg-seed-964d1931", "192.168.122.245")
M1 = _m(12000000000000000002, "ddipg-member-1-7f072fd9", "192.168.122.160")
GHOST = _m(18446744073709551557, "ddipg-member-3-7d1c4ad1", "192.168.122.86")  # > 2^63


def _run(tmp_path: Path, members: list[dict], request: str | None,
         node_name: str = "ddipg-seed", age_s: float = 0.0, **store) -> tuple[dict, str, dict]:
    """One run of the runner. `request` None writes no request (the unit started
    again by hand); `age_s` backdates the request's mtime."""
    rs = tmp_path / "release-state"
    rs.mkdir(exist_ok=True)
    if request is not None:
        (rs / "etcd-evict-pending").write_text(request)
        if age_s:
            then = time.time() - age_s
            os.utime(rs / "etcd-evict-pending", (then, then))
    k3s = tmp_path / "k3s-server"
    (k3s / "db" / "etcd").mkdir(parents=True, exist_ok=True)
    (k3s / "db" / "etcd" / "config").write_text("name: ddipg-seed-964d1931\n")
    fake = tmp_path / "fake_etcd.py"
    fake.write_text(FAKE_ETCD)
    state_file = tmp_path / "etcd.json"
    state_file.write_text(json.dumps({"members": members, **store}))
    env = {
        **os.environ,
        "SPATIUM_RELEASE_STATE": str(rs),
        "SPATIUM_LOG_DIR": str(tmp_path / "log"),
        "SPATIUM_K3S_SERVER_DIR": str(k3s),
        "SPATIUM_ETCD_MEMBERS_CMD": f'"{sys.executable}" "{fake}" list',
        "SPATIUM_ETCD_REMOVE_CMD": f'"{sys.executable}" "{fake}" remove "$1"',
        "FAKE_ETCD_STATE": str(state_file),
        "FAKE_TRIGGER": str(rs / "etcd-evict-pending"),
        "SPATIUM_NODE_NAME": node_name,
    }
    subprocess.run([sys.executable, str(SCRIPT)], env=env, capture_output=True, text=True,
                   check=False)
    answer = (rs / "etcd-evict.state").read_text() if (rs / "etcd-evict.state").exists() else ""
    results = {}
    for line in answer.splitlines()[1:]:
        host, state, detail = (line.split("\t") + ["", ""])[:3]
        results[host] = (state, detail)
    return results, answer, json.loads(state_file.read_text())


def _request(*nodes: tuple[str, str], rid: str = "a1b2c3") -> str:
    return "\n".join([CONFIRM, f"id {rid}", *(f"node\t{h}\t{ips}" for h, ips in nodes)]) + "\n"


def _module():
    """The runner as a module, loaded without writing bytecode next to it (it
    lives in mkosi.extra, which the image build copies)."""
    loader = importlib.machinery.SourceFileLoader("spatium_etcd_evict", str(SCRIPT))
    spec = importlib.util.spec_from_loader("spatium_etcd_evict", loader)
    mod = importlib.util.module_from_spec(spec)
    was, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = was
    return mod


def test_a_voter_with_no_node_is_removed_and_nothing_else(tmp_path: Path) -> None:
    """The #1284 ghost: member-3 is a voter whose Node never registered. Its ID is
    above 2^63, as a random uint64 member ID can be: it must survive exactly."""
    results, answer, etcd = _run(tmp_path, [SEED, M1, GHOST],
                                 _request(("ddipg-member-3", "192.168.122.86")))
    assert answer.startswith("id a1b2c3\n")
    assert results["ddipg-member-3"] == (
        "removed", "18446744073709551557 ddipg-member-3-7d1c4ad1")
    assert [m["name"] for m in etcd["members"]] == ["ddipg-seed-964d1931",
                                                    "ddipg-member-1-7f072fd9"]
    assert etcd["removed"] == [18446744073709551557]


def test_an_unnamed_learner_is_matched_by_its_peer_url(tmp_path: Path) -> None:
    learner = _m(777, "", "192.168.122.86", learner=True)
    results, _, etcd = _run(tmp_path, [SEED, M1, learner],
                            _request(("ddipg-member-3", "192.168.122.86,fd00::86")))
    assert results["ddipg-member-3"] == ("removed", "777 (unnamed)")
    assert 777 not in [m["ID"] for m in etcd["members"]]


def test_an_ipv6_peer_url_is_matched_without_its_brackets(tmp_path: Path) -> None:
    learner = {"ID": 778, "name": "", "peerURLs": ["https://[fd00::86]:2380"]}
    results, _, _ = _run(tmp_path, [SEED, learner], _request(("ddipg-member-3", "fd00::86")))
    assert results["ddipg-member-3"][0] == "removed"


def test_names_are_matched_exactly_never_by_prefix(tmp_path: Path) -> None:
    """Evicting ddipg-member-3 must not touch ddipg-member-30 or a hostname that
    merely starts with it."""
    m30 = _m(30, "ddipg-member-30-abcdef12", "192.168.122.30")
    other = _m(31, "ddipg-member-3-extra-12345678", "192.168.122.31")
    results, _, etcd = _run(tmp_path, [SEED, m30, other],
                            _request(("ddipg-member-3", "192.168.122.86")))
    assert results["ddipg-member-3"] == ("absent", "")
    assert len(etcd["members"]) == 3 and "removed" not in etcd


def test_this_nodes_own_member_is_never_removed(tmp_path: Path) -> None:
    results, _, etcd = _run(tmp_path, [SEED, M1],
                            _request(("ddipg-seed", "192.168.122.245")))
    assert results["ddipg-seed"] == ("absent", "")
    assert "removed" not in etcd


def test_a_node_whose_name_extends_the_seeds_is_still_evictable(tmp_path: Path) -> None:
    """The own-member guard is exact: a node named ddipg-seed-2 is not the seed
    (ddipg-seed), and its member ddipg-seed-2-abcdef12 is removable."""
    other = _m(42, "ddipg-seed-2-abcdef12", "192.168.122.42")
    results, _, etcd = _run(tmp_path, [SEED, M1, other],
                            _request(("ddipg-seed-2", "192.168.122.42")))
    assert results["ddipg-seed-2"] == ("removed", "42 ddipg-seed-2-abcdef12")
    assert [m["ID"] for m in etcd["members"]] == [SEED["ID"], M1["ID"]]


def test_a_refused_removal_reports_the_member_still_present(tmp_path: Path) -> None:
    results, _, _ = _run(tmp_path, [SEED, M1, GHOST],
                         _request(("ddipg-member-3", "192.168.122.86")),
                         refuse=[18446744073709551557])
    state, detail = results["ddipg-member-3"]
    assert state == "present"
    assert "18446744073709551557 ddipg-member-3-7d1c4ad1 still listed" in detail
    assert "remove failed: 18446744073709551557 ddipg-member-3-7d1c4ad1: grpc-status 14: " \
           "etcdserver: unhealthy cluster" in detail


def test_a_member_k3s_already_removed_counts_as_gone(tmp_path: Path) -> None:
    """A Node that existed: k3s removes the member itself through it, and the
    runner finds nothing left. Absent is the outcome we want."""
    results, _, etcd = _run(tmp_path, [SEED, M1], _request(("ddipg-member-2", "192.168.122.46")))
    assert results["ddipg-member-2"] == ("absent", "")
    assert "removed" not in etcd


def test_an_unreadable_member_list_is_an_error_for_every_node(tmp_path: Path) -> None:
    results, _, _ = _run(tmp_path, [SEED, GHOST],
                         _request(("ddipg-member-3", "192.168.122.86"),
                                  ("ddipg-member-4", "")),
                         unreadable=True)
    assert results["ddipg-member-3"][0] == "error"
    assert results["ddipg-member-4"][0] == "error"
    assert "unreadable" in results["ddipg-member-3"][1]


def test_k3s_fallback_list_without_ids_is_unreadable(tmp_path: Path) -> None:
    """When k3s's own MemberList fails, /db/info answers a canned list naming only
    itself with no IDs. That is not a one-member cluster."""
    results, _, _ = _run(tmp_path, [{"name": "ddipg-seed-964d1931",
                                     "peerURLs": ["https://192.168.122.245:2380"]}],
                         _request(("ddipg-member-3", "192.168.122.86")))
    assert results["ddipg-member-3"][0] == "error"
    assert "fallback list" in results["ddipg-member-3"][1]


def test_a_request_without_the_marker_removes_nothing(tmp_path: Path) -> None:
    request = "\n".join(["not-the-marker", "id x", "node\tddipg-member-3\t192.168.122.86"])
    results, answer, etcd = _run(tmp_path, [SEED, GHOST], request + "\n")
    assert answer == "" and "removed" not in etcd
    assert list((tmp_path / "release-state").glob("etcd-evict-pending.rejected.*"))


def test_the_remove_frame_is_member_remove_request_with_a_uint64_id() -> None:
    """etcdserverpb.MemberRemoveRequest{ID = 1 (uint64)} in one gRPC frame: no
    compression flag, 4-byte big-endian length, then field 1 as a varint."""
    mod = _module()
    assert mod.remove_frame(1) == b"\x00\x00\x00\x00\x02\x08\x01"
    assert mod.remove_frame(300) == b"\x00\x00\x00\x00\x03\x08\xac\x02"
    top = mod.remove_frame(2**64 - 1)
    assert top[:5] == b"\x00\x00\x00\x00\x0b" and top[5:] == b"\x08" + b"\xff" * 9 + b"\x01"


def test_it_speaks_grpc_over_http2_to_the_loopback_etcd_with_the_client_cert() -> None:
    """k3s's etcd serves no JSON gateway on its client port (HTTP/1.1: empty reply;
    HTTP/2 + JSON: 415 from the gRPC server), so the removal is the gRPC call."""
    text = SCRIPT.read_text()
    assert '"--http2"' in text and '"content-type: application/grpc"' in text
    assert "/etcdserverpb.Cluster/MemberRemove" in text
    assert '"--cert", str(tls / "client.crt"), "--key", str(tls / "client.key")' in text
    assert 'ETCD_URL = os.environ.get("SPATIUM_ETCD_URL", "https://127.0.0.1:2379")' in text
    assert "/db/info" in text


# ---- a request is run once, and only while it is fresh (#1326 review, finding 3) ----

def test_an_answered_request_is_never_run_again(tmp_path: Path) -> None:
    """The runner used to leave its request on disk with the last names, and had
    no expiry of its own: anything that started the unit again (a manual
    `systemctl start`, a touch of the trigger) re-ran it, against a node that
    may have re-joined since, and removed its new member. The answered request
    is now set aside, so a second run finds nothing to do."""
    results, _, _ = _run(tmp_path, [SEED, M1, GHOST],
                         _request(("ddipg-member-3", "192.168.122.86")))
    assert results["ddipg-member-3"][0] == "removed"
    rs = tmp_path / "release-state"
    assert not (rs / "etcd-evict-pending").exists()
    assert (rs / "etcd-evict-pending.done").read_text().startswith(CONFIRM + "\nid a1b2c3\n")

    # member-3 is promoted again and re-joins, under a new member name; then
    # something starts the unit again.
    rejoined = _m(4242, "ddipg-member-3-0a1b2c3d", "192.168.122.86")
    _, _, etcd = _run(tmp_path, [SEED, M1, rejoined], None)
    assert "removed" not in etcd
    assert [m["ID"] for m in etcd["members"]] == [SEED["ID"], M1["ID"], 4242]


def test_a_stale_request_is_refused_and_removes_nothing(tmp_path: Path) -> None:
    """A request the path unit never ran when it was written (the runner starts
    about a second after the supervisor writes one) is refused: nobody waits
    on it any more, and it may name a node that has re-joined since."""
    results, _, etcd = _run(tmp_path, [SEED, M1, GHOST],
                            _request(("ddipg-member-3", "192.168.122.86")), age_s=600)
    assert "removed" not in etcd
    state, detail = results["ddipg-member-3"]
    assert state == "error"
    assert "s old (the limit is 60s): nothing removed" in detail
    rs = tmp_path / "release-state"
    assert not (rs / "etcd-evict-pending").exists()
    assert (rs / "etcd-evict-pending.stale").exists()


def test_a_request_inside_the_limit_is_answered(tmp_path: Path) -> None:
    results, _, etcd = _run(tmp_path, [SEED, M1, GHOST],
                            _request(("ddipg-member-3", "192.168.122.86")), age_s=30)
    assert results["ddipg-member-3"][0] == "removed"
    assert etcd["removed"] == [GHOST["ID"]]


def test_a_failed_request_is_set_aside_too(tmp_path: Path) -> None:
    """An unreadable member list answers `error`; the supervisor asks again with
    a new request, so this one is not left to be re-run either."""
    results, _, _ = _run(tmp_path, [SEED, GHOST], _request(("ddipg-member-3", "192.168.122.86")),
                         unreadable=True)
    assert results["ddipg-member-3"][0] == "error"
    rs = tmp_path / "release-state"
    assert not (rs / "etcd-evict-pending").exists()
    assert (rs / "etcd-evict-pending.failed").exists()


def test_a_request_written_during_a_run_is_left_for_the_next(tmp_path: Path) -> None:
    """Only the request this run answered is set aside. One the supervisor writes
    while the runner works stays at the trigger's path, unexecuted."""
    nxt = _request(("ddipg-member-1", "192.168.122.160"), rid="d4e5f6")
    results, answer, etcd = _run(tmp_path, [SEED, M1, GHOST],
                                 _request(("ddipg-member-3", "192.168.122.86")),
                                 next_request=nxt)
    assert answer.startswith("id a1b2c3\n")
    assert results["ddipg-member-3"][0] == "removed"
    assert etcd["removed"] == [GHOST["ID"]]
    rs = tmp_path / "release-state"
    assert (rs / "etcd-evict-pending").read_text() == nxt
    assert "id a1b2c3" in (rs / "etcd-evict-pending.done").read_text()
