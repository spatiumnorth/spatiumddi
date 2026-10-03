"""#1284 — the seed reports a node evicted only once etcd no longer lists it.

Before, a Node DELETE that answered 404 (a node that became an etcd voter before
its Node registered) counted as the eviction: the row settled ``left`` while the
dead voter kept its seat, and every later member add was refused. These tests
drive ``etcd_evict.EtcdEvictions`` against a temp release-state dir: the request
it hands the host runner, the answers it trusts, and what it reports.
"""

from __future__ import annotations

from pathlib import Path

from spatium_supervisor import etcd_evict as ee

M3, M4 = "ddipg-member-3", "ddipg-member-4"


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0
        self.on_sleep = None          # a runner stand-in: runs when a tick waits

    def __call__(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.t += s
        if self.on_sleep:
            self.on_sleep()


def _evictions(tmp_path: Path, runner: bool = True) -> tuple[ee.EtcdEvictions, Clock]:
    clock = Clock()
    run = tmp_path / "spatium-etcd-evict"
    if runner:
        run.write_text("#!/bin/bash\n")
    ev = ee.EtcdEvictions(request_file=tmp_path / "etcd-evict-pending",
                          state_file=tmp_path / "etcd-evict.state", runner=run, clock=clock,
                          sleep=clock.sleep)
    return ev, clock


def _request(ev: ee.EtcdEvictions) -> tuple[str, list[str]]:
    lines = ev.request_file.read_text().splitlines()
    assert lines[0] == ee.CONFIRM
    assert lines[1].startswith("id ")
    return lines[1][3:], lines[2:]


def _answer(ev: ee.EtcdEvictions, request_id: str, *rows: str) -> None:
    ev.state_file.write_text("\n".join([f"id {request_id}", *rows]) + "\n")


def test_request_and_answer_round_trip() -> None:
    text = ee.render_request("abc", {M4: ["10.0.0.4"], M3: ["10.0.0.3", "fd00::3"]})
    assert text == (f"{ee.CONFIRM}\nid abc\nnode\t{M3}\t10.0.0.3,fd00::3\n"
                    f"node\t{M4}\t10.0.0.4\n")
    rid, res = ee.parse_state(f"id abc\n{M3}\tremoved\t4e73a0332d9ea29c {M3}-7d1c4ad1\n"
                              f"{M4}\tabsent\t\n")
    assert rid == "abc"
    assert res == {M3: ("removed", f"4e73a0332d9ea29c {M3}-7d1c4ad1"), M4: ("absent", "")}


def test_a_404_node_is_not_evicted_until_etcd_drops_its_member(tmp_path: Path) -> None:
    """The #1284 shape: the Node never existed, the voter did. The first tick
    asks the runner and reports nothing; the answer `present` keeps it pending
    with the reason; only `removed` confirms it."""
    ev, clock = _evictions(tmp_path)

    confirmed, reasons = ev.tick({M3: ["192.168.122.86"]})
    assert confirmed == []
    assert reasons[M3].startswith(f"waiting for the seed's etcd to drop {M3}")
    rid, nodes = _request(ev)
    assert nodes == [f"node\t{M3}\t192.168.122.86"]

    _answer(ev, rid, f"{M3}\tpresent\tetcd member {M3}-7d1c4ad1 still present: remove "
                     "failed: etcdserver: unhealthy cluster")
    clock.t += 30
    confirmed, reasons = ev.tick({M3: ["192.168.122.86"]})
    assert confirmed == []
    assert "still present: remove failed" in reasons[M3]

    rid, _ = _request(ev)
    _answer(ev, rid, f"{M3}\tremoved\t4e73a0332d9ea29c {M3}-7d1c4ad1")
    clock.t += 30
    confirmed, reasons = ev.tick({M3: ["192.168.122.86"]})
    assert confirmed == [M3] and reasons == {}


def test_an_answer_to_an_older_request_is_not_evidence(tmp_path: Path) -> None:
    ev, clock = _evictions(tmp_path)
    ev.tick({M3: []})
    _answer(ev, "some-older-request", f"{M3}\tabsent\t")
    clock.t += 30
    confirmed, reasons = ev.tick({M3: []})
    assert confirmed == [] and M3 in reasons


def test_a_confirmed_name_stays_on_the_runners_list_for_late_arrivals(tmp_path: Path) -> None:
    """The node's own re-join may add its member after the eviction: the name
    keeps being checked (and removed) for WATCH_S after etcd agreed."""
    ev, clock = _evictions(tmp_path)
    ev.tick({M3: ["192.168.122.86"]})
    rid, _ = _request(ev)
    _answer(ev, rid, f"{M3}\tabsent\t")
    clock.t += 30
    assert ev.tick({M3: ["192.168.122.86"]})[0] == [M3]

    # The backend settled the row and dropped the name; the watch goes on.
    rid2, nodes = _request(ev)
    assert rid2 != rid and nodes == [f"node\t{M3}\t192.168.122.86"]
    _answer(ev, rid2, f"{M3}\tremoved\t5e11 {M3}-0badcafe")     # a late arrival, removed
    clock.t += 30
    assert ev.tick({}) == ([], {})
    _, nodes = _request(ev)
    assert nodes == [f"node\t{M3}\t192.168.122.86"]

    clock.t += ee.WATCH_S
    rid4, _ = _request(ev)
    _answer(ev, rid4, f"{M3}\tabsent\t")
    ev.tick({})
    assert ev.watch == {} and ev.addresses == {}
    rid5, _ = _request(ev)
    assert rid5 == rid4                      # nothing left to ask: no new request


def test_a_node_promoted_again_is_not_a_late_arrival(tmp_path: Path) -> None:
    """Replace on a failed joiner exists so the same node can be promoted again,
    and that is one click, seconds after the row settles. Its new member is
    wanted: once the backend names the node as joining, the watch ends and the
    runner is no longer asked about it."""
    ev, clock = _evictions(tmp_path)
    ev.tick({M3: ["192.168.122.86"]})
    rid, _ = _request(ev)
    _answer(ev, rid, f"{M3}\tabsent\t")
    clock.t += 30
    assert ev.tick({M3: ["192.168.122.86"]})[0] == [M3]
    rid2, nodes = _request(ev)
    assert rid2 != rid and nodes == [f"node\t{M3}\t192.168.122.86"]     # watched
    _answer(ev, rid2, f"{M3}\tabsent\t")

    clock.t += 30
    assert ev.tick({}, wanted=[M3]) == ([], {})
    assert ev.watch == {} and ev.addresses == {}
    rid3, _ = _request(ev)
    assert rid3 == rid2                      # nothing left to ask: no new request

    # ...and it stays off the list when the join has settled and the name is
    # no longer wanted.
    clock.t += 30
    assert ev.tick({}) == ([], {})
    assert _request(ev)[0] == rid2


def test_a_wanted_name_is_still_evicted_when_asked_but_never_watched(tmp_path: Path) -> None:
    """A promote can land on a row whose eviction is still pending. The
    eviction the backend asks for happens; only the watch is skipped."""
    ev, clock = _evictions(tmp_path)
    ev.tick({M3: []}, wanted=[M3])
    rid, nodes = _request(ev)
    assert nodes == [f"node\t{M3}\t"]
    _answer(ev, rid, f"{M3}\tremoved\t5e11 {M3}-0badcafe")
    clock.t += 30
    assert ev.tick({M3: []}, wanted=[M3])[0] == [M3]
    assert ev.watch == {}
    assert _request(ev)[0] == rid            # confirmed and not watched: no new request


def test_a_silent_runner_is_named_and_asked_again(tmp_path: Path) -> None:
    ev, clock = _evictions(tmp_path)
    ev.tick({M3: []})
    rid, _ = _request(ev)
    clock.t += 30
    _, reasons = ev.tick({M3: []})
    assert reasons[M3].endswith("checking")
    assert _request(ev)[0] == rid            # still waiting on the same request
    clock.t += ee.RUNNER_SILENT_S
    _, reasons = ev.tick({M3: []})
    assert "etcd-evict runner has not answered" in reasons[M3]
    assert _request(ev)[0] != rid            # re-asked: the path unit fires again


def test_a_name_the_backend_dropped_is_forgotten(tmp_path: Path) -> None:
    ev, clock = _evictions(tmp_path)
    ev.tick({M3: [], M4: []})
    clock.t += 30
    ev.tick({M4: []})
    assert set(ev.pending) == {M4}


def test_a_slot_without_the_runner_keeps_the_node_delete_contract(tmp_path: Path) -> None:
    """A mixed-version window (a new supervisor on an OS slot that predates the
    runner) must not leave rows `evicting` for good: the Node delete stands."""
    ev, _ = _evictions(tmp_path, runner=False)
    assert ev.tick({M3: []}) == ([M3], {})
    assert not ev.request_file.exists()


def test_a_prompt_runner_is_confirmed_within_the_same_tick(tmp_path: Path) -> None:
    """The runner answers in about a second. The tick that asks waits for it, so
    the name is reported on the very next heartbeat, as the Node delete alone
    was before #1284."""
    ev, clock = _evictions(tmp_path)

    def runner() -> None:
        rid, _ = _request(ev)
        _answer(ev, rid, f"{M3}\tremoved\t4e73a0332d9ea29c {M3}-7d1c4ad1")
        clock.on_sleep = None

    clock.on_sleep = runner
    start = clock.t
    assert ev.tick({M3: ["192.168.122.86"]}) == ([M3], {})
    assert clock.t - start <= ee.ANSWER_WAIT_S


def test_a_slow_runner_costs_a_tick_at_most_the_wait(tmp_path: Path) -> None:
    ev, clock = _evictions(tmp_path)
    start = clock.t
    confirmed, reasons = ev.tick({M3: []})
    assert confirmed == [] and reasons[M3].endswith("checking")
    assert clock.t - start == ee.ANSWER_WAIT_S


def test_a_late_arrival_is_logged_once_and_only_for_a_watched_name(tmp_path: Path, monkeypatch) -> None:
    """dev-cc9dcf4: the answer that confirmed an eviction ("removed") was also
    logged as a late arrival, and again on the next tick. A late arrival is a
    member that shows up for a name already confirmed; each answer counts once."""
    ev, clock = _evictions(tmp_path)
    warnings: list[tuple[str, dict]] = []
    monkeypatch.setattr(ee.log, "warning", lambda event, **kw: warnings.append((event, kw)))

    ev.tick({M3: ["192.168.122.86"]})
    rid, _ = _request(ev)
    _answer(ev, rid, f"{M3}\tremoved\t4e73a0332d9ea29c {M3}-7d1c4ad1")
    clock.t += 30
    assert ev.tick({M3: ["192.168.122.86"]})[0] == [M3]
    clock.t += 30
    ev.tick({})
    assert [e for e, _ in warnings if e == "supervisor.etcd_evict.late_member_removed"] == []

    rid2, _ = _request(ev)
    _answer(ev, rid2, f"{M3}\tremoved\t5e11 {M3}-0badcafe")      # a real late arrival
    clock.t += 30
    ev.tick({})
    clock.t += 30
    late = [kw for e, kw in warnings if e == "supervisor.etcd_evict.late_member_removed"]
    assert len(late) == 1 and late[0]["node"] == M3

