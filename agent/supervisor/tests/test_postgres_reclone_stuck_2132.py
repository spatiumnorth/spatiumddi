"""#2132 — reclone_stuck_postgres_instances asks CNPG to re-clone an instance
that loops on WAL it can never get.

A former primary whose pg_rewind needs an archive the appliance does not have
(or WAL its own kill cut short), or a standby whose replication slot the #2317
cap invalidated, loops for ever: CNPG never re-clones on its own. These tests
pin the contract: an instance counts as stuck only after a never-heals
signature has held in its log for STUCK_INSTANCE_AFTER_S under one primary,
whether or not its pod reads Ready; the re-clone is CNPG's documented
``alpha.cnpg.io/unrecoverable`` pod annotation, set on ONE instance per tick,
never the primary, never during a failover or switchover, never while the
primary is not Ready, and never while another re-clone is in flight; a
missing ``pods/log`` grant is an error, not a pass.
"""

from __future__ import annotations

import json
from urllib.parse import quote

from spatium_supervisor import heartbeat, k8s_api

CLUSTER = "spatium-control-spatiumddi-postgresql"
CR_PATH = f"/apis/postgresql.cnpg.io/v1/namespaces/spatium/clusters/{CLUSTER}"
PODS_PATH = "/api/v1/namespaces/spatium/pods?labelSelector=" + quote(
    f"cnpg.io/cluster={CLUSTER}", safe=""
)
P1, P2, P3 = (f"{CLUSTER}-{n}" for n in (1, 2, 3))

# Lines as the issue's evidence has them (#2132 first, second and fourth
# occurrences; #2317's standbys).
REWIND_LOOP = (
    '{"level":"info","msg":"pg_rewind: servers diverged at WAL location 0/37B77FF8 on timeline 3"}\n'
    '{"level":"info","msg":"pg_rewind: error: could not restore file \\"000000030000000000000039\\" from archive"}\n'
    '{"level":"error","msg":"Failed to execute pg_rewind","logger":"instance-manager"}\n'
)
FUTURE_TIMELINE = (
    '{"logger":"wal-restore","msg":"Refusing to restore future timeline history file",'
    '"walName":"0000000A.history"}\n'
)
WAL_REMOVED = (
    '{"error_severity":"FATAL","message":"could not receive data from WAL stream: ERROR:  '
    'requested WAL segment 0000000C00000003000000DF has already been removed"}\n'
)
SLOT_LOST = (
    '{"error_severity":"FATAL","message":"could not receive data from WAL stream: ERROR:  '
    'can no longer get changes from replication slot \\"_cnpg_x_2\\""}\n'
)
HEALTHY = '{"level":"info","msg":"started streaming WAL from primary at 0/3000000 on timeline 4"}\n'


def _log_path(pod: str) -> str:
    return (
        f"/api/v1/namespaces/spatium/pods/{pod}/log?container=postgres"
        f"&sinceSeconds={k8s_api._STUCK_LOG_WINDOW_S}&limitBytes={k8s_api._STUCK_LOG_LIMIT_BYTES}"
    )


def _pod(instance: str, *, ready: bool = True, annotated: bool = False, terminating: bool = False):
    meta: dict = {
        "name": instance,
        "labels": {
            "cnpg.io/cluster": CLUSTER,
            "cnpg.io/instanceName": instance,
            "cnpg.io/podRole": "instance",
        },
    }
    if annotated:
        meta["annotations"] = {"alpha.cnpg.io/unrecoverable": "true"}
    if terminating:
        meta["deletionTimestamp"] = "2026-10-24T22:00:00Z"
    return {
        "metadata": meta,
        "status": {
            "phase": "Running",
            "conditions": [{"type": "Ready", "status": "True" if ready else "False"}],
        },
    }


def _join_pod(phase: str = "Running"):
    return {
        "metadata": {
            "name": f"{CLUSTER}-4-join-abcde",
            "labels": {
                "cnpg.io/cluster": CLUSTER,
                "cnpg.io/jobRole": "join",
                "cnpg.io/instanceName": f"{CLUSTER}-4",
            },
        },
        "status": {"phase": phase},
    }


class _Kube:
    """Stand-in for k8s_api._request: scripted GETs, recorded PATCHes."""

    def __init__(
        self,
        *,
        current=P1,
        target=None,
        pods=None,
        logs=None,
        log_status=None,
        patch_status=200,
        cr_status=200,
    ):
        self.cr = {
            "spec": {"instances": 3},
            "status": {"currentPrimary": current, "targetPrimary": target or current},
        }
        self.cr_status = cr_status
        self.pods = pods if pods is not None else [_pod(P1), _pod(P2, ready=False), _pod(P3)]
        self.logs = logs if logs is not None else {P2: REWIND_LOOP, P3: HEALTHY}
        self.log_status = log_status or {}
        self.patch_status = patch_status
        self.patches: list[tuple[str, dict]] = []
        self.gets: list[str] = []

    def __call__(self, method, path, body=None, content_type=None, timeout=None):
        if method == "PATCH":
            assert content_type == "application/merge-patch+json"
            self.patches.append((path, json.loads(body)))
            return self.patch_status, b"{}"
        assert method == "GET", (method, path)
        self.gets.append(path)
        if path == CR_PATH:
            return self.cr_status, json.dumps(self.cr).encode()
        if path == PODS_PATH:
            return 200, json.dumps({"items": self.pods}).encode()
        for pod, text in self.logs.items():
            if path == _log_path(pod):
                return self.log_status.get(pod, 200), text.encode()
        return 404, b"{}"

    @property
    def marked(self) -> list[str]:
        return [p.rsplit("/", 1)[1] for p, _ in self.patches]


def _run(monkeypatch, kube: _Kube, tracker: dict, now: float, after: float = 600):
    monkeypatch.setattr(k8s_api, "_request", kube)
    return k8s_api.reclone_stuck_postgres_instances(tracker, now=now, stuck_after_s=after)


def test_former_primary_looping_on_pg_rewind_is_recloned_after_the_threshold(monkeypatch):
    kube = _Kube()
    tracker: dict = {}
    first = _run(monkeypatch, kube, tracker, now=1000)
    assert first.stuck == {P2: {"signature": "pg_rewind_archive", "seconds": 0}}
    assert first.marked == [] and kube.patches == []
    # Still looping just short of the threshold: nothing yet.
    assert _run(monkeypatch, kube, tracker, now=1599).marked == []
    out = _run(monkeypatch, kube, tracker, now=1600)
    assert out.marked == [P2]
    assert kube.patches == [
        (
            f"/api/v1/namespaces/spatium/pods/{P2}",
            {"metadata": {"annotations": {"alpha.cnpg.io/unrecoverable": "true"}}},
        )
    ]
    assert P2 not in tracker


def test_a_ready_standby_that_lost_its_wal_is_recloned_too(monkeypatch):
    # #2317's shape: every pod Ready, the standby streaming nothing.
    for text, sig in (
        (WAL_REMOVED, "wal_removed"),
        (SLOT_LOST, "slot_invalidated"),
        (FUTURE_TIMELINE, "future_timeline"),
    ):
        kube = _Kube(pods=[_pod(P1), _pod(P2), _pod(P3)], logs={P2: HEALTHY, P3: text})
        tracker: dict = {}
        _run(monkeypatch, kube, tracker, now=0)
        out = _run(monkeypatch, kube, tracker, now=600)
        assert out.stuck[P3]["signature"] == sig
        assert kube.marked == [P3], sig


def test_a_loop_that_stops_resets_the_clock(monkeypatch):
    kube = _Kube()
    tracker: dict = {}
    _run(monkeypatch, kube, tracker, now=0)
    kube.logs[P2] = HEALTHY  # the rewind worked
    assert _run(monkeypatch, kube, tracker, now=300).stuck == {}
    kube.logs[P2] = REWIND_LOOP
    _run(monkeypatch, kube, tracker, now=400)
    assert _run(monkeypatch, kube, tracker, now=900).marked == []  # only 500 s this time
    assert _run(monkeypatch, kube, tracker, now=1000).marked == [P2]


def test_a_new_primary_resets_the_clock(monkeypatch):
    kube = _Kube()
    tracker: dict = {}
    _run(monkeypatch, kube, tracker, now=0)
    kube.cr["status"] = {"currentPrimary": P3, "targetPrimary": P3}
    kube.pods = [_pod(P1), _pod(P2, ready=False), _pod(P3)]
    kube.logs = {P1: HEALTHY, P2: REWIND_LOOP}
    assert _run(monkeypatch, kube, tracker, now=700).marked == []
    assert _run(monkeypatch, kube, tracker, now=1300).marked == [P2]


def test_never_during_a_failover_or_switchover(monkeypatch):
    kube = _Kube(target=P3)
    tracker = {P2: k8s_api.StuckSighting(P1, 0, "pg_rewind_archive")}
    out = _run(monkeypatch, kube, tracker, now=5000)
    assert kube.patches == [] and out.marked == []
    assert "failover" in out.deferred_reason
    assert tracker == {}  # nothing seen under the old primary carries over
    # And a Cluster naming no primary at all is not one where all are replicas.
    kube = _Kube(current="")
    kube.cr["status"] = {}
    assert _run(monkeypatch, kube, {}, now=5000).marked == []
    assert kube.patches == []


def test_never_the_primary_even_when_its_log_matches(monkeypatch):
    kube = _Kube(logs={P1: WAL_REMOVED, P2: HEALTHY, P3: HEALTHY})
    tracker: dict = {}
    _run(monkeypatch, kube, tracker, now=0)
    out = _run(monkeypatch, kube, tracker, now=10_000)
    assert out.stuck == {} and kube.patches == []
    assert _log_path(P1) not in kube.gets  # the primary's log is not even read


def test_deferred_while_the_primary_is_not_ready(monkeypatch):
    kube = _Kube(pods=[_pod(P1, ready=False), _pod(P2, ready=False), _pod(P3)])
    tracker: dict = {}
    _run(monkeypatch, kube, tracker, now=0)
    out = _run(monkeypatch, kube, tracker, now=600)
    assert kube.patches == []
    assert "not Ready" in out.deferred_reason


def test_one_reclone_at_a_time(monkeypatch):
    # #2132's fourth occurrence: every replica stuck at once.
    kube = _Kube(
        pods=[_pod(P1), _pod(P2, ready=False), _pod(P3, ready=False)],
        logs={P2: REWIND_LOOP, P3: REWIND_LOOP},
    )
    tracker: dict = {}
    _run(monkeypatch, kube, tracker, now=0)
    assert _run(monkeypatch, kube, tracker, now=600).marked == [P2]
    # The operator has not got to it yet: the annotated pod is in flight.
    kube.pods = [_pod(P1), _pod(P2, ready=False, annotated=True), _pod(P3, ready=False)]
    out = _run(monkeypatch, kube, tracker, now=630)
    assert out.marked == [] and "in flight" in out.deferred_reason
    # Its join Job running: still in flight.
    kube.pods = [_pod(P1), _pod(P3, ready=False), _join_pod("Running")]
    out = _run(monkeypatch, kube, tracker, now=700)
    assert out.marked == [] and "in flight" in out.deferred_reason
    # Rebuilt; the next one goes.
    kube.pods = [_pod(P1), _pod(P2), _pod(P3, ready=False), _join_pod("Succeeded")]
    kube.logs[P2] = HEALTHY
    assert _run(monkeypatch, kube, tracker, now=760).marked == [P3]
    assert kube.marked == [P2, P3]


def test_a_terminating_instance_counts_as_in_flight(monkeypatch):
    kube = _Kube(pods=[_pod(P1), _pod(P2, ready=False), _pod(P3, terminating=True)])
    tracker: dict = {}
    _run(monkeypatch, kube, tracker, now=0)
    assert _run(monkeypatch, kube, tracker, now=600).marked == []


def test_a_forbidden_log_read_is_an_error_not_a_pass(monkeypatch):
    kube = _Kube(log_status={P2: 403})
    tracker = {P2: k8s_api.StuckSighting(P1, 0, "pg_rewind_archive")}
    out = _run(monkeypatch, kube, tracker, now=5000)
    assert out.error and "pods/log" in out.error
    assert kube.patches == []


def test_an_unreadable_log_neither_advances_nor_resets(monkeypatch):
    kube = _Kube()
    tracker: dict = {}
    _run(monkeypatch, kube, tracker, now=0)
    kube.log_status[P2] = 400  # container restarting
    assert _run(monkeypatch, kube, tracker, now=300).stuck == {}
    assert P2 in tracker
    kube.log_status.clear()
    assert _run(monkeypatch, kube, tracker, now=600).marked == [P2]


def test_not_a_cnpg_deployment_is_a_quiet_no_op(monkeypatch):
    kube = _Kube(cr_status=404)
    tracker = {P2: k8s_api.StuckSighting(P1, 0, "x")}
    out = _run(monkeypatch, kube, tracker, now=0)
    assert out == k8s_api.PostgresReclone() and tracker == {}
    assert kube.gets == [CR_PATH]


def test_a_refused_patch_is_an_error(monkeypatch):
    kube = _Kube(patch_status=403)
    tracker: dict = {}
    _run(monkeypatch, kube, tracker, now=0)
    out = _run(monkeypatch, kube, tracker, now=600)
    assert out.marked == [] and out.error and "403" in out.error
    assert P2 in tracker  # retried next tick


def test_signatures_ignore_healthy_and_partial_lines():
    assert k8s_api.stuck_signature(HEALTHY) is None
    # "could not restore file" alone is not the archive loop.
    assert k8s_api.stuck_signature('{"msg":"could not restore file x"}') is None
    assert k8s_api.stuck_signature(REWIND_LOOP) == "pg_rewind_archive"


class _Log:
    def __init__(self):
        self.events: list[tuple[str, str, dict]] = []

    def warning(self, event, **kw):
        self.events.append(("warning", event, kw))

    def info(self, event, **kw):
        self.events.append(("info", event, kw))


def test_heartbeat_reports_once_and_logs_the_reclone(monkeypatch):
    kube = _Kube()
    monkeypatch.setattr(k8s_api, "_request", kube)
    monkeypatch.setattr(heartbeat, "_stuck_postgres", {})
    monkeypatch.setattr(heartbeat, "_stuck_postgres_reported", set())
    log = _Log()
    for now in (0, 30, 60):
        heartbeat._reclone_stuck_postgres(log, now=now)
    stuck = [e for e in log.events if e[1] == "supervisor.heartbeat.postgres_instance_stuck"]
    assert len(stuck) == 1 and stuck[0][2]["instance"] == P2
    assert "cnpg destroy" in stuck[0][2]["manual_fix"]
    heartbeat._reclone_stuck_postgres(log, now=k8s_api.STUCK_INSTANCE_AFTER_S)
    assert (
        "warning",
        "supervisor.heartbeat.postgres_instance_reclone",
        {"instance": P2, "annotation": "alpha.cnpg.io/unrecoverable"},
    ) in log.events
    assert kube.marked == [P2]
