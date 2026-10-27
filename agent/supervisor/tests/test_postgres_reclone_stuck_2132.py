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
CA_CM_PATH = f"/api/v1/namespaces/spatium/configmaps/{CLUSTER}-ca-crt"
FAKE_CA = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"

# Lines as the issue's evidence has them (#2132 first, second and fourth
# occurrences; #2317's standbys), each ONE attempt. A real loop repeats them:
# pg_rewind every 10-20 s, the rest every 1-5 s, so a 90 s window holds many.
REWIND_ONCE = (
    '{"level":"info","msg":"pg_rewind: servers diverged at WAL location 0/37B77FF8 on timeline 3"}\n'
    '{"level":"info","msg":"pg_rewind: error: could not restore file \\"000000030000000000000039\\" from archive"}\n'
    '{"level":"error","msg":"Failed to execute pg_rewind","logger":"instance-manager"}\n'
)
FUTURE_ONCE = (
    '{"logger":"wal-restore","msg":"Refusing to restore future timeline history file",'
    '"walName":"0000000A.history"}\n'
)
WAL_REMOVED_ONCE = (
    '{"error_severity":"FATAL","message":"could not receive data from WAL stream: ERROR:  '
    'requested WAL segment 0000000C00000003000000DF has already been removed"}\n'
)
SLOT_LOST_ONCE = (
    '{"error_severity":"FATAL","message":"could not receive data from WAL stream: ERROR:  '
    'can no longer get changes from replication slot \\"_cnpg_x_2\\""}\n'
)
HEALTHY = '{"level":"info","msg":"started streaming WAL from primary at 0/3000000 on timeline 4"}\n'
REWIND_LOOP = REWIND_ONCE * 6
FUTURE_TIMELINE = FUTURE_ONCE * 60
WAL_REMOVED = WAL_REMOVED_ONCE * 18
SLOT_LOST = SLOT_LOST_ONCE * 18
# What #2765's walk saw on each joiner of a forming cluster: one refusal a few
# seconds after its postgres container started, then streaming.
JOINER = FUTURE_ONCE + '{"level":"info","msg":"consistent recovery state reached"}\n' + HEALTHY


def _log_path(pod: str) -> str:
    return (
        f"/api/v1/namespaces/spatium/pods/{pod}/log?container=postgres"
        f"&sinceSeconds={k8s_api._STUCK_LOG_WINDOW_S}&limitBytes={k8s_api._STUCK_LOG_LIMIT_BYTES}"
        "&timestamps=true"
    )


def _ip(instance: str) -> str:
    return "10.42.0." + instance.rsplit("-", 1)[1]


def _slot_name(instance: str) -> str:
    return "_cnpg_" + instance.replace("-", "_")


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
            "podIP": _ip(instance),
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
        slots=None,
        status_readable=True,
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
        # walStatus of each instance's slot on the primary (None: no slot).
        # Unrecoverable by default, as every loop these tests drive is; the
        # #2765 false-positive tests set "reserved".
        self.slots = slots if slots is not None else {P1: "lost", P2: "lost", P3: "lost"}
        self.status_readable = status_readable
        self.status_reads: list[str] = []

    def status(self, pod_ip, *, ca_pem, server_hostname):
        """Stand-in for k8s_api._cnpg_instance_status (CNPG's /pg/status).
        The real one, with its TLS check, is in test_cnpg_status_tls_2132."""
        assert ca_pem == FAKE_CA and server_hostname == f"{CLUSTER}-rw"
        self.status_reads.append(pod_ip)
        if not self.status_readable:
            return None, "the primary's status endpoint could not be read: refused"
        primary = self.cr["status"].get("currentPrimary")
        return {
            "isPrimary": bool(primary) and pod_ip == _ip(primary),
            "replicationSlotsInfo": [
                {"slotName": _slot_name(i), "walStatus": w, "active": False}
                for i, w in self.slots.items()
                if i != primary and w is not False
            ],
        }, ""

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
        if path == CA_CM_PATH:
            return 200, json.dumps({"data": {"ca.crt": FAKE_CA}}).encode()
        for pod, text in self.logs.items():
            if path == _log_path(pod):
                return self.log_status.get(pod, 200), text.encode()
        return 404, b"{}"

    @property
    def marked(self) -> list[str]:
        return [p.rsplit("/", 1)[1] for p, _ in self.patches]


def _run(monkeypatch, kube: _Kube, tracker: dict, now: float, after: float = 600):
    monkeypatch.setattr(k8s_api, "_request", kube)
    monkeypatch.setattr(k8s_api, "_cnpg_instance_status", kube.status)
    return k8s_api.reclone_stuck_postgres_instances(tracker, now=now, stuck_after_s=after)


def test_former_primary_looping_on_pg_rewind_is_recloned_after_the_threshold(monkeypatch):
    kube = _Kube()
    tracker: dict = {}
    first = _run(monkeypatch, kube, tracker, now=1000)
    assert first.stuck == {P2: {"signature": "pg_rewind_archive", "seconds": 0, "confirmed": False}}
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
    # One attempt, or two, is not a loop.
    for once in (REWIND_ONCE, FUTURE_ONCE, WAL_REMOVED_ONCE, SLOT_LOST_ONCE):
        assert k8s_api.stuck_signature(once) is None
        assert k8s_api.stuck_signature(once * 2) is None
        assert k8s_api.stuck_signature(once * 3) is not None
    assert k8s_api.stuck_signature(JOINER) is None


def test_a_joining_replica_is_never_counted(monkeypatch):
    # #2765's walk: each joiner logged one future-timeline refusal 11-24 s
    # after its container started, then streamed. Even if every tick for an
    # hour still caught that line in its window, it is not a loop.
    kube = _Kube(pods=[_pod(P1), _pod(P2), _pod(P3)], logs={P2: JOINER, P3: JOINER})
    tracker: dict = {}
    for now in range(0, 3600, 30):
        out = _run(monkeypatch, kube, tracker, now=now)
        assert out.stuck == {} and out.marked == []
    assert kube.patches == [] and tracker == {}


def test_a_joining_burst_resets_once_it_stops(monkeypatch):
    # A slower join that refuses a few times in a row before it streams starts
    # the clock, and the first tick whose window no longer repeats it resets.
    kube = _Kube(pods=[_pod(P1), _pod(P2), _pod(P3)], logs={P2: FUTURE_ONCE * 5, P3: HEALTHY})
    tracker: dict = {}
    _run(monkeypatch, kube, tracker, now=0)
    assert P2 in tracker
    kube.logs[P2] = HEALTHY
    _run(monkeypatch, kube, tracker, now=90)
    assert tracker == {}
    for now in range(120, 2000, 30):
        assert _run(monkeypatch, kube, tracker, now=now).marked == []
    assert kube.patches == []


class _Log:
    def __init__(self):
        self.events: list[tuple[str, str, dict]] = []

    def warning(self, event, **kw):
        self.events.append(("warning", event, kw))

    def info(self, event, **kw):
        self.events.append(("info", event, kw))


def _events(log, name):
    return [e for e in log.events if e[1] == f"supervisor.heartbeat.{name}"]


def _fresh_heartbeat_state(monkeypatch):
    monkeypatch.setattr(heartbeat, "_stuck_postgres", {})
    monkeypatch.setattr(heartbeat, "_stuck_postgres_reported", {})
    monkeypatch.setattr(heartbeat, "_stuck_postgres_held", {})
    monkeypatch.setattr(heartbeat, "_slot_state_logged", set())


def test_heartbeat_logs_info_then_warning_once_and_the_reclone(monkeypatch):
    kube = _Kube()
    monkeypatch.setattr(k8s_api, "_request", kube)
    monkeypatch.setattr(k8s_api, "_cnpg_instance_status", kube.status)
    _fresh_heartbeat_state(monkeypatch)
    log = _Log()
    for now in (0, 30, 60, 90):
        heartbeat._reclone_stuck_postgres(log, now=now)
    looping = _events(log, "postgres_instance_looping")
    assert len(looping) == 1 and looping[0][0] == "info" and looping[0][2]["instance"] == P2
    assert _events(log, "postgres_instance_stuck") == []  # one loop seen for 90 s
    for now in (120, 150, 180):
        heartbeat._reclone_stuck_postgres(log, now=now)
    stuck = _events(log, "postgres_instance_stuck")
    assert len(stuck) == 1 and stuck[0][0] == "warning"
    assert stuck[0][2]["instance"] == P2 and stuck[0][2]["reclone_in_s"] == 480
    assert "cnpg destroy" in stuck[0][2]["manual_fix"]
    heartbeat._reclone_stuck_postgres(log, now=k8s_api.STUCK_INSTANCE_AFTER_S)
    assert (
        "warning",
        "supervisor.heartbeat.postgres_instance_reclone",
        {"instance": P2, "annotation": "alpha.cnpg.io/unrecoverable"},
    ) in log.events
    assert kube.marked == [P2]


def test_heartbeat_logs_nothing_for_a_joining_replica(monkeypatch):
    kube = _Kube(pods=[_pod(P1), _pod(P2), _pod(P3)], logs={P2: JOINER, P3: JOINER})
    monkeypatch.setattr(k8s_api, "_request", kube)
    monkeypatch.setattr(k8s_api, "_cnpg_instance_status", kube.status)
    _fresh_heartbeat_state(monkeypatch)
    log = _Log()
    for now in range(0, 1200, 30):
        heartbeat._reclone_stuck_postgres(log, now=now)
    assert log.events == []
    assert kube.patches == []


# ---------------------------------------------------------------------------
# #2765 walk: a standby that only lost its connection to the primary.
#
# pg-3 was held off the primary (nftables drop on 5432) with no WAL written.
# Its slot on the primary stayed ``reserved``, 32 MB behind, but CNPG's
# restore_command logged the future-timeline refusal on every walreceiver
# retry, so the supervisor re-cloned a standby that would have caught up by
# itself. A re-clone now needs positive evidence the WAL is gone.
NO_CONNECT_ONCE = (
    '{"error_severity":"FATAL","message":"could not connect to the primary server: '
    'connection to server at \\"spatium-control-spatiumddi-postgresql-rw\\" failed: timeout expired"}\n'
)
DISCONNECTED = (NO_CONNECT_ONCE + FUTURE_ONCE) * 16
# Case 4 of the walk: a standby whose slot the cap invalidated logs the
# WAL-removed line and the future-timeline refusal once each per retry.
CASE4 = (WAL_REMOVED_ONCE + FUTURE_ONCE) * 16


def _held_for_an_hour(monkeypatch, kube, instance=P3):
    tracker: dict = {}
    out = None
    for now in range(0, 3600, 30):
        out = _run(monkeypatch, kube, tracker, now=now)
        assert out.marked == [], now
    assert kube.patches == []
    # Still reported as looping, with the reason it is not re-cloned.
    assert instance in out.stuck and out.stuck[instance]["seconds"] >= 3000
    return out


def test_a_disconnected_standby_whose_slot_holds_its_wal_is_never_recloned(monkeypatch):
    for wal_status in ("reserved", "extended", "unreserved"):
        kube = _Kube(
            pods=[_pod(P1), _pod(P2), _pod(P3)],
            logs={P2: HEALTHY, P3: DISCONNECTED},
            slots={P2: "reserved", P3: wal_status},
        )
        out = _held_for_an_hour(monkeypatch, kube)
        assert out.stuck[P3]["signature"] == "future_timeline"
        assert out.stuck[P3]["slot"] == wal_status
        assert wal_status in out.held[P3] and "still exists" in out.held[P3]
    # The spec's rule holds for the WAL-gone lines too: a slot that still
    # reserves the WAL outranks a log line.
    kube = _Kube(
        pods=[_pod(P1), _pod(P2), _pod(P3)],
        logs={P2: HEALTHY, P3: CASE4},
        slots={P2: "reserved", P3: "reserved"},
    )
    _held_for_an_hour(monkeypatch, kube)
    # A former primary looping on pg_rewind needs its OWN WAL from the
    # divergence point, which no slot on the new primary covers: it is still
    # re-cloned whatever its slot reads.
    kube = _Kube(slots={P2: "reserved", P3: "reserved"})
    tracker: dict = {}
    _run(monkeypatch, kube, tracker, now=0)
    assert _run(monkeypatch, kube, tracker, now=600).marked == [P2]


def test_future_timeline_alone_never_reclones_without_a_lost_slot(monkeypatch):
    # No slot reserves WAL for it (NULL walStatus), or HA slots are off on
    # this Cluster: nothing says its WAL is gone, so the refusal alone holds.
    for slots in ({P2: "reserved", P3: "unset"}, {}):
        kube = _Kube(
            pods=[_pod(P1), _pod(P2), _pod(P3)],
            logs={P2: HEALTHY, P3: DISCONNECTED},
            slots=slots,
        )
        out = _held_for_an_hour(monkeypatch, kube)
        assert "future_timeline" in out.held[P3]
    # The same NULL slot with the primary saying the WAL is gone: re-cloned.
    kube = _Kube(
        pods=[_pod(P1), _pod(P2), _pod(P3)],
        logs={P2: HEALTHY, P3: CASE4},
        slots={P2: "reserved", P3: "unset"},
    )
    tracker: dict = {}
    _run(monkeypatch, kube, tracker, now=0)
    assert _run(monkeypatch, kube, tracker, now=600).marked == [P3]


def test_a_lost_or_missing_slot_is_recloned(monkeypatch):
    for text, slots in (
        (CASE4, {P2: "reserved", P3: "lost"}),  # walk case 4
        (DISCONNECTED, {P2: "reserved", P3: "lost"}),  # cut off past the cap
        (DISCONNECTED, {P2: "reserved"}),  # the slot is gone
    ):
        kube = _Kube(pods=[_pod(P1), _pod(P2), _pod(P3)], logs={P2: HEALTHY, P3: text}, slots=slots)
        tracker: dict = {}
        _run(monkeypatch, kube, tracker, now=0)
        out = _run(monkeypatch, kube, tracker, now=600)
        assert out.marked == [P3], slots
        assert out.held == {}
        # The slot was read off the PRIMARY's instance manager.
        assert kube.status_reads and set(kube.status_reads) == {_ip(P1)}
        if text is CASE4:
            assert out.stuck[P3]["signature"] == "wal_removed"


def test_slot_state_unknown_is_never_recloned(monkeypatch):
    # The primary's status cannot be read (unreachable, refused): no re-clone
    # for any loop, the pg_rewind one included. Fail towards keeping data.
    for logs, instance in (({P2: HEALTHY, P3: CASE4}, P3), ({P2: REWIND_LOOP, P3: HEALTHY}, P2)):
        kube = _Kube(logs=logs, status_readable=False)
        out = _held_for_an_hour(monkeypatch, kube, instance=instance)
        assert out.stuck[instance]["slot"] == "unknown"
        assert "could not be read" in out.held[instance]
    # A pod at the primary's address that does not say it is the primary
    # (a stale IP, a restarted pod) is no answer either.
    kube = _Kube(pods=[_pod(P1), _pod(P2), _pod(P3)], logs={P2: HEALTHY, P3: CASE4})
    real = kube.status
    monkeypatch.setattr(
        kube, "status", lambda ip, **kw: ({**real(ip, **kw)[0], "isPrimary": False}, "")
    )
    _held_for_an_hour(monkeypatch, kube)


def test_the_most_specific_signature_names_the_loop():
    # Walk case 4: the counts tie, and the old tie-break named it
    # future_timeline. The cause is the removed WAL.
    assert k8s_api.stuck_signature(CASE4) == "wal_removed"
    # Even when the generic refusal outnumbers it.
    assert k8s_api.stuck_signature(WAL_REMOVED_ONCE * 3 + FUTURE_ONCE * 30) == "wal_removed"
    assert (
        k8s_api.stuck_signature((SLOT_LOST_ONCE + WAL_REMOVED_ONCE + FUTURE_ONCE) * 5)
        == "slot_invalidated"
    )
    assert k8s_api.stuck_signature((REWIND_ONCE + FUTURE_ONCE * 3) * 4) == "pg_rewind_archive"
    # Below the repeat floor a specific line does not name the loop.
    assert k8s_api.stuck_signature(WAL_REMOVED_ONCE * 2 + FUTURE_ONCE * 30) == "future_timeline"
    assert k8s_api.stuck_signature(DISCONNECTED) == "future_timeline"


def _stamped(text: str, start: int) -> str:
    """``text`` with a kubelet timestamp (``timestamps=true``) on each line,
    one second apart from ``start`` seconds past 22:00:00Z."""
    out = []
    for n, line in enumerate(text.splitlines()):
        t = start + n
        out.append(f"2026-10-26T22:{t // 60:02d}:{t % 60:02d}.123456789Z {line}")
    return "\n".join(out) + "\n"


def test_heartbeat_is_quiet_for_a_follower_across_a_switchover(monkeypatch):
    # The walk: a healthy follower logged the refusal 4 times in 11 s after a
    # switchover, then streamed. Those lines stay in the next windows, but no
    # new ones arrive: no "looping" line, no clock that can come due.
    burst = _stamped(FUTURE_ONCE * 4, 0) + _stamped(HEALTHY, 20)
    kube = _Kube(pods=[_pod(P1), _pod(P2), _pod(P3)], logs={P2: HEALTHY, P3: burst})
    monkeypatch.setattr(k8s_api, "_request", kube)
    monkeypatch.setattr(k8s_api, "_cnpg_instance_status", kube.status)
    _fresh_heartbeat_state(monkeypatch)
    log = _Log()
    for now in (0, 30, 60):
        heartbeat._reclone_stuck_postgres(log, now=now)
    kube.logs[P3] = _stamped(HEALTHY, 100)  # the burst leaves the window
    for now in range(90, 1200, 30):
        heartbeat._reclone_stuck_postgres(log, now=now)
    assert log.events == [] and kube.patches == []
    # A live loop, logging new lines every tick, is confirmed on the second.
    kube.logs[P3] = _stamped(FUTURE_ONCE * 6, 200)
    heartbeat._reclone_stuck_postgres(log, now=1200)
    assert _events(log, "postgres_instance_looping") == []
    kube.logs[P3] = _stamped(FUTURE_ONCE * 6, 230)
    heartbeat._reclone_stuck_postgres(log, now=1230)
    assert len(_events(log, "postgres_instance_looping")) == 1


def test_a_planned_switchover_demotion_is_not_a_loop(monkeypatch):
    # #2831 / #2861: with ``primaryUpdateMethod: switchover`` every rolling
    # update demotes the old primary, which pg_rewinds and follows the new
    # one. The rewind succeeds, and the demoted instance logs a short burst
    # of future-timeline refusals while it finds the new timeline, then
    # streams. That is the path the former-primary re-clone watches, so it
    # must log nothing and re-clone nothing, before, during or after.
    demotion = _stamped(
        '{"level":"info","msg":"pg_rewind: servers diverged at WAL location 0/9000028 on timeline 4"}\n'
        '{"level":"info","msg":"pg_rewind: rewinding from last common checkpoint at 0/8000060 on timeline 4"}\n'
        '{"level":"info","msg":"pg_rewind: Done!"}\n' + FUTURE_ONCE * 4,
        0,
    ) + _stamped(HEALTHY, 20)
    kube = _Kube(
        current=P1,
        target=P2,  # the switchover is under way
        pods=[_pod(P1, ready=False), _pod(P2), _pod(P3)],
        logs={P1: demotion, P3: HEALTHY},
    )
    monkeypatch.setattr(k8s_api, "_request", kube)
    monkeypatch.setattr(k8s_api, "_cnpg_instance_status", kube.status)
    _fresh_heartbeat_state(monkeypatch)
    log = _Log()
    heartbeat._reclone_stuck_postgres(log, now=0)
    # Done: P2 is primary, P1 a Ready follower whose burst stays in the window.
    kube.cr["status"].update(currentPrimary=P2, targetPrimary=P2)
    kube.pods = [_pod(P1), _pod(P2), _pod(P3)]
    kube.logs = {P1: demotion, P3: HEALTHY}
    for now in (30, 60, 90):
        out = heartbeat._reclone_stuck_postgres(log, now=now)
        assert out.marked == [] and not any(s["confirmed"] for s in out.stuck.values())
    kube.logs[P1] = _stamped(HEALTHY, 120)  # the burst leaves the window
    for now in range(120, 1800, 30):
        heartbeat._reclone_stuck_postgres(log, now=now)
    assert log.events == [] and kube.patches == []


def test_heartbeat_logs_the_clock_reset_and_why_a_loop_is_held(monkeypatch):
    kube = _Kube(
        pods=[_pod(P1), _pod(P2), _pod(P3)],
        logs={P2: HEALTHY, P3: DISCONNECTED},
        slots={P2: "reserved", P3: "reserved"},
    )
    monkeypatch.setattr(k8s_api, "_request", kube)
    monkeypatch.setattr(k8s_api, "_cnpg_instance_status", kube.status)
    _fresh_heartbeat_state(monkeypatch)
    log = _Log()
    for now in range(0, 900, 30):
        heartbeat._reclone_stuck_postgres(log, now=now)
    stuck = _events(log, "postgres_instance_stuck")
    assert len(stuck) == 1 and stuck[0][2]["slot"] == "reserved"
    assert "still exists" in stuck[0][2]["reclone_held"]
    held = _events(log, "postgres_instance_reclone_held")
    assert len(held) == 1 and held[0][2]["instance"] == P3 and "reserved" in held[0][2]["reason"]
    assert kube.patches == []
    # A new primary (seen between two ticks, as the walk's 5b switchover was):
    # the clock restarts, and the journal says so.
    kube.cr["status"] = {"currentPrimary": P2, "targetPrimary": P2}
    kube.slots = {P1: "reserved", P3: "reserved"}
    heartbeat._reclone_stuck_postgres(log, now=900)
    reset = _events(log, "postgres_instance_stuck_clock_reset")
    assert len(reset) == 1 and reset[0][2]["instance"] == P3
    assert P1 in reset[0][2]["reason"] and P2 in reset[0][2]["reason"]
    # It is reported as stuck again once it holds under the new primary.
    for now in range(930, 1100, 30):
        heartbeat._reclone_stuck_postgres(log, now=now)
    assert len(_events(log, "postgres_instance_stuck")) == 2
