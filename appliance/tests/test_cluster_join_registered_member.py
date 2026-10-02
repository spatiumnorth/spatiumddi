"""spatium-cluster-join must not roll back a node that already joined the seed's
etcd into a standalone (foreign-CA) etcd on the same peer URL (#1052).

READY_TIMEOUT is a budget for the NODE to report Ready; the etcd side of a join
finishes long before it — k3s adds the joiner as a learner within seconds and
promotes it to voter as soon as it has caught up. Rolling such a node back
re-creates its standalone etcd, with its original first-boot CA, on the very
peer URL the seed still lists as a voter; the seed's raft can never verify that
certificate, loses quorum for good, and its k3s cycles every ~15 min. Observed
live on the nightly walk of nightly-2026.09.09 (spatiumddi#1052): member-1
became a voter, missed the 180 s Ready budget on a slow seed, was rolled back,
and the seed never served again.

The /v3 etcd gRPC gateway answers 415 on this build and the appliance ships no
etcdctl, so the fix reads membership from the joiner's own k3s journal (the same
log classify_join_failure already scans) plus the supervisor's persisted
etcd-member marker — never a live etcd query.

#1285 — only lines logged AFTER the seed's etcd accepted the member add count.
k3s logs "Adding member ... to etcd cluster" just BEFORE MemberAddAsLearner and
again on every refused retry, so that line alone once kept a node etcd never
admitted (nightly-2026.09.28: 1,616 refused adds in 27 minutes, row `joining`
for good). These tests drive the detection
helper against canned journals (SPATIUM_K3S_LOG_CMD) and a temp marker file
(SPATIUM_ETCD_MEMBER_SIDECAR), and pin the structure of do_join so a rollback
can never precede the membership decision.

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_cluster_join_registered_member.py -v

No etcd, no k3s, no appliance required.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

SCRIPT = (
    Path(__file__).parent.parent
    / "mkosi.extra"
    / "usr"
    / "local"
    / "bin"
    / "spatium-cluster-join"
)

# The real terminal fatal from a firewall-dropped join (member-2, 2026-09-10) —
# k3s never started etcd, so none of the registered-markers appear.
CA_FETCH_FATAL = (
    'time="2026-09-10T11:49:28Z" level=fatal msg="Error: preparing server: '
    "failed to bootstrap cluster data: failed to check if bootstrap data has "
    "been initialized: failed to validate token: failed to get CA certs: Get "
    '\\"https://192.168.122.89:6443/cacerts\\": context deadline exceeded '
    '(Client.Timeout exceeded while awaiting headers)"'
)
# Real joiner-side lines once etcd joined the cluster (member-2 attempt 3).
STARTING_ETCD = 'time="2026-09-10T11:49:32Z" level=info msg="Starting etcd for existing cluster member"'
ADDING_MEMBER = (
    'time="2026-09-10T11:55:19Z" level=info msg="Adding member '
    "ddipg-member-2-f439c46f=https://192.168.122.170:2380 to etcd cluster "
    '[ddipg-member-1-33157b2d=https://192.168.122.24:2380]"'
)
# The success line k3s logs once the add went through (k3s v1.36.4+k3s1
# pkg/etcd/etcd.go, join()): the member list now carries this node.
STARTING_JOIN = (
    'time="2026-09-29T07:04:37Z" level=info msg="Starting etcd to join cluster with '
    "members [ddipg-seed-c337b117=https://192.168.122.183:2380 "
    "ddipg-member-1-7f072fd9=https://192.168.122.160:2380 "
    'ddipg-member-3-7d1c4ad1=https://192.168.122.86:2380]"'
)
# A refused add, verbatim from member-4 on nightly-2026.09.28 (spatiumddi#1285):
# the seed kept a dead voter, so its etcd refused every add; k3s retried it once
# a second and gave up 15 minutes later.
REFUSED_ADD_ATTEMPT = (
    'time="2026-09-29T11:57:34Z" level=info msg="Adding member '
    "ddipg-member-4-4ee86735=https://192.168.122.195:2380 to etcd cluster "
    "[ddipg-member-3-7d1c4ad1=https://192.168.122.86:2380 "
    "ddipg-seed-c337b117=https://192.168.122.183:2380 "
    'ddipg-member-1-7f072fd9=https://192.168.122.160:2380]"'
)
REFUSED_ADD_WAIT = (
    'time="2026-09-29T11:57:34Z" level=info msg="Waiting for other members to finish '
    'joining etcd cluster: etcdserver: unhealthy cluster"'
)
REFUSED_ADD_GIVE_UP = (
    'time="2026-09-29T12:02:28Z" level=error msg="Shutdown request received: \\"failed '
    "to wait for API server to become ready: context deadline exceeded\\nthe server is "
    'currently unable to handle the request\\""'
)
REFUSED_ADD = "\n".join([REFUSED_ADD_ATTEMPT, REFUSED_ADD_WAIT] * 3 + [REFUSED_ADD_GIVE_UP])
PUBLISHED = (
    '{"level":"info","ts":"2026-09-10T11:49:34.801802Z",'
    '"caller":"etcdserver/server.go:1836","msg":"published local member to cluster through raft"}'
)


def _registered(journal: str, sidecar: str | None) -> bool:
    """Run node_registered_with_cluster_etcd against a canned journal + marker."""
    env = {
        **os.environ,
        "SPATIUM_CLUSTER_JOIN_LIB": "1",
        # _k3s_log_since honours this and ignores its "$since" arg.
        "SPATIUM_K3S_LOG_CMD": 'printf "%s" "$CANNED_JOURNAL"',
        "CANNED_JOURNAL": journal,
        "SPATIUM_ETCD_MEMBER_SIDECAR": sidecar or "/nonexistent/etcd-member",
    }
    proc = subprocess.run(
        ["bash", "-c", f'source "{SCRIPT}"\nnode_registered_with_cluster_etcd since'],
        env=env, capture_output=True, text=True, check=False,
    )
    return proc.returncode == 0


def test_a_started_etcd_marker_means_registered() -> None:
    assert _registered(STARTING_ETCD, None) is True


def test_an_adding_member_line_alone_is_not_registered() -> None:
    """#1285 — k3s logs this line BEFORE it asks etcd to add the member, and on
    every refused retry. On its own it proves nothing about membership."""
    assert _registered(ADDING_MEMBER, None) is False


def test_a_refused_add_is_not_registered() -> None:
    """#1285 — the verbatim refused-add journal: 'Adding member' then etcd's
    'unhealthy cluster' refusal, over and over, then k3s giving up. Never a
    member, so the rollback is safe and must run."""
    assert _registered(REFUSED_ADD, None) is False


def test_a_starting_etcd_to_join_marker_means_registered() -> None:
    """k3s logs this only after MemberAddAsLearner succeeded (or the member list
    already has this node): the add went through."""
    assert _registered(STARTING_JOIN, None) is True


def test_a_published_member_marker_means_registered() -> None:
    assert _registered(PUBLISHED, None) is True


def test_a_ca_fetch_failure_is_not_registered() -> None:
    """REGRESSION GUARD: a join that died at bootstrap/CA-fetch never started
    etcd — no marker — so the classic rollback stays safe for it (it never
    became a voter, so there is no ghost to strand)."""
    assert _registered(CA_FETCH_FATAL, None) is False


def test_the_persisted_marker_is_a_fallback_when_the_log_is_silent(tmp_path: Path) -> None:
    """The supervisor writes ``true`` to the etcd-member sidecar when its
    firewall audit last confirmed membership; honour it when the journal read
    turned up nothing (a truncated/rotated log)."""
    marker = tmp_path / "etcd-member"
    marker.write_text("true\n")
    assert _registered("nothing useful here", str(marker)) is True


def test_no_marker_and_no_sidecar_is_not_registered(tmp_path: Path) -> None:
    marker = tmp_path / "etcd-member"  # does not exist
    assert _registered("nothing useful here", str(marker)) is False


def test_a_false_sidecar_is_not_registered(tmp_path: Path) -> None:
    marker = tmp_path / "etcd-member"
    marker.write_text("false\n")
    assert _registered("nothing useful here", str(marker)) is False


# ── Structural guards on do_join (the fix's ordering must hold) ───────────────

def _do_join() -> str:
    text = SCRIPT.read_text()
    return text[text.index("do_join() {"):text.index("do_leave() {")]


def test_the_membership_check_precedes_any_rollback() -> None:
    """The registered-member decision (and its joined budget) must run BEFORE
    restore_identity — a rollback that fires first is the defect."""
    dj = _do_join()
    assert 'node_registered_with_cluster_etcd "$k3s_started_at"' in dj
    assert dj.index('node_registered_with_cluster_etcd "$k3s_started_at"') < dj.index(
        'restore_identity "$identity_backup"'
    )
    assert 'wait_ready "$JOINED_READY_TIMEOUT"' in dj


def test_the_kept_membership_branch_exits_before_the_rollback() -> None:
    """When a registered member cannot turn Ready in the joined budget, the
    runner keeps its identity and exits — it must never fall through to the
    destructive restore."""
    dj = _do_join()
    assert "membership kept, nothing wiped" in dj
    assert dj.index("membership kept, nothing wiped") < dj.index(
        'restore_identity "$identity_backup"'
    )


def test_a_redriven_member_is_not_re_wiped() -> None:
    """A re-fired join on a node kept as a member restarts + waits; it must not
    reach backup_and_wipe_identity."""
    dj = _do_join()
    guard = dj.index("re-driving without an identity wipe")
    assert guard < dj.index('identity_backup="$(backup_and_wipe_identity pre-join)"')


def test_the_fix_uses_no_etcd_gateway_or_etcdctl() -> None:
    """The /v3 gRPC gateway answers 415 on this build and no etcdctl is baked —
    the fix must not CALL either (an earlier draft did, and was inert). Checked
    against executable lines only: the comments explain why we avoid them, and
    the operator-facing reason string names tcp/2379-2380 as ports to check."""
    code = [
        ln for ln in SCRIPT.read_text().splitlines() if not ln.lstrip().startswith("#")
    ]
    for forbidden in ("/v3/cluster", "127.0.0.1:2382", "etcdctl", "member/remove"):
        offenders = [ln for ln in code if forbidden in ln]
        assert not offenders, f"{forbidden}: {offenders}"


def test_the_journal_anchor_carries_its_zone() -> None:
    """#1285 — journalctl reads a bare --since timestamp as LOCAL time, and an
    operator can set the appliance's zone: the anchor must name UTC, or the scan
    window is hours off and a standalone boot's etcd lines count as this
    attempt's."""
    dj = _do_join()
    assert "k3s_started_at=\"$(date -u '+%Y-%m-%d %H:%M:%S UTC')\"" in dj


def test_wait_ready_takes_an_optional_budget() -> None:
    text = SCRIPT.read_text()
    wr = text[text.index("wait_ready() {"):text.index("do_join() {")]
    assert 'budget="${1:-$READY_TIMEOUT}"' in wr
