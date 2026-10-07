"""#1284 — an eviction is done when etcd agrees, not when the k8s Node is gone.

Fleet → Replace flags a node for eviction and the seed deletes its k8s Node.
k3s removes a server's etcd member only through its Node (the Node's deletion,
or the ``etcd.k3s.cattle.io/remove`` annotation). A node can be an etcd member
with no Node at all: a failed joiner whose own automatic re-join added its
member, which k3s promoted to voter within seconds, dies before its Node
registers. ``k8s_api.delete_node`` then answers 404, which it counts as
success, and the seed used to report the node evicted on that alone. The row
settled ``left`` while the dead voter kept its seat: two live voters of three,
no fault tolerance, and etcd's strict reconfiguration check refusing every
later member add ("etcdserver: unhealthy cluster").

So the seed asks its host runner (``spatium-etcd-evict``, a root oneshot behind
``spatiumddi-etcd-evict.path``) to remove the node's etcd member and to report
what etcd lists. The supervisor cannot do that itself: its process user can
read neither the etcd client key nor the host's loopback etcd port. A name is
reported evicted only once the runner says etcd no longer has it. Until then
the heartbeat carries a reason (``evict_pending``), and the row stays
``evicting`` with it.

A member that appears for an evicted name after it was confirmed is removed
too. That happens when the node's own re-join was already in flight when
Replace landed. The name stays on the runner's list for ``WATCH_S`` after its
confirmation. The list lives in memory, so a supervisor restart forgets it.
The window is short on purpose. Members are matched by hostname, and a
replacement box installed under the same hostname must never be taken for a
late arrival. Such a replacement needs an install, a pairing, an approval and
a promote, which takes well over five minutes.

The evicted node itself can be wanted back much sooner. Replace on a failed
joiner exists so that the same node can be promoted again, and that is one
click, seconds after the row settles. Its new member must not be taken for a
late arrival either, so the backend names the nodes it has asked to join
(``join_node_names``) and the watch on such a name ends at once.

A seed whose OS slot predates the runner keeps the old behaviour (evicted once
the Node is gone), so a mixed-version window never leaves a row ``evicting``
for good.

The request and the answer are plain files in the release-state bind mount,
the same trigger/sidecar pattern as the join, leave and restore runners:
- request (atomic write, the path unit fires on it): the confirm marker, an
  ``id`` line, then ``node<TAB><hostname><TAB><ip>[,<ip>…]`` per node;
- answer: an ``id`` line echoing the request, then
  ``<hostname><TAB><absent|removed|present|error><TAB><detail>`` per node.
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path

import structlog

log = structlog.get_logger(__name__)

# Must stay byte-identical to CONFIRM in the host runner
# (appliance/mkosi.extra/usr/local/bin/spatium-etcd-evict).
CONFIRM = "SPATIUMDDI-ETCD-EVICT-CONFIRM-V1"
_RELEASE_STATE = Path("/var/lib/spatiumddi-host/release-state")
REQUEST_FILE = _RELEASE_STATE / "etcd-evict-pending"
STATE_FILE = _RELEASE_STATE / "etcd-evict.state"
# The runner ships on the OS slot; /host-root is the #402 read-only bind of it.
RUNNER = Path("/host-root/usr/local/bin/spatium-etcd-evict")
# How long an evicted name stays on the runner's list after etcd agreed. A
# re-join already in flight when Replace landed adds its member seconds after
# its k3s restart (26 s after the block lifted live, then 14 s to the voter
# promotion; nightly-2026.09.28). A same-hostname replacement box cannot get
# that far in five minutes: its install alone takes about ten.
WATCH_S = 5 * 60
# A runner that has not answered a request this long is named in the reason.
RUNNER_SILENT_S = 90.0
# How long a tick waits for the runner's answer to the request it just wrote.
# The runner answers in about a second; waiting here means a confirmed
# eviction reaches the backend on the next heartbeat, as the Node delete alone
# did before. Otherwise the report can land a tick or two later, in the window
# where the control plane's own re-apply after a Replace may have its api down
# (dev-fccd273, 2026-09-29: the row settled only when the api came back).
ANSWER_WAIT_S = 8.0

DONE_STATES = ("absent", "removed")


# ---- pure ------------------------------------------------------------------------

def render_request(request_id: str, nodes: dict[str, list[str]]) -> str:
    lines = [CONFIRM, f"id {request_id}"]
    for name in sorted(nodes):
        ips = ",".join(str(a) for a in (nodes[name] or []) if str(a).strip())
        lines.append(f"node\t{name}\t{ips}")
    return "\n".join(lines) + "\n"


def parse_state(text: str) -> tuple[str, dict[str, tuple[str, str]]]:
    """(request id, {hostname: (state, detail)}) from the runner's answer."""
    request_id = ""
    out: dict[str, tuple[str, str]] = {}
    for raw in (text or "").splitlines():
        line = raw.rstrip("\n")
        if line.startswith("id "):
            request_id = line[3:].strip()
            continue
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0] and parts[1]:
            out[parts[0]] = (parts[1], parts[2] if len(parts) > 2 else "")
    return request_id, out


def pending_reason(name: str, state: str, detail: str) -> str:
    """The Fleet-facing reason for an eviction etcd has not agreed to yet."""
    what = detail.strip() or f"its etcd member is {state}"
    return f"waiting for the seed's etcd to drop {name}: {what}"[:480]


# ---- the seed's bookkeeping ------------------------------------------------------

class EtcdEvictions:
    """Which evictions etcd has confirmed, tick by tick. Paths and the clock are
    injectable for the unit tests."""

    def __init__(self, request_file: Path = REQUEST_FILE, state_file: Path = STATE_FILE,
                 runner: Path = RUNNER, clock=time.monotonic, watch_s: float = WATCH_S,
                 sleep=time.sleep, answer_wait_s: float = ANSWER_WAIT_S):
        self.request_file, self.state_file, self.runner = request_file, state_file, runner
        self.clock, self.watch_s = clock, watch_s
        self.sleep, self.answer_wait_s = sleep, answer_wait_s
        self.pending: dict[str, float] = {}      # name -> when it was first asked
        self.watch: dict[str, float] = {}        # confirmed name -> watch until
        self.wanted: set[str] = set()            # names the backend asked to join
        self.addresses: dict[str, list[str]] = {}
        self.request_id = ""
        self.requested_at = 0.0
        self.unanswered_since = 0.0
        self.applied_id = ""
        self._warned_no_runner = False

    def available(self) -> bool:
        try:
            return self.runner.exists()
        except OSError:
            return False

    def _results(self) -> dict[str, tuple[str, str]] | None:
        """The runner's answer to the CURRENT request; None when it has not
        answered it (an older answer is not evidence about this one)."""
        if not self.request_id:
            return None
        try:
            request_id, results = parse_state(self.state_file.read_text(encoding="utf-8"))
        except OSError:
            return None
        return results if request_id == self.request_id else None

    def _write_request(self, nodes: dict[str, list[str]]) -> None:
        self.request_id = uuid.uuid4().hex[:12]
        self.requested_at = self.clock()
        if not self.unanswered_since:
            self.unanswered_since = self.requested_at
        try:
            self.request_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.request_file.with_name(self.request_file.name + ".new")
            tmp.write_text(render_request(self.request_id, nodes), encoding="utf-8")
            tmp.replace(self.request_file)
        except OSError as exc:
            log.warning("supervisor.etcd_evict.request_write_failed", error=str(exc))

    def tick(self, asked: dict[str, list[str]],
             wanted: list[str] | tuple[str, ...] = ()) -> tuple[list[str], dict[str, str]]:
        """One seed heartbeat. `asked`: the names the backend still wants evicted
        whose k8s Node is already deleted, with their IPs. `wanted`: the names
        it has asked to join; an evicted node promoted again is not a late
        arrival, so its watch ends. Returns the names etcd has now confirmed
        gone, and a reason for each one still waiting."""
        now = self.clock()
        self.wanted = {str(n) for n in wanted if str(n)}
        for name in sorted(self.wanted & set(self.watch)):
            self.watch.pop(name)
            log.info("supervisor.etcd_evict.watch_ended", node=name,
                     detail="the control plane asked this node to join again")
        if not self.available():
            # An OS slot without the runner: the pre-#1284 contract (the Node's
            # deletion is the eviction), so a mixed-version window never leaves a
            # row `evicting` for good.
            if asked and not self._warned_no_runner:
                log.warning("supervisor.etcd_evict.runner_missing", runner=str(self.runner),
                            detail="evicting on the Node delete alone (pre-#1284 behaviour)")
                self._warned_no_runner = True
            self.pending.clear()
            return sorted(asked), {}
        for name, ips in asked.items():
            self.pending.setdefault(name, now)
            if ips:
                self.addresses[name] = list(ips)
        for name in [n for n in self.pending if n not in asked]:
            self.pending.pop(name)           # the backend dropped it (cleared by hand)
        for name in [n for n, until in self.watch.items() if until <= now]:
            self.watch.pop(name)
        for name in [n for n in self.addresses if n not in self.pending and n not in self.watch]:
            self.addresses.pop(name)

        # The answer to the request already out, then a new request when that
        # one is answered (or the runner went silent), and its answer too if
        # the runner gives it within ANSWER_WAIT_S.
        results = self._results()
        confirmed, reasons = self._apply(results, self.request_id)
        active = {n: self.addresses.get(n, []) for n in (set(self.pending) | set(self.watch))}
        answered = results is not None or not self.request_id
        silent = now - self.requested_at > RUNNER_SILENT_S
        if active and (answered or silent):
            self._write_request(active)
            fresh = self._await_answer()
            if fresh is not None:
                more, fresher = self._apply(fresh, self.request_id)
                confirmed += more
                reasons = {n: r for n, r in {**reasons, **fresher}.items() if n in self.pending}
        return confirmed, reasons

    def _await_answer(self) -> dict[str, tuple[str, str]] | None:
        deadline = self.clock() + self.answer_wait_s
        while True:
            results = self._results()
            if results is not None or self.clock() >= deadline:
                return results
            self.sleep(0.25)

    def _apply(self, results: dict[str, tuple[str, str]] | None,
               answer_id: str = "") -> tuple[list[str], dict[str, str]]:
        """Confirm the pending names an answer says etcd no longer lists; a
        reason for each one still waiting. A late arrival is logged only for a
        name that was already being watched, once per answer."""
        now = self.clock()
        if results is not None:
            self.unanswered_since = 0.0
        watched_before = set(self.watch)
        confirmed: list[str] = []
        reasons: dict[str, str] = {}
        for name in sorted(self.pending):
            state, detail = (results or {}).get(name, ("", ""))
            if state in DONE_STATES:
                confirmed.append(name)
                self.pending.pop(name)
                if name not in self.wanted:
                    self.watch[name] = now + self.watch_s
                log.info("supervisor.etcd_evict.confirmed", node=name, etcd=state,
                         detail=detail)
            elif state:
                reasons[name] = pending_reason(name, state, detail)
            elif (results is None and self.unanswered_since
                  and now - self.unanswered_since > RUNNER_SILENT_S):
                reasons[name] = (f"waiting for the seed's etcd to drop {name}: the seed's "
                                 f"etcd-evict runner has not answered for "
                                 f"{int(now - self.unanswered_since)}s")
            else:
                reasons[name] = f"waiting for the seed's etcd to drop {name}: checking"
        if results is not None and answer_id and answer_id != self.applied_id:
            self.applied_id = answer_id
            for name in sorted(watched_before & set(self.watch)):
                state, detail = results.get(name, ("", ""))
                if state == "removed":
                    log.warning("supervisor.etcd_evict.late_member_removed", node=name,
                                detail=detail, watch_left_s=int(self.watch[name] - now))
        return confirmed, reasons
