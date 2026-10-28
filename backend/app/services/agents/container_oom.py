"""Report an OOM kill the agent could not report itself (#2018, #2023).

#2023 extends this to the DHCP side: the ``dhcp-kea`` container is group-killed
the same way, and :data:`DHCP_DRIVER_SERVICE` maps a ``kea`` row onto it.

#1725 / #1898 made a DNS daemon killed by its container's memory limit read
as *not serving* (``oom_killed: …``) and raise **Agent daemon not serving**.
The agent writes that record: its supervisor loop sees ``named`` gone, finds
the cgroup's ``oom_kill`` counter moved, and persists ``daemon_oom.json``
before it exits, so the restarted agent can report it.

On the appliance that never happens. The kubelet (cgroup v2, Kubernetes
1.28+) sets ``memory.oom.group`` on every container, so the kernel kills
the whole container at once: ``named``, the agent, tini. The agent dies in
the same instant and writes nothing, and the restarted agent cannot see the
kill either: a restarted container is a new cgroup whose counter starts at
zero. The server row read ``ok`` through 13 kills in a row.

The kubelet is the one party that did see it. The supervisor reports each
role container's ``lastState.terminated`` and ``state.running.startedAt``
on its heartbeat (``role_health[<service>]["container"]``, its watchdog),
and this module turns that into the daemon state the agent would have
reported, with the same ``oom_killed:`` prefix and the same clearing rule
(the daemon has stayed up for :data:`STABLE_SECONDS`). Two callers:

* the DNS agent heartbeat, so an agent that comes back up and says ``ok``
  does not overwrite a kill it never saw;
* the supervisor heartbeat, so a container stuck in CrashLoopBackOff — no
  agent heartbeat at all — still reads not serving.

The grace clock (``daemon_status_since``) starts at the kill's
``finishedAt``, not when the report reached us, so the alert fires five
minutes after the kill rather than five minutes after the watchdog's next
pass.

Compose is untouched: Docker does not group-kill, so the agent's own record
works there, and no supervisor reports a container there. A plain Helm
install (the umbrella chart) group-kills like the appliance but has no
supervisor, so this does not reach it; see ``docs/features/DNS.md`` 8.0.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import structlog

from app.services.agents.daemon_state import (
    STATUS_DEGRADED,
    apply_reported_daemon_state,
)

logger = structlog.get_logger(__name__)

ReasonSource = Literal["agent", "supervisor"]

#: The heartbeat ``daemon.reason`` prefix, shared with the DNS agent's
#: ``oom_watch.REASON_PREFIX``.
REASON_PREFIX = "oom_killed:"

#: How long the container has to stay up before a kill stops counting. The
#: agent's ``oom_watch.STABLE_SECONDS``: above Kubernetes' 300 s maximum
#: crash-loop back-off plus a zone load, so a container that only survives
#: between back-offs never reads as recovered.
STABLE_SECONDS = 600.0

#: dns_server.driver -> the role chart's container (and component) name.
DNS_DRIVER_SERVICE = {
    "bind9": "dns-bind9",
    "powerdns": "dns-powerdns",
    "technitium": "dns-technitium",
}

#: dhcp_server.driver -> the role chart's container (#2023). The DHCP side of
#: the same kubelet group kill: ``kea-dhcp4`` / ``kea-dhcp6`` and the DHCP agent
#: share the ``dhcp-kea`` container, so when Kea reaches its limit the agent dies
#: with it. ``windows_dhcp`` is agentless and has no container.
DHCP_DRIVER_SERVICE = {"kea": "dhcp-kea"}

#: Both families in one lookup. The driver names are disjoint (``bind9`` /
#: ``powerdns`` / ``technitium`` vs ``kea``), so a driver alone says which
#: server table a row came from.
DRIVER_SERVICE = {**DNS_DRIVER_SERVICE, **DHCP_DRIVER_SERVICE}

_DAEMON_NAME = {
    "bind9": "named",
    "powerdns": "pdns_server",
    "technitium": "the Technitium DNS server",
    "kea": "Kea",
}

#: The kubelet's word for a container its cgroup's OOM killer ended.
_OOM_REASON = "OOMKilled"

#: How old the appliance's last supervisor heartbeat may be before its
#: ``role_health`` stops counting on the DNS agent heartbeat. The watchdog
#: snapshot is refreshed every 300 s and rides every ~30 s heartbeat, so three
#: watchdog passes is generous. Past it the snapshot is not evidence of
#: anything: a supervisor that stopped heartbeating leaves its last report in
#: the column, and a "not running, OOMKilled" frozen there would otherwise
#: override the agent's ``ok`` for ever.
ROLE_HEALTH_FRESH_SECONDS = 900.0


#: The heartbeat ``daemon.reason`` prefixes the SUPERVISOR writes when the
#: kubelet's container state, not the agent, is the evidence (#2961).
CRASH_LOOP_PREFIX = "crash_loop:"
AGENT_SILENT_PREFIX = "agent_unreachable:"

#: A container is crash-looping once the kubelet has restarted it at least
#: this many times WITHIN :data:`CRASH_LOOP_WINDOW`, it is not currently a
#: healthy, ready pod, and it has not stayed up for :data:`STABLE_SECONDS`.
#: The count is the increase this control plane has itself watched the
#: kubelet's ``restartCount`` make across supervisor heartbeats
#: (:func:`carry_restart_history`), never the lifetime total: every node
#: reboot and every slot upgrade adds one restart to every container on the
#: node, so a lifetime count of 3 says only that the node has rebooted three
#: times, and after the next reboot such a container is restarted, recently
#: ended and not yet ready, which is a crash loop in every other respect
#: (#2928 / #2945 learned this for the console and the Overview chip). A
#: reboot is one restart in the window; the #2188 drill was six in four
#: minutes.
CRASH_LOOP_MIN_RESTARTS = 3
CRASH_LOOP_WINDOW = timedelta(minutes=15)

#: The backend-owned key, on each ``role_health[<service>]`` entry, holding
#: the ``restartCount`` values observed and when (``[{"at", "n"}, ...]``).
#: Carried forward from the stored row on every supervisor heartbeat; a value
#: the supervisor itself sends under this key is discarded.
RESTART_HISTORY_KEY = "restart_history"
_RESTART_HISTORY_MAX = 64

#: How long the agent may be silent, while its appliance's supervisor is not,
#: before the supervisor's word replaces the stale last agent report (#2961).
#: Silence is counted from the later of the agent's last heartbeat and the
#: container's current start, so a container that has just (re)started (a
#: reboot, a slot upgrade, a role-chart rollout) gets the whole threshold for
#: its agent to come up. Above the 90-120 s the health sweeps allow before
#: they read the row ``unreachable``, so a missed heartbeat or two stays
#: quiet. The alert's five-minute grace then runs from when the supervisor
#: first SAW the silence, not from the agent's last heartbeat: a supervisor
#: that was down too (the node rebooting) would otherwise stamp a silence
#: already older than the grace and page on its first heartbeat back.
AGENT_SILENT_SECONDS = 180.0

#: What the kubelet-sourced OOM reason above starts with, as opposed to the
#: agent's own record ("oom_killed: named was killed for exceeding ..."). Both
#: share :data:`REASON_PREFIX`, so the source is read from this shape.
_KUBELET_OOM_RE = re.compile(
    r"^oom_killed: the (?:"
    + "|".join(
        re.escape(v) for v in sorted({*DNS_DRIVER_SERVICE.values(), *DHCP_DRIVER_SERVICE.values()})
    )
    + r") container \("
)


def is_oom_reason(reason: str | None) -> bool:
    return str(reason or "").strip().startswith(REASON_PREFIX)


def is_crash_loop_reason(reason: str | None) -> bool:
    return str(reason or "").strip().startswith(CRASH_LOOP_PREFIX)


def is_silent_agent_reason(reason: str | None) -> bool:
    return str(reason or "").strip().startswith(AGENT_SILENT_PREFIX)


def reason_source(reason: str | None) -> ReasonSource:
    """Who produced a daemon ``reason``: ``"supervisor"`` when the kubelet's
    container state is the evidence (a crash loop, a silent agent, or the
    kubelet-sourced OOM text), ``"agent"`` when the agent said it (#2962)."""
    text = str(reason or "").strip()
    if is_crash_loop_reason(text) or is_silent_agent_reason(text):
        return "supervisor"
    if _KUBELET_OOM_RE.match(text):
        return "supervisor"
    return "agent"


def daemon_reported_by(status: str | None, reason: str | None) -> ReasonSource | None:
    """Who a server's current daemon state came from, for the API and the
    chip (#2962): :func:`reason_source` of a state that is not ``ok``, None
    for ``ok`` or never reported (there is nothing to attribute)."""
    if status is None or status == "ok":
        return None
    return reason_source(reason)


def _parse_ts(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        ts = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


def container_oom_report(
    role_health: dict[str, Any] | None,
    driver: str | None,
    now: datetime,
) -> tuple[dict[str, str], datetime] | None:
    """``({"status", "reason"}, killed_at)`` while the server's container
    was last ended by the OOM killer and has not since stayed up for
    :data:`STABLE_SECONDS`; None otherwise (no report, another reason, or
    a kill the daemon has outlived)."""
    service = DRIVER_SERVICE.get(driver or "")
    if service is None or not isinstance(role_health, dict):
        return None
    entry = role_health.get(service)
    if not isinstance(entry, dict):
        return None
    runtime = entry.get("container")
    if not isinstance(runtime, dict):
        return None
    last = runtime.get("last_termination")
    if not isinstance(last, dict) or last.get("reason") != _OOM_REASON:
        return None

    running_since = _parse_ts(runtime.get("running_since"))
    if running_since is not None and (now - running_since).total_seconds() >= STABLE_SECONDS:
        return None

    killed_at = _parse_ts(last.get("finished_at"))
    if killed_at is None or killed_at > now:
        killed_at = now
    limit = str(runtime.get("memory_limit") or "").strip()
    limit_txt = f"its {limit} memory limit" if limit else "its memory limit"
    try:
        restarts = int(runtime.get("restart_count") or 0)
    except (TypeError, ValueError):
        restarts = 0
    if restarts <= 0:
        restarted = ""
    elif restarts == 1:
        restarted = "restarted once, "
    else:
        restarted = f"restarted {restarts} times, "
    daemon = _DAEMON_NAME.get(driver or "", "the DNS daemon")
    state = "up again" if running_since is not None else "not running"
    if driver in DHCP_DRIVER_SERVICE:
        # No "RPZ blocklists" advice here: a Kea over its limit is a lease
        # table, a packet backlog or a very large number of subnets.
        what = f"{daemon} and the DHCP agent with it"
        advice = (
            "raise the container's memory limit, or shrink what Kea holds (lease "
            "table, subnets, reservations); see docs/features/DHCP.md."
        )
    else:
        what = f"{daemon} and the DNS agent with it"
        advice = (
            "Large RPZ blocklists are the usual cause: raise the limit or shrink the "
            "lists (docs/features/DNS.md 8.0)."
        )
    reason = (
        f"{REASON_PREFIX} the {service} container ({what}) "
        f"was killed for exceeding {limit_txt} ({restarted}last at "
        f"{killed_at.strftime('%Y-%m-%dT%H:%M:%SZ')}, {state}) and restarts into the same "
        f"config. {advice}"
    )
    return {"status": STATUS_DEGRADED, "reason": reason}, killed_at


def _container_entry(
    role_health: dict[str, Any] | None, driver: str | None
) -> tuple[str, dict[str, Any], dict[str, Any]] | None:
    """``(service, role_health entry, container runtime)`` for the server's
    container, or None."""
    service = DRIVER_SERVICE.get(driver or "")
    if service is None or not isinstance(role_health, dict):
        return None
    entry = role_health.get(service)
    if not isinstance(entry, dict):
        return None
    runtime = entry.get("container")
    if not isinstance(runtime, dict):
        return None
    return service, entry, runtime


def _what(driver: str | None, service: str) -> str:
    daemon = _DAEMON_NAME.get(driver or "", "the DNS daemon")
    agent = "DHCP" if driver in DHCP_DRIVER_SERVICE else "DNS"
    return f"the {service} container ({daemon} and the {agent} agent with it)"


def _evidence(runtime: dict[str, Any]) -> str:
    """ "lifetime restart count N, last ended with reason X, exit code Y at T"
    for a container's kubelet history. The count is the kubelet's lifetime
    total (every node reboot adds one), so it is labelled as such."""
    try:
        restarts = int(runtime.get("restart_count") or 0)
    except (TypeError, ValueError):
        restarts = 0
    parts = [f"lifetime restart count {restarts}"]
    last = runtime.get("last_termination")
    if isinstance(last, dict):
        reason = str(last.get("reason") or "").strip() or "unknown"
        code = last.get("exit_code")
        at = _parse_ts(last.get("finished_at"))
        text = f"last ended with reason {reason}"
        if code is not None:
            text += f", exit code {code}"
        if at is not None:
            text += f" at {at.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        parts.append(text)
    return ", ".join(parts)


def _restart_count(runtime: Any) -> int | None:
    if not isinstance(runtime, dict):
        return None
    try:
        return int(runtime.get("restart_count") or 0)
    except (TypeError, ValueError):
        return None


def _read_history(entry: Any) -> list[tuple[datetime, int]]:
    """The stored ``restart_history`` of a role_health entry, oldest first;
    malformed items are dropped."""
    if not isinstance(entry, dict):
        return []
    raw = entry.get(RESTART_HISTORY_KEY)
    if not isinstance(raw, list):
        return []
    out: list[tuple[datetime, int]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        at = _parse_ts(item.get("at"))
        n = item.get("n")
        if isinstance(n, bool) or not isinstance(n, int):
            continue
        if at is not None:
            out.append((at, n))
    out.sort(key=lambda t: t[0])
    return out


def _window_baseline(
    history: list[tuple[datetime, int]], now: datetime
) -> tuple[int, list[tuple[datetime, int]]] | None:
    """``(baseline count, observations inside the window)``. The baseline is
    the last count observed at or before the window opened or, when this
    control plane has not been watching that long, the first count it saw
    (which is therefore never itself counted as a restart)."""
    if not history:
        return None
    cutoff = now - CRASH_LOOP_WINDOW
    before = [h for h in history if h[0] <= cutoff]
    inside = [h for h in history if h[0] > cutoff]
    if before:
        return before[-1][1], inside
    return history[0][1], inside[1:]


def carry_restart_history(
    previous: dict[str, Any] | None,
    incoming: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """``incoming`` (a supervisor heartbeat's ``role_health``) with each
    container's observed ``restartCount`` history carried forward from
    ``previous`` (the stored one) under :data:`RESTART_HISTORY_KEY` (#2961).

    The kubelet reports only a lifetime count, so "restarted N times in the
    last 15 minutes" has to be measured here, from successive heartbeats. A
    count is recorded when it is first seen to change; the history restarts
    when the pod changes (a new pod's count starts again at 0) or the count
    goes down. Entries older than the window are pruned except the last one,
    which is the window's baseline."""
    prev = previous if isinstance(previous, dict) else {}
    out: dict[str, Any] = {}
    for svc, entry in incoming.items():
        if not isinstance(entry, dict):
            out[svc] = entry
            continue
        entry = dict(entry)
        entry.pop(RESTART_HISTORY_KEY, None)  # backend-owned, never trusted
        count = _restart_count(entry.get("container"))
        if count is None:
            out[svc] = entry
            continue
        old = prev.get(svc)
        history = _read_history(old)
        same_pod = isinstance(old, dict) and old.get("container_id") == entry.get("container_id")
        if not history or not same_pod or count < history[-1][1]:
            history = [(now, count)]
        elif count > history[-1][1]:
            history.append((now, count))
        cutoff = now - CRASH_LOOP_WINDOW
        before = [h for h in history if h[0] <= cutoff]
        history = before[-1:] + [h for h in history if h[0] > cutoff]
        history = history[-_RESTART_HISTORY_MAX:]
        entry[RESTART_HISTORY_KEY] = [
            {"at": at.strftime("%Y-%m-%dT%H:%M:%SZ"), "n": n} for at, n in history
        ]
        out[svc] = entry
    return out


def restarts_in_window(
    role_health: dict[str, Any] | None, driver: str | None, now: datetime
) -> tuple[int, datetime | None]:
    """``(restarts observed inside the window, when the crash-loop threshold
    was first reached in it)`` for the server's container; ``(0, None)``
    without a history."""
    found = _container_entry(role_health, driver)
    if found is None:
        return 0, None
    _service, entry, _runtime = found
    base = _window_baseline(_read_history(entry), now)
    if base is None:
        return 0, None
    baseline, inside = base
    reached: datetime | None = None
    for at, n in inside:
        if n - baseline >= CRASH_LOOP_MIN_RESTARTS:
            reached = at
            break
    latest = inside[-1][1] if inside else baseline
    return max(0, latest - baseline), reached


def container_crash_loop_report(
    role_health: dict[str, Any] | None,
    driver: str | None,
    now: datetime,
) -> tuple[dict[str, str], datetime] | None:
    """``({"status", "reason"}, since)`` while the server's container is
    crash-looping whatever the kubelet calls the cause (#2961): restarted at
    least :data:`CRASH_LOOP_MIN_RESTARTS` times inside
    :data:`CRASH_LOOP_WINDOW` as this control plane watched it
    (:func:`restarts_in_window`), not a healthy pod, and not up for
    :data:`STABLE_SECONDS`. ``since`` is when the threshold was reached, so
    the alert's grace runs from the moment it was a loop. None otherwise, and
    for an OOM kill (that has its own verdict, :func:`container_oom_report`)."""
    found = _container_entry(role_health, driver)
    if found is None:
        return None
    service, entry, runtime = found
    last = runtime.get("last_termination")
    if not isinstance(last, dict) or last.get("reason") == _OOM_REASON:
        return None
    if entry.get("status") not in ("unhealthy", "starting"):
        return None
    running_since = _parse_ts(runtime.get("running_since"))
    if running_since is not None and (now - running_since).total_seconds() >= STABLE_SECONDS:
        return None
    recent, reached = restarts_in_window(role_health, driver, now)
    if reached is None or recent < CRASH_LOOP_MIN_RESTARTS:
        return None
    since = min(reached, now)
    state = "up again" if running_since is not None else "not running"
    window = int(CRASH_LOOP_WINDOW.total_seconds() // 60)
    reason = (
        f"{CRASH_LOOP_PREFIX} {_what(driver, service)} is crash-looping: "
        f"{recent} restarts in the last {window} min; {_evidence(runtime)} ({state}). "
        "The supervisor reports this from the kubelet's container state; the agent "
        "dies with the container and cannot. Check the container's logs and its "
        "termination reason on the appliance."
    )
    return {"status": STATUS_DEGRADED, "reason": reason}, since


def agent_silent_report(
    role_health: dict[str, Any] | None,
    driver: str | None,
    agent_last_seen: datetime | None,
    now: datetime,
) -> tuple[dict[str, str], datetime] | None:
    """``({"status", "reason"}, now)`` for a server whose agent has been
    silent for :data:`AGENT_SILENT_SECONDS` while its appliance's supervisor
    is heartbeating and reports the container (#2961). The row would
    otherwise keep the last thing the agent said, usually ``ok``. Silence is
    counted from the later of the agent's last heartbeat and the container's
    current start (a container that has just started is given the whole
    threshold), and the verdict's ``since`` is now: the moment the supervisor
    first saw it, so the alert's grace is never already spent by a silence
    the supervisor itself was not there to see (a rebooting node). None when
    the agent has never reported (unknown, not an alarm) or has been heard
    from recently."""
    found = _container_entry(role_health, driver)
    if found is None or agent_last_seen is None:
        return None
    service, _entry, runtime = found
    anchor = agent_last_seen
    running_since = _parse_ts(runtime.get("running_since"))
    if running_since is not None and running_since > anchor:
        anchor = running_since
    if (now - anchor).total_seconds() < AGENT_SILENT_SECONDS:
        return None
    reason = (
        f"{AGENT_SILENT_PREFIX} the agent in {_what(driver, service)} has not "
        f"heartbeated since {agent_last_seen.strftime('%Y-%m-%dT%H:%M:%SZ')}, while the "
        f"appliance's supervisor is still reporting. Kubelet history: {_evidence(runtime)}."
    )
    return {"status": STATUS_DEGRADED, "reason": reason}, now


def container_verdict(
    role_health: dict[str, Any] | None,
    driver: str | None,
    agent_last_seen: datetime | None,
    now: datetime,
) -> tuple[dict[str, str], datetime] | None:
    """The supervisor's verdict for a server whose agent cannot speak for
    itself, strongest first: an OOM kill, a crash loop, a silent agent."""
    return (
        container_oom_report(role_health, driver, now)
        or container_crash_loop_report(role_health, driver, now)
        or agent_silent_report(role_health, driver, agent_last_seen, now)
    )


def fresh_role_health(appliance: Any, now: datetime) -> dict[str, Any] | None:
    """``appliance.role_health`` while the supervisor that reported it is
    still heartbeating (:data:`ROLE_HEALTH_FRESH_SECONDS`); None otherwise,
    and for no appliance."""
    if appliance is None:
        return None
    seen = getattr(appliance, "last_seen_at", None)
    if seen is None or (now - seen).total_seconds() > ROLE_HEALTH_FRESH_SECONDS:
        return None
    health = getattr(appliance, "role_health", None)
    return health if isinstance(health, dict) else None


def effective_daemon_report(
    reported: dict[str, Any] | None,
    role_health: dict[str, Any] | None,
    driver: str | None,
    now: datetime,
) -> tuple[dict[str, Any] | None, datetime]:
    """The daemon state to persist for a DNS or DHCP agent heartbeat: the agent's
    own word, unless the kubelet saw an OOM kill the agent did not (its
    report is then ``ok``, a deferred start, anything but its own
    ``oom_killed:`` record). Returns ``(report, stamp)``; ``stamp`` is the
    kill time when the kubelet's report is the one used."""
    if isinstance(reported, dict) and (
        is_oom_reason(reported.get("reason")) or is_crash_loop_reason(reported.get("reason"))
    ):
        return reported, now
    # A crash loop is held the same way: between crashes the restarted agent
    # says ``ok`` (#2961). A silent agent is not: this heartbeat IS the agent.
    verdict = container_oom_report(role_health, driver, now) or container_crash_loop_report(
        role_health, driver, now
    )
    if verdict is None:
        return reported, now
    return verdict[0], verdict[1]


def server_last_heard(server: Any) -> datetime | None:
    """When the server's agent last heartbeated: DNSServer calls the stamp
    ``last_seen_at``, DHCPServer ``agent_last_seen``. None for a server whose
    silence is deliberate (paused for maintenance, disabled), so the silent-agent
    verdict never reads it."""
    if getattr(server, "maintenance_mode", False) or getattr(server, "is_enabled", True) is False:
        return None
    if getattr(server, "driver", None) in DHCP_DRIVER_SERVICE:
        return getattr(server, "agent_last_seen", None)
    return getattr(server, "last_seen_at", None)


def verdict_needs_write(server: Any, role_health: dict[str, Any] | None, now: datetime) -> bool:
    """Whether :func:`apply_container_oom` would write to ``server``."""
    verdict = container_verdict(
        role_health, getattr(server, "driver", None), server_last_heard(server), now
    )
    if verdict is None:
        return False
    return _differs(server.daemon_reason, verdict[0]["reason"])


def _differs(current: str | None, new: str) -> bool:
    """A verdict replaces the row's reason unless that reason is already an
    equal-or-stronger supervisor verdict. OOM is never rewritten (the first
    text carries the kill's own timing); a crash loop and a silent agent are
    refreshed in place so their restart count stays current, but a silent
    agent never replaces a crash loop or an OOM."""
    cur = str(current or "")
    if is_oom_reason(new):
        return not is_oom_reason(cur)
    if is_crash_loop_reason(new):
        return not is_oom_reason(cur) and cur != new
    return not (is_oom_reason(cur) or is_crash_loop_reason(cur)) and cur != new


def apply_container_oom(
    server: Any,
    role_health: dict[str, Any] | None,
    *,
    now: datetime | None = None,
) -> bool:
    """Stamp the supervisor's verdict onto ``server`` (a DNSServer or, since
    #2023, a DHCPServer): the kubelet's OOM kill (#2018), a crash loop or a
    silent agent (#2961). For the supervisor heartbeat, which is the only
    report there is while the container crash-loops. Never clears: the agent's
    next ``ok`` heartbeat does that once the verdict has expired. Returns
    whether it wrote."""
    stamp = now or datetime.now(UTC)
    verdict = container_verdict(
        role_health, getattr(server, "driver", None), server_last_heard(server), stamp
    )
    if verdict is None or not _differs(server.daemon_reason, verdict[0]["reason"]):
        return False
    report, since = verdict
    apply_reported_daemon_state(
        server,
        report,
        agent_kind="dhcp" if getattr(server, "driver", None) in DHCP_DRIVER_SERVICE else "dns",
        server_id=str(server.id),
        now=min(since, stamp),
    )
    logger.warning(
        "agent_daemon_state_from_supervisor",
        server_id=str(server.id),
        reason_source=reason_source(report["reason"]),
        since=since.isoformat(),
    )
    return True


__all__ = [
    "DHCP_DRIVER_SERVICE",
    "DNS_DRIVER_SERVICE",
    "DRIVER_SERVICE",
    "ROLE_HEALTH_FRESH_SECONDS",
    "REASON_PREFIX",
    "STABLE_SECONDS",
    "AGENT_SILENT_PREFIX",
    "CRASH_LOOP_PREFIX",
    "RESTART_HISTORY_KEY",
    "agent_silent_report",
    "apply_container_oom",
    "carry_restart_history",
    "restarts_in_window",
    "container_crash_loop_report",
    "container_oom_report",
    "container_verdict",
    "daemon_reported_by",
    "is_crash_loop_reason",
    "is_silent_agent_reason",
    "reason_source",
    "server_last_heard",
    "verdict_needs_write",
    "effective_daemon_report",
    "fresh_role_health",
    "is_oom_reason",
]
