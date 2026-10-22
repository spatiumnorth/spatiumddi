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

from datetime import UTC, datetime
from typing import Any

import structlog

from app.services.agents.daemon_state import (
    STATUS_DEGRADED,
    apply_reported_daemon_state,
)

logger = structlog.get_logger(__name__)

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


def is_oom_reason(reason: str | None) -> bool:
    return str(reason or "").strip().startswith(REASON_PREFIX)


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
    if isinstance(reported, dict) and is_oom_reason(reported.get("reason")):
        return reported, now
    oom = container_oom_report(role_health, driver, now)
    if oom is None:
        return reported, now
    return oom[0], oom[1]


def apply_container_oom(
    server: Any,
    role_health: dict[str, Any] | None,
    *,
    now: datetime | None = None,
) -> bool:
    """Stamp the kubelet's OOM verdict onto ``server`` (a DNSServer or, since
    #2023, a DHCPServer) when the
    row does not already say so. For the supervisor heartbeat, which is the
    only report there is while the container crash-loops. Never clears: the
    agent's next ``ok`` heartbeat does that once the verdict has expired.
    Returns whether it wrote."""
    stamp = now or datetime.now(UTC)
    oom = container_oom_report(role_health, getattr(server, "driver", None), stamp)
    if oom is None or is_oom_reason(server.daemon_reason):
        return False
    report, killed_at = oom
    apply_reported_daemon_state(
        server,
        report,
        agent_kind="dhcp" if getattr(server, "driver", None) in DHCP_DRIVER_SERVICE else "dns",
        server_id=str(server.id),
        now=min(killed_at, stamp),
    )
    logger.warning(
        "agent_daemon_oom_from_kubelet",
        server_id=str(server.id),
        killed_at=killed_at.isoformat(),
    )
    return True


__all__ = [
    "DHCP_DRIVER_SERVICE",
    "DNS_DRIVER_SERVICE",
    "DRIVER_SERVICE",
    "ROLE_HEALTH_FRESH_SECONDS",
    "REASON_PREFIX",
    "STABLE_SECONDS",
    "apply_container_oom",
    "container_oom_report",
    "effective_daemon_report",
    "fresh_role_health",
    "is_oom_reason",
]
