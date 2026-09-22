"""Ingest the daemon state agents report on every heartbeat (#1067).

The DNS and DHCP agents both carry a ``daemon`` object on the heartbeat:
``{"status": "ok"}`` while the daemon is up, ``{"status": "degraded",
"reason": ...}`` while it is not serving. The DNS agent says ``degraded``
from the moment its daemon start is deferred (no bundle rendered yet,
#1056 / #1061 — ``"start deferred, no bundle yet"``) until the first bundle
lands, and after a failed apply; the DHCP agent says it when Kea's control
socket is unreachable or a config was rejected. Until #1067 both request
models declared the field and both handlers ignored it, so a registered,
heartbeating server whose daemon never started read exactly like a healthy
one: ``status`` active, ``last_seen_at`` seconds old, ``config_apply_status``
ok — measured for twelve minutes on a member restarting every two minutes on
its liveness probe.

One function for both handlers, the #882 shape (``config_apply.py``), so
the semantics cannot drift apart:

* **absent / empty** — a pre-#1061 agent, or one with nothing to say yet
  (the DNS agent's dict is ``{}`` until something sets it). Leave every
  column untouched: writing ``ok`` would fabricate a state, and NULLing
  would erase a real report.
* **any non-empty status** is stored, clipped to the column. The vocabulary
  is the agents' (``ok`` / ``degraded`` today), and the read side treats
  anything that is not ``ok`` as not serving. A word this control plane has
  never seen is still a state the agent chose to report; hiding it behind
  the last known one would recreate #1067 for the next word.
* ``daemon_status_since`` means *since this status*: it moves only when the
  status changes, so a row can say how long a daemon has been degraded —
  what the persistence alert needs and what an operator reads first.
  ``last_seen_at`` already says whether the report is current.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol

import structlog

logger = structlog.get_logger(__name__)

STATUS_OK = "ok"
STATUS_DEGRADED = "degraded"

# Bounds mirroring the columns. The agent is authenticated but its payload is
# still agent-supplied; a buggy or compromised one must not write past the
# column width.
_MAX_STATUS = 20
_MAX_REASON = 2000


class _HasDaemonStateColumns(Protocol):
    daemon_status: str | None
    daemon_reason: str | None
    daemon_status_since: datetime | None


def _clip(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:limit]


def is_unhealthy(status: str | None) -> bool:
    """A reported daemon status that is not ``ok``.

    NULL is *unknown* — never reported — and deliberately not unhealthy: an
    agentless driver or a pre-#1061 agent has no daemon state to give, and
    alarming on every one of those on upgrade day would say nothing true.
    """
    return status is not None and status != STATUS_OK


def apply_reported_daemon_state(
    server: _HasDaemonStateColumns,
    reported: dict[str, Any] | None,
    *,
    agent_kind: str,
    server_id: str,
    now: datetime | None = None,
) -> None:
    """Persist ``reported`` (the heartbeat's ``daemon`` field) onto ``server``."""
    if not reported or not isinstance(reported, dict):
        return
    status = _clip(reported.get("status"), _MAX_STATUS)
    if status is None:
        return
    stamp = now or datetime.now(UTC)

    previous = server.daemon_status
    server.daemon_status = status
    # The reason describes a state that is not ``ok``; on ``ok`` it is over,
    # and last week's "start deferred" next to a green status misleads.
    server.daemon_reason = (
        None if status == STATUS_OK else _clip(reported.get("reason"), _MAX_REASON)
    )
    if status != previous or server.daemon_status_since is None:
        server.daemon_status_since = stamp

    if status != previous:
        log = logger.warning if is_unhealthy(status) else logger.info
        log(
            "agent_daemon_state_changed",
            agent_kind=agent_kind,
            server_id=server_id,
            status=status,
            previous=previous,
            reason=server.daemon_reason,
        )
