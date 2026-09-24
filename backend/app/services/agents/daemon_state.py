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
  is the agents' (``ok`` / ``degraded`` today). A word this control plane
  has never seen is still a state the agent chose to report; hiding it
  behind the last known one would recreate #1067 for the next word.
* **not serving** is :func:`is_not_serving`, and it is the ONE reading of
  these columns: the ``agent_daemon_degraded`` alert, both server responses
  (``daemon_not_serving``) and, through those, the chip, the banner and the
  dashboard all use it. Anything that is not ``ok`` is not serving — except
  a ``degraded`` that is the agent echoing a failed config apply into this
  field (:func:`is_config_apply_verdict`). That state is #882's:
  ``config_apply_status`` carries it with the severity each verdict
  deserves, and a *reverted* daemon is up, serving its last-known-good
  config. Reading it here as well put a red "not serving" chip on every
  routine revert.
* ``daemon_status_since`` means *since this state*: it moves when the status
  changes, or when the same ``degraded`` crosses between not serving and a
  config-apply echo — never on a repeated report — so a row can say how
  long its daemon has been in the state the UI shows. It is also the
  alert's grace clock. ``last_seen_at`` already says whether the report is
  current.
"""

from __future__ import annotations

import re
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
    Whether an unhealthy status means *not serving* is :func:`is_not_serving`.
    """
    return status is not None and status != STATUS_OK


# The agents also echo a failed config apply (#882) into the daemon field.
# The DNS agent does it for every verdict (agent ``sync.py``:
# ``config_apply_<reverted|revert_failed|no_previous>: <error>``). The DHCP
# agent writes ``config_apply_reverted: <error>`` after a rollback, and
# otherwise leaves Kea's own refusal in place (``_reload_socket``:
# ``dhcp4_config_rejected: <error>`` / ``dhcp6_…``) — which is what survives
# a failed apply with nothing, or nothing that works, to roll back to. Both
# halves of that contract are pinned: each agent's own suite asserts the exact
# prefixes it emits (``test_config_revert.py``, and the DHCP agent's
# ``test_config_test_preflight.py``), and ``tests/test_agent_daemon_state.py``
# asserts this pattern reads every one of them — so a reworded reason fails a
# test rather than quietly reading as "not serving".
_CONFIG_APPLY_REASON = re.compile(r"^(?:config_apply_\w+|dhcp[46]_config_rejected):")


def is_config_apply_verdict(reason: str | None) -> bool:
    """Whether a daemon ``reason`` is the agent echoing a failed config apply."""
    if not reason:
        return False
    return _CONFIG_APPLY_REASON.match(reason.strip()) is not None


def is_not_serving(status: str | None, reason: str | None) -> bool | None:
    """The #1067 condition: does the agent report a daemon that is not serving?

    ``None`` when the agent has never reported a daemon state — unknown,
    never ``ok`` and never an alarm. ``False`` on ``ok``, and on a report
    that is a config-apply echo (:func:`is_config_apply_verdict`), which
    ``config_apply_status`` reports at #882's severity. ``True`` for anything
    else that is not ``ok``.
    """
    if status is None:
        return None
    if status == STATUS_OK:
        return False
    return not is_config_apply_verdict(reason)


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
    was_not_serving = is_not_serving(previous, server.daemon_reason)
    server.daemon_status = status
    # The reason describes a state that is not ``ok``; on ``ok`` it is over,
    # and last week's "start deferred" next to a green status misleads.
    server.daemon_reason = (
        None if status == STATUS_OK else _clip(reported.get("reason"), _MAX_REASON)
    )
    not_serving = is_not_serving(status, server.daemon_reason)
    # A new state, not a new report. The same ``degraded`` crossing between a
    # config-apply echo and a daemon that is not serving restarts the clock
    # too: otherwise a start deferred a minute ago inherits the start time of
    # an hours-old revert, skips the alert's grace, and pages at once with a
    # duration that was never true.
    changed = status != previous or not_serving != was_not_serving
    if changed or server.daemon_status_since is None:
        server.daemon_status_since = stamp

    if changed:
        log = logger.warning if is_unhealthy(status) else logger.info
        log(
            "agent_daemon_state_changed",
            agent_kind=agent_kind,
            server_id=server_id,
            status=status,
            previous=previous,
            not_serving=not_serving,
            reason=server.daemon_reason,
        )
