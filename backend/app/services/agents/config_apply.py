"""Ingest the config-apply verdict agents report on every heartbeat (#882).

Three agents (DNS, DHCP, looking-glass) report the same structure on the
same field, and three heartbeat handlers persist it onto three tables with
the same four columns. One function so the semantics cannot drift apart —
in particular the "only overwrite on a real report" rule, which is what
stops a pre-#882 agent (which sends no ``config`` at all) from silently
clearing a genuine failure recorded by a newer one.

The counterpart lives in each agent's ``config_apply.py``; the status
vocabulary is shared and must stay in sync.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol

import structlog

logger = structlog.get_logger(__name__)

STATUS_OK = "ok"
STATUS_REVERTED = "reverted"
STATUS_REVERT_FAILED = "revert_failed"
STATUS_NO_PREVIOUS = "no_previous"

VALID_STATUSES = frozenset({STATUS_OK, STATUS_REVERTED, STATUS_REVERT_FAILED, STATUS_NO_PREVIOUS})

#: Statuses meaning "this server is NOT running the config we hold". Every
#: read surface — the alert rule, the server-list chip, the MCP tool —
#: filters on this set rather than re-listing the strings.
FAILED_STATUSES = frozenset({STATUS_REVERTED, STATUS_REVERT_FAILED, STATUS_NO_PREVIOUS})

# An agent that applied a bundle but had some zones refused by its daemon
# (PowerDNS takes zones one at a time) reports ``reverted`` with an error that
# starts with this prefix, since there is no "partial" status. Nothing was
# rolled back and every other zone is served, so the alert must not say it
# was. Mirrors the DNS agent's ``sync.PARTIAL_APPLY_PREFIX``.
PARTIAL_APPLY_PREFIX = "partial apply: "


def is_partial_apply(status: str | None, error: str | None) -> bool:
    """True for a ``reverted`` verdict that is really a partial apply."""
    return status == STATUS_REVERTED and (error or "").startswith(PARTIAL_APPLY_PREFIX)


#: Severity per status. A revert is a warning: the daemon is healthy and
#: serving, just not what was asked for. The other two are critical —
#: ``revert_failed`` means the fallback ALSO failed, and ``no_previous``
#: means there was never a working config to fall back to, so the service
#: may not be answering at all.
SEVERITY_BY_STATUS = {
    STATUS_REVERTED: "warning",
    STATUS_REVERT_FAILED: "critical",
    STATUS_NO_PREVIOUS: "critical",
}

# Bounds mirroring the columns. The agent already truncates, but the
# heartbeat is an authenticated-agent-supplied payload and a compromised or
# simply buggy agent must not be able to write past the column width.
_MAX_ERROR = 2000
_MAX_ETAG = 128
_MAX_STATUS = 20


class _HasConfigApplyColumns(Protocol):
    config_apply_status: str | None
    config_apply_error: str | None
    config_failed_etag: str | None
    config_apply_at: datetime | None


def _clip(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:limit]


def apply_reported_status(
    server: _HasConfigApplyColumns,
    reported: dict[str, Any] | None,
    *,
    agent_kind: str,
    server_id: str,
) -> None:
    """Persist ``reported`` onto ``server``'s config-apply columns.

    ``reported`` is the heartbeat's ``config`` field. Three shapes matter
    and are handled differently:

    * **absent / empty** — a pre-#882 agent, which sends ``{}`` or nothing.
      Leave every column untouched. Writing ``ok`` here would be a
      fabrication, and NULLing the columns would erase a real failure that
      a newer agent had reported before a downgrade.
    * **an unrecognised status** — a newer agent than this control plane, or
      a corrupt payload. Log and leave the columns alone, for the same
      reason: guessing is worse than admitting we do not know.
    * **a known status** — write all four columns together, so a stale
      ``config_apply_error`` can never outlive the failure it described.
    """
    if not reported or not isinstance(reported, dict):
        return

    status = _clip(reported.get("status"), _MAX_STATUS)
    if status is None:
        return
    if status not in VALID_STATUSES:
        logger.warning(
            "agent_config_apply_unknown_status",
            agent_kind=agent_kind,
            server_id=server_id,
            status=status,
        )
        return

    previous = server.config_apply_status
    server.config_apply_status = status
    # Cleared as a group on ``ok``: the error and the failed etag describe a
    # failure that is over, and a chip tooltip showing last week's
    # named-checkconf output next to a green status is worse than showing
    # nothing.
    if status == STATUS_OK:
        server.config_apply_error = None
        server.config_failed_etag = None
    else:
        server.config_apply_error = _clip(reported.get("error"), _MAX_ERROR)
        server.config_failed_etag = _clip(reported.get("failed_etag"), _MAX_ETAG)
    server.config_apply_at = datetime.now(UTC)

    if status != previous:
        log = logger.warning if status in FAILED_STATUSES else logger.info
        log(
            "agent_config_apply_status_changed",
            agent_kind=agent_kind,
            server_id=server_id,
            status=status,
            previous=previous,
            failed_etag=server.config_failed_etag,
            phase=_clip(reported.get("phase"), 32),
        )
