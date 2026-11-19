"""Batched retention deletes + the prunes for tables that grew forever (#2274).

A single ``DELETE ... WHERE ts < cutoff`` over millions of rows is one long
transaction: it holds locks, bloats WAL and can hit the statement timeout, so
the whole prune rolls back and the table keeps growing (#2185). So every
delete here goes through :func:`batched_delete`, which removes at most
``batch_size`` rows per statement and commits each batch in its own
transaction.

Each prune is a ``RetentionRule``: a ``PlatformSettings`` column holding the
window in days (0 = keep forever), the model, and the predicate for a row that
is both old enough and *terminal* (resolved, delivered, closed, expired).
Open or in-flight rows are never deleted whatever their age. Every delete is a
plain predicate over rows that stay deletable, so a retry or a second run
finds nothing left to do (non-negotiable #9).

``audit_log`` is deliberately absent: it stays retained forever.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import ColumnElement, and_, delete, exists, func, not_, or_, select
from sqlalchemy.orm import aliased

from app.config import settings as app_config
from app.db import task_sessionmaker
from app.models.ai import AIChatMessage, AIChatSession
from app.models.alerts import AlertEvent
from app.models.auth import UserSession
from app.models.change_request import ChangeRequest
from app.models.conformity import ConformityResult
from app.models.event_subscription import EventOutbox
from app.models.ipam import IpMacHistory
from app.models.nmap import NmapScan
from app.models.settings import PlatformSettings
from app.models.system_upgrade import SystemUpgradeRun
from app.models.wol_schedule import WolRun

logger = structlog.get_logger(__name__)

#: Rows per delete statement / transaction.
BATCH_SIZE = 10_000


async def batched_delete(
    model: Any,
    where: ColumnElement[bool],
    *,
    batch_size: int = BATCH_SIZE,
    session_factory: Any = None,
) -> int:
    """Delete every ``model`` row matching ``where``, ``batch_size`` at a time.

    Each batch is its own statement and transaction, picked by primary key
    (``DELETE ... WHERE id IN (SELECT id ... LIMIT n)``), so no transaction
    holds more than ``batch_size`` row locks. Stops on the first short batch.
    A failure in batch N leaves batches 1..N-1 committed: re-running resumes.
    ``model`` needs an ``id`` primary key. Returns the rows removed.
    """
    if batch_size < 1:
        raise ValueError("batch_size must be >= 1")
    total = 0

    async def _run(factory: Any) -> int:
        nonlocal total
        while True:
            async with factory() as db:
                ids = select(model.id).where(where).limit(batch_size)
                result = await db.execute(delete(model).where(model.id.in_(ids)))
                await db.commit()
            removed = max(int(result.rowcount or 0), 0)
            total += removed
            if removed < batch_size:
                return total

    if session_factory is not None:
        return await _run(session_factory)
    async with task_sessionmaker(command_timeout=app_config.task_db_long_command_timeout) as f:
        return await _run(f)


@dataclass(frozen=True)
class RetentionRule:
    name: str
    field: str  # PlatformSettings column: window in days, 0 = keep forever
    default_days: int
    model: Any
    predicate: Callable[[datetime], ColumnElement[bool]]


def _conformity(cutoff: datetime) -> ColumnElement[bool]:
    # Keep the newest result per (policy, resource) whatever its age: the
    # engine reads it as the "previous status" for a target that has not been
    # evaluated since (a disabled policy, a target out of scope).
    newer = aliased(ConformityResult)
    return and_(
        ConformityResult.evaluated_at < cutoff,
        exists().where(
            newer.policy_id == ConformityResult.policy_id,
            newer.resource_kind == ConformityResult.resource_kind,
            newer.resource_id == ConformityResult.resource_id,
            newer.evaluated_at > ConformityResult.evaluated_at,
        ),
    )


def _ai_chat(cutoff: datetime) -> ColumnElement[bool]:
    # Idle: neither the session nor any of its messages touched since cutoff.
    # Proposals and messages go with the session (ON DELETE CASCADE).
    return and_(
        AIChatSession.modified_at < cutoff,
        not_(
            exists().where(
                AIChatMessage.session_id == AIChatSession.id,
                AIChatMessage.created_at >= cutoff,
            )
        ),
    )


RULES: tuple[RetentionRule, ...] = (
    RetentionRule(
        "alert_event",
        "alert_event_retention_days",
        180,
        AlertEvent,
        lambda c: and_(AlertEvent.resolved_at.is_not(None), AlertEvent.resolved_at < c),
    ),
    RetentionRule(
        "ip_mac_history",
        "ip_mac_history_retention_days",
        365,
        IpMacHistory,
        # Acknowledged / known rows are operator decisions (new-device watch):
        # dropping one would make the MAC "new" again.
        lambda c: and_(
            IpMacHistory.last_seen < c,
            IpMacHistory.classification.not_in(("acknowledged", "known")),
        ),
    ),
    RetentionRule(
        "nmap_scan",
        "nmap_scan_retention_days",
        90,
        NmapScan,
        lambda c: and_(
            NmapScan.status.in_(("completed", "failed", "cancelled")),
            func.coalesce(NmapScan.finished_at, NmapScan.created_at) < c,
        ),
    ),
    RetentionRule(
        "conformity_result", "conformity_result_retention_days", 365, ConformityResult, _conformity
    ),
    RetentionRule(
        "event_outbox",
        "event_outbox_retention_days",
        7,
        EventOutbox,
        lambda c: and_(
            EventOutbox.state == "delivered",
            func.coalesce(EventOutbox.delivered_at, EventOutbox.modified_at) < c,
        ),
    ),
    RetentionRule(
        "user_session",
        "user_session_retention_days",
        30,
        UserSession,
        lambda c: or_(
            UserSession.expires_at < c,
            and_(
                UserSession.revoked.is_(True),
                func.coalesce(UserSession.last_seen_at, UserSession.created_at) < c,
            ),
        ),
    ),
    RetentionRule("ai_chat_session", "ai_chat_retention_days", 90, AIChatSession, _ai_chat),
    RetentionRule(
        "change_request",
        "change_request_retention_days",
        365,
        ChangeRequest,
        lambda c: and_(
            ChangeRequest.state.in_(("rejected", "executed", "failed", "expired", "cancelled")),
            ChangeRequest.modified_at < c,
        ),
    ),
    RetentionRule(
        "wol_run",
        "run_log_retention_days",
        90,
        WolRun,
        lambda c: and_(
            WolRun.status != "in_progress",
            func.coalesce(WolRun.finished_at, WolRun.started_at) < c,
        ),
    ),
    RetentionRule(
        "system_upgrade_run",
        "run_log_retention_days",
        90,
        SystemUpgradeRun,
        lambda c: and_(
            SystemUpgradeRun.state.in_(("succeeded", "failed", "aborted")),
            func.coalesce(SystemUpgradeRun.finished_at, SystemUpgradeRun.started_at) < c,
        ),
    ),
)

#: Reported in place of a count when a table's prune failed.
FAILED = -1


async def prune_unbounded_tables(
    *, now: datetime | None = None, batch_size: int = BATCH_SIZE
) -> dict[str, int]:
    """Run every rule against the current settings; ``{table: rows removed}``.

    A rule whose window is 0 (or negative) is skipped. A failing table is
    logged, reported as :data:`FAILED`, and does not stop the others.
    """
    now = now or datetime.now(UTC)
    async with task_sessionmaker(command_timeout=app_config.task_db_long_command_timeout) as f:
        async with f() as db:
            ps = await db.get(PlatformSettings, 1)
        out: dict[str, int] = {}
        for rule in RULES:
            days = rule.default_days if ps is None else getattr(ps, rule.field)
            if days <= 0:
                continue
            try:
                out[rule.name] = await batched_delete(
                    rule.model,
                    rule.predicate(now - timedelta(days=days)),
                    batch_size=batch_size,
                    session_factory=f,
                )
            except Exception as exc:
                logger.error("retention_prune_failed", table=rule.name, error=repr(exc))
                out[rule.name] = FAILED
        return out
