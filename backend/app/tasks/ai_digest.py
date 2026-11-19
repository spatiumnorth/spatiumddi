"""Daily Operator Copilot digest (issue #90 Phase 2).

Once per day, roll up the last 24 h of activity (audit log + alert
events + lease churn + utilization deltas), send the rollup to the
highest-priority enabled :class:`AIProvider` for an executive summary,
and push the resulting text through the existing audit-forward
targets so it lands in Slack / Teams / Discord / SMTP without the
operator having to wire a new transport.

Gates / configuration:

* ``PlatformSettings.ai_daily_digest_enabled`` — master kill switch.
  Default off so the cron is harmless on a fresh install. Operators
  flip this in Settings → AI when they want the rollup.
* No SMTP / webhook target wired? The dispatch helper short-circuits
  with no targets — the task still runs, the LLM still composes,
  the result is logged but goes nowhere visible. That's the right
  behaviour: surface the cost in usage stats, no silent breakage.
* No AIProvider enabled? Bail fast — the digest needs an LLM to
  compose the summary. Logs ``ai_digest_no_provider`` so operators
  can see why no digest landed.

The digest is a one-shot, non-streaming completion (we buffer the
whole assistant response inside the task and emit it once). No tool
calls — the rollup data is already collected in the prompt.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.celery_app import celery_app
from app.config import settings
from app.db import task_connect_args
from app.drivers.llm import ChatMessage, ChatRequest, get_driver
from app.models.ai import AIProvider
from app.models.alerts import AlertEvent
from app.models.audit import AuditLog
from app.models.dhcp import DHCPLease
from app.models.settings import PlatformSettings
from app.services import audit_forward
from app.tasks.module_gate import module_gated

logger = structlog.get_logger(__name__)

_SINGLETON_ID = 1
# Keep the rollup payload bounded — too much data and the model runs
# over its context window or charges out of proportion to a digest.
_MAX_TOP_USERS = 5
_MAX_TOP_RESOURCE_TYPES = 8
_MAX_RECENT_ALERTS = 10
# Hard cap so the rendered prompt stays well under any reasonable
# context window. Most digests come in under 5 KB.
_PROMPT_BUDGET_CHARS = 12000


_DIGEST_SYSTEM_PROMPT = """\
You are summarising the previous 24 hours of activity for a network
operator running SpatiumDDI (an IPAM / DNS / DHCP control plane).

You will receive a JSON-shaped activity rollup. Produce a concise
executive summary in 200–300 words covering:

* What changed at the resource layer (creates / updates / deletes,
  grouped by resource family).
* Alert events fired and resolved, with severity highlights.
* DHCP lease churn (granted / revoked / total active).
* Notable user activity (top contributors, unusual access patterns).
* Anything that looks like a regression or risk worth investigating.

Write in plain English — this is read in an inbox, not parsed by a
machine. Do NOT include the raw JSON. Do NOT speculate beyond the
data. If a section has no activity, skip it rather than padding.
""".strip()


async def _gather_activity(db: AsyncSession, *, since: datetime, until: datetime) -> dict[str, Any]:
    """Build the rollup payload the LLM will summarise.

    Every query is read-only and runs against the audit / alerts /
    lease tables — sized for hosts with thousands of changes / day,
    not millions. If a deployment outgrows the simple ``count(*)``
    aggregations we'll move them into a dedicated aggregator that
    indexes on ``timestamp`` first.
    """
    audit_total = (
        await db.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.timestamp >= since, AuditLog.timestamp < until)
        )
    ).scalar_one()

    audit_by_resource = (
        await db.execute(
            select(AuditLog.resource_type, func.count())
            .where(AuditLog.timestamp >= since, AuditLog.timestamp < until)
            .group_by(AuditLog.resource_type)
            .order_by(desc(func.count()))
            .limit(_MAX_TOP_RESOURCE_TYPES)
        )
    ).all()

    audit_by_action = (
        await db.execute(
            select(AuditLog.action, func.count())
            .where(AuditLog.timestamp >= since, AuditLog.timestamp < until)
            .group_by(AuditLog.action)
            .order_by(desc(func.count()))
        )
    ).all()

    audit_top_users = (
        await db.execute(
            select(AuditLog.user_display_name, func.count())
            .where(
                AuditLog.timestamp >= since,
                AuditLog.timestamp < until,
                AuditLog.user_display_name.isnot(None),
            )
            .group_by(AuditLog.user_display_name)
            .order_by(desc(func.count()))
            .limit(_MAX_TOP_USERS)
        )
    ).all()

    audit_failures = (
        await db.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.timestamp >= since,
                AuditLog.timestamp < until,
                AuditLog.result != "success",
            )
        )
    ).scalar_one()

    alerts_fired = (
        await db.execute(
            select(func.count())
            .select_from(AlertEvent)
            .where(AlertEvent.fired_at >= since, AlertEvent.fired_at < until)
        )
    ).scalar_one()

    alerts_resolved = (
        await db.execute(
            select(func.count())
            .select_from(AlertEvent)
            .where(
                AlertEvent.resolved_at.isnot(None),
                AlertEvent.resolved_at >= since,
                AlertEvent.resolved_at < until,
            )
        )
    ).scalar_one()

    alerts_open = (
        await db.execute(
            select(func.count()).select_from(AlertEvent).where(AlertEvent.resolved_at.is_(None))
        )
    ).scalar_one()

    recent_alerts = (
        (
            await db.execute(
                select(AlertEvent)
                .where(AlertEvent.fired_at >= since, AlertEvent.fired_at < until)
                .order_by(desc(AlertEvent.fired_at))
                .limit(_MAX_RECENT_ALERTS)
            )
        )
        .scalars()
        .all()
    )

    leases_active = (
        await db.execute(
            select(func.count()).select_from(DHCPLease).where(DHCPLease.expires_at > until)
        )
    ).scalar_one()

    leases_granted = (
        await db.execute(
            select(func.count())
            .select_from(DHCPLease)
            .where(DHCPLease.starts_at >= since, DHCPLease.starts_at < until)
        )
    ).scalar_one()

    return {
        "window_start_utc": since.isoformat(),
        "window_end_utc": until.isoformat(),
        "audit": {
            "total": int(audit_total),
            "failures": int(audit_failures),
            "by_resource_type": [
                {"resource_type": rt, "count": int(c)} for rt, c in audit_by_resource
            ],
            "by_action": [{"action": a, "count": int(c)} for a, c in audit_by_action],
            "top_users": [{"user": u, "count": int(c)} for u, c in audit_top_users],
        },
        "alerts": {
            "fired_in_window": int(alerts_fired),
            "resolved_in_window": int(alerts_resolved),
            "currently_open": int(alerts_open),
            "recent": [
                {
                    "fired_at": ev.fired_at.isoformat() if ev.fired_at else None,
                    "severity": ev.severity,
                    "subject_type": ev.subject_type,
                    "subject": ev.subject_display,
                    "message": ev.message,
                    "resolved": ev.resolved_at is not None,
                }
                for ev in recent_alerts
            ],
        },
        "dhcp": {
            "active_leases": int(leases_active),
            "granted_in_window": int(leases_granted),
        },
    }


async def _generate_summary(
    provider: AIProvider, rollup: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    """Single-shot completion against ``provider``. No tool calls;
    the prompt already carries every fact we want summarised.

    Returns ``(summary_text, usage_stats)`` where ``usage_stats``
    captures whatever the driver could surface (tokens, cost).
    """
    import json

    # Render the rollup as JSON; truncate if it accidentally balloons
    # past the budget (unlikely with our caps, but cheap insurance).
    rollup_text = json.dumps(rollup, indent=2, default=str)
    if len(rollup_text) > _PROMPT_BUDGET_CHARS:
        rollup_text = rollup_text[:_PROMPT_BUDGET_CHARS] + "\n…[truncated]"

    driver = get_driver(provider)
    request = ChatRequest(
        messages=[
            ChatMessage(role="system", content=_DIGEST_SYSTEM_PROMPT),
            ChatMessage(
                role="user",
                content=f"Activity rollup:\n```json\n{rollup_text}\n```",
            ),
        ],
        model=provider.default_model or "",
        temperature=0.4,
    )

    chunks: list[str] = []
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    async for chunk in driver.chat(request):
        if chunk.content_delta:
            chunks.append(chunk.content_delta)
        if chunk.finish_reason:
            prompt_tokens = chunk.prompt_tokens
            completion_tokens = chunk.completion_tokens

    summary = "".join(chunks).strip()
    return summary, {
        "model": provider.default_model,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
    }


async def _dispatch_digest(summary: str, rollup: dict[str, Any]) -> int:
    """Push the digest as a ``kind="digest"`` payload through every
    enabled audit-forward target. Returns the number of targets the
    payload was attempted against — caller logs it.
    """
    payload: dict[str, Any] = {
        "kind": "digest",
        "title": "SpatiumDDI Daily Operator Digest",
        "severity": "info",
        "resource_type": "ai.digest",
        "fired_at": datetime.now(UTC).isoformat(),
        "message": summary,
        "summary": summary,
        # Keep the raw rollup attached so downstream pipelines (Splunk,
        # ELK) can re-derive structured stats without re-querying.
        "rollup": rollup,
    }

    targets = await audit_forward._load_targets()  # noqa: SLF001
    if not targets:
        return 0
    coros = [audit_forward._deliver_to_target(t, payload) for t in targets]  # noqa: SLF001
    await asyncio.gather(*coros, return_exceptions=True)
    return len(targets)


async def _run() -> dict[str, Any]:
    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            ps = await db.get(PlatformSettings, _SINGLETON_ID)
            if ps is None:
                return {"status": "no_settings_row"}
            if not ps.ai_daily_digest_enabled:
                return {"status": "disabled"}

            provider = (
                await db.execute(
                    select(AIProvider)
                    .where(AIProvider.is_enabled.is_(True))
                    .order_by(AIProvider.priority.asc(), AIProvider.name.asc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            if provider is None:
                logger.info("ai_digest_no_provider")
                return {"status": "no_provider"}

            now = datetime.now(UTC)
            since = now - timedelta(hours=24)
            rollup = await _gather_activity(db, since=since, until=now)

        # Run the LLM call outside the DB transaction so a slow upstream
        # provider doesn't pin a connection.
        try:
            summary, usage = await _generate_summary(provider, rollup)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ai_digest_llm_failed",
                provider=provider.name,
                error=str(exc),
            )
            return {"status": "llm_error", "error": str(exc)}

        if not summary:
            logger.warning("ai_digest_empty_summary", provider=provider.name)
            return {"status": "empty_summary"}

        target_count = await _dispatch_digest(summary, rollup)
        logger.info(
            "ai_digest_dispatched",
            provider=provider.name,
            model=usage.get("model"),
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
            target_count=target_count,
            summary_chars=len(summary),
        )
        return {
            "status": "ok",
            "provider": provider.name,
            "target_count": target_count,
            "summary_chars": len(summary),
            "usage": usage,
        }
    finally:
        await engine.dispose()


@celery_app.task(
    name="app.tasks.ai_digest.send_daily_digest",
    bind=True,
    autoretry_for=(Exception,),
    retry_backoff=True,
    max_retries=2,
)
@module_gated("ai.copilot")
def send_daily_digest(self: Any) -> dict[str, Any]:  # noqa: ARG001
    """Beat-fired entrypoint. The async helper does all the real work."""
    return asyncio.run(_run())


__all__ = ["send_daily_digest"]
