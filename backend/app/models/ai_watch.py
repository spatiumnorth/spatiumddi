"""Copilot Watch (issue #4405): an opt-in agent that reviews what the
detectors found and files findings.

Five tables:

* ``ai_watch_config`` — one row (``id = 1``): the operator's settings,
  plus the small amount of state the trigger logic keeps between ticks.
* ``ai_watch_run`` — one row per run, including every run that was
  skipped (budget, no eligible provider, maintenance mode ...): a skipped
  run is recorded, never silent.
* ``ai_finding`` — a narrative over one or more pieces of evidence the
  deterministic detectors produced. Not an ``alert_event``: an alert is
  one rule against one subject and resolves itself; a finding spans
  several and has a triage state.
* ``ai_finding_feedback`` — one verdict per user per finding.
* ``ai_finding_mute`` — a fingerprint the operator does not want filed
  again, until a time or for good.

Watch only observes and advises. Nothing here stages or applies a change.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

WATCH_CONFIG_ID = 1

# What started a run.
TRIGGER_MANUAL = "manual"
TRIGGER_EVENT = "event"
TRIGGER_SWEEP = "sweep"
WATCH_TRIGGERS: tuple[str, ...] = (TRIGGER_MANUAL, TRIGGER_EVENT, TRIGGER_SWEEP)

RUN_RUNNING = "running"
RUN_OK = "ok"
RUN_FAILED = "failed"
RUN_SKIPPED = "skipped"
WATCH_RUN_STATES: tuple[str, ...] = (RUN_RUNNING, RUN_OK, RUN_FAILED, RUN_SKIPPED)

# Why Watch is paused. ``manual`` and ``failures`` stay until an operator
# resumes; ``budget`` lifts by itself at ``paused_until`` (the next UTC
# midnight, when the daily budget resets).
PAUSE_MANUAL = "manual"
PAUSE_BUDGET = "budget"
PAUSE_FAILURES = "failures"
WATCH_PAUSE_REASONS: tuple[str, ...] = (PAUSE_MANUAL, PAUSE_BUDGET, PAUSE_FAILURES)

FINDING_OPEN = "open"
FINDING_ACKNOWLEDGED = "acknowledged"
FINDING_DISMISSED = "dismissed"
FINDING_RESOLVED = "resolved"
FINDING_STATES: tuple[str, ...] = (
    FINDING_OPEN,
    FINDING_ACKNOWLEDGED,
    FINDING_DISMISSED,
    FINDING_RESOLVED,
)
# States in which a finding is still live: a later run updates it instead
# of filing another one, and it closes when its evidence clears.
FINDING_ACTIVE_STATES: tuple[str, ...] = (FINDING_OPEN, FINDING_ACKNOWLEDGED)

FINDING_KINDS: tuple[str, ...] = (
    "outage",
    "config_apply",
    "capacity",
    "drift",
    "compliance",
    "security",
    "performance",
    "other",
)
FINDING_SEVERITIES: tuple[str, ...] = ("info", "warning", "critical")
FINDING_CONFIDENCES: tuple[str, ...] = ("low", "medium", "high")
FEEDBACK_VERDICTS: tuple[str, ...] = ("useful", "not_useful", "wrong")


class AIWatchConfig(TimestampMixin, Base):
    """Singleton settings + trigger state for Copilot Watch."""

    __tablename__ = "ai_watch_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=WATCH_CONFIG_ID)

    # The arming switch. The feature module makes the surface exist;
    # nothing is sent to a model until this is on, and it can only be
    # turned on with both budgets set and an eligible provider.
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    paused: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    paused_reason: Mapped[str | None] = mapped_column(String(20), nullable=True)
    paused_detail: Mapped[str] = mapped_column(
        Text, nullable=False, default="", server_default=sa_text("''")
    )
    paused_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    paused_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Provider pin. NULL means the highest-priority enabled provider that
    # is eligible. Eligible = marked on-prem (``ai_provider.is_on_prem``),
    # or any enabled provider once ``allow_hosted_provider`` is on. Watch
    # sends install data with nobody watching, so a hosted provider is a
    # separate explicit decision, not something chat's configuration implies.
    provider_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ai_provider.id", ondelete="SET NULL"), nullable=True
    )
    allow_hosted_provider: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )

    # Triggers. 0 hours turns the scheduled sweep off.
    sweep_interval_hours: Mapped[int] = mapped_column(
        Integer, nullable=False, default=24, server_default=sa_text("24")
    )
    event_trigger_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    event_debounce_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=300, server_default=sa_text("300")
    )

    # Tool allowlist. NULL means the built-in default list
    # (``services.ai.watch.tools.DEFAULT_WATCH_TOOLS``). Whatever is
    # stored, write tools, ``propose_*`` tools and tools that send traffic
    # outward are never offered.
    enabled_tools: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)

    # Spend. Both are required (> 0) to enable Watch.
    daily_token_budget: Mapped[int] = mapped_column(
        Integer, nullable=False, default=200_000, server_default=sa_text("200000")
    )
    daily_cost_budget_usd: Mapped[Decimal] = mapped_column(
        Numeric(10, 2), nullable=False, default=Decimal("2.00"), server_default=sa_text("2.00")
    )
    max_runs_per_hour: Mapped[int] = mapped_column(
        Integer, nullable=False, default=6, server_default=sa_text("6")
    )
    max_rounds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=4, server_default=sa_text("4")
    )
    max_tokens_per_run: Mapped[int] = mapped_column(
        Integer, nullable=False, default=40_000, server_default=sa_text("40000")
    )

    # ── Trigger state, written by the tick ──────────────────────────
    last_sweep_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # When the first not-yet-reviewed alert change was seen; the event
    # run fires ``event_debounce_seconds`` after it, so one outage that
    # opens 40 alerts is one run.
    event_pending_since: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # ``{alert_event_id: severity}`` for the open alerts as of the last
    # look. A new id, or a higher severity on a known one, is what "new or
    # escalated" means. NULL until the first look, which only records.
    alert_cursor: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    run_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    run_requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    consecutive_failures: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=sa_text("0")
    )


class AIWatchRun(UUIDPrimaryKeyMixin, Base):
    """One run of Copilot Watch, or one recorded skip."""

    __tablename__ = "ai_watch_run"

    trigger: Mapped[str] = mapped_column(String(20), nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    # Set when ``state = skipped``: ``budget_exhausted``, ``no_provider``,
    # ``hosted_not_allowed``, ``rate_limited``, ``maintenance``,
    # ``principal_not_read_only``, ``paused``.
    skip_reason: Mapped[str | None] = mapped_column(String(40), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    provider_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ai_provider.id", ondelete="SET NULL"), nullable=True
    )
    # Snapshots: the provider row can be renamed or deleted later.
    provider_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    model: Mapped[str] = mapped_column(String(255), nullable=False, default="")

    tokens_in: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tokens_out: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # NULL when the model is not on the rate sheet (a local model): the
    # cost is unknown, not zero. The token budget still counts it.
    cost_usd: Mapped[Decimal | None] = mapped_column(Numeric(12, 6), nullable=True)
    rounds: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tool_calls: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    evidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_opened: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_updated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_resolved: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Findings the model returned that cited no evidence that exists.
    # A high number means the model is inventing.
    findings_dropped: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_muted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # The evidence pack sent, every model reply and every tool result, in
    # order, so an operator can see how a conclusion was reached.
    transcript: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (Index("ix_ai_watch_run_started_at", "started_at"),)


class AIFinding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One finding: what is wrong, why Watch thinks so, what to do."""

    __tablename__ = "ai_finding"

    # sha256 over the kind and the sorted subjects of the evidence. Stable
    # across runs while the same things are wrong, so a later run updates
    # this row instead of filing another.
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # ``[{ref, type, id, subject, display, cleared}]`` — every entry was
    # checked to exist when the finding was filed or last updated.
    evidence: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    recommendations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    confidence: Mapped[str] = mapped_column(String(10), nullable=False, default="medium")
    state: Mapped[str] = mapped_column(String(20), nullable=False, default=FINDING_OPEN)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # The run that last filed or updated it, and the model that wrote the
    # current text (feedback rates are reported per model).
    run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ai_watch_run.id", ondelete="SET NULL"), nullable=True
    )
    model: Mapped[str] = mapped_column(String(255), nullable=False, default="")

    # Who acknowledged or dismissed it, and what they said.
    state_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    state_changed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    state_note: Mapped[str] = mapped_column(Text, nullable=False, default="")

    __table_args__ = (
        # At most one live finding per fingerprint.
        Index(
            "uq_ai_finding_fingerprint_active",
            "fingerprint",
            unique=True,
            postgresql_where=sa_text("state IN ('open', 'acknowledged')"),
        ),
        Index("ix_ai_finding_state_last_seen", "state", "last_seen_at"),
    )


class AIFindingFeedback(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A user's verdict on a finding. One per user per finding."""

    __tablename__ = "ai_finding_feedback"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ai_finding.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="CASCADE"), nullable=False
    )
    verdict: Mapped[str] = mapped_column(String(20), nullable=False)
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")

    __table_args__ = (
        UniqueConstraint("finding_id", "user_id", name="uq_ai_finding_feedback_finding_user"),
    )


class AIFindingMute(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A fingerprint Watch must not file again while the mute holds."""

    __tablename__ = "ai_finding_mute"

    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    # NULL = until an operator removes it.
    until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # What the muted finding was about, kept so the mute list stays
    # readable after the finding row is gone.
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ai_finding.id", ondelete="SET NULL"), nullable=True
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )

    __table_args__ = (UniqueConstraint("fingerprint", name="uq_ai_finding_mute_fingerprint"),)


__all__ = [
    "AIFinding",
    "AIFindingFeedback",
    "AIFindingMute",
    "AIWatchConfig",
    "AIWatchRun",
]
