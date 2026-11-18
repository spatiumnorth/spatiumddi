"""Copilot Watch: settings, runs, findings, feedback, mutes (#4405)

Five tables for the opt-in agent that reviews what the detectors found
and files findings:

* ``ai_watch_config`` — one row (``id = 1``) of settings and trigger
  state. Not inserted here: the row is created with its defaults the first
  time the settings are read, so a fresh install and an upgrade end up the
  same.
* ``ai_watch_run`` — one row per run, skipped runs included.
* ``ai_finding`` — the findings, with a partial unique index so at most
  one live (open or acknowledged) finding exists per fingerprint.
* ``ai_finding_feedback`` — one verdict per user per finding.
* ``ai_finding_mute`` — fingerprints not to file again.

Plus ``ai_provider.is_on_prem``: the operator's statement that a provider
runs on infrastructure they control. Watch uses only such providers unless
hosted use is explicitly allowed. Existing providers get ``false``: nothing
is assumed to be on-prem.

No ``feature_module`` row is written (#1069): ``ai.watch`` ships off through
its catalog default.

Revision ID: c8f4a1d27e53
Revises: b6d2e9f41a07
Create Date: 2026-11-18 12:00:00.000000
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "c8f4a1d27e53"
down_revision = "b6d2e9f41a07"
branch_labels = None
depends_on = None


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "modified_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    ]


def upgrade() -> None:
    op.add_column(
        "ai_provider",
        sa.Column("is_on_prem", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )

    op.create_table(
        "ai_watch_config",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("paused", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("paused_reason", sa.String(length=20), nullable=True),
        sa.Column("paused_detail", sa.Text(), server_default=sa.text("''"), nullable=False),
        sa.Column("paused_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("paused_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("provider_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "allow_hosted_provider", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column(
            "sweep_interval_hours", sa.Integer(), server_default=sa.text("24"), nullable=False
        ),
        sa.Column(
            "event_trigger_enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False
        ),
        sa.Column(
            "event_debounce_seconds", sa.Integer(), server_default=sa.text("300"), nullable=False
        ),
        sa.Column("enabled_tools", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "daily_token_budget", sa.Integer(), server_default=sa.text("200000"), nullable=False
        ),
        sa.Column(
            "daily_cost_budget_usd",
            sa.Numeric(precision=10, scale=2),
            server_default=sa.text("2.00"),
            nullable=False,
        ),
        sa.Column("max_runs_per_hour", sa.Integer(), server_default=sa.text("6"), nullable=False),
        sa.Column("max_rounds", sa.Integer(), server_default=sa.text("4"), nullable=False),
        sa.Column(
            "max_tokens_per_run", sa.Integer(), server_default=sa.text("40000"), nullable=False
        ),
        sa.Column("last_sweep_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("event_pending_since", sa.DateTime(timezone=True), nullable=True),
        sa.Column("alert_cursor", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("run_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("run_requested_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "consecutive_failures", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        *_timestamps(),
        sa.ForeignKeyConstraint(["provider_id"], ["ai_provider.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["run_requested_by_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "ai_watch_run",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("trigger", sa.String(length=20), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("skip_reason", sa.String(length=40), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("provider_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("provider_name", sa.String(length=255), server_default="", nullable=False),
        sa.Column("model", sa.String(length=255), server_default="", nullable=False),
        sa.Column("tokens_in", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("tokens_out", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("cost_usd", sa.Numeric(precision=12, scale=6), nullable=True),
        sa.Column("rounds", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("tool_calls", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("evidence_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("findings_opened", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("findings_updated", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("findings_resolved", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("findings_dropped", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("findings_muted", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("transcript", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("requested_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["provider_id"], ["ai_provider.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["requested_by_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ai_watch_run_started_at", "ai_watch_run", ["started_at"])

    op.create_table(
        "ai_finding",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=40), nullable=False),
        sa.Column("severity", sa.String(length=10), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("explanation", sa.Text(), server_default="", nullable=False),
        sa.Column(
            "evidence",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "recommendations",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("confidence", sa.String(length=10), server_default="medium", nullable=False),
        sa.Column("state", sa.String(length=20), server_default="open", nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("model", sa.String(length=255), server_default="", nullable=False),
        sa.Column("state_changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("state_changed_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("state_note", sa.Text(), server_default="", nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["run_id"], ["ai_watch_run.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["state_changed_by_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_ai_finding_fingerprint_active",
        "ai_finding",
        ["fingerprint"],
        unique=True,
        postgresql_where=sa.text("state IN ('open', 'acknowledged')"),
    )
    op.create_index("ix_ai_finding_state_last_seen", "ai_finding", ["state", "last_seen_at"])

    op.create_table(
        "ai_finding_feedback",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("verdict", sa.String(length=20), nullable=False),
        sa.Column("note", sa.Text(), server_default="", nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["finding_id"], ["ai_finding.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("finding_id", "user_id", name="uq_ai_finding_feedback_finding_user"),
    )

    op.create_table(
        "ai_finding_mute",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reason", sa.Text(), server_default="", nullable=False),
        sa.Column("title", sa.String(length=255), server_default="", nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        *_timestamps(),
        sa.ForeignKeyConstraint(["finding_id"], ["ai_finding.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("fingerprint", name="uq_ai_finding_mute_fingerprint"),
    )


def downgrade() -> None:
    op.drop_table("ai_finding_mute")
    op.drop_table("ai_finding_feedback")
    op.drop_index("ix_ai_finding_state_last_seen", table_name="ai_finding")
    op.drop_index("uq_ai_finding_fingerprint_active", table_name="ai_finding")
    op.drop_table("ai_finding")
    op.drop_index("ix_ai_watch_run_started_at", table_name="ai_watch_run")
    op.drop_table("ai_watch_run")
    op.drop_table("ai_watch_config")
    op.drop_column("ai_provider", "is_on_prem")
