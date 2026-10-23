"""alert_event: one OPEN event per (rule, subject) (#2261)

``ix_alert_event_rule_subject_open`` was a plain partial index, so two
evaluator passes running at once could both open an event for the same new
match. The evaluator indexes open events by subject in a dict, so only one of
the pair was ever resolved and the other stayed open for good.

The upgrade first resolves the duplicates already on disk — for each
``(rule_id, subject_type, subject_id)`` with more than one open row it keeps
the earliest-fired one (the original firing; ties broken by id) and stamps
``resolved_at = now()`` on the rest — then rebuilds the index as UNIQUE.
Resolving rather than deleting keeps the extra rows in the event history.

It also adds ``alert_event.delivery_pending_since`` (nullable, plus a partial
index on the non-NULL rows). An evaluator pass stamps it when it queues a
delivery to run after its commit, and the sender clears it when it claims the
event; a stamp that outlives the pass means the worker died between the commit
and the send, and the next pass re-sends it. Every existing row is NULL, which
the re-send sweep ignores, so the upgrade pages for nothing already stored.

The downgrade restores the non-unique index and drops the column. The
duplicates it resolved stay resolved: they were never a real second condition.

Revision ID: b4d81f2e6a93
Revises: e4b8c2d17a95
Create Date: 2026-10-20 10:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "b4d81f2e6a93"
down_revision = "e4b8c2d17a95"
branch_labels = None
depends_on = None

_INDEX = "ix_alert_event_rule_subject_open"
_COLUMNS = ["rule_id", "subject_type", "subject_id"]
_OPEN = sa.text("resolved_at IS NULL")
_PENDING_INDEX = "ix_alert_event_delivery_pending"
_PENDING = sa.text("delivery_pending_since IS NOT NULL")


def upgrade() -> None:
    op.execute("""
        UPDATE alert_event AS e
           SET resolved_at = now()
          FROM (
                SELECT id,
                       row_number() OVER (
                           PARTITION BY rule_id, subject_type, subject_id
                           ORDER BY fired_at, id
                       ) AS rn
                  FROM alert_event
                 WHERE resolved_at IS NULL
               ) AS ranked
         WHERE e.id = ranked.id
           AND ranked.rn > 1
        """)
    op.drop_index(_INDEX, table_name="alert_event")
    op.create_index(_INDEX, "alert_event", _COLUMNS, unique=True, postgresql_where=_OPEN)
    op.add_column(
        "alert_event",
        sa.Column("delivery_pending_since", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        _PENDING_INDEX, "alert_event", ["delivery_pending_since"], postgresql_where=_PENDING
    )


def downgrade() -> None:
    op.drop_index(_PENDING_INDEX, table_name="alert_event")
    op.drop_column("alert_event", "delivery_pending_since")
    op.drop_index(_INDEX, table_name="alert_event")
    op.create_index(_INDEX, "alert_event", _COLUMNS, postgresql_where=_OPEN)
