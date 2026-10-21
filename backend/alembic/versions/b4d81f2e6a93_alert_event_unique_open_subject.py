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

The downgrade restores the non-unique index. The duplicates it resolved stay
resolved: they were never a real second condition.

Revision ID: b4d81f2e6a93
Revises: d3a7f19c52e8
Create Date: 2026-10-20 10:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "b4d81f2e6a93"
down_revision = "d3a7f19c52e8"
branch_labels = None
depends_on = None

_INDEX = "ix_alert_event_rule_subject_open"
_COLUMNS = ["rule_id", "subject_type", "subject_id"]
_OPEN = sa.text("resolved_at IS NULL")


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


def downgrade() -> None:
    op.drop_index(_INDEX, table_name="alert_event")
    op.create_index(_INDEX, "alert_event", _COLUMNS, postgresql_where=_OPEN)
