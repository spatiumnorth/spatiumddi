"""alert_event.subject_id holds a conformity subject (#2277).

The conformity engine keys its alert events as
``<policy uuid>:<target kind>:<target uuid>`` — 80 to 89 characters for
every target kind except ``platform``. The column was VARCHAR(64), so the
INSERT failed (StringDataRightTruncation) and no conformity alert against a
subnet, IP address, DNS zone, DHCP scope or multicast group has ever opened:
the failure aborted the whole policy pass, so its results and
``last_evaluated_at`` were lost with it.

Widened to 128.

* Widening a varchar is a catalogue-only change in PostgreSQL: no table
  rewrite, and the partial index ``ix_alert_event_rule_subject_open`` is not
  rebuilt.
* Safe for the previous release during a rolling upgrade, which only writes
  values that fit the old width.

Downgrade narrows it back. Rows longer than 64 characters can only have been
written by this release's conformity engine and cannot be represented in the
old column, so they are deleted first; they are alert history, not audit
records.

Revision ID: e2b9c46f1a83
Revises: f6a2d81c3e57
Create Date: 2026-10-21
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "e2b9c46f1a83"
down_revision = "f6a2d81c3e57"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "alert_event",
        "subject_id",
        existing_type=sa.String(length=64),
        type_=sa.String(length=128),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.execute("DELETE FROM alert_event WHERE length(subject_id) > 64")
    op.alter_column(
        "alert_event",
        "subject_id",
        existing_type=sa.String(length=128),
        type_=sa.String(length=64),
        existing_nullable=False,
    )
