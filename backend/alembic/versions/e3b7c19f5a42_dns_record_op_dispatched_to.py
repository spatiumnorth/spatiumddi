"""dns_record_op.dispatched_to + dispatched_poll_at (#2042)

The agent process a queued DNS op was last shipped to. A DNS agent sends a
per-process instance id on every config poll; the long-poll stamps it on each
op it marks ``in_flight``. When a replacement agent polls, any op still
``in_flight`` to a different instance was paged into a long-poll the API held
for the agent that went away, so it is returned to ``pending`` and shipped on
that poll, instead of waiting out the 5-minute unacknowledged reset.

``dispatched_poll_at`` is when the long-poll that shipped the op started. Two
polls can be held for one server at once (the departed agent's and its
replacement's); only a poll that started AFTER the one that shipped an op may
take it back, so the departed agent's poll never takes an op from the new one.

Nullable, no backfill: NULL means the op was shipped by a control plane, or to
an agent, that did not record an instance, and is never read as "another
instance".

Revision ID: e3b7c19f5a42
Revises: c8e1f5a92d47
Create Date: 2026-10-17

"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "e3b7c19f5a42"
down_revision = "c8e1f5a92d47"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "dns_record_op",
        sa.Column("dispatched_to", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "dns_record_op",
        sa.Column("dispatched_poll_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("dns_record_op", "dispatched_poll_at")
    op.drop_column("dns_record_op", "dispatched_to")
