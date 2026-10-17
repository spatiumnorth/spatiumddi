"""dns_record_op.dispatched_to (#2042)

The agent process a queued DNS op was last shipped to. A DNS agent sends a
per-process instance id on every config poll; the long-poll stamps it on each
op it marks ``in_flight``. When a replacement agent polls, any op still
``in_flight`` to a different instance was paged into a long-poll the API held
for the agent that went away, so it is returned to ``pending`` and shipped on
that poll, instead of waiting out the 5-minute unacknowledged reset.

Nullable, no backfill: NULL means the op was shipped by a control plane, or to
an agent, that did not record an instance, and is never read as "another
instance".

Revision ID: e3b7c19f5a42
Revises: d7a2e94b1c60
Create Date: 2026-10-17

"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "e3b7c19f5a42"
down_revision = "d7a2e94b1c60"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "dns_record_op",
        sa.Column("dispatched_to", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("dns_record_op", "dispatched_to")
