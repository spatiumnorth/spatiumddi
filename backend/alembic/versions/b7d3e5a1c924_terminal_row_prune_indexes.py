"""Partial indexes for the terminal-row prune (#1254).

``prune_log_entries`` now ages out delivered / dead ``event_outbox`` rows,
applied / superseded / failed ``dns_record_op`` rows and acked / failed
``dhcp_config_op`` rows. Each of those tables is dominated by live rows or
by terminal ones depending on load, and none had an index on the age column,
so every chunk of the prune would sequential-scan. These are partial indexes
over the terminal states only, so they stay small and add no write cost to
the pending / in-flight rows the hot paths touch.

Revision ID: b7d3e5a1c924
Revises: ede3bcd2aff4
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "b7d3e5a1c924"
down_revision: str | None = "ede3bcd2aff4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_event_outbox_terminal_modified",
        "event_outbox",
        ["modified_at"],
        postgresql_where=sa.text("state IN ('delivered', 'dead')"),
    )
    op.create_index(
        "ix_dns_record_op_terminal_updated",
        "dns_record_op",
        ["updated_at"],
        postgresql_where=sa.text("state IN ('applied', 'superseded', 'failed')"),
    )
    op.create_index(
        "ix_dhcp_config_op_terminal_created",
        "dhcp_config_op",
        ["created_at"],
        postgresql_where=sa.text("status IN ('acked', 'failed')"),
    )


def downgrade() -> None:
    op.drop_index("ix_dhcp_config_op_terminal_created", table_name="dhcp_config_op")
    op.drop_index("ix_dns_record_op_terminal_updated", table_name="dns_record_op")
    op.drop_index("ix_event_outbox_terminal_modified", table_name="event_outbox")
