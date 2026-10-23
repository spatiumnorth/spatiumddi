"""dns_record_op: partial index on the ops waiting out a retry backoff (#2289)

``ix_dns_record_op_server_backoff`` on ``(server_id, next_attempt_at)``,
only over ``pending`` rows with ``next_attempt_at`` set. Every page of ops an
agent is shipped looks up the ops still backing off for the page's RRsets
(``agent_config._backed_off_candidates``). With no index on
``next_attempt_at`` that lookup read every queued op the server had, so its
cost grew with the whole backlog: at 1.41M pending ops one page cost the
planner ~2M and Postgres JIT-compiled it for minutes. Through this index it
reads only the ops actually waiting, which is none at all in the common case.

Partial, so it holds only those rows and costs nothing to keep for the rest
of the queue. Built non-concurrently, as ``d8e1b5a26c47``'s index was:
Alembic runs each revision in a transaction. The build still reads the whole
table, holding writes to it meanwhile, but that is one sequential scan: 83 ms
over 230k ops on a scratch Postgres 16, so a few seconds at the 1.4M of the
largest backlog measured.

Revision ID: f27379a82b17
Revises: e7b3d19a4c26
Create Date: 2026-10-21 04:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "f27379a82b17"
down_revision = "e7b3d19a4c26"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_dns_record_op_server_backoff",
        "dns_record_op",
        ["server_id", "next_attempt_at"],
        postgresql_where=sa.text("state = 'pending' AND next_attempt_at IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_dns_record_op_server_backoff", table_name="dns_record_op")
