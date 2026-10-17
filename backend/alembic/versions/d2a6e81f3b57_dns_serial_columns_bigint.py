"""#1975 — SOA serials are unsigned 32-bit; the columns holding them were int32.

An SOA serial runs 0..4294967295 (RFC 1035 §3.3.13), but
``dns_zone.last_serial``, ``dns_server_zone_state.current_serial`` and
``dns_record_op.target_serial`` were ``INTEGER`` (max 2147483647), so a zone
served under a serial of 2^31 or more failed to store with "integer out of
range" and the agent's zone-state report 500'd. Widen all three to BIGINT.
Widening is lossless; the downgrade narrows back and fails if a stored serial
no longer fits, which is the honest answer.

Revision ID: d2a6e81f3b57
Revises: c4f19a2e7d53
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "d2a6e81f3b57"
down_revision = "c4f19a2e7d53"
branch_labels = None
depends_on = None

_COLUMNS = (
    ("dns_zone", "last_serial"),
    ("dns_server_zone_state", "current_serial"),
    ("dns_record_op", "target_serial"),
)


def upgrade() -> None:
    for table, col in _COLUMNS:
        op.alter_column(table, col, type_=sa.BigInteger(), existing_type=sa.Integer())


def downgrade() -> None:
    for table, col in _COLUMNS:
        op.alter_column(table, col, type_=sa.Integer(), existing_type=sa.BigInteger())
