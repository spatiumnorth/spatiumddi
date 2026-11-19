"""DNS views: per-view dnssec-validation / allow-recursion / rate-limit / minimal-responses (#3569)

Adds nullable ``dns_view`` columns; NULL inherits the group's setting, which is
what every existing row does, so every rendered config is unchanged.

Revision ID: d7b2e5a91c46
Revises: c4d8a1f6b329
Create Date: 2026-11-13
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "d7b2e5a91c46"
down_revision = "c4d8a1f6b329"
branch_labels = None
depends_on = None

_INT_COLS = ("rrl_responses_per_second", "rrl_window", "rrl_slip")
_BOOL_COLS = ("rrl_enabled", "minimal_responses")


def upgrade() -> None:
    op.add_column("dns_view", sa.Column("dnssec_validation", sa.String(length=10), nullable=True))
    op.add_column(
        "dns_view",
        sa.Column("allow_recursion", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    for col in _BOOL_COLS:
        op.add_column("dns_view", sa.Column(col, sa.Boolean(), nullable=True))
    for col in _INT_COLS:
        op.add_column("dns_view", sa.Column(col, sa.Integer(), nullable=True))


def downgrade() -> None:
    for col in (*_INT_COLS, *reversed(_BOOL_COLS)):
        op.drop_column("dns_view", col)
    op.drop_column("dns_view", "allow_recursion")
    op.drop_column("dns_view", "dnssec_validation")
