"""audit_chain_checkpoint: where the nightly chain verifier got to (#2286)

The verifier used to load the whole ``audit_log`` into memory on every run.
It now walks the chain in pages and records the last row it verified clean
here, so the next night reads only what was added since (plus a periodic
full pass). A single row, written by the verifier; a missing row just means
"walk everything".

Revision ID: e7b2d4c81f06
Revises: e4b8c27d91f3
Create Date: 2026-10-21 10:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "e7b2d4c81f06"
down_revision = "e4b8c27d91f3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_chain_checkpoint",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("verified_seq", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("verified_hash", sa.String(length=64), nullable=True),
        sa.Column("full_pass_done_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("audit_chain_checkpoint")
