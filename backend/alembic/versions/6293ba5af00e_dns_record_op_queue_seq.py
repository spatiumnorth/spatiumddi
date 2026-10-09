"""#1489 — DNS record ops ship in the order they were queued.

Adds ``dns_record_op.seq``, filled from a new sequence
``dns_record_op_seq_seq`` on every insert. Ops shipped to an agent were
ordered by ``(created_at, id)``. ``created_at`` is the transaction START,
so every op one transaction queues ties on it, and ``id`` is a random UUID:
a delete and a create of the same record, queued together, reached each
server in a random order, and where the delete landed last the record was
gone on that server while every op read ``applied``. Ops now ship, and
supersede each other, in ``(created_at, seq)`` order.

The column is nullable and has no backfill. ``dns_record_op`` is never
pruned and can hold hundreds of thousands of rows, so a NOT NULL or
identity column would rewrite the table under an exclusive lock during the
upgrade. Rows queued before this migration keep NULL and the old ``id``
tie-break, which is what they had; every row queued after it has a value.

Downgrade drops the column and the sequence. The older code never reads
either.

Revision ID: 6293ba5af00e
Revises: 199eb1562927
Create Date: 2026-10-03
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "6293ba5af00e"
down_revision = "199eb1562927"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(sa.schema.CreateSequence(sa.Sequence("dns_record_op_seq_seq")))
    # Added without a default, then given one: a column added WITH a volatile
    # default (nextval) is filled for every existing row, which rewrites the
    # table. Setting the default afterwards applies it to new rows only.
    op.add_column("dns_record_op", sa.Column("seq", sa.BigInteger(), nullable=True))
    op.alter_column(
        "dns_record_op",
        "seq",
        server_default=sa.text("nextval('dns_record_op_seq_seq'::regclass)"),
    )
    op.execute("ALTER SEQUENCE dns_record_op_seq_seq OWNED BY dns_record_op.seq")


def downgrade() -> None:
    # Dropping the column drops the sequence it owns.
    op.drop_column("dns_record_op", "seq")
    op.execute("DROP SEQUENCE IF EXISTS dns_record_op_seq_seq")
