"""The ops a stored DNS agent bundle covers: those committed before its render read (#1111).

Two nullable columns, no backfill, no table rewrite.

``dns_record_op.xact_id``: the id of the transaction that queued the op
(``pg_current_xact_id()``, as bigint). ``dns_agent_bundle.visible_xacts``:
the snapshot the render read under (``pg_current_snapshot()``, as text).

The ops page a stored bundle ships, and the ops a split-horizon render
retires, were gated by ``created_at <= snapshot_at``. ``created_at`` is
``now()``, the op's transaction START, so a bulk write that started before
a render and committed after the render's records query passed the gate
with records the body never read. While only a current bundle was served
that could not reach an agent (the write's own dirty mark made the body
stale), but a render that retired such ops marked them applied unseen, and
the inline fallback served its own render without re-checking. An op is now
covered when its transaction is visible in the render's snapshot, i.e. it
committed before the render read anything.

Ops queued and bundles rendered before this migration carry NULL and keep
the time gate. The default is set after the column is added so the existing
rows of ``dns_record_op`` (1.67 M on a 1 M-record group) are not rewritten.
``pg_current_xact_id`` / ``pg_current_snapshot`` / ``pg_visible_in_snapshot``
are PostgreSQL 13+; the product requires 15+.

Linear after ``d9a4c27e18f3``: a server on that revision takes this one as
a plain upgrade.

Revision ID: f3a9d61c07e4
Revises: d9a4c27e18f3
Create Date: 2026-09-24
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "f3a9d61c07e4"
down_revision = "d9a4c27e18f3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("dns_record_op", sa.Column("xact_id", sa.BigInteger(), nullable=True))
    op.alter_column(
        "dns_record_op",
        "xact_id",
        server_default=sa.text("(pg_current_xact_id()::text)::bigint"),
    )
    op.add_column("dns_agent_bundle", sa.Column("visible_xacts", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("dns_agent_bundle", "visible_xacts")
    op.drop_column("dns_record_op", "xact_id")
