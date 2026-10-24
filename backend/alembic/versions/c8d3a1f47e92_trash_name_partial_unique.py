"""customer / overlay_network / network_service name keys: partial, live rows only (#2738)

All three tables are soft-deletable and none was in the Trash, and their name
keys were FULL unique constraints, so a deleted row held its name for good: the
operator could neither see, restore nor purge it, and re-creating the name
answered 409. They are Trash types now, and (as for ``ip_space`` in #491) the
name key covers only live rows (``WHERE deleted_at IS NULL``), so a deleted name
is free to reuse; a restore that would collide with a live row is refused
instead.

No dedup is needed before creating the new indexes: live rows were already
unique under the full constraints, and a partial index over a subset of rows
cannot be violated by rows that satisfied the full one.

Rows of these three types that are already soft-deleted when this runs get a
fresh clock (``deleted_at = now()``): they were never visible in the Trash, so
nobody has had the retention period to restore them, and the first nightly sweep
must not purge them. Each gets a full retention period from the upgrade.

Downgrade restores the full constraints and fails if a deleted row now shares a
name with a live one (a name reused after this migration); purge or rename the
deleted row first. The original delete times are not restored.

Revision ID: c8d3a1f47e92
Revises: a3c7e91f2d58
Create Date: 2026-10-24 12:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "c8d3a1f47e92"
down_revision = "a3c7e91f2d58"
branch_labels = None
depends_on = None

# (table, constraint/index name, columns)
_KEYS = (
    ("customer", "uq_customer_name", ["name"]),
    ("overlay_network", "uq_overlay_network_name", ["name"]),
    ("network_service", "uq_network_service_customer_name", ["customer_id", "name"]),
)


def restart_retention_clock(bind: sa.engine.Connection) -> None:
    """Give every already-soft-deleted row of the three tables a fresh delete time."""
    for table, _name, _cols in _KEYS:
        bind.execute(sa.text(f"UPDATE {table} SET deleted_at = now() WHERE deleted_at IS NOT NULL"))


def upgrade() -> None:
    restart_retention_clock(op.get_bind())
    for table, name, cols in _KEYS:
        op.drop_constraint(name, table, type_="unique")
        op.create_index(
            name,
            table,
            cols,
            unique=True,
            postgresql_where=sa.text("deleted_at IS NULL"),
        )


def downgrade() -> None:
    for table, name, cols in reversed(_KEYS):
        op.drop_index(name, table_name=table)
        op.create_unique_constraint(name, table, cols)
