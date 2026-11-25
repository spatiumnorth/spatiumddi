"""Issue #3361 — edit / delete locks on IPAM, DNS and DHCP objects.

Adds the lock columns of ``app.models.base.LockMixin`` to every lockable table:
``ip_space``, ``ip_block``, ``subnet``, ``ip_address``, ``dns_server_group``,
``dns_view``, ``dns_zone``, ``dns_record``, ``dhcp_scope`` and
``dhcp_static_assignment``.

* ``lock_level`` — ``edit`` or ``delete``; NULL on every existing row, which is
  an unlocked row (nothing is backfilled).
* ``locked_by`` — username snapshot of whoever set the lock.
* ``locked_at`` / ``lock_expires_at`` — when it was set, and the optional lapse
  time (the hook for #63's change-window lock).
* ``lock_reason`` — required when a lock is set.

All five columns are nullable with no default, so the ALTERs are metadata-only.

Revision ID: a3361c0de1f7
Revises: d8b3f6a1c274
Create Date: 2026-11-14
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "a3361c0de1f7"
down_revision = "d8b3f6a1c274"
branch_labels = None
depends_on = None

_TABLES = (
    "ip_space",
    "ip_block",
    "subnet",
    "ip_address",
    "dns_server_group",
    "dns_view",
    "dns_zone",
    "dns_record",
    "dhcp_scope",
    "dhcp_static_assignment",
)


def upgrade() -> None:
    for table in _TABLES:
        op.add_column(table, sa.Column("lock_level", sa.String(length=16), nullable=True))
        op.add_column(table, sa.Column("locked_by", sa.String(length=255), nullable=True))
        op.add_column(table, sa.Column("locked_at", sa.DateTime(timezone=True), nullable=True))
        op.add_column(table, sa.Column("lock_reason", sa.Text(), nullable=True))
        op.add_column(table, sa.Column("lock_expires_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    for table in reversed(_TABLES):
        for col in ("lock_expires_at", "lock_reason", "locked_at", "locked_by", "lock_level"):
            op.drop_column(table, col)
