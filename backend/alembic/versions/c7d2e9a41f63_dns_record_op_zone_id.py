"""DNS record ops carry the id of the zone they were queued for.

``dns_record_op`` identified its zone by name only. Zone names are unique per
(group, view), so where two views of one group serve the same name an op
could not be attributed to one of them, and the per-server pending-ops list,
narrowed to the zones an API token is bound to, matched the other view's ops
too. ``zone_id`` is set by every enqueue path from now on.

Nullable, and existing rows are left NULL rather than backfilled: a row
queued before this revision has no record of which view's zone it belonged
to, and guessing from the name is exactly the ambiguity being removed. The
pending-ops list falls back to the name for those rows only where the name
is unambiguous. ``ON DELETE SET NULL`` keeps the op history when a zone row
is purged.

Revision ID: c7d2e9a41f63
Revises: d7a2e94b1c60
Create Date: 2026-10-17
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision: str = "c7d2e9a41f63"
down_revision: str | None = "d7a2e94b1c60"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "dns_record_op",
        sa.Column("zone_id", UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_dns_record_op_zone_id",
        "dns_record_op",
        "dns_zone",
        ["zone_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_dns_record_op_zone_id", "dns_record_op", ["zone_id"])


def downgrade() -> None:
    op.drop_index("ix_dns_record_op_zone_id", table_name="dns_record_op")
    op.drop_constraint("fk_dns_record_op_zone_id", "dns_record_op", type_="foreignkey")
    op.drop_column("dns_record_op", "zone_id")
