"""dns_zone (group, view, name) uniqueness: live rows only (#3824)

``dns_zone`` is soft-deletable, but ``uq_dns_zone_group_view_name`` was a full
unique constraint. PostgreSQL treats NULLs as distinct, so a trashed zone with
no view never held its name; a trashed zone in a view did, and creating, moving,
re-pinning or renaming a zone onto that name answered a 409 naming only the
columns. As for ``ip_space`` (#491) and the #2738 tables, the key now covers
live rows only (``WHERE deleted_at IS NULL``); a Trash restore that would
collide with a live zone is refused by the restore check instead.

No dedup is needed: a partial index over a subset of rows cannot be violated by
rows that satisfied the full constraint.

Downgrade restores the full constraint and fails if a trashed zone now shares
its name and view with a live one; purge or rename the trashed zone first.

Revision ID: d5a1c8e37b24
Revises: a4040c7e91d3
Create Date: 2026-11-12 09:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "d5a1c8e37b24"
down_revision = "a4040c7e91d3"
branch_labels = None
depends_on = None

_NAME = "uq_dns_zone_group_view_name"


def upgrade() -> None:
    op.drop_constraint(_NAME, "dns_zone", type_="unique")
    op.create_index(
        _NAME,
        "dns_zone",
        ["group_id", "view_id", "name"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )


def downgrade() -> None:
    clash = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT count(*) FROM (SELECT 1 FROM dns_zone WHERE view_id IS NOT NULL "
                "GROUP BY group_id, view_id, name HAVING count(*) > 1) t"
            )
        )
        .scalar()
    )
    if clash:
        raise RuntimeError(
            f"{clash} DNS zone name(s) exist both live and in the Trash within one view; "
            "restoring the full unique constraint would fail. Purge or rename the trashed "
            "zones (Admin -> Trash) and run the downgrade again."
        )
    op.drop_index(_NAME, table_name="dns_zone")
    op.create_unique_constraint(_NAME, "dns_zone", ["group_id", "view_id", "name"])
