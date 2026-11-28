"""Optional built-in icons on IP addresses and DNS records (#5022).

Revision ID: d7b3a95c1e48
Revises: c4d8e1a7b9f2
Create Date: 2026-11-27 12:00:00

* ``ip_address.icon`` and ``dns_record.icon``: nullable, the operator's
  explicit ``mdi:<name>`` choice. NULL means "automatic" (a device-class,
  IP-role or linked-address default resolved at read time), so no backfill.
* ``icon_default``: operator overrides of the shipped default-icon mapping.
  Empty on every install until an operator changes an entry; the shipped
  mapping itself lives in code and is never seeded here.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "d7b3a95c1e48"
down_revision: str | None = "c4d8e1a7b9f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ip_address", sa.Column("icon", sa.String(length=80), nullable=True))
    op.add_column("dns_record", sa.Column("icon", sa.String(length=80), nullable=True))
    op.create_table(
        "icon_default",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("match_value", sa.String(length=100), nullable=False),
        sa.Column("icon", sa.String(length=80), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column(
            "modified_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.UniqueConstraint("kind", "match_value", name="uq_icon_default_kind_match"),
    )


def downgrade() -> None:
    op.drop_table("icon_default")
    op.drop_column("dns_record", "icon")
    op.drop_column("ip_address", "icon")
