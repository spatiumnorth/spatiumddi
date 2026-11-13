"""Index dns_record (zone_id, lower(name)) for the DDNS name-holder check (#3807).

``_name_holder`` matches ``lower(name) = :hostname`` inside the zone, which
``ix_dns_record_zone_name`` on ``(zone_id, name)`` cannot serve, so every
unchanged DDNS renewal read the whole forward zone to check one name.

Revision ID: f3a8d2c61b94
Revises: d5a1c8e37b24
"""

from __future__ import annotations

from alembic import op

revision: str = "f3a8d2c61b94"
down_revision: str | None = "d5a1c8e37b24"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_dns_record_zone_lower_name "
        "ON dns_record (zone_id, lower(name))"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_dns_record_zone_lower_name")
