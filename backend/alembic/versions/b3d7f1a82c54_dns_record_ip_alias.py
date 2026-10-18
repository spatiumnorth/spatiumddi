"""dns_record.ip_alias: mark an IP address's user-added aliases (#2084)

An address's A/AAAA aliases and its own host records are both
``auto_generated`` with ``ip_address_id`` set, so IPAM's DNS sync loaded the
aliases as the host record and the alias lists listed a host record
published into an extra zone as an alias. ``ip_alias`` states which is which.

Backfill: among auto-generated CNAME / A / AAAA rows tied to an address, a
row is the HOST record when it is an A / AAAA named like the address's
hostname (case-insensitive) in its forward zone or one of its extra zones,
or is the row ``ip_address.dns_record_id`` points at. Everything else is an
alias. PTR rows are never aliases.

Revision ID: b3d7f1a82c54
Revises: a2078c5e1d90
Create Date: 2026-10-18 12:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "b3d7f1a82c54"
down_revision = "a2078c5e1d90"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "dns_record",
        sa.Column("ip_alias", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.execute("""
        UPDATE dns_record r SET ip_alias = true
        FROM ip_address ip
        WHERE r.ip_address_id = ip.id
          AND r.auto_generated
          AND r.record_type IN ('CNAME', 'A', 'AAAA')
          AND ip.dns_record_id IS DISTINCT FROM r.id
          AND NOT (
            r.record_type IN ('A', 'AAAA')
            AND ip.hostname IS NOT NULL
            AND lower(r.name) = lower(ip.hostname)
            AND (
              r.zone_id = ip.forward_zone_id
              OR (
                jsonb_typeof(ip.extra_zone_ids::jsonb) = 'array'
                AND ip.extra_zone_ids::jsonb @> to_jsonb(r.zone_id::text)
              )
            )
          )
        """)


def downgrade() -> None:
    op.drop_column("dns_record", "ip_alias")
