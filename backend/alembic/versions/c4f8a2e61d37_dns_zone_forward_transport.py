"""dns_zone.forward_transport + forward_tls_hostname: a forward zone's own upstream transport (#2121)

A conditional forward zone used to inherit the server group's
``forward_transport`` (#50), so a group forwarding over DNS-over-TLS sent
every forward zone's queries over TLS too, validated against the GROUP's
certificate name. A forward zone usually points at something internal that
speaks plain DNS only (Tailscale MagicDNS, an AD domain controller, a VPC
resolver), so those zones SERVFAILed with no per-zone way out.

The transport is now the zone's own setting, defaulting to plain DNS.

Backfill: every existing zone gets ``do53``, including forward zones in
groups that forward over TLS today. That is deliberate — it is the fix for
the zones the inheritance broke. A zone that really did want DoT has to be
switched back per zone; the CHANGELOG says so.

Revision ID: c4f8a2e61d37
Revises: b3d7f1a82c54
Create Date: 2026-10-18 18:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "c4f8a2e61d37"
down_revision = "b3d7f1a82c54"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The server_default IS the backfill: every existing row reads ``do53``.
    op.add_column(
        "dns_zone",
        sa.Column(
            "forward_transport",
            sa.String(length=10),
            nullable=False,
            server_default=sa.text("'do53'"),
        ),
    )
    op.add_column(
        "dns_zone",
        sa.Column("forward_tls_hostname", sa.String(length=255), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("dns_zone", "forward_tls_hostname")
    op.drop_column("dns_zone", "forward_transport")
