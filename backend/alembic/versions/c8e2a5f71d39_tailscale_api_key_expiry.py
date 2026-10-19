"""tailscale_tenant: record when the API access token expires (#2138)

Tailscale caps an API access token at 90 days, and an expired token turns
every sync into an HTTP 401 that nothing alerted on. Two nullable columns:

* ``api_key_expires_at`` — when the stored token stops working. NULL means
  UNKNOWN; there is no backfill, because no existing row has ever reported
  an expiry and a guessed "created + 90 days" would assert one it never had.
  The first test-connection, save or daily refresh fills it in.
* ``api_key_expiry_source`` — ``api`` (read from Tailscale's keys endpoint)
  or ``operator`` (typed into the tenant form), checked by a constraint.

Revision ID: c8e2a5f71d39
Revises: b3d7f1a82c54
Create Date: 2026-10-18 14:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "c8e2a5f71d39"
down_revision = "b3d7f1a82c54"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tailscale_tenant",
        sa.Column("api_key_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "tailscale_tenant",
        sa.Column("api_key_expiry_source", sa.String(length=16), nullable=True),
    )
    op.create_check_constraint(
        "ck_tailscale_tenant_api_key_expiry_source",
        "tailscale_tenant",
        "api_key_expiry_source IS NULL OR api_key_expiry_source IN ('api', 'operator')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_tailscale_tenant_api_key_expiry_source", "tailscale_tenant", type_="check"
    )
    op.drop_column("tailscale_tenant", "api_key_expiry_source")
    op.drop_column("tailscale_tenant", "api_key_expires_at")
