"""tailscale_tenant: record when the API access token expires (#2138)

Tailscale caps an API access token at 90 days, and an expired token turns
every sync into an HTTP 401 that nothing alerted on. Two nullable columns:

* ``api_key_expires_at`` — when the stored token stops working. NULL means
  UNKNOWN; there is no backfill, because no existing row has ever reported
  an expiry and a guessed "created + 90 days" would assert one it never had.
  The first test-connection, save or daily refresh fills it in.
* ``api_key_expiry_source`` — ``api`` (read from Tailscale's keys endpoint)
  or ``operator`` (typed into the tenant form), checked by a constraint.

And one row: a ``secret_expiring`` alert rule ("Credential expiring or
rejected", warning, 30 days, enabled), inserted only when no rule of that
type or name exists. It is seeded HERE, once, rather than at app startup:
a startup seed keyed on "no such rule exists" re-creates the rule on every
restart after an operator deliberately deletes it. A migration runs once per
database, so deleting the rule is final. The downgrade leaves it alone,
since by then it may carry operator edits and its events.

Revision ID: c8e2a5f71d39
Revises: c4a8e1f26d93
Create Date: 2026-10-18 14:00:00.000000
"""

import uuid

import sqlalchemy as sa

from alembic import op

revision = "c8e2a5f71d39"
down_revision = "c4a8e1f26d93"
branch_labels = None
depends_on = None


SECRET_EXPIRING_RULE_NAME = "Credential expiring or rejected"

SECRET_EXPIRING_RULE_DESCRIPTION = (
    "Fires for each credential SpatiumDDI depends on that expires within the "
    "threshold: supervisor mTLS certificates, API tokens, the Let's Encrypt "
    "Web UI certificate and Tailscale API access tokens. A Tailscale tenant "
    "whose sync was refused with HTTP 401 fires critical at once, since its "
    "token is already dead. Severity escalates as expiry nears; resolves when "
    "the credential is replaced."
)

# Inserted only when no ``secret_expiring`` rule (and no rule of this name)
# exists, so an operator who already made their own never gets each expiry
# twice. Module-level so the test suite, which builds its schema with
# ``create_all`` rather than by migrating, runs the exact statement.
SEED_SECRET_EXPIRING_RULE_SQL = sa.text("""
    INSERT INTO alert_rule (
        id, name, description, rule_type, severity, threshold_days,
        enabled, notify_syslog, notify_webhook, notify_smtp
    )
    SELECT CAST(:id AS UUID), CAST(:name AS VARCHAR), CAST(:description AS TEXT),
           'secret_expiring', 'warning', 30,
           true, true, true, false
    WHERE NOT EXISTS (
        SELECT 1 FROM alert_rule
        WHERE rule_type = 'secret_expiring' OR name = CAST(:name AS VARCHAR)
    )
    """)


def seed_params() -> dict[str, object]:
    return {
        "id": uuid.uuid4(),
        "name": SECRET_EXPIRING_RULE_NAME,
        "description": SECRET_EXPIRING_RULE_DESCRIPTION,
    }


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
    op.get_bind().execute(SEED_SECRET_EXPIRING_RULE_SQL, seed_params())


def downgrade() -> None:
    op.drop_constraint(
        "ck_tailscale_tenant_api_key_expiry_source", "tailscale_tenant", type_="check"
    )
    op.drop_column("tailscale_tenant", "api_key_expiry_source")
    op.drop_column("tailscale_tenant", "api_key_expires_at")
