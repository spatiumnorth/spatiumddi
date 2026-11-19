"""audit_forward_target log streams (#4545)

Adds the per-target opt-in for forwarding the DNS query log and the DHCP
activity log, the filters and sampling that go with it, and the drop counter
the ``log_forward_dropping`` alert reads. Both stream flags default to false,
so no existing target starts forwarding client queries on upgrade.

And one row: the ``log_forward_dropping`` alert rule (warning, enabled),
inserted only when no rule of that type or name exists. Seeded HERE, once,
rather than at app startup (the #2138 / #2044 pattern): a startup seed keyed on
"no such rule exists" re-creates the rule on every restart after an operator
deletes it, and two replicas booting together can both try to insert it. The
downgrade leaves it alone, since it may carry operator edits and its events.

Revision ID: e5a2c8d4f7b1
Revises: d8b3f6a1c274
Create Date: 2026-11-19 09:00:00.000000
"""

import uuid

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "e5a2c8d4f7b1"
down_revision = "d8b3f6a1c274"
branch_labels = None
depends_on = None


LOG_FORWARD_DROPPING_RULE_NAME = "Log stream forwarding dropping entries"

LOG_FORWARD_DROPPING_RULE_DESCRIPTION = (
    "Fires for each syslog forward target that dropped DNS query log or "
    "DHCP activity log entries in the last 15 minutes because its "
    "collector was slow or unreachable and the target's queue filled. "
    "Auto-resolves 15 minutes after the last drop."
)

# Module-level so the test suite, which builds its schema with ``create_all``
# rather than by migrating, runs the exact statement.
SEED_LOG_FORWARD_DROPPING_RULE_SQL = sa.text("""
    INSERT INTO alert_rule (
        id, name, description, rule_type, severity,
        enabled, notify_syslog, notify_webhook, notify_smtp
    )
    SELECT CAST(:id AS UUID), CAST(:name AS VARCHAR), CAST(:description AS TEXT),
           'log_forward_dropping', 'warning',
           true, true, true, false
    WHERE NOT EXISTS (
        SELECT 1 FROM alert_rule
        WHERE rule_type = 'log_forward_dropping'
           OR name = CAST(:name AS VARCHAR)
    )
    """)


def seed_params() -> dict[str, object]:
    return {
        "id": uuid.uuid4(),
        "name": LOG_FORWARD_DROPPING_RULE_NAME,
        "description": LOG_FORWARD_DROPPING_RULE_DESCRIPTION,
    }


def upgrade() -> None:
    op.add_column(
        "audit_forward_target",
        sa.Column(
            "stream_dns_query_log", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
    )
    op.add_column(
        "audit_forward_target",
        sa.Column(
            "stream_dhcp_activity_log",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "audit_forward_target",
        sa.Column("log_stream_filters", postgresql.JSONB(), nullable=True),
    )
    op.add_column(
        "audit_forward_target",
        sa.Column(
            "dns_query_sample_percent",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("100"),
        ),
    )
    op.add_column(
        "audit_forward_target",
        sa.Column(
            "log_stream_dropped_total",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )
    op.add_column(
        "audit_forward_target",
        sa.Column("log_stream_last_drop_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.get_bind().execute(SEED_LOG_FORWARD_DROPPING_RULE_SQL, seed_params())


def downgrade() -> None:
    op.drop_column("audit_forward_target", "log_stream_last_drop_at")
    op.drop_column("audit_forward_target", "log_stream_dropped_total")
    op.drop_column("audit_forward_target", "dns_query_sample_percent")
    op.drop_column("audit_forward_target", "log_stream_filters")
    op.drop_column("audit_forward_target", "stream_dhcp_activity_log")
    op.drop_column("audit_forward_target", "stream_dns_query_log")
