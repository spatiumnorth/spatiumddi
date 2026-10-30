"""dhcp_server: which agent process owns the server identity (#3143)

The DHCP side of #2044 / #2219. Two DHCP agent processes live on ONE server
identity (a cloned Kea VM keeping its ``agent_id``, two containers given one
state dir) authenticate against the server's one ``agent_token_hash``, so each
registration or rotation staled the other's token and the pair traded 401s and
re-registrations forever. The control plane now keeps one owner per server,
with the same columns ``dns_server`` gained in ``f4c2a8e61b93``:

- ``agent_instance`` / ``agent_instance_seen_at``: the instance id the owning
  agent sends on its config polls, and when it last polled.
- ``agent_instances_displaced``: the instance ids the owner replaced, newest
  last, capped. An id in this list that polls or registers again while the
  owner is live is a second live agent, not a replacement, and is refused
  with 409.
- ``duplicate_agent_first_at`` / ``duplicate_agent_last_at`` /
  ``duplicate_agent_ip``: the current duplicate episode, for the server row
  chip and the ``dhcp_agent_duplicate_instance`` alert.

All nullable, no backfill: NULL is "no agent with an instance id has polled
yet", and the first one to poll becomes the owner.

And one row: the ``dhcp_agent_duplicate_instance`` alert rule ("Two DHCP agents
on one server", warning, enabled), inserted only when no rule of that type or
name exists. Seeded HERE, once, rather than at app startup (the #2138
pattern), so an operator who deletes it keeps it deleted. The downgrade leaves
it alone, since by then it may carry operator edits and its events.

Revision ID: 833ee80c8c6b
Revises: c4f81e2a9d37
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "833ee80c8c6b"
down_revision: str | None = "c4f81e2a9d37"
branch_labels: str | None = None
depends_on: str | None = None


DUPLICATE_INSTANCE_RULE_NAME = "Two DHCP agents on one server"

DUPLICATE_INSTANCE_RULE_DESCRIPTION = (
    "Fires when two live DHCP agent processes share one server identity — "
    "usually a cloned VM or a copied agent state directory that kept the same "
    "agent_id. Only the most recent agent is served; the other is refused and "
    "keeps serving a configuration that no longer changes. Auto-resolves ten "
    "minutes after the extra agent stops polling."
)

# Inserted only when no rule of this type (and none of this name) exists.
# Module-level so the test suite, which builds its schema with ``create_all``
# rather than by migrating, runs the exact statement.
SEED_DUPLICATE_INSTANCE_RULE_SQL = sa.text("""
    INSERT INTO alert_rule (
        id, name, description, rule_type, severity,
        enabled, notify_syslog, notify_webhook, notify_smtp
    )
    SELECT CAST(:id AS UUID), CAST(:name AS VARCHAR), CAST(:description AS TEXT),
           'dhcp_agent_duplicate_instance', 'warning',
           true, true, true, false
    WHERE NOT EXISTS (
        SELECT 1 FROM alert_rule
        WHERE rule_type = 'dhcp_agent_duplicate_instance'
           OR name = CAST(:name AS VARCHAR)
    )
    """)


def seed_params() -> dict[str, object]:
    return {
        "id": uuid.uuid4(),
        "name": DUPLICATE_INSTANCE_RULE_NAME,
        "description": DUPLICATE_INSTANCE_RULE_DESCRIPTION,
    }


def upgrade() -> None:
    op.add_column("dhcp_server", sa.Column("agent_instance", sa.String(length=64), nullable=True))
    op.add_column(
        "dhcp_server",
        sa.Column("agent_instance_seen_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "dhcp_server",
        sa.Column("agent_instances_displaced", postgresql.JSONB(), nullable=True),
    )
    op.add_column(
        "dhcp_server",
        sa.Column("duplicate_agent_first_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "dhcp_server",
        sa.Column("duplicate_agent_last_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "dhcp_server", sa.Column("duplicate_agent_ip", sa.String(length=45), nullable=True)
    )
    op.get_bind().execute(SEED_DUPLICATE_INSTANCE_RULE_SQL, seed_params())


def downgrade() -> None:
    op.drop_column("dhcp_server", "duplicate_agent_ip")
    op.drop_column("dhcp_server", "duplicate_agent_last_at")
    op.drop_column("dhcp_server", "duplicate_agent_first_at")
    op.drop_column("dhcp_server", "agent_instances_displaced")
    op.drop_column("dhcp_server", "agent_instance_seen_at")
    op.drop_column("dhcp_server", "agent_instance")
