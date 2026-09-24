"""Daemon state reported by DNS / DHCP agents on their heartbeat (#1067).

The agents have carried a ``daemon`` object on every heartbeat since the
protocol was written — ``{"status": "degraded", "reason": "start deferred,
no bundle yet"}`` while a DNS agent waits for its first bundle (#1061),
``{"status": "ok"}`` once the daemon is up — and both heartbeat handlers
declared the field and read nothing from it. A registered, heartbeating
server whose daemon never started therefore read exactly like a healthy
one: ``status`` active, ``last_seen_at`` fresh, ``config_apply_status`` ok.
This migration is the storage that makes the field mean something, the
same three-column shape on both agent-managed server tables.

Revision ID: b7d21c9e4f06
Revises: c5e8a1f3d027
Create Date: 2026-09-21
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "b7d21c9e4f06"
down_revision = "c5e8a1f3d027"
branch_labels = None
depends_on = None


# NULLable throughout: NULL means "this agent has never reported a daemon
# state" — a pre-#1061 agent still in the field, or an agentless driver
# (Windows DNS, the cloud providers, ``technitium_api``) that has no daemon
# of its own to report on. The read side treats NULL as UNKNOWN, never as
# ``ok``. ``daemon_status_since`` is the stamp of the heartbeat that FIRST
# reported the current status (it moves only on a status change), so a row
# can say how long a daemon has been degraded.
_TABLES = ("dns_server", "dhcp_server")


def upgrade() -> None:
    for table in _TABLES:
        op.add_column(table, sa.Column("daemon_status", sa.String(20), nullable=True))
        op.add_column(table, sa.Column("daemon_reason", sa.Text(), nullable=True))
        op.add_column(
            table,
            sa.Column("daemon_status_since", sa.DateTime(timezone=True), nullable=True),
        )
        # Partial index over the unhealthy states only — the alert sweep and
        # the server-list chip both ask "which daemons are NOT serving", and
        # on a healthy fleet that matches ~nothing (the #882 index's reasoning).
        op.create_index(
            f"ix_{table}_daemon_unhealthy",
            table,
            ["daemon_status"],
            unique=False,
            postgresql_where=sa.text("daemon_status IS NOT NULL AND daemon_status <> 'ok'"),
        )


def downgrade() -> None:
    for table in _TABLES:
        op.drop_index(f"ix_{table}_daemon_unhealthy", table_name=table)
        op.drop_column(table, "daemon_status_since")
        op.drop_column(table, "daemon_reason")
        op.drop_column(table, "daemon_status")
