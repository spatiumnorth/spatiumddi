"""Configurable cadence for the agentless DHCP health sweep and MAC-block sync (#4759).

Both jobs ran on a hard-coded 60 s beat and reached every agentless DHCP
server each time (on Windows DHCP, a WinRM / PowerShell session on the
domain controller per call). The beat stays at 60 s; the tasks now gate
on these settings, like the lease pull already does.

* ``dhcp_health_check_interval_seconds`` / ``dhcp_health_check_last_run_at``
* ``dhcp_mac_blocks_sync_interval_seconds`` / ``dhcp_mac_blocks_sync_last_run_at``

The intervals default to 60, the cadence before this change, so an
upgrade changes nothing until an operator raises them.

Revision ID: c4d8e2f61a95
Revises: ede3bcd2aff4
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "c4d8e2f61a95"
down_revision: str | None = "ede3bcd2aff4"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "platform_settings",
        sa.Column(
            "dhcp_health_check_interval_seconds",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("60"),
        ),
    )
    op.add_column(
        "platform_settings",
        sa.Column("dhcp_health_check_last_run_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "platform_settings",
        sa.Column(
            "dhcp_mac_blocks_sync_interval_seconds",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("60"),
        ),
    )
    op.add_column(
        "platform_settings",
        sa.Column("dhcp_mac_blocks_sync_last_run_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("platform_settings", "dhcp_mac_blocks_sync_last_run_at")
    op.drop_column("platform_settings", "dhcp_mac_blocks_sync_interval_seconds")
    op.drop_column("platform_settings", "dhcp_health_check_last_run_at")
    op.drop_column("platform_settings", "dhcp_health_check_interval_seconds")
