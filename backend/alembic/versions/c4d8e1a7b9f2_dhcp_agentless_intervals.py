"""Configurable agentless DHCP health-sweep + MAC-block-sync intervals (#4759).

Revision ID: c4d8e1a7b9f2
Revises: e4a91c7d52b3
Create Date: 2026-11-22 12:00:00

Both beat tasks used to run every 60 s against every agentless DHCP server,
one WinRM session each, with no way to slow them down. Adds:

* ``platform_settings.dhcp_health_interval_seconds`` (default 60) and
  ``dhcp_mac_blocks_sync_interval_seconds`` (default 60), plus their
  ``*_last_run_at`` stamps -- the same shape as the lease-pull interval.
* ``dhcp_server.mac_blocks_pushed`` -- whether a MAC deny list was ever
  pushed to the server, so the sync can skip the WinRM round trip when there
  is nothing to push and nothing to clear. Existing rows start TRUE so the
  first sync after the upgrade still reads (and, if empty, clears) each
  server's filter list once.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "c4d8e1a7b9f2"
down_revision: str | None = "e4a91c7d52b3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "platform_settings",
        sa.Column(
            "dhcp_health_interval_seconds",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("60"),
        ),
    )
    op.add_column(
        "platform_settings",
        sa.Column("dhcp_health_last_run_at", sa.DateTime(timezone=True), nullable=True),
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
    op.add_column(
        "dhcp_server",
        sa.Column(
            "mac_blocks_pushed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
    )
    # New rows have never been pushed to.
    op.alter_column("dhcp_server", "mac_blocks_pushed", server_default=sa.false())


def downgrade() -> None:
    op.drop_column("dhcp_server", "mac_blocks_pushed")
    op.drop_column("platform_settings", "dhcp_mac_blocks_sync_last_run_at")
    op.drop_column("platform_settings", "dhcp_mac_blocks_sync_interval_seconds")
    op.drop_column("platform_settings", "dhcp_health_last_run_at")
    op.drop_column("platform_settings", "dhcp_health_interval_seconds")
