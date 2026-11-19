"""DHCPv6 HA state per DHCP server (#1258).

Adds ``dhcp_server.ha_state_v6`` — the state kea-dhcp6's HA hook reports, kept
beside ``ha_state`` (kea-dhcp4's) because the two daemons are separate
processes with separate state machines. Nullable and left NULL: NULL means no
DHCPv6 HA is rendered for the server, which is true of every existing row until
its agent upgrades and reports one.

Revision ID: d3a9c5e71b42
Revises: b6d2e9f41a07
Create Date: 2026-11-19
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "d3a9c5e71b42"
down_revision = "d8b3f6a1c274"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("dhcp_server", sa.Column("ha_state_v6", sa.String(length=50), nullable=True))


def downgrade() -> None:
    op.drop_column("dhcp_server", "ha_state_v6")
