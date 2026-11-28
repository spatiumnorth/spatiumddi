"""Additional appliance network interfaces (#4428).

One JSONB column, NOT NULL, defaulting to the empty list. No backfill and
nothing to derive: an install upgrades into this feature with no extra
interfaces managed, which is also what every existing row means.

WHY THE DESIRED SET LIVES ON THE APPLIANCE ROW
----------------------------------------------
A NIC, its VLAN sub-interfaces and the route back to a DHCP relay exist
on exactly one box. The fleet-wide host-config planes (snmp, ntp, ssh ...)
render from ``platform_settings`` because each describes the FLEET; a
fleet-wide interface list would ask every other node to configure
hardware it does not have. Same reasoning as
``desired_removable_mounts`` (e3b9d7412c5a).

WHY THE REPORTED STATE IS NOT A COLUMN
--------------------------------------
What the node actually runs (live addresses, link state, the last apply
verdict) rides inside ``cluster_health["netif"]``, stored verbatim from
the heartbeat (the #402 pattern). Desired and actual disagreeing is a
normal, transient condition, so a second column could only be a stale
copy of what the node already reports.

Revision ID: f4a7d2c81e59
Revises: c4d8e1a7b9f2
Create Date: 2026-11-28
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "f4a7d2c81e59"
down_revision = "c4d8e1a7b9f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "appliance",
        sa.Column(
            "desired_network_interfaces",
            JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("appliance", "desired_network_interfaces")
