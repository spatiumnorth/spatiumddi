"""dhcp_lease / dhcp_lease_history relay agent information (#54)

Kea stores the option-82 body a relay sent for a lease once
``store-extended-info`` is on (rendered for every group with an option-82
class). The agent now ships it, and these columns hold it: on ``dhcp_lease``
the whole body plus its circuit-id (sub-option 1) and remote-id (sub-option
2), each uppercase hex; on ``dhcp_lease_history`` the circuit-id and
remote-id, copied when the lease leaves the active set. Two partial indexes
serve the circuit-id / remote-id lease filters.

Every existing row gets NULL, which reads as "no option 82 recorded" — which
is exactly what is known about it. Nothing is backfilled: the next lease
event for a relayed lease fills it in.

Revision ID: b9b98b65f49c
Revises: d8b3f6a1c274
Create Date: 2026-11-21 12:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "b9b98b65f49c"
down_revision = "d8b3f6a1c274"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for column in ("relay_agent_info", "relay_circuit_id", "relay_remote_id"):
        op.add_column("dhcp_lease", sa.Column(column, sa.String(length=510), nullable=True))
    for column in ("relay_circuit_id", "relay_remote_id"):
        op.add_column(
            "dhcp_lease_history", sa.Column(column, sa.String(length=510), nullable=True)
        )
    op.create_index(
        "ix_dhcp_lease_relay_circuit",
        "dhcp_lease",
        ["relay_circuit_id"],
        postgresql_where=sa.text("relay_circuit_id IS NOT NULL"),
    )
    op.create_index(
        "ix_dhcp_lease_relay_remote",
        "dhcp_lease",
        ["relay_remote_id"],
        postgresql_where=sa.text("relay_remote_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_dhcp_lease_relay_remote", table_name="dhcp_lease")
    op.drop_index("ix_dhcp_lease_relay_circuit", table_name="dhcp_lease")
    for column in ("relay_circuit_id", "relay_remote_id"):
        op.drop_column("dhcp_lease_history", column)
    for column in ("relay_agent_info", "relay_circuit_id", "relay_remote_id"):
        op.drop_column("dhcp_lease", column)
