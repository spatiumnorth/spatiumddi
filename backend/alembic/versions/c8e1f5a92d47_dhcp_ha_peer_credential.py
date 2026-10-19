"""Kea HA peer credential per DHCP server group; agent capabilities per server.

Adds ``dhcp_server_group.ha_peer_credential_encrypted`` — the CA + peer
certificate + key the group's Kea HA peers authenticate to each other with on
the hook's dedicated listener (``app/services/dhcp/ha_peer_auth.py``) — and
``dhcp_server.agent_capabilities``, the list an agent reports on its heartbeat
so the control plane renders that credential only once every Kea member can
load it.

Every existing group gets a freshly generated credential here, HA or not, so a
group that gains its second member later needs no further step. Nothing is
rendered from it until every Kea member reports ``ha_peer_tls``, so applying
this migration changes no running configuration: the agents in the field
predate the capability and keep their current HA config until they upgrade.

``agent_capabilities`` is left NULL — unknown, which the gate treats as "does
not support it" — and is filled in by the first heartbeat after the upgrade.

Importing ``app`` here is deliberate, as in ``b3c71e9a4d25``: the ciphertext
has to be exactly what the application reads back, under the install's own
key, and the generator is the application's.

Revision ID: c8e1f5a92d47
Revises: c4f8a2e61d37
Create Date: 2026-10-17
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "c8e1f5a92d47"
down_revision = "c4f8a2e61d37"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.services.dhcp.ha_peer_auth import encrypted_credential

    op.add_column(
        "dhcp_server_group",
        sa.Column("ha_peer_credential_encrypted", sa.LargeBinary(), nullable=True),
    )
    op.add_column(
        "dhcp_server",
        sa.Column("agent_capabilities", postgresql.JSONB(), nullable=True),
    )
    conn = op.get_bind()
    group_ids = conn.execute(
        sa.text("SELECT id FROM dhcp_server_group WHERE ha_peer_credential_encrypted IS NULL")
    ).scalars()
    for group_id in list(group_ids):
        conn.execute(
            sa.text(
                "UPDATE dhcp_server_group SET ha_peer_credential_encrypted = :value "
                "WHERE id = :id"
            ),
            {"value": encrypted_credential(), "id": group_id},
        )


def downgrade() -> None:
    op.drop_column("dhcp_server", "agent_capabilities")
    op.drop_column("dhcp_server_group", "ha_peer_credential_encrypted")
