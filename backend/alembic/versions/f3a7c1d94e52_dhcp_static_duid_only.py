"""DUID-only DHCPv6 reservations: nullable static MAC, ``ip_address.duid`` (#3900).

A DHCPv6 client is identified by its DUID, and the reservation model already
carried one (#368), but ``dhcp_static_assignment.mac_address`` was NOT NULL so a
reservation keyed on the DUID alone could not be stored, and an IPAM address
row had nowhere to hold one. This makes the MAC nullable behind a CHECK that
still demands an identifier (a MAC or a DUID), adds a per-scope unique index
on the DUID, and adds ``ip_address.duid`` so a ``static_dhcp`` v6 address
can carry it into the reservation it mirrors to.

Revision ID: f3a7c1d94e52
Revises: ede3bcd2aff4
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "f3a7c1d94e52"
down_revision: str | None = "ede3bcd2aff4"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.alter_column("dhcp_static_assignment", "mac_address", nullable=True)
    op.create_check_constraint(
        "ck_dhcp_static_identity",
        "dhcp_static_assignment",
        "mac_address IS NOT NULL OR duid IS NOT NULL",
    )
    op.create_index(
        "uq_dhcp_static_scope_duid",
        "dhcp_static_assignment",
        ["scope_id", "duid"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL AND duid IS NOT NULL"),
    )
    op.add_column("ip_address", sa.Column("duid", sa.String(length=400), nullable=True))


def downgrade() -> None:
    op.drop_column("ip_address", "duid")
    op.drop_index("uq_dhcp_static_scope_duid", table_name="dhcp_static_assignment")
    op.drop_constraint("ck_dhcp_static_identity", "dhcp_static_assignment", type_="check")
    # A DUID-only reservation has no MAC to restore; it cannot survive the
    # NOT NULL column, so it goes (its scope re-learns the client by lease).
    op.execute("DELETE FROM dhcp_static_assignment WHERE mac_address IS NULL")
    op.alter_column("dhcp_static_assignment", "mac_address", nullable=False)
