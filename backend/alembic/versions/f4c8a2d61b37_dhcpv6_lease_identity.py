"""DHCPv6 lease identity: DUID + IAID beside the MAC (#1141).

A DHCPv4 lease is identified by its client's MAC. A DHCPv6 lease is
identified by the client's DUID and the IA's IAID, and usually carries no
MAC at all — Kea records a hardware address only when it can derive one. So
``dhcp_lease.mac_address`` (and the history table's) was NOT NULL, the
agent dropped every v6 lease before sending it, and none ever reached IPAM
or DDNS.

* ``mac_address`` becomes nullable on both tables.
* ``duid`` (Kea's colon-separated lowercase hex) and ``iaid`` are added.
* A CHECK requires one identity or the other: a lease naming neither could
  never be matched, renewed or released.
* ``(server_id, duid)`` is indexed, mirroring ``(server_id, mac_address)``.

Additive for every existing row (all carry a MAC), no backfill.

Downgrade deletes the rows that have no MAC before restoring NOT NULL — they
are DHCPv6 leases the older code cannot represent at all, and the agent
reports the live ones again on its next lease-table snapshot.

Revision ID: f4c8a2d61b37
Revises: e6b2f07a3c91
Create Date: 2026-09-24
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "f4c8a2d61b37"
down_revision: str | None = "e6b2f07a3c91"
branch_labels: str | None = None
depends_on: str | None = None

_TABLES = ("dhcp_lease", "dhcp_lease_history")


def upgrade() -> None:
    for table in _TABLES:
        op.alter_column(table, "mac_address", nullable=True)
        op.add_column(table, sa.Column("duid", sa.String(400), nullable=True))
        op.add_column(table, sa.Column("iaid", sa.BigInteger(), nullable=True))
        op.create_check_constraint(
            f"ck_{table}_identity", table, "mac_address IS NOT NULL OR duid IS NOT NULL"
        )
    op.create_index("ix_dhcp_lease_server_duid", "dhcp_lease", ["server_id", "duid"])


def downgrade() -> None:
    op.drop_index("ix_dhcp_lease_server_duid", table_name="dhcp_lease")
    for table in _TABLES:
        op.drop_constraint(f"ck_{table}_identity", table, type_="check")
        op.execute(sa.text(f"DELETE FROM {table} WHERE mac_address IS NULL"))
        op.drop_column(table, "iaid")
        op.drop_column(table, "duid")
        op.alter_column(table, "mac_address", nullable=False)
