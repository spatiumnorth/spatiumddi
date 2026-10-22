"""dhcp_lease: dedupe, then one row per lease identity per server (#2262)

The agentless lease pull (Windows DHCP / FortiGate) did select-then-insert on
``(server_id, ip_address)`` with no lock and no unique constraint, so two
overlapping pulls both inserted the same lease. Every later pull then raised
``MultipleResultsFound`` for that address and the server's whole pull aborted
on every tick.

The unique key is the lease IDENTITY, the one ``agents._lease_identity``
matches on: (address, MAC) for a DHCPv4 lease, (address, DUID, IAID) for a
DHCPv6 one. It is deliberately not ``(server_id, ip_address)``: the Kea
lease-event path keeps one row per client on an address, because an agent
restart replays an old client's grant and release after the address has gone
to a new client (#1110, #1318), and a plain address key would fail those
batches.

Existing duplicates are deleted first, keeping the most recently seen row of
each identity. The downgrade drops the two indexes; the deleted duplicates
carried nothing the kept row does not, so they are not restored.

Revision ID: e4b8c2d17a95
Revises: e4c9b2a17f60
Create Date: 2026-10-20 10:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "e4b8c2d17a95"
down_revision = "e4c9b2a17f60"
branch_labels = None
depends_on = None

# Module-level so the tests, which build their schema with ``create_all``,
# run the exact statement. PARTITION BY groups NULLs together, so a v6 lease
# with no IAID dedupes the same way the NULLS NOT DISTINCT index compares it.
DEDUPE_LEASES_SQL = sa.text("""
    DELETE FROM dhcp_lease
    WHERE id IN (
        SELECT id FROM (
            SELECT
                id,
                row_number() OVER (
                    PARTITION BY
                        server_id,
                        ip_address,
                        CASE WHEN duid IS NULL THEN mac_address::text ELSE NULL END,
                        duid,
                        CASE WHEN duid IS NULL THEN NULL ELSE iaid END
                    ORDER BY last_seen_at DESC, id DESC
                ) AS rn
            FROM dhcp_lease
        ) ranked
        WHERE ranked.rn > 1
    )
    """)


def upgrade() -> None:
    op.execute(DEDUPE_LEASES_SQL)
    op.create_index(
        "uq_dhcp_lease_server_ip_mac",
        "dhcp_lease",
        ["server_id", "ip_address", "mac_address"],
        unique=True,
        postgresql_where=sa.text("duid IS NULL"),
    )
    op.create_index(
        "uq_dhcp_lease_server_ip_duid",
        "dhcp_lease",
        ["server_id", "ip_address", "duid", "iaid"],
        unique=True,
        postgresql_where=sa.text("duid IS NOT NULL"),
        postgresql_nulls_not_distinct=True,
    )


def downgrade() -> None:
    op.drop_index("uq_dhcp_lease_server_ip_duid", table_name="dhcp_lease")
    op.drop_index("uq_dhcp_lease_server_ip_mac", table_name="dhcp_lease")
