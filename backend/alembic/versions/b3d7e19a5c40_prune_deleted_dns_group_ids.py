"""IPAM dns_group_ids: drop ids of DNS server groups that no longer exist (#3433)

``ip_space`` / ``ip_block`` / ``subnet`` hold DNS group assignments as a JSONB
id list with no foreign key, and deleting a group never cleared the id, so
Edit Subnet kept showing "inheriting 1 group(s)" for a group that was gone.
The delete route now prunes the id; this removes the ids already stranded.
Data-only; the downgrade is a no-op (the removed ids named nothing).

Revision ID: b3d7e19a5c40
Revises: 833ee80c8c6b
"""

from __future__ import annotations

from alembic import op

revision: str = "b3d7e19a5c40"
down_revision: str | None = "833ee80c8c6b"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    for table in ("ip_space", "ip_block", "subnet"):
        op.execute(f"""
            UPDATE {table} SET dns_group_ids = COALESCE((
                SELECT jsonb_agg(e) FROM jsonb_array_elements(dns_group_ids) e
                WHERE e IN (SELECT to_jsonb(id::text) FROM dns_server_group)
            ), '[]'::jsonb)
            WHERE dns_group_ids IS NOT NULL
              AND jsonb_typeof(dns_group_ids) = 'array'
              AND dns_group_ids <> '[]'::jsonb
              AND EXISTS (
                SELECT 1 FROM jsonb_array_elements(dns_group_ids) x
                WHERE x NOT IN (SELECT to_jsonb(id::text) FROM dns_server_group)
              )
            """)


def downgrade() -> None:
    pass
