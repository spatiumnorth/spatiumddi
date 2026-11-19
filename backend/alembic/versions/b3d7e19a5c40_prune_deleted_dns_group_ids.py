"""IPAM dns_group_ids: drop ids of DNS server groups that no longer exist (#3433)

``ip_space`` / ``ip_block`` / ``subnet`` hold DNS group assignments as a JSONB
id list with no foreign key, and deleting a group never cleared the id, so
Edit Subnet kept showing "inheriting 1 group(s)" for a group that was gone.
The delete route now prunes the id; this removes the ids already stranded.

An entry is kept when it names a live group. Ids compare by their 32 hex
digits: before #2923 the API stored an id as given, and the readers resolve
any spelling Python's ``uuid.UUID`` accepts (upper-case, braced, unhyphenated,
``urn:uuid:``), so comparing text would clear a live binding. The fold is
``app.services.ipam.zone_binding.norm_uuid_sql``, inlined so the migration
does not move with the app. The order of the entries kept is preserved (the
first one picks the reverse-zone group). Trash rows are included. Data-only; the downgrade is a no-op (the
removed ids named nothing).

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
    live = "(SELECT replace(id::text, '-', '') FROM dns_server_group)"

    def norm(expr: str) -> str:
        return f"regexp_replace(lower({expr}), 'urn:|uuid:|[{{}}-]', '', 'g')"

    for table in ("ip_space", "ip_block", "subnet"):
        op.execute(f"""
            UPDATE {table} SET dns_group_ids = COALESCE((
                SELECT jsonb_agg(e ORDER BY o)
                FROM jsonb_array_elements(dns_group_ids) WITH ORDINALITY AS t(e, o)
                WHERE COALESCE({norm("e #>> '{}'")} IN {live}, false)
            ), '[]'::jsonb)
            WHERE jsonb_typeof(dns_group_ids) = 'array'
              AND EXISTS (
                SELECT 1 FROM jsonb_array_elements(dns_group_ids) x
                WHERE COALESCE({norm("x #>> '{}'")} NOT IN {live}, false)
              )
            """)  # noqa: S608


def downgrade() -> None:
    pass
