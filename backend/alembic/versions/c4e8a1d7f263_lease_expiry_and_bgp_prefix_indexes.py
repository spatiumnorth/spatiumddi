"""Partial index for the lease-expiry sweep, GiST on the BGP route prefix (#1255)

* ``ix_dhcp_lease_active_expires_at`` — ``(expires_at) WHERE state = 'active'``.
  The sweep filters ``state = 'active' AND expires_at < cutoff``; ``active``
  is most of the table, so the single-column ``state`` index never narrowed it.
* ``ix_bgp_lg_route_prefix_gist`` — GiST ``inet_ops`` on ``bgp_lg_route.prefix``
  for the ``>>=`` / ``<<=`` containment queries (hijack-coverage alert,
  reachability, the route list's prefix filter), which a btree cannot serve.

Revision ID: c4e8a1d7f263
Revises: b6d2e9f41a07
Create Date: 2026-11-18 10:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "c4e8a1d7f263"
down_revision = "b6d2e9f41a07"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # CONCURRENTLY: bgp_lg_route takes continuous collector writes and can hold
    # a full Internet table; a plain build would block them. It cannot run in a
    # transaction, hence autocommit_block. The leading DROP ... IF EXISTS clears the
    # INVALID index an interrupted build leaves, so a retry does not fail on the name.
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS ix_dhcp_lease_active_expires_at")
        op.create_index(
            "ix_dhcp_lease_active_expires_at",
            "dhcp_lease",
            ["expires_at"],
            postgresql_where=sa.text("state = 'active'"),
            postgresql_concurrently=True,
        )
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS ix_bgp_lg_route_prefix_gist")
        op.create_index(
            "ix_bgp_lg_route_prefix_gist",
            "bgp_lg_route",
            ["prefix"],
            postgresql_using="gist",
            postgresql_ops={"prefix": "inet_ops"},
            postgresql_concurrently=True,
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.drop_index(
            "ix_bgp_lg_route_prefix_gist",
            table_name="bgp_lg_route",
            postgresql_concurrently=True,
        )
        op.drop_index(
            "ix_dhcp_lease_active_expires_at",
            table_name="dhcp_lease",
            postgresql_concurrently=True,
        )
