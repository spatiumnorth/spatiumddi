"""Stored DNS agent config bundles (#1111).

One table and eight columns, all additive; no backfill and no data
migration. An install upgrades into this with no bundle stored for any
server, which is also what every existing row means: the long-poll then
either builds inline once (``dns_agent_bundle_inline_fallback``, the
migration-release default) or holds until the worker's render lands.

WHY A TABLE, AND WHY POSTGRES
-----------------------------
The agent config bundle used to be assembled inside the api request path,
once per agent long-poll that observed a change, with peak memory
proportional to the group's record count and — at 1.09 M ``dns_record``
rows — a records query that no longer fit asyncpg's 30 s
``command_timeout`` (every poll of every agent answered 503, for as long
as anyone watched). It is now rendered once per (server, watermark) in
the worker, which has no HTTP liveness probe and no 30 s statement
ceiling, and served as stored bytes. Postgres is the only store every
node's api can read on the appliance: Redis is capped at 256 MB and a
PVC is node-local. CNPG replication puts the row on every node.

WHY THE COUNTERS LIVE ON THE SERVER ROW
---------------------------------------
``bundle_dirty_seq`` is bumped in the same transaction as any change that
feeds the bundle, so it commits or rolls back with the change and can
never be lost to a Redis outage; ``bundle_watermark`` is the sequence the
newest stored bundle was rendered at. "Current" is one integer
comparison on a row the long-poll already refreshes on every wake — no
assembly, no content hash. The ``bundle_render_*`` trio is the control
plane's own verdict on its last render, kept apart from #882's
``config_failed_etag`` (the agent's verdict, cleared by its next healthy
heartbeat).

Revision ID: c4d1e7f90a2b
Revises: b7d21c9e4f06
Create Date: 2026-09-22
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "c4d1e7f90a2b"
down_revision = "b7d21c9e4f06"
branch_labels = None
depends_on = None


_SERVER_COLUMNS = (
    "bundle_dirty_seq",
    "bundle_watermark",
    "bundle_etag",
    "bundle_built_at",
    "bundle_rendered_by",
    "bundle_render_count",
    "bundle_render_status",
    "bundle_render_error",
    "bundle_render_at",
)


def upgrade() -> None:
    op.create_table(
        "dns_agent_bundle",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "server_id",
            UUID(as_uuid=True),
            sa.ForeignKey("dns_server.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("dirty_watermark", sa.BigInteger(), nullable=False),
        sa.Column("snapshot_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("etag", sa.String(128), nullable=False),
        sa.Column("structural_etag", sa.String(128), nullable=False),
        sa.Column("ships_ops", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("body", sa.LargeBinary(), nullable=False),
        sa.Column("body_bytes", sa.Integer(), nullable=False),
        sa.Column("body_gzip_bytes", sa.Integer(), nullable=False),
        sa.Column("records", sa.Integer(), nullable=False),
        sa.Column("render_ms", sa.Integer(), nullable=False),
        sa.Column("rendered_by", sa.String(16), nullable=False),
        sa.Column(
            "built_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "server_id", "dirty_watermark", name="uq_dns_agent_bundle_server_watermark"
        ),
    )
    op.create_index(
        "ix_dns_agent_bundle_server_built", "dns_agent_bundle", ["server_id", "built_at"]
    )
    # The body is stored already gzip-compressed. EXTERNAL keeps TOAST from
    # spending CPU trying to compress it again on every store (and from
    # inflating it when it cannot).
    op.execute("ALTER TABLE dns_agent_bundle ALTER COLUMN body SET STORAGE EXTERNAL")

    op.add_column(
        "dns_server",
        sa.Column("bundle_dirty_seq", sa.BigInteger(), nullable=False, server_default="0"),
    )
    op.add_column("dns_server", sa.Column("bundle_watermark", sa.BigInteger(), nullable=True))
    op.add_column("dns_server", sa.Column("bundle_etag", sa.String(128), nullable=True))
    op.add_column(
        "dns_server", sa.Column("bundle_built_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("dns_server", sa.Column("bundle_rendered_by", sa.String(16), nullable=True))
    op.add_column(
        "dns_server",
        sa.Column("bundle_render_count", sa.BigInteger(), nullable=False, server_default="0"),
    )
    op.add_column("dns_server", sa.Column("bundle_render_status", sa.String(20), nullable=True))
    op.add_column("dns_server", sa.Column("bundle_render_error", sa.Text(), nullable=True))
    op.add_column(
        "dns_server", sa.Column("bundle_render_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    for column in reversed(_SERVER_COLUMNS):
        op.drop_column("dns_server", column)
    op.drop_index("ix_dns_agent_bundle_server_built", table_name="dns_agent_bundle")
    op.drop_table("dns_agent_bundle")
