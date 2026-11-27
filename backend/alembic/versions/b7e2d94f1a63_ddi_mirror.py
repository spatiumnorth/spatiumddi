"""Commercial-DDI live mirror — target + mirrored object tables (#4729).

Revision ID: b7e2d94f1a63
Revises: c4d8e1a7b9f2
Create Date: 2026-11-27 12:00:00

``ddi_mirror_target`` holds one commercial DDI estate (Infoblox first) with its
Fernet-encrypted password; ``ddi_mirror_object`` holds what was pulled from it,
keyed ``(target, kind, source_ref)`` and cascading with the target. The mirror
never writes live IPAM / DNS / DHCP, so there are no ownership columns on those
tables. The ``migration.ddi_mirror`` module is deliberately not seeded: it
ships disabled from the catalog default, and an override row means only
"an operator changed this" (#1069).
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "b7e2d94f1a63"
down_revision: str | None = "c4d8e1a7b9f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    now = sa.text("now()")
    op.create_table(
        "ddi_mirror_target",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("vendor", sa.String(length=32), nullable=False, server_default="infoblox"),
        sa.Column("base_url", sa.String(length=512), nullable=False),
        sa.Column("api_version", sa.String(length=16), nullable=False, server_default="v2.12"),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("ca_bundle_pem", sa.Text(), nullable=False, server_default=""),
        sa.Column("username", sa.String(length=255), nullable=False, server_default=""),
        sa.Column(
            "password_encrypted",
            sa.LargeBinary(),
            nullable=False,
            server_default=sa.text("''::bytea"),
        ),
        sa.Column("network_view", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("dns_view", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("sync_interval_seconds", sa.Integer(), nullable=False, server_default="900"),
        sa.Column("page_size", sa.Integer(), nullable=False, server_default="500"),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sync_error", sa.Text(), nullable=True),
        sa.Column("last_sync_warning", sa.Text(), nullable=True),
        sa.Column("source_version", sa.String(length=64), nullable=True),
        sa.Column("object_count", sa.Integer(), nullable=True),
        sa.Column("last_report", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=now),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=False, server_default=now),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ddi_mirror_target_name", "ddi_mirror_target", ["name"], unique=True)

    op.create_table(
        "ddi_mirror_object",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "target_id",
            sa.UUID(),
            sa.ForeignKey("ddi_mirror_target.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("source_ref", sa.String(length=512), nullable=False),
        sa.Column("name", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("view", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("value", sa.Text(), nullable=False, server_default=""),
        sa.Column("comment", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "data",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=now),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=False, server_default=now),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("target_id", "kind", "source_ref", name="uq_ddi_mirror_object_ref"),
    )
    op.create_index("ix_ddi_mirror_object_target_kind", "ddi_mirror_object", ["target_id", "kind"])


def downgrade() -> None:
    op.drop_index("ix_ddi_mirror_object_target_kind", table_name="ddi_mirror_object")
    op.drop_table("ddi_mirror_object")
    op.drop_index("ix_ddi_mirror_target_name", table_name="ddi_mirror_target")
    op.drop_table("ddi_mirror_target")
