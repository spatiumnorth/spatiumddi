"""VMware vSphere integration — target table + IPAM provenance + settings toggle (#4740).

Revision ID: a7d3f9c1e268
Revises: c4d8e1a7b9f2
Create Date: 2026-11-27 12:00:00

One row per vCenter Server (``vsphere_target``). ``vsphere_target_id`` FK on
``ip_address`` + ``ip_block`` + ``subnet``, ON DELETE CASCADE, so removing a
target sweeps what it mirrored (the API hands operator-made rows back first,
#2287). Today only ``ip_address`` rows are written; the block and subnet
columns exist because every integration's ownership FK lives on all three
tables (``integration_ownership``). A platform-settings column mirrors the
``integrations.vsphere`` module switch for readers outside the app; no module
row is seeded (the catalog default, off, applies).
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "a7d3f9c1e268"
down_revision: str | None = "c4d8e1a7b9f2"
branch_labels = None
depends_on = None

_IPAM_TABLES = ("ip_address", "ip_block", "subnet")


def upgrade() -> None:
    op.create_table(
        "vsphere_target",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False, server_default="443"),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("ca_bundle_pem", sa.Text(), nullable=False, server_default=""),
        sa.Column("username", sa.String(length=255), nullable=False, server_default=""),
        sa.Column(
            "password_encrypted",
            sa.LargeBinary(),
            nullable=False,
            server_default=sa.text("''::bytea"),
        ),
        sa.Column(
            "ipam_space_id",
            sa.UUID(),
            sa.ForeignKey("ip_space.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("mirror_vms", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("mirror_hosts", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("sync_interval_seconds", sa.Integer(), nullable=False, server_default="120"),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sync_error", sa.Text(), nullable=True),
        sa.Column("vcenter_version", sa.String(length=64), nullable=True),
        sa.Column("host_count", sa.Integer(), nullable=True),
        sa.Column("vm_count", sa.Integer(), nullable=True),
        sa.Column("last_discovery", sa.dialects.postgresql.JSONB(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "modified_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_vsphere_target_name", "vsphere_target", ["name"], unique=True)

    for table in _IPAM_TABLES:
        op.add_column(
            table,
            sa.Column(
                "vsphere_target_id",
                sa.UUID(),
                sa.ForeignKey("vsphere_target.id", ondelete="CASCADE"),
                nullable=True,
            ),
        )
        op.create_index(f"ix_{table}_vsphere_target_id", table, ["vsphere_target_id"])

    op.add_column(
        "platform_settings",
        sa.Column(
            "integration_vsphere_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("platform_settings", "integration_vsphere_enabled")
    for table in reversed(_IPAM_TABLES):
        op.drop_index(f"ix_{table}_vsphere_target_id", table_name=table)
        op.drop_column(table, "vsphere_target_id")
    op.drop_index("ix_vsphere_target_name", table_name="vsphere_target")
    op.drop_table("vsphere_target")
