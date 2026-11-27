"""Multi-tenancy phase 1: the ``tenant`` table and tenant bindings (#4263).

Revision ID: d7a3b9c15e48
Revises: c4d8e1a7b9f2
Create Date: 2026-11-27 12:00:00

Adds ``tenant`` and a nullable ``tenant_id`` on ``ip_space``, ``group`` and
``api_token`` (RESTRICT: a tenant still referenced cannot be deleted).

Name uniqueness becomes per tenant where a tenant is set: ``ix_ip_space_name``
and ``ix_group_name`` now cover only rows with no tenant (so an install with no
tenants behaves exactly as before), and ``ix_ip_space_tenant_name`` /
``ix_group_tenant_name`` cover rows with one. No existing row has a tenant, so
no data is touched.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "d7a3b9c15e48"
down_revision: str | None = "c4d8e1a7b9f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenant",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=sa.text("''")),
        sa.Column("customer_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "modified_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["customer_id"], ["customer.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("uq_tenant_name_lower", "tenant", [sa.text("lower(name)")], unique=True)

    for table in ("ip_space", "group", "api_token"):
        op.add_column(table, sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True))
        op.create_foreign_key(
            f"fk_{table}_tenant_id", table, "tenant", ["tenant_id"], ["id"], ondelete="RESTRICT"
        )
        op.create_index(f"ix_{table}_tenant_id", table, ["tenant_id"])

    op.drop_index("ix_ip_space_name", table_name="ip_space")
    op.create_index(
        "ix_ip_space_name",
        "ip_space",
        ["name"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL AND tenant_id IS NULL"),
    )
    op.create_index(
        "ix_ip_space_tenant_name",
        "ip_space",
        ["tenant_id", "name"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL AND tenant_id IS NOT NULL"),
    )

    op.drop_index("ix_group_name", table_name="group")
    op.create_index(
        "ix_group_name",
        "group",
        ["name"],
        unique=True,
        postgresql_where=sa.text("tenant_id IS NULL"),
    )
    op.create_index(
        "ix_group_tenant_name",
        "group",
        ["tenant_id", "name"],
        unique=True,
        postgresql_where=sa.text("tenant_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_group_tenant_name", table_name="group")
    op.drop_index("ix_group_name", table_name="group")
    op.create_index("ix_group_name", "group", ["name"], unique=True)

    op.drop_index("ix_ip_space_tenant_name", table_name="ip_space")
    op.drop_index("ix_ip_space_name", table_name="ip_space")
    op.create_index(
        "ix_ip_space_name",
        "ip_space",
        ["name"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )

    for table in ("api_token", "group", "ip_space"):
        op.drop_index(f"ix_{table}_tenant_id", table_name=table)
        op.drop_constraint(f"fk_{table}_tenant_id", table, type_="foreignkey")
        op.drop_column(table, "tenant_id")

    op.drop_index("uq_tenant_name_lower", table_name="tenant")
    op.drop_table("tenant")
