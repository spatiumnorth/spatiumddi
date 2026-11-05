"""Let deleting a user keep the API tokens it minted for others (#2144).

``api_token.created_by_user_id`` was NOT NULL with ``ON DELETE RESTRICT``.
Before service accounts every token was minted by its own owner, whose delete
cascades the token away, so the restriction never fired. A superadmin now
mints tokens for a service account, so deleting that superadmin was refused
for as long as any of those tokens existed. The column becomes nullable with
``ON DELETE SET NULL``: the token keeps working, and who minted it stays in
the audit log.

The downgrade restores NOT NULL, filling a cleared creator with the token's
owner first (nothing issues an ownerless token, so every row has one).

Revision ID: e3a9c5f17b26
Revises: c4e8a2d6b917
"""

from __future__ import annotations

from alembic import op

revision: str = "e3a9c5f17b26"
down_revision: str | None = "c4e8a2d6b917"
branch_labels = None
depends_on = None

_FK = "api_token_created_by_user_id_fkey"


def upgrade() -> None:
    op.drop_constraint(_FK, "api_token", type_="foreignkey")
    op.alter_column("api_token", "created_by_user_id", nullable=True)
    op.create_foreign_key(
        _FK, "api_token", "user", ["created_by_user_id"], ["id"], ondelete="SET NULL"
    )


def downgrade() -> None:
    op.drop_constraint(_FK, "api_token", type_="foreignkey")
    op.execute(
        "UPDATE api_token SET created_by_user_id = user_id "
        "WHERE created_by_user_id IS NULL AND user_id IS NOT NULL"
    )
    op.alter_column("api_token", "created_by_user_id", nullable=False)
    op.create_foreign_key(
        _FK, "api_token", "user", ["created_by_user_id"], ["id"], ondelete="RESTRICT"
    )
