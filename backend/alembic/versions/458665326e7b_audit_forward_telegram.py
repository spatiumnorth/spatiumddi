"""Telegram delivery for webhook forward targets.

Adds the ``telegram_*`` columns to ``audit_forward_target`` for the new
``webhook_flavor="telegram"``:

* ``telegram_bot_token_encrypted`` — Fernet ciphertext of the bot token,
  same convention as ``smtp_password_encrypted`` (the API returns only
  ``telegram_bot_token_set``). Registered for the cross-install backup
  rewrap.
* ``telegram_chat_id`` — numeric chat id or ``@channelusername``.
* ``telegram_message_thread_id`` — optional forum topic.
* ``telegram_api_base`` — optional self-hosted Bot API server; empty
  means Telegram's public API.

``webhook_flavor`` is a plain ``String(16)`` with no CHECK constraint, so
the new flavor value itself needs no schema change.

Additive only, with server defaults on the NOT NULL columns, so it is
safe for N-1 code during a rolling upgrade.

Revision ID: 458665326e7b
Revises: 61566a119901
Create Date: 2026-10-04
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "458665326e7b"
down_revision = "61566a119901"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "audit_forward_target",
        sa.Column("telegram_bot_token_encrypted", sa.LargeBinary(), nullable=True),
    )
    op.add_column(
        "audit_forward_target",
        sa.Column(
            "telegram_chat_id",
            sa.String(length=64),
            server_default=sa.text("''"),
            nullable=False,
        ),
    )
    op.add_column(
        "audit_forward_target",
        sa.Column("telegram_message_thread_id", sa.Integer(), nullable=True),
    )
    op.add_column(
        "audit_forward_target",
        sa.Column(
            "telegram_api_base",
            sa.String(length=255),
            server_default=sa.text("''"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("audit_forward_target", "telegram_api_base")
    op.drop_column("audit_forward_target", "telegram_message_thread_id")
    op.drop_column("audit_forward_target", "telegram_chat_id")
    op.drop_column("audit_forward_target", "telegram_bot_token_encrypted")
