"""Webhook forward-target URL + Authorization header: Fernet-encrypted (#1502).

``audit_forward_target.url`` / ``auth_header`` and the legacy single-webhook
pair on ``platform_settings`` (``audit_forward_webhook_url`` /
``audit_forward_webhook_auth_header``) were stored in clear. For the Slack,
Discord and Teams flavors the URL is the credential (anyone holding it can
post into the channel), and the header is a collector token. Every value is
copied into a new ``*_encrypted`` ``LargeBinary`` column with the same
``encrypt_str`` every other ``*_encrypted`` column uses, and the application
stops reading or writing the plaintext columns.

The plaintext columns are NOT dropped here: this is the expand half of the
expand/contract contract (#296), the same as ``b3c71e9a4d25`` (#1364). During
a rolling upgrade the old api pods still select them on every target and
settings read. They are made nullable, though, for two reasons: the new
application no longer names them in an INSERT (their ``''`` server default
covers that, nullable or not), and the "exclude secrets" diagnostic archive
writes NULL into every column in ``LEGACY_PLAINTEXT_SECRET_COLUMNS``, which a
NOT NULL column would refuse on restore. The contract half drops them in the
following release. Until then they hold the pre-upgrade values, unread.

Importing ``app.core.crypto`` is deliberate, as in ``b3c71e9a4d25``: the
ciphertext has to be exactly what the application reads back, under the
install's own key, and the restore order (migrate in phase 6, cross-install
rewrap in phase 7) handles a value already under the local key.

Revision ID: e51ab0dede3e
Revises: 61566a119901
Create Date: 2026-10-04
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "e51ab0dede3e"
down_revision = "61566a119901"
branch_labels = None
depends_on = None

# (table, plaintext column, encrypted column)
_PAIRS: tuple[tuple[str, str, str], ...] = (
    ("audit_forward_target", "url", "url_encrypted"),
    ("audit_forward_target", "auth_header", "auth_header_encrypted"),
    (
        "platform_settings",
        "audit_forward_webhook_url",
        "audit_forward_webhook_url_encrypted",
    ),
    (
        "platform_settings",
        "audit_forward_webhook_auth_header",
        "audit_forward_webhook_auth_header_encrypted",
    ),
)


def upgrade() -> None:
    from app.core.crypto import encrypt_str

    conn = op.get_bind()
    for table, plain, encrypted in _PAIRS:
        op.add_column(table, sa.Column(encrypted, sa.LargeBinary(), nullable=True))
        op.alter_column(
            table,
            plain,
            existing_type=sa.String(length=1024),
            existing_server_default="",
            nullable=True,
        )
        rows = conn.execute(
            sa.text(f"SELECT id, {plain} FROM {table} WHERE {plain} IS NOT NULL AND {plain} <> ''")
        ).all()
        for row_id, value in rows:
            conn.execute(
                sa.text(f"UPDATE {table} SET {encrypted} = :value WHERE id = :id"),
                {"value": encrypt_str(value), "id": row_id},
            )


def downgrade() -> None:
    from app.core.crypto import decrypt_str

    # The plaintext columns were kept. Copy the current values back, in case
    # they were changed since the upgrade, then drop the encrypted columns.
    conn = op.get_bind()
    for table, plain, encrypted in _PAIRS:
        rows = conn.execute(
            sa.text(f"SELECT id, {encrypted} FROM {table} WHERE {encrypted} IS NOT NULL")
        ).all()
        for row_id, token in rows:
            try:
                value = decrypt_str(bytes(token))
            except ValueError:
                # Not readable under this install's key: leave the plaintext
                # column as it was.
                continue
            conn.execute(
                sa.text(f"UPDATE {table} SET {plain} = :value WHERE id = :id"),
                {"value": value, "id": row_id},
            )
        # Cleared since the upgrade, or blanked by an "exclude secrets"
        # restore: the old application maps these as non-null strings.
        conn.execute(sa.text(f"UPDATE {table} SET {plain} = '' WHERE {plain} IS NULL"))
        op.drop_column(table, encrypted)
