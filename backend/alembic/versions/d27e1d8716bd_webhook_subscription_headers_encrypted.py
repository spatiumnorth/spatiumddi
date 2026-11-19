"""Typed-webhook subscription headers: Fernet-encrypted at rest (#1579).

``event_subscription.headers`` was a plaintext JSONB dict holding the
custom headers merged into every delivery — documented in the model as
"auth tokens, routing hints", so in practice ``Authorization: Bearer …``
receiver credentials. The subscription's HMAC ``secret`` next to it was
already Fernet-encrypted; the headers were not, and they were not
registered as a secret column either, so backup rewrap skipped them and
the "exclude secrets" archive mode kept them. The API also returned the
full dict on every subscription response.

This mirrors the audit-forward fix in #1506 / #1502 — itself following
#b3c71e9a4d25 (#1364). Every value is copied into a new
``headers_encrypted`` ``LargeBinary`` column, serialised with the same
``encrypt_dict`` every other dict-shaped ``*_encrypted`` column uses
(``auth_provider.secrets_encrypted``, cloud credentials), and the
application stops reading or writing the plaintext column. The dict
itself is unchanged, so deliveries keep sending the same headers.

The plaintext column is NOT dropped here: this is the expand half of the
expand/contract contract (#296). During a rolling upgrade the old api
pods still select it on every subscription read and would fail until
replaced. It is already nullable (JSONB, no server default), unlike the
#1506 pair. The contract half drops it in the following release. Until
then it holds the pre-upgrade values, unread; the "exclude secrets"
scrubber writes NULL into it via ``LEGACY_PLAINTEXT_SECRET_COLUMNS``.

Importing ``app.core.crypto`` is deliberate, as in ``b3c71e9a4d25``: the
ciphertext has to be exactly what the application reads back, under the
install's own key, and the restore order (migrate in phase 6,
cross-install rewrap in phase 7) handles a value already under the
local key.

Originally branched off 61566a119901; reparented onto
e51ab0dede3e when #1506 merged first, to keep a single head.
The two migrations touch different tables, so the order is
immaterial.

Revision ID: d27e1d8716bd
Revises: 6293ba5af00e
Create Date: 2026-10-04
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "d27e1d8716bd"
down_revision = "6293ba5af00e"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.crypto import encrypt_dict

    op.add_column(
        "event_subscription",
        sa.Column("headers_encrypted", sa.LargeBinary(), nullable=True),
    )
    conn = op.get_bind()
    rows = conn.execute(
        sa.text(
            "SELECT id, headers FROM event_subscription "
            "WHERE headers IS NOT NULL AND headers <> '{}'::jsonb"
        )
    ).all()
    for row_id, headers in rows:
        # JSONB comes back as a dict via SQLAlchemy; a driver change
        # could hand back raw text instead, so accept both.
        if isinstance(headers, str):
            import json

            headers = json.loads(headers)
        if not headers:
            continue
        conn.execute(
            sa.text("UPDATE event_subscription SET headers_encrypted = :value WHERE id = :id"),
            {"value": encrypt_dict(dict(headers)), "id": row_id},
        )


def downgrade() -> None:
    import json

    from app.core.crypto import decrypt_dict

    # The plaintext column was kept. Copy the current values back, in
    # case they were changed since the upgrade, then drop the encrypted
    # column. A row whose headers were cleared since the upgrade has no
    # encrypted value but may still hold its pre-upgrade plaintext:
    # clear that first, or the downgrade sends the cleared credential
    # again.
    conn = op.get_bind()
    conn.execute(
        sa.text("UPDATE event_subscription SET headers = NULL WHERE headers_encrypted IS NULL")
    )
    rows = conn.execute(
        sa.text(
            "SELECT id, headers_encrypted FROM event_subscription "
            "WHERE headers_encrypted IS NOT NULL"
        )
    ).all()
    for row_id, token in rows:
        try:
            headers = decrypt_dict(bytes(token))
        except ValueError:
            # Not readable under this install's key: leave the plaintext
            # column as it was.
            continue
        conn.execute(
            sa.text("UPDATE event_subscription SET headers = CAST(:value AS jsonb) WHERE id = :id"),
            {"value": json.dumps(headers), "id": row_id},
        )
    op.drop_column("event_subscription", "headers_encrypted")
