"""DNS server group TSIG secret: Fernet-encrypted at rest (#1364).

``dns_server_group.tsig_key_secret`` was the one credential SpatiumDDI
stored in clear. It is not a minor one: the BIND9 agent grants the group key
``allow-update`` and ``allow-transfer`` on every primary zone the group
serves, by key rather than by address, so anyone who reads the database or
an unencrypted backup could transfer and rewrite every zone for as long as
the key was in use.

The value is copied into ``tsig_key_secret_encrypted`` (``LargeBinary``),
encrypted with the same ``encrypt_str`` every other ``*_encrypted`` column
uses, and the application stops reading or writing the plaintext column. The
secret itself is unchanged, so agents keep working with no re-render.

The plaintext column is NOT dropped here: that is the expand half of the
expand/contract contract (#296). During a rolling upgrade of a multi-node
control plane the old api pods still select ``tsig_key_secret`` on every
group read, the agents' config long-poll included, and would fail until
replaced. The contract half drops it in the following release. Until then
it holds the pre-upgrade secret, unread; rotating the group key
(``POST /dns/groups/{id}/group-tsig-key/rotate``) once the upgrade has
finished makes that copy a dead secret.

Importing ``app.core.crypto`` here is deliberate: the ciphertext has to be
exactly what the application reads back, under the install's own key. A
backup restore runs this migration (phase 6) before the cross-install
rewrap (phase 7), which tries the source key, then the local one, and counts
a value already under the local key as done, so values written here survive
a restore from an older archive.

Revision ID: b3c71e9a4d25
Revises: f4a8c2e71d09
Create Date: 2026-10-01
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "b3c71e9a4d25"
down_revision = "f4a8c2e71d09"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.crypto import encrypt_str

    op.add_column(
        "dns_server_group",
        sa.Column("tsig_key_secret_encrypted", sa.LargeBinary(), nullable=True),
    )
    conn = op.get_bind()
    rows = conn.execute(
        sa.text(
            "SELECT id, tsig_key_secret FROM dns_server_group "
            "WHERE tsig_key_secret IS NOT NULL AND tsig_key_secret <> ''"
        )
    ).all()
    for row_id, secret in rows:
        conn.execute(
            sa.text(
                "UPDATE dns_server_group SET tsig_key_secret_encrypted = :value WHERE id = :id"
            ),
            {"value": encrypt_str(secret), "id": row_id},
        )


def downgrade() -> None:
    from app.core.crypto import decrypt_str

    # The plaintext column was kept. Copy the current secret back into it, in
    # case it was rotated since the upgrade, then drop the column this
    # migration added.
    conn = op.get_bind()
    rows = conn.execute(
        sa.text(
            "SELECT id, tsig_key_secret_encrypted FROM dns_server_group "
            "WHERE tsig_key_secret_encrypted IS NOT NULL"
        )
    ).all()
    for row_id, token in rows:
        try:
            secret = decrypt_str(bytes(token))
        except ValueError:
            # Not readable under this install's key: leave the plaintext
            # column as it was.
            continue
        conn.execute(
            sa.text("UPDATE dns_server_group SET tsig_key_secret = :value WHERE id = :id"),
            {"value": secret, "id": row_id},
        )
    op.drop_column("dns_server_group", "tsig_key_secret_encrypted")
