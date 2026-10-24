"""Drop the plaintext webhook forward-target columns (contract half of #1502).

``e51ab0dede3e`` copied ``audit_forward_target.url`` / ``auth_header`` and the
legacy single-webhook pair on ``platform_settings``
(``audit_forward_webhook_url`` / ``audit_forward_webhook_auth_header``) into
Fernet-encrypted ``*_encrypted`` columns and stopped reading them, but kept
them for one release so a rolling upgrade's old pods kept working (#296).
That release has shipped; this drops them. Its pods are safe against the
drop during a rolling upgrade: they map neither column, and the one place they
write them (blanking a leftover when a secret is replaced) checks the column
exists first.

Before each drop, a plaintext value still present is encrypted into its
``*_encrypted`` column when that column is empty (NULL, or the empty bytea an
"exclude secrets" restore writes). An encrypted value already there is left
alone: it is what the application has been reading since ``e51ab0dede3e``,
and a plaintext column a pre-upgrade pod wrote afterwards is no newer by any
measure the row records. Importing ``app.core.crypto`` is deliberate, as in
``e51ab0dede3e``: the ciphertext must be exactly what the application reads
back, under the install's own key.

A value the fold writes back is restored from a column the application has
not read since ``e51ab0dede3e``, so it may be one an admin has since cleared:
on a build that blanked nothing on a clear, a cleared value left the old
plaintext in place beside a NULL ciphertext, which is the same state as one
never rewritten. So every target the fold writes into is left DISABLED
(``audit_forward_target.enabled``; for the legacy single webhook,
``platform_settings.audit_forward_webhook_enabled``), and its id and name are
logged, so an admin turns it back on knowingly instead of audit events
starting to flow to an endpoint that may have been removed. A row the fold does
not write into is left exactly as it is.

Each column is dropped only if present, so a schema built from the models (a
test database, a fresh install that never ran ``e51ab0dede3e``'s expand) and
a database a selective restore has already folded
(``app.services.backup.legacy_columns``) both upgrade cleanly.

The downgrade re-adds the columns nullable with a ``''`` default — the shape
``e51ab0dede3e`` left them in — and EMPTY: the values stay in the encrypted
columns, which is all the previous release reads, and ``e51ab0dede3e``'s own
downgrade copies them back into the clear if the install goes further back.

Revision ID: c2b203844c95
Revises: a3c7e91f2d58
Create Date: 2026-10-23
"""

from __future__ import annotations

import logging
from typing import Any

import sqlalchemy as sa

from alembic import op

logger = logging.getLogger("alembic.runtime.migration")

revision = "c2b203844c95"
down_revision = "a3c7e91f2d58"
branch_labels = None
depends_on = None

# (table, plaintext column, encrypted column). Identifiers come only from here.
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


def _columns(conn: sa.engine.Connection, table: str) -> set[str]:
    return {c["name"] for c in sa.inspect(conn).get_columns(table)}


# table -> (enabled column, label column or None). The legacy webhook is one
# row (id 1) with no name of its own.
_ENABLED: dict[str, tuple[str, str | None]] = {
    "audit_forward_target": ("enabled", "name"),
    "platform_settings": ("audit_forward_webhook_enabled", None),
}


def upgrade() -> None:
    from app.core.crypto import encrypt_str

    conn = op.get_bind()
    rearmed: dict[tuple[str, Any], None] = {}
    for table, plain, encrypted in _PAIRS:
        if plain not in _columns(conn, table):
            continue
        rows = conn.execute(
            sa.text(
                f"SELECT id, {plain} FROM {table} "  # noqa: S608
                f"WHERE {plain} IS NOT NULL AND {plain} <> '' "
                f"AND ({encrypted} IS NULL OR octet_length({encrypted}) = 0)"
            )
        ).all()
        for row_id, value in rows:
            conn.execute(
                sa.text(f"UPDATE {table} SET {encrypted} = :value WHERE id = :id"),  # noqa: S608
                {"value": encrypt_str(value), "id": row_id},
            )
            rearmed[(table, row_id)] = None
        op.drop_column(table, plain)

    for table, row_id in rearmed:
        flag, label = _ENABLED[table]
        name = ""
        if label is not None:
            name = conn.execute(
                sa.text(f"SELECT {label} FROM {table} WHERE id = :id"),  # noqa: S608
                {"id": row_id},
            ).scalar_one_or_none()
        conn.execute(
            sa.text(f"UPDATE {table} SET {flag} = false WHERE id = :id"),  # noqa: S608
            {"id": row_id},
        )
        logger.warning(
            "c2b203844c95: restored a plaintext webhook value into %s id=%s%s and "
            "left it disabled; re-enable it once the endpoint is confirmed",
            table,
            row_id,
            f" name={name!r}" if name else "",
        )


def downgrade() -> None:
    conn = op.get_bind()
    for table, plain, _encrypted in _PAIRS:
        if plain in _columns(conn, table):
            continue
        op.add_column(
            table,
            sa.Column(plain, sa.String(length=1024), nullable=True, server_default=""),
        )
