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
measure the row records. The fold is
``app.services.backup.legacy_columns.fold_plaintext_columns``, shared with the
selective restore of an archive taken before this drop so the two paths cannot
disagree; it imports ``app.core.crypto`` deliberately, as ``e51ab0dede3e``
does: the ciphertext must be exactly what the application reads back, under
the install's own key.

A value the fold writes back is restored from a column the application has
not read since ``e51ab0dede3e``, so it may be one an admin has since cleared:
on a build that blanked nothing on a clear, a cleared value left the old
plaintext in place beside a NULL ciphertext, which is the same state as one
never rewritten. So every target the fold writes into is left DISABLED
(``audit_forward_target.enabled``; for the legacy single webhook,
``platform_settings.audit_forward_webhook_enabled``), its id and name are
logged, and an ``audit_log`` row per target records it (the log line goes
with the migrate Job; the audit row stays), so an admin turns it back on
knowingly instead of audit events starting to flow to an endpoint that may
have been removed. A row the fold does not write into is left exactly as it is.

Each column is dropped only if present, so a schema built from the models (a
test database, a fresh install that never ran ``e51ab0dede3e``'s expand) and
a database a selective restore has already folded
(``app.services.backup.legacy_columns``) both upgrade cleanly.

The downgrade re-adds the columns nullable with a ``''`` default — the shape
``e51ab0dede3e`` left them in — and EMPTY: the values stay in the encrypted
columns, which is all the previous release reads, and ``e51ab0dede3e``'s own
downgrade copies them back into the clear if the install goes further back.

Revision ID: c2b203844c95
Revises: c8d3a1f47e92
Create Date: 2026-10-23
"""

from __future__ import annotations

import logging

import sqlalchemy as sa

from alembic import op

logger = logging.getLogger("alembic.runtime.migration")

revision = "c2b203844c95"
down_revision = "c8d3a1f47e92"
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


def upgrade() -> None:
    # The fold is shared with the selective restore of an archive taken
    # before this drop, so the two cannot disagree. The audit row per target
    # it leaves disabled outlives this Job's log.
    from app.services.backup.legacy_columns import (
        fold_plaintext_columns,
        record_disabled_sync,
    )

    conn = op.get_bind()
    result = fold_plaintext_columns(conn)
    recorded = record_disabled_sync(conn, result.disabled, source=f"schema upgrade {revision}")
    for target in result.disabled:
        logger.warning(
            "c2b203844c95: restored a plaintext webhook value into %s id=%s%s and "
            "left it disabled; re-enable it once the endpoint is confirmed",
            target.table,
            target.row_id,
            f" name={target.name!r}" if target.name else "",
        )
    if not recorded:
        logger.warning("c2b203844c95: the audit rows for the targets above were not written")


def downgrade() -> None:
    conn = op.get_bind()
    for table, plain, _encrypted in _PAIRS:
        if plain in _columns(conn, table):
            continue
        op.add_column(
            table,
            sa.Column(plain, sa.String(length=1024), nullable=True, server_default=""),
        )
