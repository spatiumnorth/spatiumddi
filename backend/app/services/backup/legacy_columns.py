"""Restoring an archive that still carries columns a migration has dropped.

A contract migration that drops a column breaks a *selective* restore of any
archive taken before it: ``pg_restore --data-only`` emits a ``COPY`` naming
every column the archive's table had, and PostgreSQL refuses a ``COPY`` into a
column that no longer exists — so the whole selective restore rolls back. A
full restore is unaffected: it recreates the archive's schema and the
post-restore ``alembic upgrade`` runs the contract migration over it.

For the plaintext secret columns listed here, the selective prelude re-adds
each one (nullable, ``IF NOT EXISTS``) to the tables it reloads, so the
archive's rows load as they were; after the post-restore migration step,
:func:`fold_dropped_plaintext_columns` encrypts any value left in one into its
``*_encrypted`` column — only where that column is empty, exactly as the
contract migration does — and drops the column again.
"""

from __future__ import annotations

import structlog
from sqlalchemy import Connection, inspect, text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

logger = structlog.get_logger(__name__)

# (table, dropped plaintext column, encrypted column, plaintext column's SQL
# type). Mirrors ``_PAIRS`` in migration ``c2b203844c95``, which dropped them.
DROPPED_PLAINTEXT_SECRET_COLUMNS: tuple[tuple[str, str, str, str], ...] = (
    ("audit_forward_target", "url", "url_encrypted", "varchar(1024)"),
    ("audit_forward_target", "auth_header", "auth_header_encrypted", "varchar(1024)"),
    (
        "platform_settings",
        "audit_forward_webhook_url",
        "audit_forward_webhook_url_encrypted",
        "varchar(1024)",
    ),
    (
        "platform_settings",
        "audit_forward_webhook_auth_header",
        "audit_forward_webhook_auth_header_encrypted",
        "varchar(1024)",
    ),
)


def selective_readd_sql(tables: list[str]) -> str:
    """``ALTER TABLE … ADD COLUMN IF NOT EXISTS`` for every dropped column on a
    table the selective restore reloads, so an older archive's ``COPY`` loads."""
    wanted = set(tables)
    return "".join(
        f'ALTER TABLE "public"."{table}" ADD COLUMN IF NOT EXISTS "{plain}" {sql_type};\n'
        for table, plain, _enc, sql_type in DROPPED_PLAINTEXT_SECRET_COLUMNS
        if table in wanted
    )


def _existing_columns(sync_conn: Connection, tables: list[str]) -> dict[str, set[str]]:
    insp = inspect(sync_conn)
    return {
        t: ({c["name"] for c in insp.get_columns(t)} if insp.has_table(t) else set())
        for t in tables
    }


async def fold_dropped_plaintext_columns(db_url: str) -> int:
    """Encrypt any value left in a dropped plaintext column into its empty
    ``*_encrypted`` column, then drop the plaintext column. One transaction.

    Acts only where BOTH columns exist: a database a failed post-restore
    upgrade left before the expand migration has no encrypted column to fill,
    and the contract migration (which skips a column already dropped) will do
    this itself when the upgrade is re-run. Returns how many values were
    encrypted.
    """
    from app.core.crypto import encrypt_str  # noqa: PLC0415

    engine = create_async_engine(db_url, poolclass=NullPool)
    folded = 0
    try:
        async with engine.begin() as conn:
            tables = sorted({t for t, *_ in DROPPED_PLAINTEXT_SECRET_COLUMNS})
            present = await conn.run_sync(_existing_columns, tables)
            for table, plain, encrypted, _type in DROPPED_PLAINTEXT_SECRET_COLUMNS:
                if plain not in present[table] or encrypted not in present[table]:
                    continue
                rows = (
                    await conn.execute(
                        text(
                            f"SELECT id, {plain} FROM {table} "  # noqa: S608
                            f"WHERE {plain} IS NOT NULL AND {plain} <> '' "
                            f"AND ({encrypted} IS NULL OR octet_length({encrypted}) = 0)"
                        )
                    )
                ).all()
                for row_id, value in rows:
                    await conn.execute(
                        text(f"UPDATE {table} SET {encrypted} = :v WHERE id = :id"),  # noqa: S608
                        {"v": encrypt_str(value), "id": row_id},
                    )
                folded += len(rows)
                await conn.execute(text(f'ALTER TABLE "{table}" DROP COLUMN "{plain}"'))
    finally:
        await engine.dispose()
    if folded:
        logger.info("backup_restore_legacy_plaintext_folded", values=folded)
    return folded
