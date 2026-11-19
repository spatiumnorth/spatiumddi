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
``*_encrypted`` column — only where that column is empty — leaves every target
it wrote into disabled with an audit row saying why, and drops the column
again. The contract migration runs the same :func:`fold_plaintext_columns`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import structlog
from sqlalchemy import Connection, inspect, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.db import task_connect_args

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


# table -> (enabled column, label column or None). The legacy single webhook
# is one ``platform_settings`` row with no name of its own.
_ENABLED_COLUMN: dict[str, tuple[str, str | None]] = {
    "audit_forward_target": ("enabled", "name"),
    "platform_settings": ("audit_forward_webhook_enabled", None),
}

# Carried in the audit row's ``new_value`` so the rows are findable.
FOLDED_DISABLED_REASON = "webhook_value_restored_from_plaintext_column"


@dataclass(frozen=True)
class FoldedTarget:
    """A forward target (or the Settings webhook) whose URL or header was
    filled from a leftover plaintext column, and which was left disabled."""

    table: str
    row_id: str
    name: str | None
    was_enabled: bool

    @property
    def display(self) -> str:
        if self.table == "platform_settings":
            return "Settings webhook"
        return self.name or self.row_id


@dataclass
class FoldResult:
    values: int = 0
    disabled: list[FoldedTarget] = field(default_factory=list)
    # Whether the audit rows for ``disabled`` were written.
    audit_recorded: bool = False


def fold_plaintext_columns(sync_conn: Connection) -> FoldResult:
    """The fold both the contract migration and a selective restore run.

    For every dropped plaintext column still present beside its encrypted
    column: encrypt a value left in it into the encrypted column when that
    is empty (NULL, or the empty bytea an "exclude secrets" restore writes),
    then drop the plaintext column. An encrypted value already there is left
    alone.

    A value written back this way comes from a column the application has
    not read since encryption at rest, so it may be one an admin has since
    cleared: on a build that blanked nothing on a clear, a cleared value left
    the old plaintext beside a NULL ciphertext, which is the same state as one
    never rewritten. Every row it writes into is therefore left DISABLED and
    returned, so the caller records it (:func:`disabled_audit_rows`) and an
    admin turns it back on knowingly. A row it does not write into is left
    exactly as it is. Runs in the caller's transaction.
    """
    from app.core.crypto import encrypt_str  # noqa: PLC0415

    result = FoldResult()
    tables = sorted({t for t, *_ in DROPPED_PLAINTEXT_SECRET_COLUMNS})
    present = _existing_columns(sync_conn, tables)
    touched: dict[tuple[str, Any], None] = {}
    for table, plain, encrypted, _type in DROPPED_PLAINTEXT_SECRET_COLUMNS:
        if plain not in present[table] or encrypted not in present[table]:
            continue
        rows = sync_conn.execute(
            text(
                f"SELECT id, {plain} FROM {table} "  # noqa: S608
                f"WHERE {plain} IS NOT NULL AND {plain} <> '' "
                f"AND ({encrypted} IS NULL OR octet_length({encrypted}) = 0)"
            )
        ).all()
        for row_id, value in rows:
            sync_conn.execute(
                text(f"UPDATE {table} SET {encrypted} = :v WHERE id = :id"),  # noqa: S608
                {"v": encrypt_str(value), "id": row_id},
            )
            touched[(table, row_id)] = None
        result.values += len(rows)
        sync_conn.execute(text(f'ALTER TABLE "{table}" DROP COLUMN "{plain}"'))

    for table, row_id in touched:
        flag, label = _ENABLED_COLUMN[table]
        cols = f"{flag}, {label}" if label else flag
        row = sync_conn.execute(
            text(f"SELECT {cols} FROM {table} WHERE id = :id"),  # noqa: S608
            {"id": row_id},
        ).one()
        sync_conn.execute(
            text(f"UPDATE {table} SET {flag} = false WHERE id = :id"),  # noqa: S608
            {"id": row_id},
        )
        result.disabled.append(
            FoldedTarget(
                table=table,
                row_id=str(row_id),
                name=(row[1] if label else None),
                was_enabled=bool(row[0]),
            )
        )
    return result


def disabled_audit_rows(disabled: list[FoldedTarget], *, source: str) -> list[Any]:
    """One ``AuditLog`` row per target the fold left disabled. ``source``
    names the path that ran the fold."""
    from app.models.audit import AuditLog  # noqa: PLC0415

    rows = []
    for t in disabled:
        flag = _ENABLED_COLUMN[t.table][0]
        rows.append(
            AuditLog(
                user_id=None,
                user_display_name="system",
                auth_source="system",
                action="update",
                resource_type=t.table,
                resource_id=t.row_id,
                resource_display=t.display,
                result="success",
                changed_fields=[flag],
                old_value={flag: t.was_enabled},
                new_value={
                    flag: False,
                    "reason": FOLDED_DISABLED_REASON,
                    "source": source,
                    "detail": (
                        "Its URL or auth header was restored from a column kept from "
                        "an older build, which may hold a value that was cleared. "
                        "Left disabled; re-enable it once the endpoint is confirmed."
                    ),
                },
            )
        )
    return rows


def record_disabled_sync(
    sync_conn: Connection, disabled: list[FoldedTarget], *, source: str
) -> bool:
    """Write :func:`disabled_audit_rows` on ``sync_conn`` in a savepoint of
    the caller's transaction, for the contract migration. Returns False, and
    leaves the caller's transaction intact, if they cannot be written."""
    if not disabled:
        return True
    try:
        with Session(bind=sync_conn, join_transaction_mode="create_savepoint") as session:
            session.add_all(disabled_audit_rows(disabled, source=source))
            session.commit()
    except Exception as exc:  # noqa: BLE001 — the fold and the disable stand
        logger.warning("legacy_plaintext_fold_audit_failed", error=str(exc))
        return False
    return True


def disabled_warning(names: list[str]) -> str:
    """The restore warning naming the targets left disabled."""
    return (
        f"{len(names)} audit forward target(s) had a URL or auth header restored "
        "from a column kept from an older build, which may hold a value that was "
        f"cleared, and were left disabled: {', '.join(names)}. Re-enable each once "
        "its endpoint is confirmed."
    )


async def disabled_since(db_url: str, since: datetime) -> list[str]:
    """Targets the fold left disabled, by the audit rows written at or after
    ``since`` — so a restore can report the ones its own upgrade step's
    migration disabled, which ran in a subprocess whose output is not kept."""
    engine = create_async_engine(db_url, poolclass=NullPool, connect_args=task_connect_args())
    try:
        async with engine.connect() as conn:
            rows = await conn.execute(
                text(
                    "SELECT resource_display FROM audit_log "
                    "WHERE new_value->>'reason' = :reason AND timestamp >= :since "
                    "ORDER BY seq"
                ),
                {"reason": FOLDED_DISABLED_REASON, "since": since},
            )
            return [r[0] for r in rows]
    finally:
        await engine.dispose()


async def fold_dropped_plaintext_columns(db_url: str) -> FoldResult:
    """:func:`fold_plaintext_columns` over ``db_url`` in one transaction, then
    an audit row per target it left disabled, committed through an ordinary
    session once the disable is.

    Acts only where BOTH columns exist: a database a failed post-restore
    upgrade left before the expand migration has no encrypted column to fill,
    and the contract migration (which skips a column already dropped) will do
    this itself when the upgrade is re-run.
    """
    from app.db import _json_serializer  # noqa: PLC0415

    engine = create_async_engine(
        db_url,
        poolclass=NullPool,
        json_serializer=_json_serializer,
        connect_args=task_connect_args(),
    )
    try:
        async with engine.begin() as conn:
            result = await conn.run_sync(fold_plaintext_columns)
        if result.disabled:
            try:
                async with AsyncSession(engine) as db:
                    db.add_all(disabled_audit_rows(result.disabled, source="backup_restore"))
                    await db.commit()
                result.audit_recorded = True
            except Exception as exc:  # noqa: BLE001 — the disable is committed
                logger.warning("legacy_plaintext_fold_audit_failed", error=str(exc))
    finally:
        await engine.dispose()
    if result.values:
        logger.info("backup_restore_legacy_plaintext_folded", values=result.values)
    for t in result.disabled:
        logger.warning(
            "backup_restore_legacy_plaintext_target_disabled",
            table=t.table,
            id=t.row_id,
            name=t.name,
            audit_recorded=result.audit_recorded,
        )
    return result
