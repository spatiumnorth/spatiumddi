"""Alembic upgrade-on-restore (issue #117 Phase 2).

When an operator restores an archive whose ``schema_version`` is
older than the local install's expected head, the destination's
freshly-restored database is at the source's schema head — every
migration that landed between source and destination is missing.
Without this step the operator has to ``docker compose exec api
alembic upgrade head`` manually before the install boots cleanly.

The flow:

1. After the data replay phase, read the local install's expected
   head from the alembic ``ScriptDirectory`` (NOT from the database
   — the DB is now at the source's head). Single-head schemas only;
   multi-head environments aren't on the supported matrix.
2. Compare against ``manifest.schema_version``:
     - equal → no-op, ``state="up_to_date"``
     - source head is an ancestor of local head → run
       ``alembic upgrade head`` against the freshly-restored DB,
       capture the ladder of revisions that ran. ``state="upgraded"``.
     - source head not in the local script chain → operator's
       destination install is OLDER than the source. Don't run
       anything; surface ``state="incompatible_newer"`` so the
       operator knows the schema in the database is ahead of this
       install's code.
     - upgrade fails on an object that "already exists" → the
       signature of a stale ``alembic_version`` over a schema that is
       already at head. ``alembic stamp head`` runs only after every
       table and column head declares is found in the database
       (``state="auto_recovered"``); otherwise ``state="failed"``,
       naming what is missing, and ``alembic_version`` is left where
       the upgrade stopped (#1233).
     - source head is missing from the manifest entirely → an old
       Phase 1 archive that didn't carry ``schema_version``.
       ``state="unknown"`` — operator gets a heads-up, no upgrade
       attempt.

Failures of the upgrade subprocess itself are logged and surfaced
via ``state="failed"`` + ``error`` rather than raised — the data
is in. The operator can re-run ``alembic upgrade head`` manually
once they've fixed whatever blocked the migration.
"""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import structlog
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.services.backup.archive import _pg_env_from_url

logger = structlog.get_logger(__name__)


def _alembic_ini() -> Path | None:
    """Locate ``alembic.ini`` for the running process.

    Delegates to the shared locator rather than hardcoding ``/app``: the
    file is at ``/app/alembic.ini`` in the container image but at
    ``./alembic.ini`` under CI and a dev host venv. Hardcoding the
    container path made `schema_direction_error` return None — i.e.
    "direction is fine, proceed" — everywhere else, silently disabling
    the #781 gate rather than erring toward refusal.
    """
    from app.core.schema_check import _locate_alembic_ini  # noqa: PLC0415

    return _locate_alembic_ini()


_ALEMBIC_TIMEOUT_SECONDS = 30 * 60

MigrationState = Literal[
    "up_to_date",
    "upgraded",
    "auto_recovered",
    "incompatible_newer",
    "unknown",
    "failed",
]


# Patterns alembic / asyncpg / psql emit when a revision meets an
# object it would create. After a restore that is the signature of a
# stale ``alembic_version`` over a schema already at head — but only
# the signature: head is stamped only once the schema is verified to
# carry what head declares (#1233).
_DRIFT_ERROR_PATTERNS = (
    "DuplicateTableError",
    "DuplicateColumnError",
    "DuplicateObjectError",
    "already exists",
)


@dataclass
class MigrationOutcome:
    """Result of the alembic upgrade-on-restore pass."""

    state: MigrationState
    source_head: str | None
    local_head: str | None
    migrations_applied: list[str]
    error: str | None = None


def _local_head() -> str | None:
    """Return the local install's expected single alembic head.

    Reads from the on-disk script directory, NOT the database (the
    database is at the source's head right after restore). Returns
    None when the script directory carries multiple heads — the
    upgrade-on-restore flow doesn't try to disambiguate; operators
    on multi-head schemas resolve manually.
    """
    ini = _alembic_ini()
    if ini is None:
        return None
    cfg = Config(str(ini))
    script = ScriptDirectory.from_config(cfg)
    heads = script.get_heads()
    if len(heads) != 1:
        return None
    return heads[0]


def _is_ancestor(script: ScriptDirectory, ancestor: str, descendant: str) -> bool:
    """Return True when ``ancestor`` appears anywhere in the
    revision chain leading to ``descendant``. ``iterate_revisions``
    walks descendant → ancestor via ``down_revision`` links.
    """
    if ancestor == descendant:
        return True
    try:
        for rev in script.iterate_revisions(descendant, "base"):
            if rev.revision == ancestor:
                return True
    except Exception:  # noqa: BLE001
        # Unknown revision id, branched chain, etc.
        return False
    return False


def _migrations_between(script: ScriptDirectory, source: str, target: str) -> list[str]:
    """Return the ordered (oldest → newest) list of revision ids
    that will run on ``alembic upgrade head`` from ``source`` to
    ``target``. Best-effort — failure to walk falls back to an
    empty list so the outcome carries a clear "we ran upgrade but
    don't know which revisions" rather than aborting.
    """
    try:
        revs = list(script.iterate_revisions(target, source))
    except Exception:  # noqa: BLE001
        return []
    # ``iterate_revisions`` yields newest → oldest; reverse so the
    # response shows the order migrations actually run.
    return [r.revision for r in reversed(revs) if r.revision != source]


def schema_direction_error(source_head: str | None) -> str | None:
    """Return an error if this build cannot migrate ``source_head`` forward.

    Callable BEFORE anything destructive happens. ``maybe_upgrade_after_
    restore`` performs the same test, but only after the dump has already
    been replayed — at which point refusing is theatre: the database has
    been overwritten, ``alembic_version`` sits ahead of the running code,
    and the api's schema-head readiness gate keeps the pod out of the
    Service until someone upgrades or restores something older (#781).

    Returns None when the direction is fine (same head, an ancestor we can
    upgrade, or a manifest that never recorded one).
    """
    source_head = (str(source_head).strip() if source_head is not None else "") or None
    if not source_head:
        return None  # pre-format_version-2 archive; nothing to compare
    local_head = _local_head()
    if local_head is None:
        # FAIL CLOSED. This gate exists to protect the database that is
        # already here, and the archive has told us it carries a specific
        # schema. If we cannot read our own head — alembic.ini unlocatable,
        # or a multi-head tree we will not disambiguate — we cannot know the
        # direction, and proceeding is the outcome that destroys data.
        return (
            "Cannot verify this archive's schema direction: this install's own "
            "alembic head is unreadable (alembic.ini not found, or the migration "
            f"tree has multiple heads), while the archive declares {source_head!r}. "
            "Refusing rather than risk overwriting the database with a schema this "
            "build cannot migrate."
        )
    if source_head == local_head:
        return None
    ini = _alembic_ini()
    if ini is None:
        return None
    script = ScriptDirectory.from_config(Config(str(ini)))
    if _is_ancestor(script, source_head, local_head):
        return None
    return (
        f"This archive was taken on a NEWER schema than this install: its head "
        f"{source_head!r} is not an ancestor of {local_head!r}. Restoring it would "
        f"overwrite the database with data this build cannot migrate, leaving the "
        f"api unable to start. Upgrade SpatiumDDI on this install first, then "
        f"re-run the restore."
    )


async def maybe_upgrade_after_restore(
    *,
    manifest_schema_version: str | None,
    db_url: str,
) -> MigrationOutcome:
    """Walk the alembic skew check + run ``alembic upgrade head``
    if the source is on an older head. Idempotent; safe to call
    on a same-or-newer source (no-op + diagnostic state).
    """
    local_head = _local_head()
    source_head = (manifest_schema_version or "").strip() or None

    if source_head is None:
        return MigrationOutcome(
            state="unknown",
            source_head=None,
            local_head=local_head,
            migrations_applied=[],
            error="archive manifest has no schema_version",
        )
    if local_head is None:
        return MigrationOutcome(
            state="unknown",
            source_head=source_head,
            local_head=None,
            migrations_applied=[],
            error="local alembic head is ambiguous (multiple heads or no alembic.ini)",
        )
    if source_head == local_head:
        return MigrationOutcome(
            state="up_to_date",
            source_head=source_head,
            local_head=local_head,
            migrations_applied=[],
        )

    ini = _alembic_ini()
    cfg = Config(str(ini) if ini else "alembic.ini")
    script = ScriptDirectory.from_config(cfg)

    if not _is_ancestor(script, source_head, local_head):
        # Source's head isn't in our chain → either it's newer than
        # what this build knows about, or it came from a branched /
        # forked schema. Either way, we can't safely upgrade.
        return MigrationOutcome(
            state="incompatible_newer",
            source_head=source_head,
            local_head=local_head,
            migrations_applied=[],
            error=(
                f"source schema head {source_head!r} is not an ancestor of this "
                f"install's expected head {local_head!r}. The destination install "
                "is older than the source — upgrade SpatiumDDI on this destination, "
                "then re-run the restore."
            ),
        )

    # Source is on a known older head. Run ``alembic upgrade head``.
    planned = _migrations_between(script, source_head, local_head)

    pg_env, _dbname = _pg_env_from_url(db_url)
    full_env = {**os.environ, **pg_env, "DATABASE_URL": db_url}
    cmd = [
        "alembic",
        "-c",
        str(_alembic_ini() or "alembic.ini"),
        "upgrade",
        "head",
    ]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        env=full_env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=_ALEMBIC_TIMEOUT_SECONDS
        )
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return MigrationOutcome(
            state="failed",
            source_head=source_head,
            local_head=local_head,
            migrations_applied=[],
            error=f"alembic upgrade timed out after {_ALEMBIC_TIMEOUT_SECONDS}s",
        )

    if proc.returncode != 0:
        output = stderr.decode(errors="replace") or stdout.decode(errors="replace")
        # The TAIL: alembic logs one INFO line per revision before the
        # traceback, so on a long ladder the first 1500 characters hold
        # only those, and the exception — the part worth reading, and
        # the part the drift match below looks for — was cut off.
        msg = output[-1500:]
        logger.error(
            "backup_restore_alembic_upgrade_failed",
            source_head=source_head,
            local_head=local_head,
            stderr=msg,
        )

        # Drift-recovery path. The dump just restored carries the
        # source's ``alembic_version`` row, which can be stale
        # relative to the *schema* the dump emits — pg_dump
        # captures whatever DDL is present regardless of the
        # alembic_version value. Concretely: if a backup was
        # taken when alembic_version had drifted (operator ran
        # ``alembic stamp`` to fix an earlier inconsistency, then
        # later restored from a backup taken before that fix),
        # the restore brings back BOTH the up-to-date schema AND
        # the stale alembic_version. ``alembic upgrade head`` then
        # fails on the first migration with "table already exists".
        #
        # "already exists" is only the SIGNATURE of that case, not
        # proof of it (#1233): any revision that meets one object it
        # would create fails the same way, from any revision. With
        # one transaction per revision (#1204) everything before it
        # stays committed and everything after it never ran, so
        # stamping head on the signature alone records a partially
        # migrated schema as current. Stamp only once the schema is
        # shown to carry what head declares; otherwise leave
        # ``alembic_version`` where the upgrade stopped, so a manual
        # ``alembic upgrade head`` resumes from the right place.
        if any(p in output for p in _DRIFT_ERROR_PATTERNS):
            failed_at = _failing_revision(output)
            verdict = await _verify_schema_at_head(db_url)
            if not verdict.ok:
                logger.error(
                    "backup_restore_alembic_drift_unverified",
                    source_head=source_head,
                    local_head=local_head,
                    failed_at=failed_at,
                    stopped_at=verdict.version_num,
                    missing_tables=verdict.missing_tables[:20],
                    missing_columns=verdict.missing_columns[:20],
                    check_error=verdict.error,
                )
                return MigrationOutcome(
                    state="failed",
                    source_head=source_head,
                    local_head=local_head,
                    migrations_applied=[],
                    error=_unverified_drift_error(
                        msg=msg,
                        failed_at=failed_at,
                        local_head=local_head,
                        verdict=verdict,
                    ),
                )
            stamp_ok, stamp_err = await _try_alembic_stamp_head(db_url)
            if stamp_ok:
                logger.info(
                    "backup_restore_alembic_drift_recovered",
                    source_head=source_head,
                    local_head=local_head,
                    failed_at=failed_at,
                )
                return MigrationOutcome(
                    state="auto_recovered",
                    source_head=source_head,
                    local_head=local_head,
                    migrations_applied=[],
                    error=(
                        "alembic_version was stale: the upgrade stopped on an "
                        "object that already exists"
                        + (f" (revision {failed_at!r})" if failed_at else "")
                        + f", and every table and column {local_head!r} declares "
                        "is present in the restored schema, so head was stamped "
                        "to align. No migrations actually ran."
                    ),
                )
            return MigrationOutcome(
                state="failed",
                source_head=source_head,
                local_head=local_head,
                migrations_applied=[],
                error=(
                    f"alembic upgrade failed and stamp-head recovery also "
                    f"failed. Upgrade error: {msg}; stamp error: {stamp_err}"
                ),
            )

        return MigrationOutcome(
            state="failed",
            source_head=source_head,
            local_head=local_head,
            migrations_applied=[],
            error=f"alembic upgrade failed (exit {proc.returncode}): {msg}",
        )

    logger.info(
        "backup_restore_alembic_upgrade_applied",
        source_head=source_head,
        local_head=local_head,
        planned=planned,
    )
    return MigrationOutcome(
        state="upgraded",
        source_head=source_head,
        local_head=local_head,
        migrations_applied=planned,
    )


# ``alembic`` logs each revision to stderr as it starts it:
#   INFO  [alembic.runtime.migration] Running upgrade a1b2 -> c3d4, message
_RUNNING_UPGRADE_RE = re.compile(r"Running upgrade .*?-> ([0-9A-Za-z_]+)")


def _failing_revision(output: str) -> str | None:
    """Return the revision ``alembic upgrade`` was running when it failed.

    That is the last one it announced: a revision is logged before its
    DDL runs, and the upgrade stops at the first that raises. None when
    the output carries no announcement (it failed before the first one).
    """
    found = _RUNNING_UPGRADE_RE.findall(output)
    return found[-1] if found else None


@dataclass
class SchemaVerdict:
    """Does the database carry every table and column head declares?

    ``ok`` is True only when the check RAN and found nothing missing;
    a check that could not run is ``ok=False`` with ``error`` set, so
    the caller fails closed rather than stamping on no evidence.
    """

    ok: bool
    missing_tables: list[str]
    missing_columns: list[str]
    version_num: str | None = None
    error: str | None = None


def _missing_objects(sync_conn, metadata) -> tuple[list[str], list[str]]:
    """Tables and ``table.column`` pairs ``metadata`` declares that the
    connected database lacks.

    Deliberately one-directional, and limited to tables and columns.
    What head declares must exist: a revision that stopped short leaves
    exactly that missing, and it is the evidence that holds on a database
    migrated cleanly to head. The reverse direction does not: measured on
    a database at head, the models omit a column the initial schema still
    carries (``subnet.ntp_servers``) and index / constraint names differ
    in dozens of places, so a full ``compare_metadata`` would refuse the
    very case this recovery exists for.
    """
    insp = inspect(sync_conn)
    missing_tables: list[str] = []
    missing_columns: list[str] = []
    by_schema: dict[str | None, list] = {}
    for table in metadata.tables.values():
        by_schema.setdefault(table.schema, []).append(table)
    for schema, tables in by_schema.items():
        present = set(insp.get_table_names(schema=schema))
        columns = insp.get_multi_columns(schema=schema)
        for table in sorted(tables, key=lambda t: t.name):
            label = f"{schema}.{table.name}" if schema else table.name
            if table.name not in present:
                missing_tables.append(label)
                continue
            have = {c["name"] for c in columns.get((schema, table.name), [])}
            missing_columns.extend(
                f"{label}.{col.name}" for col in table.columns if col.name not in have
            )
    return missing_tables, missing_columns


async def _verify_schema_at_head(db_url: str) -> SchemaVerdict:
    """Check the restored database against the models this build ships.

    ``app.core.schema_check`` cannot answer this: it compares
    ``alembic_version`` with the bundled head, and that row is exactly
    what is stale here, and what a stamp would overwrite (#1233).
    """
    from app.models import Base  # noqa: PLC0415 — registers every mapped table

    engine = create_async_engine(db_url, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            tables, columns = await conn.run_sync(_missing_objects, Base.metadata)
            # Informational only: where the upgrade stopped, for the
            # operator. Read after the check, and only if the table
            # exists, so its absence cannot abort the transaction the
            # check runs in.
            version_num = None
            if await conn.run_sync(lambda c: inspect(c).has_table("alembic_version")):
                row = (await conn.execute(text("SELECT version_num FROM alembic_version"))).first()
                version_num = row[0] if row else None
    except Exception as exc:  # noqa: BLE001 — any failure means "not verified"
        first_line = (str(exc).splitlines() or [""])[0][:300]
        return SchemaVerdict(
            ok=False,
            missing_tables=[],
            missing_columns=[],
            error=f"{type(exc).__name__}: {first_line}",
        )
    finally:
        await engine.dispose()
    return SchemaVerdict(
        ok=not tables and not columns,
        missing_tables=tables,
        missing_columns=columns,
        version_num=version_num,
    )


def _unverified_drift_error(
    *, msg: str, failed_at: str | None, local_head: str, verdict: SchemaVerdict
) -> str:
    """Operator-facing reason the drift recovery refused to stamp head."""
    where = f"at revision {failed_at!r} " if failed_at else ""
    if verdict.error is not None:
        why = (
            f"the restored schema could not be checked against {local_head!r} "
            f"({verdict.error}), so head was NOT stamped."
        )
    else:
        shown: list[str] = []
        if verdict.missing_tables:
            names = ", ".join(verdict.missing_tables[:10])
            more = len(verdict.missing_tables) - 10
            shown.append(f"tables {names}" + (f" and {more} more" if more > 0 else ""))
        if verdict.missing_columns:
            names = ", ".join(verdict.missing_columns[:10])
            more = len(verdict.missing_columns) - 10
            shown.append(f"columns {names}" + (f" and {more} more" if more > 0 else ""))
        why = (
            f"the restored schema is NOT at {local_head!r}: it lacks "
            + "; ".join(shown)
            + ". Head was NOT stamped, because that would record a partially "
            "migrated schema as current."
        )
    stopped = (
        f" alembic_version is at {verdict.version_num!r}, the last revision that "
        "committed, so `alembic upgrade head` resumes from there once the "
        "conflicting object is dealt with."
        if verdict.version_num
        else ""
    )
    return (
        f"alembic upgrade stopped {where}on an object that already exists, and "
        f"{why}{stopped} Upgrade error: {msg}"
    )


async def _try_alembic_stamp_head(db_url: str) -> tuple[bool, str | None]:
    """Run ``alembic stamp head`` against the configured database.
    Returns ``(success, error_message)``. Used to recover from
    schema-vs-alembic-version drift after a restore.
    """
    pg_env, _dbname = _pg_env_from_url(db_url)
    full_env = {**os.environ, **pg_env, "DATABASE_URL": db_url}
    cmd = ["alembic", "-c", str(_alembic_ini() or "alembic.ini"), "stamp", "head"]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        env=full_env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=_ALEMBIC_TIMEOUT_SECONDS
        )
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return False, f"alembic stamp timed out after {_ALEMBIC_TIMEOUT_SECONDS}s"
    if proc.returncode != 0:
        msg = (stderr.decode(errors="replace") or stdout.decode(errors="replace"))[-500:]
        return False, f"alembic stamp head failed (exit {proc.returncode}): {msg}"
    return True, None
