"""Apply a backup archive to the running install (issue #117 Phase
1a).

Two shapes:

* **Full restore** (no ``sections``) — hard overwrite. Clear the schema,
  then replay the archive's script (``pg_restore``'s output for a
  custom-format archive, the dump itself for a Phase 1 plain one) through
  ``psql``, both in one transaction. Clearing first is what makes an
  archive older than this install restorable at all: ``pg_restore
  --clean`` dropped only what the archive contained, so the tables later
  migrations added survived and broke the replay (#1363).
* **Selective restore** (``sections`` given) — TRUNCATE CASCADE + a
  data-only reload, over the **FK-cascade closure** of the selected
  sections' tables. The closure matters because CASCADE empties every
  table holding a foreign key into a truncated one; restoring only the
  selection deleted the difference (#781).

Safety rails:

* The operator must type the confirmation phrase
  ``RESTORE-FROM-BACKUP`` server-side; restore endpoints reject
  anything else.
* A pre-restore safety dump is written to
  ``/var/lib/spatiumddi/backups/pre-restore-{ts}.zip`` before any
  destructive change touches the DB. If the apply fails for any
  reason, the pre-restore dump is the operator's recovery path.
* Manifest version checks: the destination refuses archives whose
  ``format_version`` is newer than the running build (operators
  who downgraded need to upgrade first).
* The schema-direction check runs BEFORE anything destructive, so an
  archive this build cannot migrate forward is refused with the
  database still intact. ``allow_newer_schema`` overrides it for the
  A/B-rollback case.
* The data replay itself is atomic — clearing and replay run in one
  ``psql --single-transaction``, and a ``pg_restore`` that fails part way
  never lets psql reach end of input and commit. What is *not* atomic is the restore as
  a whole: the post-replay secret rewrap walks 65 columns/fields
  committing one at a time, so it can leave a half-migrated credential
  store. That is reported rather than hidden — see ``RewrapOutcome``'s
  ``aborted`` flag.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import tempfile
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from sqlalchemy import text

from app.services.backup.archive import (
    BackupArchiveError,
    _pg_env_from_url,
    _pg_subprocess_env,
    build_backup_archive,
    extract_archive_members,
)
from app.services.backup.crypto import BackupCryptoError, decrypt_secrets
from app.services.backup.migrations import (
    MigrationOutcome,
    maybe_upgrade_after_restore,
    schema_direction_error,
)
from app.services.backup.rewrap import (
    ENCRYPTED_COLUMNS,
    JSONB_ENCRYPTED_FIELDS,
    RewrapOutcome,
    rewrap_secrets,
)

logger = structlog.get_logger(__name__)

CONFIRM_PHRASE = "RESTORE-FROM-BACKUP"
# Phase 1 archives are version 1 (plain SQL); Phase 2+ are
# version 2 (custom-format dump). Both are accepted at restore;
# the dispatcher below routes to psql or pg_restore based on the
# manifest's ``dump_format`` field.
SUPPORTED_FORMAT_VERSIONS = {1, 2}
PRE_RESTORE_DIR = Path("/var/lib/spatiumddi/backups")

# A replay can run a while on a hefty install; same envelope as pg_dump so
# the matched-pair runs are bounded together. Since #1363 a full restore runs
# pg_restore feeding psql, and the whole replay shares this one deadline.
_PG_RESTORE_TIMEOUT_SECONDS = 30 * 60


class BackupRestoreError(Exception):
    """Restore-time failures distinct from
    ``BackupArchiveError`` (zip-shape problem) and
    ``BackupCryptoError`` (passphrase wrong)."""


@dataclass
class RestoreOutcome:
    manifest: dict[str, Any]
    pre_restore_path: str | None
    secrets_payload_keys: list[str]
    duration_ms: int
    selective: bool = False
    restored_sections: list[str] | None = None
    restored_tables: list[str] | None = None
    # Tables restored because ``TRUNCATE … CASCADE`` would have emptied
    # them, not because the operator selected their section. Empty on a
    # full restore. Surfaced so the operator can see that a selective
    # restore necessarily reached past the sections they ticked (#781).
    cascade_widened_tables: list[str] = field(default_factory=list)
    migration: MigrationOutcome | None = None
    rewrap: RewrapOutcome | None = None
    # Operator-actionable post-restore advisories that don't block
    # the restore. Currently used to flag PowerDNS DNSSEC zones —
    # signing keys live in the agent's LMDB volume (not in this
    # archive), so a restored DNSSEC-enabled zone re-signs on the
    # destination agent and produces *new* DS records the operator
    # must re-publish to the parent registrar.
    warnings: list[str] = field(default_factory=list)


async def _terminate_other_db_connections(pg_env: dict[str, str]) -> None:
    """Kick every other connection to the target database so psql's
    DROP / TRUNCATE statements don't deadlock against the worker /
    beat / agents. Postgres won't let us terminate our own session,
    which is fine — psql itself opens a brand-new connection on the
    next call.

    Failures here are logged but non-fatal; if the pool drops are
    enough on their own (no other connections present) the replay
    proceeds normally.
    """
    full_env = {**os.environ, **pg_env}
    sql = (
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
        "WHERE datname = current_database() AND pid <> pg_backend_pid();"
    )
    proc = await asyncio.create_subprocess_exec(
        "psql",
        "--set=ON_ERROR_STOP=0",
        f"--command={sql}",
        env=full_env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        logger.warning("backup_restore_terminate_timeout")
        return
    if proc.returncode != 0:
        logger.warning(
            "backup_restore_terminate_nonzero",
            stderr=stderr.decode(errors="replace")[:300],
            stdout=stdout.decode(errors="replace")[:300],
        )


# #1363 — a full restore must land on a schema holding exactly what the
# archive carries. ``pg_restore --clean`` drops only the objects the ARCHIVE
# contains, so every table a later migration added survived the replay with
# its constraints. An archive older than ``dns_agent_bundle`` (every
# 2026.09.04-1 archive) then failed outright: ``--clean`` could not drop
# ``dns_server_pkey`` while ``dns_agent_bundle_server_id_fkey`` depended on
# it, and the single transaction rolled back to a 400. A newer table with no
# such key survived instead, and stopped the post-restore ``alembic upgrade``
# on "already exists" — the drift branch #1233 had to tighten, entered by a
# path that has nothing to do with a stale ``alembic_version``.
#
# So this runs first, in the SAME transaction as the replay: a failed replay
# rolls the clearing back with it and the database is untouched. It drops
# every table, view, sequence, standalone type and routine in ``public``
# except an extension's members — ``CREATE EXTENSION IF NOT EXISTS`` in the
# dump is then a no-op, and no extension needs re-creating (pg_trgm, #879, is
# optional and may not be creatable by this role). Backups dump the whole
# database with no exclusions, so nothing dropped here is lost: the archive
# recreates everything that should exist. Names are captured as text up
# front, because a CASCADE drop removes later rows' objects and a regclass of
# a dropped oid renders as a bare number.
_CLEAR_PUBLIC_SCHEMA_SQL = """\
-- One NOTICE per cascaded constraint would otherwise bury the error, if any.
SET client_min_messages = warning;
DO $clear$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT format('%I.%I', n.nspname, c.relname) AS obj,
               CASE c.relkind
                   WHEN 'v' THEN 'VIEW'
                   WHEN 'm' THEN 'MATERIALIZED VIEW'
                   WHEN 'f' THEN 'FOREIGN TABLE'
                   WHEN 'S' THEN 'SEQUENCE'
                   ELSE 'TABLE'
               END AS kind
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relkind IN ('r', 'p', 'f', 'm', 'v', 'S')
          AND NOT EXISTS (
              SELECT 1 FROM pg_depend d
              WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e'
          )
        -- Tables first; whatever they take with them is skipped by IF EXISTS.
        ORDER BY CASE c.relkind WHEN 'r' THEN 0 WHEN 'p' THEN 0 ELSE 1 END, c.relname
    LOOP
        EXECUTE format('DROP %s IF EXISTS %s CASCADE', r.kind, r.obj);
    END LOOP;

    FOR r IN
        SELECT format('%I.%I', n.nspname, t.typname) AS obj
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = 'public'
          -- Not 'm': a multirange is internal to its range, which drops it.
          -- Dropping one directly is an ERROR, not a no-op, in any order.
          AND (
              t.typtype IN ('e', 'd', 'r')
              OR (t.typtype = 'c' AND EXISTS (
                  SELECT 1 FROM pg_class c WHERE c.oid = t.typrelid AND c.relkind = 'c'
              ))
          )
          AND NOT EXISTS (
              SELECT 1 FROM pg_depend d
              WHERE d.classid = 'pg_type'::regclass AND d.objid = t.oid AND d.deptype = 'e'
          )
    LOOP
        EXECUTE format('DROP TYPE IF EXISTS %s CASCADE', r.obj);
    END LOOP;

    FOR r IN
        SELECT format('%I.%I(%s)', n.nspname, p.proname,
                      pg_get_function_identity_arguments(p.oid)) AS obj
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
          AND NOT EXISTS (
              SELECT 1 FROM pg_depend d
              WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e'
          )
    LOOP
        EXECUTE format('DROP ROUTINE IF EXISTS %s CASCADE', r.obj);
    END LOOP;
END
$clear$;
"""

_REPLAY_CHUNK_BYTES = 64 * 1024


def _error_excerpt(stderr: str, limit: int = 1500) -> str:
    """psql's stderr from its first ``ERROR`` line, which is the reason;
    anything before it is notices and warnings."""
    idx = stderr.find("ERROR:")
    if idx != -1:
        stderr = stderr[stderr.rfind("\n", 0, idx) + 1 :]
    return stderr[:limit]


async def _script_chunks(script: bytes | Path):
    """Yield a plain dump in chunks: from memory when the caller already
    holds it (the archive's bytes, which restore has just unzipped), else
    from disk without blocking the loop."""
    if isinstance(script, bytes):
        view = memoryview(script)
        for start in range(0, len(view), _REPLAY_CHUNK_BYTES):
            yield bytes(view[start : start + _REPLAY_CHUNK_BYTES])
        return
    with script.open("rb") as fh:
        while chunk := await asyncio.to_thread(fh.read, _REPLAY_CHUNK_BYTES):
            yield chunk


async def _stop(proc: asyncio.subprocess.Process) -> None:
    """Kill ``proc`` if it is running, and reap it.

    Its stdout is drained first: ``Process.wait()`` returns only once every
    pipe has closed, and a killed producer's stdout still holds output
    nobody will read, so without the drain the wait never returns.
    """
    if proc.returncode is None:
        proc.kill()
    if proc.stdout is not None:
        await proc.stdout.read()
    await proc.wait()


async def _saw_token(stream: asyncio.StreamReader, token: bytes) -> bool:
    """Drain ``stream`` to EOF; True when ``token`` appeared in it.

    Keeps only a token-sized tail between reads, so a script that prints a
    lot (one row per ``setval``) costs no memory.
    """
    seen, tail = False, b""
    while chunk := await stream.read(_REPLAY_CHUNK_BYTES):
        window = tail + chunk
        seen = seen or token in window
        tail = window[-len(token) :]
    return seen


async def _replay_clean(source, db_url: str, *, producer=None) -> None:
    r"""Clear the schema and replay a SQL script, in ONE transaction (#1363).

    ``source`` yields the script's bytes: a plain dump read from disk, or
    ``pg_restore``'s script output for a custom-format archive (``producer``
    is that process, so its failure can be told apart). Everything reaches
    ``psql --single-transaction`` through stdin as one script, prefixed by
    :data:`_CLEAR_PUBLIC_SCHEMA_SQL` — one ``-f -`` rather than several
    ``-f`` files, because only psql 15+ wraps several in one transaction.

    The script is streamed, not staged: an install's dump can be larger than
    the api pod's scratch space. The cost of streaming is that psql reaching
    end of input COMMITS, so a producer that dies half way through must
    never let it get there. When the producer fails, psql is killed with its
    stdin still open — the server then sees the connection drop mid
    transaction and rolls everything back, the clearing included.

    Success is psql ACKNOWLEDGING the end of the script, not just exiting 0:
    a per-run token is ``\echo``-ed after the last statement, and only its
    appearance on stdout proves psql read everything. Handing every byte to
    the pipe proves nothing, since psql can leave early with exit 0 (a
    ``\q``) while a small script still fits in the pipe.
    """
    pg_env, _dbname = _pg_env_from_url(db_url)
    await _terminate_other_db_connections(pg_env)
    psql = await asyncio.create_subprocess_exec(
        "psql",
        "--quiet",
        "--no-psqlrc",
        "--set=ON_ERROR_STOP=1",
        "--single-transaction",
        "--file=-",
        env=_pg_subprocess_env(pg_env),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdin, stdout, stderr = psql.stdin, psql.stdout, psql.stderr
    assert stdin is not None and stdout is not None and stderr is not None
    token = f"spatium-replay-complete-{secrets.token_hex(16)}".encode("ascii")
    acknowledged = asyncio.ensure_future(_saw_token(stdout, token))
    psql_stderr = asyncio.ensure_future(stderr.read())
    producer_stderr = (
        asyncio.ensure_future(producer.stderr.read())
        if producer is not None and producer.stderr is not None
        else None
    )

    async def kill_all() -> None:
        # psql's stdout already has its reader (the acknowledgement task), so
        # it is drained through that rather than by ``_stop``: two readers
        # on one stream is an error.
        if psql.returncode is None:
            psql.kill()
        # Waits for the reader to hit EOF without re-raising anything it
        # failed with: cleanup must not replace the error being reported.
        await asyncio.wait({acknowledged})
        await psql.wait()
        if producer is not None:
            await _stop(producer)

    def psql_gone() -> bool:
        return psql.returncode is not None or stdin.is_closing()

    async def copy() -> bool:
        """Stream the script into psql; False when psql stopped reading.

        Checked per chunk rather than left to the write: once psql exits,
        asyncio's pipe transport DISCARDS further writes and ``drain()`` does
        not raise, so a loop waiting for an exception would pump the rest of
        the dump into nothing before reporting the error.
        """
        try:
            stdin.write(_CLEAR_PUBLIC_SCHEMA_SQL.encode("utf-8"))
            await stdin.drain()
            async for chunk in source:
                if psql_gone():
                    return False
                stdin.write(chunk)
                await stdin.drain()
            # On its own line: the script need not end with a newline.
            stdin.write(b"\n\\echo " + token + b"\n")
            await stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            return False
        return not psql_gone()

    # Set once psql has been given end of input: from then on it may be
    # committing, so a timeout can no longer promise nothing was applied.
    eof_sent = False
    delivered = False
    saw_end = False
    try:
        # One deadline for the whole replay, not one per step.
        async with asyncio.timeout(_PG_RESTORE_TIMEOUT_SECONDS):
            delivered = await copy()
            if not delivered:
                # psql stopped reading, which only an error does. Stop the
                # producer now: left running it blocks on a full pipe nobody
                # drains. psql's own error is the one to report.
                if producer is not None:
                    await _stop(producer)
            elif producer is not None:
                await producer.wait()
                if producer.returncode != 0:
                    # psql has not seen end of input, so it has not committed;
                    # the handler below kills it.
                    err = (
                        (await producer_stderr).decode(errors="replace")[:1500]
                        if producer_stderr is not None
                        else ""
                    )
                    raise BackupRestoreError(
                        f"pg_restore failed (exit {producer.returncode}): {err}; "
                        "nothing was applied"
                    )
            if delivered:
                # End of input: psql COMMITs, or rolls back on an error in the
                # final statements.
                stdin.close()
                eof_sent = True
            await psql.wait()
            saw_end = await acknowledged
    except TimeoutError as exc:
        await kill_all()
        outcome = (
            "the outcome is unknown — psql may have committed before it was stopped"
            if eof_sent
            else "nothing was applied"
        )
        raise BackupRestoreError(
            f"restore replay exceeded {_PG_RESTORE_TIMEOUT_SECONDS}s timeout; {outcome}"
        ) from exc
    except BaseException:
        await kill_all()
        raise
    if psql.returncode == 0 and not saw_end:
        # psql left before the end of the script yet reported success (a
        # ``\q`` in it, say). With --single-transaction that commits what it
        # read, so this must not read as a completed restore.
        raise BackupRestoreError(
            "replay stopped before the end of the archive (psql exited 0 without "
            "reading all of it); the database may hold a partial restore"
        )
    if psql.returncode != 0:
        err = _error_excerpt((await psql_stderr).decode(errors="replace"))
        raise BackupRestoreError(
            f"replay failed (psql exit {psql.returncode}): {err}; nothing was applied"
        )


async def _run_psql(script: bytes | Path, db_url: str) -> None:
    """Replay a plain-format (Phase 1) dump over a cleared schema (#1363)."""
    await _replay_clean(_script_chunks(script), db_url)


async def _run_pg_restore(dump_path: Path, db_url: str) -> None:
    """Replay a ``--format=custom`` archive (Phase 2+) over a cleared schema.

    ``pg_restore`` turns the archive into its SQL script (``--file=-``), and
    :func:`_replay_clean` applies it after clearing the schema, in one
    transaction (#1363). ``--clean`` is gone: everything it would drop is
    already gone, and it never dropped what mattered — the tables the archive
    does not contain. ``--no-owner`` + ``--no-acl`` strip role/grant clauses
    (matched to pg_dump's flags).
    """
    producer = await asyncio.create_subprocess_exec(
        "pg_restore",
        "--no-owner",
        "--no-acl",
        "--file=-",
        str(dump_path),
        # Script mode never connects, so it gets no connection credentials.
        env=_pg_subprocess_env({}),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout = producer.stdout
    assert stdout is not None

    async def script():
        while chunk := await stdout.read(_REPLAY_CHUNK_BYTES):
            yield chunk

    try:
        await _replay_clean(script(), db_url, producer=producer)
    finally:
        # _replay_clean reaps the producer on every path it owns; this covers
        # a failure before it gets that far (terminating connections, starting
        # psql), which would otherwise leave pg_restore blocked on a full pipe.
        await _stop(producer)


async def _truncate_tables(tables: list[str], db_url: str) -> None:
    """``TRUNCATE … RESTART IDENTITY CASCADE`` for the supplied
    table list. Used by selective restore — we wipe the selected
    sections' tables before pg_restore re-loads their data.

    CASCADE is intentional: when an operator restores "DNS only"
    onto an install where IPAM rows reference DNS rows, the
    cascading DELETE wipes those references too. Without CASCADE
    the TRUNCATE would fail with a FK constraint error and the
    operator would have to know the dependency graph in advance.
    The restore UI warns about this up front.
    """
    if not tables:
        return
    pg_env, _dbname = _pg_env_from_url(db_url)
    full_env = {**os.environ, **pg_env}
    quoted = ", ".join(f'"{t}"' for t in tables)
    cmd = [
        "psql",
        "--set=ON_ERROR_STOP=1",
        "--single-transaction",
        f"--command=TRUNCATE TABLE {quoted} RESTART IDENTITY CASCADE",
    ]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        env=full_env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
    except TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise BackupRestoreError("TRUNCATE timed out (>5 min)") from exc
    if proc.returncode != 0:
        msg = (stderr.decode(errors="replace") or stdout.decode(errors="replace"))[:1500]
        raise BackupRestoreError(f"TRUNCATE failed (exit {proc.returncode}): {msg}")


async def _run_pg_restore_data_only(dump_path: Path, db_url: str, tables: list[str]) -> None:
    """``pg_restore --data-only --disable-triggers --table=…``.

    Used by selective restore. ``--data-only`` skips schema
    commands (the tables already exist after TRUNCATE);
    ``--disable-triggers`` lets the COPY apply rows in any order
    without triggering FK checks mid-load (we re-enable triggers
    when the transaction commits). ``--single-transaction`` keeps
    the load atomic.

    Important: pg_restore --table is repeatable; we pass each
    table separately so the operator can pick a subset cleanly.
    """
    if not tables:
        raise BackupRestoreError("selective restore: no tables to load")
    pg_env, dbname = _pg_env_from_url(db_url)
    await _terminate_other_db_connections(pg_env)
    full_env = {**os.environ, **pg_env}
    cmd = [
        "pg_restore",
        "--dbname",
        dbname,
        "--data-only",
        "--disable-triggers",
        "--no-owner",
        "--no-acl",
        "--single-transaction",
        "--exit-on-error",
    ]
    for table in tables:
        cmd.extend(["--table", table])
    cmd.append(str(dump_path))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        env=full_env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=_PG_RESTORE_TIMEOUT_SECONDS
        )
    except TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise BackupRestoreError(
            f"pg_restore --data-only exceeded {_PG_RESTORE_TIMEOUT_SECONDS}s timeout"
        ) from exc
    if proc.returncode != 0:
        msg = (stderr.decode(errors="replace") or stdout.decode(errors="replace"))[:1500]
        raise BackupRestoreError(f"pg_restore --data-only failed (exit {proc.returncode}): {msg}")


async def _write_pre_restore_safety_dump(db) -> str | None:
    """Take a passphrase-less local archive of the *current* state
    before clobbering anything. The passphrase is the literal
    string ``pre-restore-safety`` — operators who need to read this
    archive use that constant. The intent is "let the operator roll
    back via a SQL replay if Phase 1a's hard-overwrite was a
    mistake," not "long-term forensic vault."

    Because that passphrase is public, filesystem permissions are the
    only protection for the SECRET_KEY inside: the directory is 0700
    (tightened if it already existed looser) and the file is created
    0600 up front, never written world-readable and chmod'd after.
    """
    try:
        PRE_RESTORE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    except (PermissionError, OSError) as exc:
        logger.warning(
            "pre_restore_safety_dir_unavailable",
            path=str(PRE_RESTORE_DIR),
            error=str(exc),
        )
        return None
    try:
        os.chmod(PRE_RESTORE_DIR, 0o700)
    except OSError as exc:
        # A directory this process doesn't own (a root-owned volume shared
        # through fsGroup) can't be tightened. That must not cost the
        # operator the rollback copy: the file below is still created 0600.
        logger.warning(
            "pre_restore_safety_dir_chmod_failed",
            path=str(PRE_RESTORE_DIR),
            error=str(exc),
        )
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    # Random suffix + O_EXCL (#1571): the name had one-second
    # resolution and was written with an overwriting write, so two
    # restores in the same second overwrote the FIRST rollback copy
    # with the second — destroying exactly the copy the first
    # restore might need. O_EXCL makes a residual collision fail
    # this dump (soft-fail path below) instead of overwriting.
    out_path = PRE_RESTORE_DIR / f"pre-restore-{timestamp}-{secrets.token_hex(3)}.zip"
    try:
        archive_bytes, _filename = await build_backup_archive(
            db,
            passphrase="pre-restore-safety",
            passphrase_hint="auto pre-restore safety dump (issue #117 Phase 1a)",
        )
        fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(archive_bytes)
    except (BackupArchiveError, OSError) as exc:
        logger.warning(
            "pre_restore_safety_dump_failed",
            path=str(out_path),
            error=str(exc),
        )
        return None
    return str(out_path)


async def _collect_post_restore_warnings(db_url: str) -> list[str]:
    """Surface operator-actionable advisories after a restore.

    Currently flags PowerDNS DNSSEC zones (issue #127 Phase 4d):
    DNSSEC signing keys live in the agent's LMDB volume (NOT in
    this archive), so the destination agent will regenerate keys
    and produce *new* DS records on its first sync. The operator
    must re-publish those DS records to the parent registrar or
    DNSSEC validation will fail externally. The warning includes
    the count + a sample of zone names so the operator knows how
    much registrar work is queued up.
    """
    pg_env, _dbname = _pg_env_from_url(db_url)
    full_env = {**os.environ, **pg_env}
    sql = (
        "SELECT z.name FROM dns_zone z "
        "JOIN dns_server_group g ON g.id = z.group_id "
        "JOIN dns_server s ON s.group_id = g.id "
        "WHERE z.dnssec_enabled = TRUE "
        "AND z.deleted_at IS NULL "
        "AND s.driver = 'powerdns' "
        "GROUP BY z.name ORDER BY z.name LIMIT 11;"
    )
    proc = await asyncio.create_subprocess_exec(
        "psql",
        "--no-align",
        "--tuples-only",
        "--set=ON_ERROR_STOP=0",
        f"--command={sql}",
        env=full_env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return []
    if proc.returncode != 0:
        return []
    zones = [line.strip() for line in stdout.decode(errors="replace").splitlines() if line.strip()]
    if not zones:
        return []
    sample = ", ".join(zones[:10])
    suffix = f" (and {len(zones) - 10} more)" if len(zones) > 10 else ""
    return [
        (
            f"PowerDNS DNSSEC: {len(zones)} signed zone(s) restored — "
            f"{sample}{suffix}. Signing keys live in the agent's LMDB "
            f"volume (not in this archive), so the destination agent "
            f"will regenerate keys on first sync and produce NEW DS "
            f"records. Re-publish those DS records to each zone's "
            f"parent registrar or external DNSSEC validation will fail."
        )
    ]


#: Session-level Postgres advisory lock serialising restores (#1571).
#: Neither restore endpoint took any lock, so two concurrent restores
#: interleaved their schema clear and replay — each replaying over
#: the other's half-cleared schema. Fixed key (this is a whole-install
#: operation, there is only ever one restore at a time), derived from
#: a label rather than hand-picked so it cannot collide with the
#: crc32-based per-resource keys elsewhere by accident.
_RESTORE_LOCK_KEY = zlib.crc32(b"spatiumddi:backup-restore") - 2**31


async def apply_backup_restore(db, **kwargs: Any) -> RestoreOutcome:
    """Restore under the install-wide advisory lock (#1571).

    ``pg_try_advisory_lock`` is non-blocking on purpose: a second
    restore is refused immediately with an operator-readable error
    rather than queued behind a replay that disposes the connection
    pool mid-flight. The lock is session-level, held on ``db``'s
    connection; Phase 4 of the restore disposes the whole pool,
    which releases it on the success path, and the ``finally`` below
    releases it on every path that gets there first. A process that
    dies mid-restore releases it with its connection — it cannot
    wedge restores the way a row-based mutex could.
    """
    if db is None:  # unit tests drive the phases with stubs
        return await _apply_backup_restore_inner(db, **kwargs)
    acquired = (
        await db.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": _RESTORE_LOCK_KEY})
    ).scalar_one()
    if not acquired:
        raise BackupRestoreError(
            "another restore is already in progress on this install — "
            "wait for it to finish before starting a second one"
        )
    await db.commit()
    try:
        return await _apply_backup_restore_inner(db, **kwargs)
    finally:
        try:
            await db.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": _RESTORE_LOCK_KEY})
            await db.commit()
        except Exception:  # noqa: BLE001 — pool disposal releases it anyway
            logger.debug("backup_restore_advisory_unlock_failed", exc_info=True)


async def _apply_backup_restore_inner(
    db,
    *,
    archive_bytes: bytes,
    passphrase: str,
    confirmation_phrase: str,
    db_url: str,
    sections: list[str] | None = None,
    allow_newer_schema: bool = False,
) -> RestoreOutcome:
    """Validate, decrypt-check, take a safety dump, then replay the
    archive via psql (Phase 1 plain dumps) or pg_restore (Phase 2+
    custom dumps).

    When ``sections`` is None or empty → **full restore** (hard
    overwrite of every table). When ``sections`` is a non-empty
    list of section keys (from
    :mod:`app.services.backup.sections`) → **selective restore**:
    TRUNCATE CASCADE followed by
    ``pg_restore --data-only --disable-triggers --table=…``, over the
    **FK-cascade closure** of the selected sections' tables rather than
    the selection alone. ``platform_internal`` is always included
    (alembic_version + oui_vendor pin install state). Selective
    restore requires the archive to be in custom format —
    ``pg_restore --table=`` doesn't work on plain dumps.

    The closure is not an optimisation: ``CASCADE`` empties every table
    holding a foreign key into a truncated one, so restoring only the
    selection *deleted* the difference (#781). Everything CASCADE reaches
    is therefore restored from the same archive, and the tables that were
    pulled in beyond the selection come back on
    :attr:`RestoreOutcome.cascade_widened_tables` plus an operator-facing
    warning — the restore is deliberately wider than what was ticked, so
    it says so rather than doing it quietly.

    ``allow_newer_schema`` overrides the pre-replay refusal to restore an
    archive whose schema head this build does not know. It exists for the
    A/B-rollback case; the override is logged and the outcome leads with a
    warning that the api's schema-head readiness gate may now fail.

    The async ``db`` session is used only to pull the alembic head
    for the safety dump and to dispose of the connection pool
    cleanly before the subprocess runs. The actual schema rewrite
    happens out-of-process to avoid the SQLAlchemy connection
    pool fighting with the destructive replay.
    """
    if confirmation_phrase != CONFIRM_PHRASE:
        raise BackupRestoreError(f"confirmation phrase must be exactly '{CONFIRM_PHRASE}'")
    if not passphrase:
        raise BackupRestoreError("passphrase is required")

    started = datetime.now(UTC)
    schema_override_warning: str | None = None

    # Phase 1: parse + validate the archive, fail fast if it's
    # malformed, before taking the destructive safety dump path.
    manifest, db_bytes, dump_format, secrets_enc = extract_archive_members(archive_bytes)
    fmt_version = manifest.get("format_version")
    if fmt_version not in SUPPORTED_FORMAT_VERSIONS:
        raise BackupRestoreError(
            f"unsupported backup format_version: {fmt_version!r} "
            f"(this build expects one of {sorted(SUPPORTED_FORMAT_VERSIONS)}). "
            f"Upgrade SpatiumDDI before restoring this archive."
        )

    # Phase 2: passphrase verify. Decrypt secrets.enc up front so
    # we fail with "wrong passphrase" before deleting anything.
    try:
        secrets_payload = decrypt_secrets(secrets_enc, passphrase=passphrase)
    except BackupCryptoError as exc:
        raise BackupRestoreError(str(exc)) from exc

    # Phase 2b: refuse a schema we cannot migrate forward, while the
    # database is still intact. The same test runs post-replay inside
    # ``maybe_upgrade_after_restore``, but by then the data is already
    # overwritten and "refusing" only reports the damage (#781).
    # Prefer the manifest, fall back to secrets.enc — which carries the same
    # head and is already decrypted by Phase 2. Reading only the manifest let
    # an archive with no recorded schema_version slip past the gate entirely,
    # even though the head was recoverable a few lines up.
    direction_error = schema_direction_error(
        manifest.get("schema_version") or secrets_payload.get("schema_version")
    )
    if direction_error and not allow_newer_schema:
        raise BackupRestoreError(direction_error)
    if direction_error and allow_newer_schema:
        # The refusal exists because ``alembic_version`` ending up ahead
        # of the running code trips the api's strict schema-head
        # readiness gate. That is a real failure — but making it
        # absolute removed the A/B-rollback path, where an operator who
        # rolled back *because* the new build broke is told to upgrade
        # into the build they just escaped (#781).
        #
        # It also catches more than it means to: ``_is_ancestor``
        # returns False on ANY exception, so a forked, squashed or
        # renamed revision is indistinguishable from a genuinely newer
        # one. This override covers that case too.
        logger.warning(
            "backup_restore_newer_schema_override",
            detail=direction_error,
            manifest_schema_version=manifest.get("schema_version"),
        )
        schema_override_warning = (
            "Schema-direction check OVERRIDDEN: " + direction_error + " Restoring "
            "anyway because allow_newer_schema was set. The database's "
            "alembic_version may now be ahead of this build, which the api's "
            "schema-head readiness gate rejects — upgrade to a build at or past "
            "the archive's head, or expect /health/ready to fail."
        )

    # Phase 2c (#1575): selective-restore shape checks. Both refusals
    # below are knowable from the parsed archive + the caller's section
    # list alone, so they run HERE — before the Phase 3 safety dump
    # writes a full-size archive to disk and Phase 4 disposes the
    # connection pool. They used to sit in Phase 5, after both, so every
    # invalid selective attempt paid for a safety dump and a pool cycle
    # and got refused anyway.
    selective = bool(sections)
    if selective and dump_format != "custom":
        raise BackupRestoreError(
            "selective restore needs an archive whose database dump is in "
            "pg_dump's custom format (dump_format=custom). This archive is "
            "plain SQL — only full restore is supported."
        )
    if selective:
        from app.services.backup.sections import SECTIONS_BY_KEY  # noqa: PLC0415

        unknown_sections = [k for k in sections or [] if k not in SECTIONS_BY_KEY]
        if unknown_sections:
            raise BackupRestoreError(
                f"unknown section keys: {unknown_sections}. Call GET /backup/sections "
                "for the catalog."
            )

    # Phase 3: pre-restore safety dump. Soft-fails — if the api
    # container can't write to ``/var/lib/spatiumddi/backups`` (no
    # mounted volume in dev compose, e.g.) we proceed with a logged
    # warning. Operators on production deployments should mount the
    # path, which is documented in the deployment guide.
    pre_restore_path = await _write_pre_restore_safety_dump(db)

    # Phase 4: dispose of SQLAlchemy's connection pool. psql opens
    # its own connection, and leaving the async pool busy stalls
    # the replay's DROP / TRUNCATE statements (the schema clearing
    # of a full restore, the TRUNCATE of a selective one) — we'd
    # deadlock against the worker / beat / agents reading at the
    # same time. ``engine.dispose()`` closes every pooled
    # connection cleanly so the pool comes back empty after the
    # restore. ``_terminate_other_db_connections`` (called by each
    # replay helper below) then kicks anything still attached
    # via the worker / beat / agent containers' own engines.
    from app.db import engine as global_engine  # noqa: PLC0415

    await db.close()
    await global_engine.dispose()

    # Phase 5: replay. Three paths:
    #  - selective restore (sections supplied) — TRUNCATE +
    #    ``pg_restore --data-only --disable-triggers --table=…``.
    #    Requires custom format; plain archives can't be selective.
    #  - full restore against custom format → ``pg_restore``.
    #  - full restore against plain format → ``psql``. Phase 1
    #    archives stay restorable through this path forever.
    # ``selective`` and the two selective-shape refusals (plain format,
    # unknown section keys) are decided in Phase 2c, before the safety
    # dump and the pool disposal (#1575).
    restored_sections: list[str] | None = None
    restored_tables: list[str] | None = None
    cascade_widened: list[str] = []

    with tempfile.TemporaryDirectory(prefix="spatium-restore-") as tmpdir:
        if selective:
            # Lazy import — keeps the section catalog out of the
            # restore module's import graph for callers that don't
            # touch selective.
            from app.services.backup.sections import (  # noqa: PLC0415
                cascade_closure,
                tables_for_sections,
            )

            requested = list(sections or [])
            # ``platform_internal`` (alembic_version + oui_vendor)
            # always rides along — the schema head pin + the OUI
            # cache are install-state, not user-data, and a
            # selective restore that omits them yields a confusing
            # half-state.
            effective = list(requested)
            if "platform_internal" not in effective:
                effective.append("platform_internal")
            selected_tables = tables_for_sections(effective)
            restored_sections = effective

            # The TRUNCATE below is CASCADE, so it also empties every
            # table holding a foreign key into a selected one —
            # catalogued or not, chosen or not. Restoring only the
            # selection therefore DELETED the difference: measured on
            # the shipped catalog, "auth" cascades into 130 tables and
            # refilled 11 (#781). Restore the whole closure instead, so
            # everything the operation touches ends consistent with the
            # archive. Deliberately wider than the operator ticked —
            # but the alternative is not "narrower", it is "emptied".
            closure = cascade_closure(selected_tables)
            cascade_widened = sorted(closure - set(selected_tables))
            # Preserve the catalog's ordering for the selection, then
            # append the widened set; pg_restore resolves its own
            # dependency order, so this only affects readability.
            restored_tables = selected_tables + cascade_widened
            if cascade_widened:
                logger.info(
                    "backup_restore_cascade_widened",
                    selected_sections=effective,
                    selected_table_count=len(selected_tables),
                    widened_table_count=len(cascade_widened),
                    widened_tables=cascade_widened,
                )

            dump_path = Path(tmpdir) / "database.dump"
            dump_path.write_bytes(db_bytes)
            # Step 1: wipe the selection + everything CASCADE reaches.
            await _truncate_tables(restored_tables, db_url)
            # Step 2: data-only re-load of that same closure.
            await _run_pg_restore_data_only(dump_path, db_url, restored_tables)
        elif dump_format == "custom":
            dump_path = Path(tmpdir) / "database.dump"
            dump_path.write_bytes(db_bytes)
            await _run_pg_restore(dump_path, db_url)
        else:
            # Streamed from the bytes already in memory: staging them on
            # disk only to read them back cost a full write of the dump.
            await _run_psql(db_bytes, db_url)

    # Phase 6: alembic upgrade-on-restore. The destination DB is now
    # at the source's schema head; if local code expects a newer
    # head, run ``alembic upgrade head`` over the just-restored DB
    # so the install boots cleanly without operator intervention.
    # Same-head + truly-newer-source cases are no-ops with diagnostic
    # state. Failures are surfaced, never raised — operator can
    # re-run ``alembic upgrade head`` manually.
    try:
        migration_outcome = await maybe_upgrade_after_restore(
            manifest_schema_version=manifest.get("schema_version"),
            db_url=db_url,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("backup_restore_migration_failed", error=str(exc))
        migration_outcome = MigrationOutcome(
            state="failed",
            source_head=manifest.get("schema_version"),
            local_head=None,
            migrations_applied=[],
            error=f"migration step aborted: {exc}",
        )

    # Phase 7: cross-install secret rewrap. Walks every Fernet-
    # encrypted column + the backup_target.config JSONB blob and
    # re-encrypts with the destination install's key. No-op when
    # source + dest keys match. Failures are counted, not raised —
    # one bad row mustn't kill an otherwise-clean restore.
    # Runs AFTER the alembic upgrade so the schema is at the local
    # code's expected shape (encrypted columns may have moved /
    # been renamed across migrations).
    from app.config import settings as _settings  # noqa: PLC0415

    try:
        rewrap_outcome = await rewrap_secrets(
            db_url=db_url,
            source_secret_key=secrets_payload.get("platform_secret_key", "") or "",
            source_credential_key=secrets_payload.get("platform_credential_encryption_key", "")
            or "",
            dest_secret_key=_settings.secret_key,
            dest_credential_key=_settings.credential_encryption_key or "",
        )
    except Exception as exc:  # noqa: BLE001
        # Rewrap failure shouldn't blow away the whole restore —
        # the data is in. Log loudly + surface in the response so
        # the operator knows to apply the recovered SECRET_KEY
        # manually.
        #
        # ``rewrap_secrets`` now absorbs walk failures itself and returns
        # a partial outcome with ``aborted=True``, precisely so the
        # counters survive; this branch is the backstop for something
        # raised before it could (a bad key pair, say). A fresh
        # ``RewrapOutcome()`` is honest HERE — nothing was walked — but it
        # was NOT honest when it also swallowed a mid-walk abort (#781).
        logger.error("backup_restore_rewrap_failed", error=str(exc))
        rewrap_outcome = RewrapOutcome()
        rewrap_outcome.aborted = True
        rewrap_outcome.failures.append({"reason": f"rewrap-aborted: {exc}"})

    # Phase 4d (issue #127): scan the restored DB for PowerDNS
    # DNSSEC-enabled zones and surface a registrar-republish
    # advisory. Failure here is non-fatal — the data is in.
    try:
        post_warnings = await _collect_post_restore_warnings(db_url)
    except Exception as exc:  # noqa: BLE001
        logger.warning("backup_restore_warning_scan_failed", error=str(exc))
        post_warnings = []

    # The override is the first thing an operator should read back.
    if schema_override_warning:
        post_warnings.insert(0, schema_override_warning)

    # Say plainly that the restore reached past the ticked sections.
    # An operator who picked "DNS" and finds their IPAM rows reverted
    # should learn it here, not by noticing later.
    if cascade_widened:
        post_warnings.append(
            f"Selective restore also restored {len(cascade_widened)} table(s) outside "
            "the sections you selected, because a foreign key from them into the "
            "selected data means PostgreSQL's TRUNCATE ... CASCADE would otherwise "
            "have emptied them without repopulating: "
            + ", ".join(cascade_widened[:12])
            + (f", and {len(cascade_widened) - 12} more" if len(cascade_widened) > 12 else "")
            + "."
        )

    # A half-migrated credential store is the one restore outcome an
    # operator must act on immediately, so it rides the same amber
    # warnings channel the DNSSEC-republish advisory uses rather than
    # sitting in a counter nobody reads (#781).
    if rewrap_outcome.aborted:
        total = len(ENCRYPTED_COLUMNS) + len(JSONB_ENCRYPTED_FIELDS)
        post_warnings.append(
            "Secret rewrap stopped part-way through: "
            f"{rewrap_outcome.columns_visited} of {total} encrypted locations "
            f"(columns and JSONB fields) were visited and "
            f"{rewrap_outcome.rewrapped_rows} row(s) were re-encrypted under this "
            "install's key. The rest are still encrypted with the SOURCE install's "
            "key and will fail to decrypt. Recover the source key from the "
            "archive's secrets.enc and re-run the restore, or the affected "
            "credentials must be re-entered by hand."
        )

    duration_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
    logger.info(
        "backup_restore_applied",
        manifest_app_version=manifest.get("app_version"),
        manifest_schema_version=manifest.get("schema_version"),
        pre_restore_path=pre_restore_path,
        duration_ms=duration_ms,
        selective=selective,
        restored_sections=restored_sections,
        migration_state=migration_outcome.state,
        migrations_applied=len(migration_outcome.migrations_applied),
        rewrap_same_install=rewrap_outcome.same_install,
        rewrap_rows=rewrap_outcome.rewrapped_rows,
        rewrap_jsonb=rewrap_outcome.rewrapped_jsonb_fields,
        rewrap_idempotent=rewrap_outcome.skipped_idempotent_rows,
        rewrap_failed=rewrap_outcome.failed_rows,
        rewrap_aborted=rewrap_outcome.aborted,
        warning_count=len(post_warnings),
    )
    return RestoreOutcome(
        manifest=manifest,
        pre_restore_path=pre_restore_path,
        secrets_payload_keys=sorted(secrets_payload.keys()),
        duration_ms=duration_ms,
        selective=selective,
        restored_sections=restored_sections,
        restored_tables=restored_tables,
        cascade_widened_tables=cascade_widened,
        migration=migration_outcome,
        rewrap=rewrap_outcome,
        warnings=post_warnings,
    )
