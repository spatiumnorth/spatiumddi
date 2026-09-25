"""Apply a backup archive to the running install (issue #117 Phase
1a).

Two shapes:

* **Full restore** (no ``sections``) — hard overwrite. Replay the
  archive over every table via ``pg_restore --clean`` (custom-format
  archives) or ``psql`` (Phase 1 plain dumps).
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
* The data replay itself is atomic — ``--single-transaction`` on both
  the psql and pg_restore paths. What is *not* atomic is the restore as
  a whole: the post-replay secret rewrap walks 65 columns/fields
  committing one at a time, so it can leave a half-migrated credential
  store. That is reported rather than hidden — see ``RewrapOutcome``'s
  ``aborted`` flag.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from app.services.backup.archive import (
    BackupArchiveError,
    _pg_env_from_url,
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

# Either binary can run a while on a hefty install; same envelope
# as pg_dump so the matched-pair runs are bounded together.
_PSQL_TIMEOUT_SECONDS = 30 * 60
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


async def _run_psql(sql_path: Path, db_url: str) -> None:
    pg_env, _dbname = _pg_env_from_url(db_url)
    # Kick every other connection first so the DROP / TRUNCATE in
    # the dump's --clean preamble doesn't deadlock against the
    # worker / beat / dns-bind9 / dhcp-kea / frontend SSE polls.
    await _terminate_other_db_connections(pg_env)
    full_env = {**os.environ, **pg_env}
    cmd = [
        "psql",
        "--set=ON_ERROR_STOP=1",
        "--single-transaction",
        f"--file={sql_path}",
    ]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        env=full_env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=_PSQL_TIMEOUT_SECONDS)
    except TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise BackupRestoreError(f"psql exceeded {_PSQL_TIMEOUT_SECONDS}s timeout") from exc
    if proc.returncode != 0:
        msg = (stderr.decode(errors="replace") or stdout.decode(errors="replace"))[:1500]
        raise BackupRestoreError(f"psql failed (exit {proc.returncode}): {msg}")


async def _run_pg_restore(dump_path: Path, db_url: str) -> None:
    """Replay a ``--format=custom`` archive via pg_restore (Phase
    2+). ``--clean --if-exists`` ensures the destination's
    matching objects get dropped before recreate; ``--no-owner``
    + ``--no-acl`` strip role/grant clauses (matched to pg_dump's
    flags); ``--single-transaction`` makes the whole replay
    atomic. ``--exit-on-error`` so the first failure aborts
    instead of the default behaviour of trying to keep going.
    """
    pg_env, dbname = _pg_env_from_url(db_url)
    await _terminate_other_db_connections(pg_env)
    full_env = {**os.environ, **pg_env}
    cmd = [
        "pg_restore",
        "--dbname",
        dbname,
        "--clean",
        "--if-exists",
        "--no-owner",
        "--no-acl",
        "--single-transaction",
        "--exit-on-error",
        str(dump_path),
    ]
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
            f"pg_restore exceeded {_PG_RESTORE_TIMEOUT_SECONDS}s timeout"
        ) from exc
    if proc.returncode != 0:
        msg = (stderr.decode(errors="replace") or stdout.decode(errors="replace"))[:1500]
        raise BackupRestoreError(f"pg_restore failed (exit {proc.returncode}): {msg}")


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
    """
    try:
        PRE_RESTORE_DIR.mkdir(parents=True, exist_ok=True)
    except (PermissionError, OSError) as exc:
        logger.warning(
            "pre_restore_safety_dir_unavailable",
            path=str(PRE_RESTORE_DIR),
            error=str(exc),
        )
        return None
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    out_path = PRE_RESTORE_DIR / f"pre-restore-{timestamp}.zip"
    try:
        archive_bytes, _filename = await build_backup_archive(
            db,
            passphrase="pre-restore-safety",
            passphrase_hint="auto pre-restore safety dump (issue #117 Phase 1a)",
        )
        out_path.write_bytes(archive_bytes)
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


async def apply_backup_restore(
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

    # Phase 3: pre-restore safety dump. Soft-fails — if the api
    # container can't write to ``/var/lib/spatiumddi/backups`` (no
    # mounted volume in dev compose, e.g.) we proceed with a logged
    # warning. Operators on production deployments should mount the
    # path, which is documented in the deployment guide.
    pre_restore_path = await _write_pre_restore_safety_dump(db)

    # Phase 4: dispose of SQLAlchemy's connection pool. psql opens
    # its own connection, and leaving the async pool busy stalls
    # the TRUNCATE / DROP statements emitted by pg_dump --clean —
    # we'd deadlock against the worker / beat / agents reading at
    # the same time. ``engine.dispose()`` closes every pooled
    # connection cleanly so the pool comes back empty after the
    # restore. ``_terminate_other_db_connections`` (called from
    # ``_run_psql`` below) then kicks anything still attached
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
    selective = bool(sections)
    restored_sections: list[str] | None = None
    restored_tables: list[str] | None = None
    cascade_widened: list[str] = []

    if selective and dump_format != "custom":
        raise BackupRestoreError(
            "selective restore needs an archive whose database dump is in "
            "pg_dump's custom format (dump_format=custom). This archive is "
            "plain SQL — only full restore is supported."
        )

    with tempfile.TemporaryDirectory(prefix="spatium-restore-") as tmpdir:
        if selective:
            # Lazy import — keeps the section catalog out of the
            # restore module's import graph for callers that don't
            # touch selective.
            from app.services.backup.sections import (  # noqa: PLC0415
                SECTIONS_BY_KEY,
                cascade_closure,
                tables_for_sections,
            )

            requested = list(sections or [])
            unknown = [k for k in requested if k not in SECTIONS_BY_KEY]
            if unknown:
                raise BackupRestoreError(
                    f"unknown section keys: {unknown}. Call GET /backup/sections "
                    "for the catalog."
                )
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
            sql_path = Path(tmpdir) / "database.sql"
            sql_path.write_bytes(db_bytes)
            await _run_psql(sql_path, db_url)

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
