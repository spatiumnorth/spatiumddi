"""Build + read SpatiumDDI backup archives (issue #117 Phase 1a).

Layout (matches the spec in the issue body):

.. code-block:: text

    spatiumddi-backup-{hostname}-{YYYYMMDD-HHMMSS}-{random}.zip
    ├── manifest.json     # version, schema head, hostname, created_at
    ├── database.sql      # pg_dump --format=plain
    ├── secrets.enc       # passphrase-wrapped SECRET_KEY + metadata
    └── README.txt        # human-readable restore note

Phase 1a deliberately does **not** re-encrypt every Fernet-encrypted
column at backup time. Encrypted-at-rest fields stay encrypted with
the source install's ``SECRET_KEY`` inside ``database.sql``; the key
itself ships separately inside ``secrets.enc``, wrapped with the
operator's passphrase. Same-install restores are seamless;
cross-install restores require the operator to apply the recovered
``SECRET_KEY`` to the destination's environment before secret-bearing
rows decrypt cleanly.

The whole flow is sync-friendly — ``pg_dump`` is the bottleneck and
it's invoked via a subprocess with the right ``PGPASSWORD`` env. We
use a temp directory rather than an in-memory ``BytesIO`` so very
large installs don't OOM the api container.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import secrets
import socket
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.services.backup.crypto import encrypt_secrets, hint_reveals_passphrase

logger = structlog.get_logger(__name__)

# Hard ceilings — a runaway dump on a misconfigured install
# shouldn't lock up the api forever. 30 minutes covers any
# realistic SpatiumDDI install (single-digit GB at the absolute
# top end); operators with bigger fleets need to revisit this.
_PG_DUMP_TIMEOUT_SECONDS = 30 * 60

# Ceiling on a backup archive as downloaded from a destination, in
# compressed bytes — the same 2 GB the upload endpoints enforce
# (``app.api.v1.backup.router._MAX_UPLOAD_BYTES``). Destination
# downloads used to have no cap at all (#1568).
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024

# Ceiling on the database member's DECLARED uncompressed size
# (``ZipInfo.file_size``) that ``extract_archive_members`` will read
# into memory (#1568). Same 20 GiB the restore drill allows a scratch
# database (``SPATIUM_DRILL_MAX_DB_BYTES`` default): far above any
# realistic dump, far below "crafted zip header OOMs the api".
_MAX_DUMP_MEMBER_BYTES = 20 * 1024**3


class BackupArchiveError(Exception):
    """Raised when archive building or reading fails for a reason
    that has nothing to do with crypto (pg_dump exit non-zero, zip
    is malformed, manifest missing, etc.).
    """


# ── URL parsing ────────────────────────────────────────────────────────


def _pg_env_from_url(url: str) -> tuple[dict[str, str], str]:
    """Translate a ``postgresql+asyncpg://user:pw@host:port/db`` URL
    into the env vars + dbname ``pg_dump`` / ``psql`` expect.
    """
    # Strip any ``+driver`` so urlparse parses the netloc cleanly.
    sanitised = url.replace("+asyncpg", "").replace("+psycopg2", "")
    parsed = urlparse(sanitised)
    if not parsed.hostname:
        raise BackupArchiveError(f"could not parse host from database URL: {url!r}")
    if not parsed.path or parsed.path == "/":
        raise BackupArchiveError(f"could not parse dbname from database URL: {url!r}")
    dbname = parsed.path.lstrip("/")
    env: dict[str, str] = {
        "PGHOST": parsed.hostname,
        "PGPORT": str(parsed.port or 5432),
        "PGDATABASE": dbname,
    }
    if parsed.username:
        env["PGUSER"] = parsed.username
    if parsed.password:
        env["PGPASSWORD"] = parsed.password
    return env, dbname


# Env vars pg_dump / psql / pg_restore legitimately need: PATH to find the
# binary, plus locale/timezone for correct output. Everything else in the
# parent process env (OPENAI_API_KEY, fingerbank keys, …) is deliberately
# NOT inherited by the subprocess (#10).
_SUBPROCESS_ENV_ALLOW = ("PATH", "HOME", "LANG", "LC_", "TZ", "TMPDIR")


def _pg_subprocess_env(pg_env: dict[str, str]) -> dict[str, str]:
    """A minimal environment for a Postgres CLI subprocess: an allowlisted
    slice of the parent env plus the PG* connection vars. Avoids leaking
    unrelated parent-process secrets into pg_dump/psql via ``/proc/<pid>/
    environ``."""
    base = {k: v for k, v in os.environ.items() if k.startswith(_SUBPROCESS_ENV_ALLOW)}
    base.update(pg_env)
    return base


# ── Archive building ───────────────────────────────────────────────────


async def _run_pg_dump(out_path: Path, *, snapshot_id: str | None = None) -> None:
    """Invoke ``pg_dump --format=custom --no-owner --no-privileges``
    against the configured database, writing to ``out_path``.

    ``--no-owner`` + ``--no-privileges`` strip role/grant clauses
    from the dump so a restore onto a fresh install with a
    different db role still works without manual editing.

    ``--format=custom`` (Phase 2a) replaces ``--format=plain`` as
    the default — it's the format ``pg_restore`` knows how to walk
    selectively (``--table=...`` filtering for selective restore
    in Phase 2b). Operators who want a human-readable SQL stream
    can still get one via ``pg_restore -f - database.dump``. Phase
    1 archives (plain SQL) stay restorable through the
    auto-detection path in :mod:`app.services.backup.restore`.

    ``snapshot_id`` (Phase 3) is an exported Postgres snapshot
    handle from a separate transaction. When set, pg_dump runs
    inside that transaction's view via ``--snapshot=<id>`` —
    used by the exclude-secrets diagnostic mode where the caller
    NULLs encrypted columns inside a REPEATABLE READ tx, exports
    a snapshot, hands it here, then ROLLBACKs after the dump
    completes so the live DB never observes the NULLed state.
    """
    pg_env, _dbname = _pg_env_from_url(str(settings.database_url))
    full_env = _pg_subprocess_env(pg_env)
    cmd = [
        "pg_dump",
        "--format=custom",
        "--no-owner",
        "--no-privileges",
        "--quote-all-identifiers",
        # No ``--clean`` / ``--if-exists``: a full restore clears
        # the whole schema itself before replaying (#1363 — the
        # archive's own DROPs never reached tables a later
        # migration added), and selective restore must not carry
        # a global cleanup at all.
        f"--file={out_path}",
    ]
    if snapshot_id:
        cmd.append(f"--snapshot={snapshot_id}")
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        env=full_env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=_PG_DUMP_TIMEOUT_SECONDS
        )
    except TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise BackupArchiveError(f"pg_dump exceeded {_PG_DUMP_TIMEOUT_SECONDS}s timeout") from exc
    if proc.returncode != 0:
        # Surface the first ~1000 chars of pg_dump's stderr so
        # operators can debug "auth failed" vs. "version mismatch"
        # vs. "permission denied" without tailing logs.
        msg = (stderr.decode(errors="replace") or stdout.decode(errors="replace"))[:1000]
        raise BackupArchiveError(f"pg_dump failed (exit {proc.returncode}): {msg}")


async def _read_alembic_head(db: AsyncSession) -> str | None:
    try:
        row = await db.execute(text("SELECT version_num FROM alembic_version LIMIT 1"))
        return row.scalar()
    except Exception:
        # Fresh install / no alembic table — surface as None;
        # restore will still proceed, just without a version-skew
        # warning surface to fall back on.
        return None


def _readme_text(manifest: dict[str, Any]) -> str:
    dump_format = manifest.get("dump_format", "plain")
    dump_member = "database.dump" if dump_format == "custom" else "database.sql"
    dump_summary = (
        "pg_dump --format=custom (no-owner, no-privileges) — "
        "read with pg_restore --list / pg_restore --table=<name>"
        if dump_format == "custom"
        else "pg_dump --format=plain (no-owner, no-privileges)"
    )
    return f"""SpatiumDDI backup — {manifest.get("created_at", "(unknown time)")}

This archive contains a snapshot of one SpatiumDDI install:

  manifest.json   -  the table of contents below
  {dump_member}   -  {dump_summary}
  secrets.enc     -  passphrase-wrapped envelope containing the source
                     install's SECRET_KEY (and credential_encryption_key
                     if separately set). Required for cross-install
                     restores to be able to read Fernet-encrypted rows.
                     DO NOT lose your passphrase — there is no recovery.

Source install:
  app version    {manifest.get("app_version", "?")}
  schema head    {manifest.get("schema_version", "?")}
  hostname       {manifest.get("hostname", "?")}

To restore: open SpatiumDDI on the destination install as a superadmin,
go to Administration -> Platform -> Backup, click "Restore from file",
upload this zip, supply your passphrase, type the confirmation phrase,
and click Apply. Restoring overwrites the destination install's data.

Cross-install caveat (Phase 1a):
  Fernet-encrypted columns inside database.sql were encrypted with the
  source install's SECRET_KEY. After restoring on a different install:
    1. Decrypt secrets.enc with your passphrase (the SpatiumDDI restore
       UI does this for you; or run a Python one-liner using
       cryptography's PBKDF2HMAC + AESGCM).
    2. Apply the recovered SECRET_KEY (and, if present,
       credential_encryption_key) to the destination's .env / secret
       store and restart the api / worker / beat containers.
    3. Encrypted-at-rest rows (auth provider creds, agent PSKs, etc.)
       will read cleanly.
  Same-install restores (matching SECRET_KEY) skip step 2 entirely.
"""


async def _run_pg_dump_plain(out_path: Path) -> None:
    """Plain-format variant of :func:`_run_pg_dump` used by the
    exclude-secrets diagnostic mode (Phase 3). Writes SQL text so
    the caller can post-process encrypted columns to empty bytes
    in-memory before zipping. ``pg_export_snapshot`` semantics
    don't help here — the exported snapshot reflects committed
    state, so a side transaction's uncommitted UPDATEs aren't
    visible to a separate pg_dump subprocess. Text post-processing
    is the simplest correct alternative.
    """
    pg_env, _dbname = _pg_env_from_url(str(settings.database_url))
    full_env = _pg_subprocess_env(pg_env)
    cmd = [
        "pg_dump",
        "--format=plain",
        "--no-owner",
        "--no-privileges",
        "--quote-all-identifiers",
        f"--file={out_path}",
    ]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        env=full_env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=_PG_DUMP_TIMEOUT_SECONDS
        )
    except TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise BackupArchiveError(f"pg_dump exceeded {_PG_DUMP_TIMEOUT_SECONDS}s timeout") from exc
    if proc.returncode != 0:
        msg = (stderr.decode(errors="replace") or stdout.decode(errors="replace"))[:1000]
        raise BackupArchiveError(f"pg_dump failed (exit {proc.returncode}): {msg}")


def _scrub_dump_text(dump_text: str) -> str:
    """Walk a plain-format pg_dump and replace REDACTABLE Fernet-encrypted
    values with an empty placeholder — both the ``LargeBinary`` columns and
    the JSONB-embedded secrets registered in ``JSONB_ENCRYPTED_FIELDS``
    (backup-driver credentials, SNMPv3 passphrases, syslog TLS CAs, APT GPG
    keys + mirror passwords).

    Not every encrypted column: ``redactable_columns()`` withholds machine
    identity an operator cannot re-enter — the appliance CA and Web-UI TLS
    private keys, k3s join tokens, pairing-code reveals, the ACME account
    key. An empty bytea satisfies their NOT NULL constraints, so blanking
    them yields an archive whose restore SUCCEEDS and then permanently
    breaks supervisor approval, with no rotate endpoint (#781). What IS
    scrubbed is the credentials an operator can simply type back in.

    Inside a ``COPY public.foo (col1, col2, ...) FROM stdin;`` →
    ``\\.`` block, columns are tab-separated and bytea values are
    serialised as ``\\x<hex>``. We replace those with ``\\x``
    (empty bytea); columns with empty-bytea defaults stay schema-
    valid.

    Issue #117 Phase 3 — exclude-secrets diagnostic mode.
    """
    import re  # noqa: PLC0415

    from app.services.backup.rewrap import (  # noqa: PLC0415
        JSONB_ENCRYPTED_FIELDS,
        LEGACY_PLAINTEXT_SECRET_COLUMNS,
        _jsonb_secret_sites,
        redactable_columns,
    )

    # JSONB-embedded secrets, keyed by table → column → spec (#781). All of
    # them are operator-re-enterable (SNMPv3 passphrases, a syslog CA PEM,
    # APT GPG keys, a mirror password), so unlike the machine-identity
    # columns above they are safe to blank.
    jsonb_by_table: dict[str, dict[str, Any]] = {}
    for spec in JSONB_ENCRYPTED_FIELDS:
        jsonb_by_table.setdefault(spec.table.strip('"'), {})[spec.column] = spec

    by_table: dict[str, set[str]] = {}
    # NOT ENCRYPTED_COLUMNS: machine identity (appliance CA / TLS keys,
    # k3s tokens, pairing codes) is excluded, because blanking it yields
    # an archive whose restore succeeds and then permanently breaks
    # supervisor approval with no way to regenerate (#781).
    for table, _pk, enc_col in redactable_columns():
        bare = table.strip('"')
        by_table.setdefault(bare, set()).add(enc_col)
    # Plaintext leftovers of an expand/contract move (#1364): text, not
    # bytea, so they are written as NULL rather than an empty bytea.
    null_by_table: dict[str, set[str]] = {}
    for table, column in LEGACY_PLAINTEXT_SECRET_COLUMNS:
        null_by_table.setdefault(table, set()).add(column)

    # ``COPY "public"."foo" ("a", "b", ...) FROM stdin;`` — we use
    # ``--quote-all-identifiers`` on the dump, so every name is
    # wrapped in double quotes.
    copy_re = re.compile(r'^COPY "public"\."(\w+)" \(([^)]+)\) FROM stdin;')
    out: list[str] = []
    in_copy_table: str | None = None
    cols_to_scrub: list[int] = []
    cols_to_null: list[int] = []
    jsonb_cols: list[tuple[int, Any]] = []

    for line in dump_text.splitlines(keepends=False):
        if in_copy_table is None:
            m = copy_re.match(line)
            if m:
                table = m.group(1)
                cols_list = [c.strip().strip('"') for c in m.group(2).split(",")]
                scrub_set = by_table.get(table, set())
                cols_to_scrub = [i for i, c in enumerate(cols_list) if c in scrub_set]
                null_set = null_by_table.get(table, set())
                cols_to_null = [i for i, c in enumerate(cols_list) if c in null_set]
                jsonb_cols = [
                    (i, spec)
                    for i, c in enumerate(cols_list)
                    if (spec := jsonb_by_table.get(table, {}).get(c)) is not None
                ]
                if cols_to_scrub or cols_to_null or jsonb_cols:
                    in_copy_table = table
            out.append(line)
        elif line == r"\.":
            in_copy_table = None
            cols_to_scrub = []
            cols_to_null = []
            jsonb_cols = []
            out.append(line)
        else:
            parts = line.split("\t")
            for i in cols_to_scrub:
                if i < len(parts) and parts[i] != r"\N":
                    parts[i] = r"\\x"
            for i in cols_to_null:
                if i < len(parts):
                    parts[i] = r"\N"
            for idx, spec in jsonb_cols:
                if not (0 <= idx < len(parts)):
                    continue
                raw = parts[idx]
                if raw in (r"\N", ""):
                    continue
                try:
                    # COPY plain-text escapes:
                    #   ``\\`` → backslash
                    #   ``\t`` / ``\n`` / ``\r`` → tab/newline/cr
                    # Decode to the original JSON, blank every registered
                    # secret, re-encode.
                    unescaped = (
                        raw.replace(r"\\", "\x00")
                        .replace(r"\t", "\t")
                        .replace(r"\n", "\n")
                        .replace(r"\r", "\r")
                        .replace("\x00", "\\")
                    )
                    doc = json.loads(unescaped)
                except (json.JSONDecodeError, ValueError):
                    continue
                sites = _jsonb_secret_sites(spec, doc)
                if not sites:
                    continue
                for holder, key, _ciphertext in sites:
                    # ``None`` rather than ``""`` for the keyed entries: that
                    # is what the settings writers store when an operator
                    # clears a passphrase, so a scrubbed archive restores to
                    # "not configured" instead of "configured as empty".
                    # ``backup_target.config`` keeps ``""``, which is what it
                    # has always used and what its reader expects.
                    holder[key] = "" if spec.prefix else None
                new_json = json.dumps(doc, separators=(",", ":"))
                parts[idx] = (
                    new_json.replace("\\", r"\\")
                    .replace("\t", r"\t")
                    .replace("\n", r"\n")
                    .replace("\r", r"\r")
                )
            out.append("\t".join(parts))
    # pg_dump's plain output ends with a trailing newline; preserve
    # that so the round-trip is byte-clean.
    if dump_text.endswith("\n"):
        return "\n".join(out) + "\n"
    return "\n".join(out)


async def build_backup_archive(
    db: AsyncSession,
    *,
    passphrase: str,
    passphrase_hint: str | None = None,
    exclude_secrets: bool = False,
) -> tuple[bytes, str]:
    """Build a complete backup zip in memory and return
    ``(archive_bytes, suggested_filename)``.

    Caller (the API endpoint) streams the bytes back to the
    operator. Filename pattern:
    ``spatiumddi-backup-{hostname}-{YYYYMMDD-HHMMSS}-{random}.zip``.

    ``exclude_secrets`` (Phase 3 diagnostic mode): every
    Fernet-encrypted column + every ``__enc__:`` JSONB field is
    NULLed inside a REPEATABLE READ transaction whose snapshot is
    fed to pg_dump via ``--snapshot=``. The transaction is
    rolled back after the dump finishes, so the live database
    never observes the NULL state. Restoring such an archive
    yields an install with empty credential fields — the operator
    re-enters integration / auth-provider creds by hand. Useful
    for sharing snapshots with support / consultants without
    leaking the install's secrets. The manifest carries
    ``secrets_excluded: true`` so restore can show a heads-up.
    """
    if not passphrase:
        raise BackupArchiveError("passphrase is required to build a backup")
    if hint_reveals_passphrase(passphrase, passphrase_hint):
        # The write paths refuse this; a target saved before they did
        # can still hold it. Dropped rather than raised so the schedule
        # keeps producing backups — the hint is a convenience, the
        # backup is not. Never log the hint itself.
        logger.warning("backup_hint_contains_passphrase_dropped")
        passphrase_hint = None
    schema_head = await _read_alembic_head(db)
    hostname = socket.gethostname()
    created_at = datetime.now(UTC)

    # Exclude-secrets archives use plain SQL format (Phase 3) so
    # the post-dump text scrub can find + replace encrypted column
    # values directly. Selective restore on a stripped archive
    # makes no sense (you're starting fresh by definition), so
    # giving up custom-format on this path is fine.
    dump_format = "plain" if exclude_secrets else "custom"

    manifest: dict[str, Any] = {
        "format": "spatiumddi-backup",
        # Phase 2a bumps to ``format_version: 2`` because the dump
        # member name changed from ``database.sql`` to
        # ``database.dump`` and ``dump_format`` is now declared
        # explicitly. Restore detects + handles both versions —
        # Phase 1 archives stay restorable.
        "format_version": 2,
        # Either ``"plain"`` (Phase 1 / Phase 3 exclude-secrets,
        # ``database.sql`` member) or ``"custom"`` (Phase 2+,
        # ``database.dump`` member). The restore-side
        # auto-detection still falls back on member-name sniffing
        # for archives missing this field.
        "dump_format": dump_format,
        "app_version": settings.version,
        "schema_version": schema_head,
        "hostname": hostname,
        "created_at": created_at.isoformat(),
        # Phase 2 will narrow this when operators tick "exclude
        # diagnostic sections" on backup; for now we still include
        # every persistent section.
        "included_sections": ["all_persistent"],
        "secret_passphrase_hint": (passphrase_hint or "").strip()[:200],
        # Phase 3: when set, every Fernet-encrypted column was
        # scrubbed to empty bytes at dump time. The archive is
        # shareable but operators restoring it must re-enter
        # integration / auth-provider creds by hand.
        "secrets_excluded": bool(exclude_secrets),
    }

    # secrets.enc bundles enough metadata for an offline operator to
    # know what they're decrypting, plus the SECRET_KEY they need to
    # restore on a different install. When ``secrets_excluded`` is
    # true, the SECRET_KEY is still bundled so cross-install
    # restores can rewrap any *non-stripped* encrypted columns the
    # operator added between scrub and dump (race-window edge).
    secrets_payload = {
        "platform_secret_key": settings.secret_key,
        "platform_credential_encryption_key": (settings.credential_encryption_key or ""),
        "schema_version": schema_head,
        "app_version": settings.version,
        "created_at": created_at.isoformat(),
        "hostname": hostname,
    }
    secrets_envelope = encrypt_secrets(
        secrets_payload,
        passphrase=passphrase,
        hint=passphrase_hint,
    )

    with tempfile.TemporaryDirectory(prefix="spatium-backup-") as tmpdir:
        if exclude_secrets:
            # Phase 3 exclude-secrets: emit plain SQL, post-process
            # the text in memory to replace encrypted column values
            # with empty bytes / scrub ``__enc__:`` JSONB fields.
            # Live DB is never touched.
            sql_path = Path(tmpdir) / "database.sql"
            await _run_pg_dump_plain(sql_path)
            scrubbed = _scrub_dump_text(sql_path.read_text(encoding="utf-8"))
            sql_path.write_text(scrubbed, encoding="utf-8")
            dump_path = sql_path
            dump_member = "database.sql"
        else:
            # ``database.dump`` is the Phase 2+ member name (custom
            # format). The restore-side reader still falls back on
            # ``database.sql`` for Phase 1 archives.
            dump_path = Path(tmpdir) / "database.dump"
            await _run_pg_dump(dump_path)
            dump_member = "database.dump"
        # Building the zip in memory keeps the StreamingResponse
        # path simple — install sizes that legitimately need
        # disk-backed assembly are well past Phase 1's target.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                "manifest.json",
                json.dumps(manifest, indent=2, sort_keys=True),
            )
            zf.write(dump_path, arcname=dump_member)
            zf.writestr("secrets.enc", secrets_envelope)
            zf.writestr("README.txt", _readme_text(manifest))
        archive_bytes = buf.getvalue()

    safe_host = (
        "".join(c if c.isalnum() or c in "-_" else "-" for c in hostname).strip("-") or "spatiumddi"
    )
    timestamp = created_at.strftime("%Y%m%d-%H%M%S")
    # One-second resolution alone collided (#1571): two runs in the
    # same second — two targets sharing a destination, or a manual
    # run racing the schedule — wrote the SAME filename with
    # different passphrases, and the survivor would not decrypt with
    # the overwritten target's passphrase while both runs reported
    # success. A short random suffix makes each name unique.
    filename = f"spatiumddi-backup-{safe_host}-{timestamp}-{secrets.token_hex(3)}.zip"
    logger.info(
        "backup_archive_built",
        bytes=len(archive_bytes),
        hostname=hostname,
        schema_version=schema_head,
    )
    return archive_bytes, filename


# ── Archive reading ────────────────────────────────────────────────────


def read_backup_manifest(archive_bytes: bytes) -> dict[str, Any]:
    """Pull just ``manifest.json`` out of an archive without
    extracting the rest. Used by the restore endpoint's pre-flight
    so the operator can preview "this archive is from version X /
    schema Y" before they type the confirmation phrase.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as zf:
            with zf.open("manifest.json") as fh:
                manifest = json.loads(fh.read().decode("utf-8"))
    except (zipfile.BadZipFile, KeyError, json.JSONDecodeError) as exc:
        raise BackupArchiveError(f"archive is malformed: {exc}") from exc
    if not isinstance(manifest, dict):
        raise BackupArchiveError("manifest.json is not a JSON object")
    return manifest


def extract_archive_members(
    archive_bytes: bytes,
) -> tuple[dict[str, Any], bytes, str, bytes]:
    """Pull ``(manifest_dict, database_bytes, dump_format,
    secrets_enc_bytes)`` out of an archive in one pass.

    ``dump_format`` is ``"plain"`` (Phase 1 archives — the bytes
    are SQL text, restore via psql) or ``"custom"`` (Phase 2+
    archives — bytes are pg_restore's binary format). Detection
    walks the manifest's explicit ``dump_format`` field first;
    falls back on member-name sniffing (``database.sql`` →
    plain, ``database.dump`` → custom) for archives that pre-date
    the manifest field.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as zf:
            names = set(zf.namelist())
            if "manifest.json" not in names:
                raise BackupArchiveError("archive is missing required member: manifest.json")
            if "secrets.enc" not in names:
                raise BackupArchiveError("archive is missing required member: secrets.enc")
            manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
            if not isinstance(manifest, dict):
                raise BackupArchiveError("manifest.json is not a JSON object")
            # Format detection — manifest field if present,
            # otherwise fall back to member-name sniffing.
            declared = manifest.get("dump_format")
            if declared in ("plain", "custom"):
                dump_format = declared
            elif "database.dump" in names:
                dump_format = "custom"
            elif "database.sql" in names:
                dump_format = "plain"
            else:
                raise BackupArchiveError(
                    "archive is missing the database dump member "
                    "(neither database.dump nor database.sql present)"
                )
            dump_member = "database.dump" if dump_format == "custom" else "database.sql"
            if dump_member not in names:
                raise BackupArchiveError(
                    f"archive declares dump_format={dump_format!r} but "
                    f"member {dump_member!r} is missing"
                )
            # Refuse on the DECLARED size before inflating anything
            # (#1568): the archive is untrusted until the passphrase
            # check passes, and ``zf.read`` would materialise the
            # whole member in memory — a crafted header is a zip bomb
            # aimed at the api.
            declared_size = zf.getinfo(dump_member).file_size
            if declared_size > _MAX_DUMP_MEMBER_BYTES:
                raise BackupArchiveError(
                    f"archive's database member {dump_member!r} declares "
                    f"{declared_size} bytes uncompressed, which exceeds the "
                    f"{_MAX_DUMP_MEMBER_BYTES}-byte cap — refusing to read it"
                )
            db_bytes = zf.read(dump_member)
            secrets_enc = zf.read("secrets.enc")
    except (zipfile.BadZipFile, json.JSONDecodeError) as exc:
        raise BackupArchiveError(f"archive is malformed: {exc}") from exc
    return manifest, db_bytes, dump_format, secrets_enc
