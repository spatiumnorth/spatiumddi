"""Restore-verification drills (issue #702).

A drill answers the one question the backup subsystem could not:
*is the archive we wrote last night actually restorable?* It
downloads a target's newest archive, replays it into a throwaway
scratch database, runs a fixed assertion set against the result,
and drops the scratch database again.

**The live database is never written to.** Every subprocess and
every session in this module is pointed at a scratch database whose
name this module generates from a fixed prefix plus random hex —
never from operator input, and never equal to the live database
name (:func:`_scratch_db_name` asserts both).

Deliberately *not* built on :func:`app.services.backup.restore.apply_backup_restore`:
that function takes a pre-restore safety dump against the live
session and disposes the live engine's connection pool, which is
correct for an operator-initiated restore and actively wrong for an
unattended background drill. The replay helpers here are local for
the same reason — ``restore._run_psql`` terminates every other
connection to its target database, which must never become
something a drill can do.

Verdict vocabulary — ``failed`` and ``error`` are operationally
distinct and worth keeping apart:

* ``failed`` — the drill reached a verdict and the archive did not
  hold up (malformed, wrong passphrase, replay aborted, an
  assertion did not pass). This is a real finding about the backup.
* ``error`` — the drill could not reach a verdict at all
  (destination unreachable, scratch database couldn't be created).
  This says nothing about the archive.

Only ``failed`` should page someone about their backups.
"""

from __future__ import annotations

import asyncio
import os
import secrets as secrets_mod
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.config import settings
from app.core.crypto import decrypt_str
from app.models.audit import AuditLog
from app.models.backup import BackupTarget, RestoreDrill
from app.services.backup.archive import (
    BackupArchiveError,
    _pg_env_from_url,
    _pg_subprocess_env,
    extract_archive_members,
)
from app.services.backup.crypto import BackupCryptoError, decrypt_secrets
from app.services.backup.restore import SUPPORTED_FORMAT_VERSIONS
from app.services.backup.targets import (
    BackupDestinationError,
    SecretFieldError,
    decrypt_config_secrets,
    get_destination,
)

logger = structlog.get_logger(__name__)

SCRATCH_DB_PREFIX = "spatiumddi_drill_"

# A drill replays a full dump, so it gets the same envelope the
# restore path uses. The maintenance statements (CREATE / DROP
# DATABASE) are fast and get a much tighter bound.
_REPLAY_TIMEOUT_SECONDS = 30 * 60
_MAINTENANCE_TIMEOUT_SECONDS = 120
# Fetching the archive off the destination is unbounded by the driver
# (an S3 pull over a slow WAN can run long), so the drill bounds it
# itself. Without this the total runtime has no ceiling and
# STALE_IN_PROGRESS_SECONDS below would be a fiction.
_DOWNLOAD_TIMEOUT_SECONDS = 30 * 60
# The post-replay assertions open a session on the scratch database
# and walk the audit chain. Bounded for the same reason.
_ASSERT_TIMEOUT_SECONDS = 10 * 60

# How long a ``drill_last_status="in_progress"`` mutex is believed
# before the sweep treats it as stranded. A worker killed mid-drill
# never gets to stamp a terminal state, and without this the target
# would silently stop drilling forever.
#
# Derived from EVERY bounded phase, not just the replay: download +
# replay + assertions + slack for the un-timed glue between them. Set
# it below the real worst case and the sweep would start a second
# drill against a target that is still legitimately working, giving
# two concurrent scratch databases and a verdict race.
STALE_IN_PROGRESS_SECONDS = (
    _DOWNLOAD_TIMEOUT_SECONDS + _REPLAY_TIMEOUT_SECONDS + _ASSERT_TIMEOUT_SECONDS + 15 * 60
)

# The audit-chain walk materialises one ORM object per row, and it runs
# while the archive bytes and the dump bytes are both still referenced.
# On a multi-million-row audit log that is an OOM-kill mid-drill — which
# stranding the mutex and leaking the scratch database on the way out.
# Cap the walk: a break in the first 250k rows is plenty to prove the
# chain is damaged, and the nightly audit_chain_verify task does the
# exhaustive pass against the live table.
_CHAIN_VERIFY_MAX_ROWS = 250_000

# A drill puts a full second copy of the database on the SAME Postgres
# instance. On the appliance's default 8Gi CNPG volume a 6 GB install
# would fill the volume and take the production primary down with it —
# an outage caused by a read-only verification job. There is no portable
# way to ask Postgres how much free space its data volume has, so the
# risk is bounded from the other end: refuse to drill when the copy
# would exceed this size unless the operator raises the ceiling
# deliberately (``SPATIUM_DRILL_MAX_DB_BYTES``).
_DEFAULT_MAX_DB_BYTES = 20 * 1024**3

# Assertion verdicts.
PASS = "pass"
FAIL = "fail"
SKIP = "skip"


def _human_bytes(n: int) -> str:
    """Size for an operator-facing message.

    Integer GiB alone renders anything under a gigabyte as "0 GiB",
    which reads as a bug in the message rather than a small database.
    """
    for unit, scale in (("GiB", 1024**3), ("MiB", 1024**2), ("KiB", 1024)):
        if n >= scale:
            return f"{n / scale:.1f} {unit}"
    return f"{n} bytes"


def drill_mutex_is_stale(target: BackupTarget, now: datetime) -> bool:
    """True when an ``in_progress`` drill mutex was stranded rather
    than being genuinely held.

    A worker killed mid-drill — or an api pod restarted under a
    synchronous manual run — never stamps a terminal state, and the
    target would otherwise stop drilling forever and 409 every manual
    retry. ``drill_last_at`` carries the running drill's start time, so
    its age is the mutex's age. A NULL means the row was never stamped
    at all, which is also stale.

    Shared by the beat sweep and the manual run-now endpoint: both need
    the identical rule, and letting them drift would mean the scheduler
    recovers a target the operator still can't touch by hand.
    """
    if target.drill_last_at is None:
        return True
    age = (now - target.drill_last_at).total_seconds()
    if age < STALE_IN_PROGRESS_SECONDS:
        return False
    logger.warning(
        "restore_drill_stale_mutex_cleared",
        target_id=str(target.id),
        age_seconds=int(age),
    )
    return True


def _max_scratch_db_bytes() -> int:
    """Ceiling on the live database size a drill will copy.

    Env-overridable rather than a settings column: it is a safety
    property of the host's disk, not per-target configuration, and an
    operator raising it is making a deliberate statement about their
    volume. ``0`` disables the guard.
    """
    raw = os.environ.get("SPATIUM_DRILL_MAX_DB_BYTES")
    if not raw:
        return _DEFAULT_MAX_DB_BYTES
    try:
        return max(0, int(raw))
    except ValueError:
        logger.warning("restore_drill_bad_max_db_bytes", value=raw)
        return _DEFAULT_MAX_DB_BYTES


class DrillError(Exception):
    """Infrastructure failure — the drill could not reach a verdict.

    Distinct from a *failed* drill, which is a real finding about
    the archive. Raising this maps the run to ``state="error"``.
    """


@dataclass
class Assertion:
    name: str
    status: str
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "status": self.status, "detail": self.detail}


#: Terminal drill state for "we could not check this one" (#989 item 1).
#:
#: Distinct from ``error`` (something broke) and from ``failed`` (the
#: archive did not survive a test restore). A write-only destination
#: cannot be listed *by design*, so neither of the other two is honest:
#: ``error`` implies a fault to fix, ``failed`` is a claim about the
#: archive that nothing here has evidence for.
#:
#: The name is short because ``restore_drill.state`` is ``String(20)``;
#: the issue's ``cannot_drill_write_only`` does not fit, and the reason
#: belongs in ``error`` anyway, which is where it goes.
CANNOT_DRILL = "cannot_drill"


@dataclass
class DrillOutcome:
    state: str
    assertions: list[Assertion] = field(default_factory=list)
    filename: str | None = None
    archive_bytes: int | None = None
    manifest: dict[str, Any] | None = None
    scratch_db: str | None = None
    error: str | None = None


# ── scratch database lifecycle ────────────────────────────────────────


def _scratch_db_name(live_dbname: str) -> str:
    """Generate a throwaway database name.

    Fixed prefix + random hex, never operator-derived. The equality
    check against the live name is belt-and-braces — the prefix
    makes a collision essentially impossible — but this is the one
    place where a bug would replay a backup over production, so it
    is asserted explicitly rather than reasoned about.
    """
    name = f"{SCRATCH_DB_PREFIX}{secrets_mod.token_hex(6)}"
    if name == live_dbname:
        raise DrillError("generated scratch database name collided with the live database")
    return name


async def _query_scalar(sql: str, *, live_db_url: str, timeout: float) -> str:
    """Run a single read-only query against the live database and
    return the first column of the first row as text."""
    pg_env, _dbname = _pg_env_from_url(live_db_url)
    proc = await asyncio.create_subprocess_exec(
        "psql",
        "--no-align",
        "--tuples-only",
        "--set=ON_ERROR_STOP=1",
        f"--command={sql}",
        env=_pg_subprocess_env(pg_env),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise DrillError(f"query exceeded {timeout}s timeout") from exc
    if proc.returncode != 0:
        msg = (stderr.decode(errors="replace") or stdout.decode(errors="replace"))[:800]
        raise DrillError(f"query failed (exit {proc.returncode}): {msg}")
    return stdout.decode(errors="replace").strip()


async def preflight(*, live_db_url: str) -> None:
    """Prove a drill *can* run before it starts creating things.

    Two gates, both raising :class:`DrillError` (→ ``state="error"``,
    which correctly says nothing about the archive):

    1. **CREATEDB.** The appliance's permanent Postgres shape is
       CloudNativePG, whose ``initdb.owner`` is a plain LOGIN role with
       no CREATEDB and superuser access switched off. Without the
       privilege every drill dies inside ``CREATE DATABASE`` with a
       bare "permission denied", which reads as a mysterious
       infrastructure fault rather than a one-line fix. Checked up
       front so the message can name the privilege, the role, and the
       remedy.
    2. **Size.** The scratch database is a full second copy on the same
       instance. Postgres exposes no portable free-space query, so the
       exposure is bounded by refusing to copy a database larger than
       the operator has agreed to.
    """
    role_can_create = await _query_scalar(
        "SELECT rolcreatedb OR rolsuper FROM pg_roles WHERE rolname = current_user",
        live_db_url=live_db_url,
        timeout=_MAINTENANCE_TIMEOUT_SECONDS,
    )
    if role_can_create.lower() not in ("t", "true"):
        _pg_env, dbname = _pg_env_from_url(live_db_url)
        raise DrillError(
            "the database role SpatiumDDI connects as lacks CREATEDB, so a "
            "throwaway database cannot be created. On Kubernetes / appliance "
            "installs set `postgresql.cnpg.appRoleCreateDb: true` (the chart "
            "default) and let CloudNativePG reconcile the role; on "
            "docker-compose grant it directly with "
            f"`ALTER ROLE <user> CREATEDB;` against {dbname}. Restore drills "
            "cannot run until then."
        )

    ceiling = _max_scratch_db_bytes()
    if ceiling <= 0:
        return
    raw_size = await _query_scalar(
        "SELECT pg_database_size(current_database())",
        live_db_url=live_db_url,
        timeout=_MAINTENANCE_TIMEOUT_SECONDS,
    )
    try:
        size = int(raw_size)
    except ValueError:
        # Couldn't measure — don't block the drill on a probe failure,
        # but say so, because the size guard is silently not applying.
        logger.warning("restore_drill_size_probe_unreadable", value=raw_size[:120])
        return
    if size > ceiling:
        raise DrillError(
            f"the live database is {_human_bytes(size)} and a drill copies it "
            f"in full onto the same Postgres instance, which would risk filling "
            f"the volume the production database is running on. The ceiling is "
            f"{_human_bytes(ceiling)}. Raise SPATIUM_DRILL_MAX_DB_BYTES "
            f"(bytes, 0 disables the guard) once you have confirmed the data "
            f"volume has room for a second copy."
        )


async def _run_maintenance_sql(sql: str, *, live_db_url: str, timeout: float) -> None:
    """Run a single statement against the ``postgres`` maintenance
    database. CREATE / DROP DATABASE cannot run inside a
    transaction block and cannot run while connected to the
    database being created or dropped, so these are issued against
    ``postgres`` rather than either the live or scratch database.
    """
    pg_env, _dbname = _pg_env_from_url(live_db_url)
    pg_env = {**pg_env, "PGDATABASE": "postgres"}
    proc = await asyncio.create_subprocess_exec(
        "psql",
        "--set=ON_ERROR_STOP=1",
        f"--command={sql}",
        env=_pg_subprocess_env(pg_env),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise DrillError(f"maintenance statement exceeded {timeout}s timeout") from exc
    if proc.returncode != 0:
        msg = (stderr.decode(errors="replace") or stdout.decode(errors="replace"))[:800]
        raise DrillError(f"maintenance statement failed (exit {proc.returncode}): {msg}")


async def _create_scratch_db(name: str, *, live_db_url: str) -> None:
    await _run_maintenance_sql(
        f'CREATE DATABASE "{name}"',
        live_db_url=live_db_url,
        timeout=_MAINTENANCE_TIMEOUT_SECONDS,
    )


async def _drop_scratch_db(name: str, *, live_db_url: str) -> None:
    """Drop the scratch database, best-effort.

    Runs in a ``finally`` — a failure to clean up must not mask the
    drill's actual verdict, so this logs and returns rather than
    raising. ``WITH (FORCE)`` kicks any connection we left behind
    (Postgres 13+); the scratch database is ours alone, so there is
    nothing else that could legitimately be attached.
    """
    if not name.startswith(SCRATCH_DB_PREFIX):
        logger.error("restore_drill_refusing_drop", dbname=name)
        return
    try:
        await _run_maintenance_sql(
            f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)',
            live_db_url=live_db_url,
            timeout=_MAINTENANCE_TIMEOUT_SECONDS,
        )
    except DrillError as exc:
        # Leaves a stray database behind. Surfaced loudly because it
        # needs manual cleanup, but never fatal to the drill result.
        logger.error("restore_drill_scratch_drop_failed", dbname=name, error=str(exc))


async def reap_orphaned_scratch_dbs(*, live_db_url: str) -> list[str]:
    """Drop ``spatiumddi_drill_*`` databases left behind by a drill that
    never reached its ``finally``.

    The in-process cleanup covers every path the drill can *return*
    through, but not a SIGKILL — a pod eviction, an OOM kill, or a node
    drain mid-replay leaves a full-size copy of the production database
    on the instance forever. Nothing else would ever remove it, and the
    stale-mutex path re-drills under a *fresh* random name, so each
    killed drill would permanently add another copy until the volume
    filled. The fixed prefix exists precisely so this sweep is possible.

    Liveness, not age, is the safety signal: a drill holds a connection
    to its scratch database for the whole replay-and-assert window, so
    "carries the prefix AND has no backend attached" cannot match a
    drill that is still working. That avoids having to guess a safe age
    threshold, and it stays correct however long a legitimate drill
    runs.
    """
    listing = await _query_scalar(
        "SELECT string_agg(d.datname, ',') FROM pg_database d "
        "WHERE d.datname LIKE 'spatiumddi\\_drill\\_%' "
        "AND NOT EXISTS (SELECT 1 FROM pg_stat_activity a WHERE a.datname = d.datname)",
        live_db_url=live_db_url,
        timeout=_MAINTENANCE_TIMEOUT_SECONDS,
    )
    names = [n.strip() for n in listing.split(",") if n.strip()]
    reaped: list[str] = []
    for name in names:
        if not name.startswith(SCRATCH_DB_PREFIX):
            continue
        await _drop_scratch_db(name, live_db_url=live_db_url)
        reaped.append(name)
    if reaped:
        logger.warning(
            "restore_drill_reaped_orphans",
            count=len(reaped),
            databases=reaped,
            note="left behind by drills that were killed before cleanup",
        )
    return reaped


def _scratch_url(live_db_url: str, scratch_db: str) -> str:
    """Swap the database name in a SQLAlchemy URL, preserving driver,
    credentials, and any query string (``?ssl=require`` and friends).
    """
    head, sep, query = live_db_url.partition("?")
    base, _, _old_dbname = head.rpartition("/")
    if not base:
        raise DrillError(f"could not derive a scratch URL from {live_db_url!r}")
    return f"{base}/{scratch_db}{sep}{query}"


# ── replay ────────────────────────────────────────────────────────────


async def _replay_into_scratch(
    db_bytes: bytes, *, dump_format: str, scratch_db: str, live_db_url: str
) -> None:
    """Replay the archive's dump member into the scratch database.

    Raises :class:`BackupArchiveError` on a non-zero exit — a dump
    that won't replay is a finding about the archive (``failed``),
    not an infrastructure error.
    """
    pg_env, _live = _pg_env_from_url(live_db_url)
    pg_env = {**pg_env, "PGDATABASE": scratch_db}
    env = _pg_subprocess_env(pg_env)

    with tempfile.TemporaryDirectory(prefix="spatium-drill-") as tmpdir:
        suffix = "sql" if dump_format == "plain" else "dump"
        dump_path = Path(tmpdir) / f"database.{suffix}"
        dump_path.write_bytes(db_bytes)
        os.chmod(dump_path, 0o600)

        if dump_format == "plain":
            cmd = [
                "psql",
                "--set=ON_ERROR_STOP=1",
                "--single-transaction",
                f"--file={dump_path}",
            ]
        else:
            cmd = [
                "pg_restore",
                "--dbname",
                scratch_db,
                "--no-owner",
                "--no-acl",
                "--single-transaction",
                "--exit-on-error",
                str(dump_path),
            ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=_REPLAY_TIMEOUT_SECONDS
            )
        except TimeoutError as exc:
            proc.kill()
            await proc.wait()
            raise BackupArchiveError(f"replay exceeded {_REPLAY_TIMEOUT_SECONDS}s timeout") from exc
        if proc.returncode != 0:
            msg = (stderr.decode(errors="replace") or stdout.decode(errors="replace"))[:1500]
            raise BackupArchiveError(f"replay failed (exit {proc.returncode}): {msg}")


# ── assertions ────────────────────────────────────────────────────────

# Tables whose emptiness would make a restore useless. Deliberately
# short: a drill asserts the archive is *usable*, not that the
# operator's data looks a particular way.
_REQUIRED_NONEMPTY = ("user", "alembic_version")


async def _assert_against_scratch(scratch_url: str) -> list[Assertion]:
    """Open a session on the restored scratch database and run the
    post-replay checks."""
    out: list[Assertion] = []
    # NullPool: this engine lives for one drill and is disposed
    # immediately, and a pooled connection left open would block the
    # DROP DATABASE in the caller's ``finally``.
    engine = create_async_engine(scratch_url, poolclass=NullPool)
    maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    try:
        async with maker() as session:
            head = await _assert_alembic_head(session, out)
            await _assert_required_tables(session, out)
            await _assert_audit_chain(session, out, restored_head=head)
    finally:
        await engine.dispose()
    return out


async def _assert_alembic_head(session: AsyncSession, out: list[Assertion]) -> str | None:
    """Assert the restored database declares exactly one alembic
    revision, and report how it relates to the bundled head.

    A restored head *behind* the bundled head is not a failure — the
    real restore path runs ``alembic upgrade head`` afterwards
    (``maybe_upgrade_after_restore``). A head the running build has
    never heard of is a failure: nothing can migrate it forward.
    """
    from app.core.schema_check import expected_alembic_head  # noqa: PLC0415

    try:
        versions: list[str] = list(
            (await session.execute(text("SELECT version_num FROM alembic_version"))).scalars()
        )
    except Exception as exc:  # noqa: BLE001 — any DB error is a finding
        out.append(
            Assertion(
                "alembic_version_present",
                FAIL,
                f"could not read alembic_version from the restored database: {exc}",
            )
        )
        return None

    if len(versions) != 1:
        out.append(
            Assertion(
                "alembic_version_present",
                FAIL,
                f"expected exactly 1 alembic_version row, found {len(versions)}"
                + (" (multi-head schema)" if len(versions) > 1 else ""),
            )
        )
        return None

    restored = versions[0]
    bundled, err = expected_alembic_head()
    if bundled is None:
        out.append(
            Assertion(
                "alembic_version_present",
                PASS,
                f"restored at {restored}; could not compare to the bundled head ({err})",
            )
        )
        return restored

    if restored == bundled:
        out.append(
            Assertion("alembic_version_present", PASS, f"restored at bundled head {restored}")
        )
        return restored

    if _is_known_revision(restored):
        out.append(
            Assertion(
                "alembic_version_present",
                PASS,
                f"restored at {restored}, behind bundled head {bundled} — "
                f"a real restore would migrate it forward",
            )
        )
        return restored

    out.append(
        Assertion(
            "alembic_version_present",
            FAIL,
            f"restored at {restored}, which this build does not know — "
            f"it cannot be migrated to the bundled head {bundled}. The "
            f"archive was taken by a newer SpatiumDDI than this one.",
        )
    )
    return restored


def _is_known_revision(revision: str) -> bool:
    """True when the bundled alembic scripts contain ``revision``."""
    try:
        from alembic.config import Config  # noqa: PLC0415
        from alembic.script import ScriptDirectory  # noqa: PLC0415

        from app.core.schema_check import _locate_alembic_ini  # noqa: PLC0415

        ini = _locate_alembic_ini()
        if ini is None:
            return False
        script = ScriptDirectory.from_config(Config(str(ini)))
        return script.get_revision(revision) is not None
    except Exception:  # noqa: BLE001
        # Unknown revision id raises; so does a malformed script dir.
        # Either way we can't vouch for it.
        return False


async def _assert_required_tables(session: AsyncSession, out: list[Assertion]) -> None:
    """Assert the tables a restore is useless without came back with
    rows in them."""
    counts: dict[str, int | None] = {}
    for table in _REQUIRED_NONEMPTY:
        try:
            result = await session.execute(text(f'SELECT count(*) FROM "{table}"'))
            counts[table] = int(result.scalar_one())
        except Exception as exc:  # noqa: BLE001 — missing table is a finding
            out.append(
                Assertion(
                    "core_tables_populated",
                    FAIL,
                    f'could not count rows in "{table}": {exc}',
                )
            )
            return

    empty = [name for name, n in counts.items() if not n]
    summary = ", ".join(f"{name}={n}" for name, n in counts.items())
    if empty:
        out.append(
            Assertion(
                "core_tables_populated",
                FAIL,
                f"restored but empty: {', '.join(empty)} — an install restored "
                f"from this archive would have no way in ({summary})",
            )
        )
        return
    out.append(Assertion("core_tables_populated", PASS, summary))


async def _assert_audit_chain(
    session: AsyncSession, out: list[Assertion], *, restored_head: str | None
) -> None:
    """Verify the restored audit log's tamper-evident hash chain.

    Skipped when the restored schema isn't at the bundled head: the
    verifier selects through the ORM model, so a column added since
    the archive was taken would raise ``UndefinedColumn`` and read
    as tampering when it is really schema skew.
    """
    from app.core.schema_check import expected_alembic_head  # noqa: PLC0415
    from app.services.audit_chain import verify_chain  # noqa: PLC0415

    bundled, _err = expected_alembic_head()
    if bundled is not None and restored_head is not None and restored_head != bundled:
        out.append(
            Assertion(
                "audit_chain_intact",
                SKIP,
                f"restored schema is at {restored_head}, not the bundled head "
                f"{bundled} — the ORM-based verifier would misread schema skew "
                f"as tampering",
            )
        )
        return

    try:
        result = await verify_chain(session, max_rows=_CHAIN_VERIFY_MAX_ROWS)
    except Exception as exc:  # noqa: BLE001
        out.append(
            Assertion("audit_chain_intact", SKIP, f"chain verification could not run: {exc}")
        )
        return

    if result.ok:
        capped = (
            f" (capped at {_CHAIN_VERIFY_MAX_ROWS}; the nightly verify task walks the full table)"
            if result.rows_checked >= _CHAIN_VERIFY_MAX_ROWS
            else ""
        )
        out.append(
            Assertion("audit_chain_intact", PASS, f"{result.rows_checked} rows verified{capped}")
        )
        return
    first = result.breaks[0] if result.breaks else None
    detail = f"{len(result.breaks)} break(s) across {result.rows_checked} rows" + (
        f"; first at seq {first.seq} ({first.reason})" if first is not None else ""
    )
    out.append(Assertion("audit_chain_intact", FAIL, detail))


# ── readiness rollup ──────────────────────────────────────────────────


async def compute_drill_readiness(db: AsyncSession) -> list[dict[str, Any]]:
    """Per-target recovery readiness: *can this be restored, and how do
    we know?*

    Shared by the REST endpoint, the Operator Copilot tool, and the
    admin UI so all three answer identically — the question is too
    load-bearing to have three implementations that can drift.

    ``verified`` is deliberately NOT "the last drill passed":

    * A target whose latest drill hit ``error`` (destination briefly
      unreachable) has not been disproven — the alert path treats an
      error as leaving the previous verdict standing, and this must
      agree, or a transient S3 blip would report a backup proven 24 h
      ago as unverified.
    * A target that has never passed is unverified regardless of what
      else it has done. An untested backup is an unknown, not a pass.

    So: verified = has passed at some point AND the most recent
    *finished* verdict is not a failure. ``hours_since_last_pass``
    carries the staleness so callers can judge how old the proof is.

    A **write-only** target (#989 item 1) carries ``undrillable_reason``
    and is forced to ``verified: false`` — an unverifiable backup is an
    unknown, the same category as an untested one, and that holds even
    when the target passed drills before write-only was switched on. ``cannot_drill`` behaves like ``error`` here: it is
    not in the ``latest_finished_verdict`` set, so it neither counts as
    a pass nor erases an earlier one.
    """
    targets = (
        (await db.execute(select(BackupTarget).order_by(BackupTarget.name.asc()))).scalars().all()
    )
    now = datetime.now(UTC)
    out: list[dict[str, Any]] = []
    for t in targets:
        last_pass = await db.scalar(
            select(RestoreDrill.finished_at)
            .where(RestoreDrill.target_id == t.id, RestoreDrill.state == "passed")
            .order_by(RestoreDrill.finished_at.desc())
            .limit(1)
        )
        latest_finished = await db.scalar(
            select(RestoreDrill.state)
            .where(RestoreDrill.target_id == t.id, RestoreDrill.state.in_(("passed", "failed")))
            .order_by(RestoreDrill.started_at.desc())
            .limit(1)
        )
        age_hours = round((now - last_pass).total_seconds() / 3600, 1) if last_pass else None
        # A write-only destination cannot be drilled from here (#989
        # item 1). That is a supported configuration, not a fault — but
        # it must never read as healthy, so it is surfaced as its own
        # field rather than being folded into ``verified`` (which would
        # make "unverifiable by design" indistinguishable from "failed a
        # drill last night").
        undrillable_reason = (
            "this target is write-only, so SpatiumDDI cannot list or read its "
            "archives back — verify it from the destination side, or keep a second "
            "readable destination"
            if t.write_only
            else None
        )
        out.append(
            {
                "target_id": str(t.id),
                "target_name": t.name,
                "kind": t.kind,
                "enabled": t.enabled,
                "write_only": t.write_only,
                "undrillable_reason": undrillable_reason,
                "drills_scheduled": bool(t.drill_enabled and t.drill_cron),
                "drill_cron": t.drill_cron,
                "latest_verdict": t.drill_last_status,
                "latest_finished_verdict": latest_finished,
                "latest_drill_at": t.drill_last_at.isoformat() if t.drill_last_at else None,
                "last_passed_at": last_pass.isoformat() if last_pass else None,
                "hours_since_last_pass": age_hours,
                # An undrillable target is NEVER verified — asserted, not
                # inferred.
                #
                # The first cut left the expression alone, reasoning that
                # such a target "has never passed, so last_pass is None".
                # That holds only for a target created write-only on day
                # one, and the shipped hardening advice is the opposite:
                # prove an S3 target with drills for months, THEN add
                # Object Lock and tick write-only. After that flip every
                # drill returns ``cannot_drill``, which is excluded from
                # the ``latest_finished`` set — so ``last_pass`` kept
                # pointing at the old success and ``verified`` stayed true
                # forever, off a proof that can never be refreshed, while
                # ``hours_since_last_pass`` grew without bound. That is
                # precisely the "unverifiable must never read as healthy"
                # invariant this block exists to hold.
                "verified": (
                    undrillable_reason is None
                    and last_pass is not None
                    and latest_finished != "failed"
                ),
            }
        )
    return out


# ── orchestration ─────────────────────────────────────────────────────


async def run_drill_for_target(
    db: AsyncSession,
    *,
    target: BackupTarget,
    triggered_by: str = "manual",
    actor_id: uuid.UUID | None = None,
    actor_display: str = "system (schedule)",
) -> RestoreDrill:
    """Run one restore-verification drill against ``target``.

    Persists a ``running`` row up front so a long drill is visible
    in the UI while it works, then stamps the terminal state. The
    caller commits; the row is returned attached to ``db``.

    The audit row is written *here* rather than in the API handler so
    scheduled drills are audited too — this function mutates
    ``backup_target`` and inserts a ``restore_drill`` row on every run,
    and non-negotiable #4 admits no "unless a cron did it" exception.
    Mirrors ``run_backup_for_target``, which audits from the runner for
    the same reason.
    """
    started = datetime.now(UTC)
    row = RestoreDrill(target_id=target.id, state="running", triggered_by=triggered_by)
    db.add(row)
    target.drill_last_status = "in_progress"
    # While a drill is running this holds its *start* time, which is
    # what lets the sweep spot a mutex stranded by a killed worker
    # (see STALE_IN_PROGRESS_SECONDS). It's overwritten with the
    # finish time below.
    target.drill_last_at = started
    await db.commit()
    await db.refresh(row)

    live_db_url = str(settings.database_url)
    outcome = await _execute(target, live_db_url=live_db_url)

    finished = datetime.now(UTC)
    row.state = outcome.state
    row.assertions = [a.as_dict() for a in outcome.assertions]
    row.filename = outcome.filename
    row.archive_bytes = outcome.archive_bytes
    row.manifest = outcome.manifest
    row.scratch_db = outcome.scratch_db
    row.error = outcome.error
    row.finished_at = finished
    row.duration_ms = int((finished - started).total_seconds() * 1000)

    target.drill_last_status = outcome.state
    target.drill_last_at = finished
    if target.drill_enabled and target.drill_cron:
        from app.services.backup.schedule import compute_next_run  # noqa: PLC0415

        try:
            target.drill_next_run_at = compute_next_run(target.drill_cron, after=finished)
        except Exception as exc:  # noqa: BLE001
            # A bad cron shouldn't wedge the sweep on this row forever.
            logger.warning(
                "restore_drill_next_run_failed",
                target_id=str(target.id),
                cron=target.drill_cron,
                error=str(exc),
            )
            target.drill_next_run_at = None

    db.add(
        AuditLog(
            action="backup_restore_drill",
            resource_type="backup_target",
            resource_id=str(target.id),
            resource_display=target.name,
            user_id=actor_id,
            user_display_name=actor_display,
            result="success" if outcome.state == "passed" else "failure",
            error_detail=outcome.error,
            new_value={
                "drill_id": str(row.id),
                "state": outcome.state,
                "triggered_by": triggered_by,
                "filename": outcome.filename,
                "duration_ms": row.duration_ms,
                "assertions": row.assertions,
            },
        )
    )

    logger.info(
        "restore_drill_finished",
        target_id=str(target.id),
        state=outcome.state,
        filename=outcome.filename,
        duration_ms=row.duration_ms,
    )
    return row


async def _execute(target: BackupTarget, *, live_db_url: str) -> DrillOutcome:
    """Do the work, translating every failure mode into a verdict.

    Never raises: the caller always gets a ``DrillOutcome`` to
    persist.
    """
    assertions: list[Assertion] = []

    # 0. Prove the drill can run at all before creating anything. Both
    #    gates are infrastructure facts, so a failure is ``error`` —
    #    it says nothing about the archive.
    try:
        await preflight(live_db_url=live_db_url)
    except DrillError as exc:
        return DrillOutcome(state="error", error=str(exc))

    # 1. Fetch the newest archive from the destination.
    try:
        driver = get_destination(target.kind)
        plain_config = decrypt_config_secrets(driver, target.config)
        listings = await driver.list_archives(config=plain_config)
    except (BackupDestinationError, SecretFieldError, ValueError) as exc:
        if target.write_only:
            # A write-only target whose credential cannot list is the
            # recommended shape, not a fault (#989 item 1). Reporting it
            # as ``error`` every week would train the operator to ignore
            # the one state that means "we cannot verify this backup".
            return DrillOutcome(
                state=CANNOT_DRILL,
                error=(
                    "this target is write-only and its destination cannot be listed, "
                    f"so the archive cannot be verified from here ({exc}). Recovery "
                    "readiness reports it as UNVERIFIED — restore-test it from the "
                    "destination side, or keep a second readable destination."
                ),
            )
        return DrillOutcome(state="error", error=f"could not reach the destination: {exc}")

    if not listings:
        if target.write_only:
            # THE important branch. An empty listing from a destination
            # we are not permitted to list is not evidence that there
            # are no archives — and ``failed`` would state exactly that,
            # in an alert, about a target that is very likely fine. The
            # honest verdict is that we cannot tell.
            return DrillOutcome(
                state=CANNOT_DRILL,
                error=(
                    "this target is write-only, so SpatiumDDI cannot enumerate what it "
                    "holds; an empty listing here is not evidence that the destination "
                    "is empty. Recovery readiness reports it as UNVERIFIED."
                ),
            )
        assertions.append(
            Assertion(
                "archive_available",
                FAIL,
                "the destination holds no archives — there is nothing to restore from",
            )
        )
        return DrillOutcome(state="failed", assertions=assertions)

    newest = max(listings, key=lambda a: a.created_at)
    assertions.append(
        Assertion("archive_available", PASS, f"{newest.filename} ({newest.size_bytes} bytes)")
    )

    try:
        # Bounded explicitly: the destination drivers impose no ceiling
        # of their own, and an unbounded fetch would make the sweep's
        # stale-mutex threshold meaningless (see
        # STALE_IN_PROGRESS_SECONDS).
        archive_bytes = await asyncio.wait_for(
            driver.download(config=plain_config, filename=newest.filename),
            timeout=_DOWNLOAD_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        return DrillOutcome(
            state="error",
            filename=newest.filename,
            assertions=assertions,
            error=(
                f"downloading {newest.filename} from the destination exceeded "
                f"{_DOWNLOAD_TIMEOUT_SECONDS}s"
            ),
        )
    except BackupDestinationError as exc:
        return DrillOutcome(
            state="error",
            filename=newest.filename,
            assertions=assertions,
            error=f"download failed: {exc}",
        )
    if not archive_bytes:
        assertions.append(
            Assertion("archive_readable", FAIL, "archive downloaded empty from the destination")
        )
        return DrillOutcome(state="failed", filename=newest.filename, assertions=assertions)

    base = DrillOutcome(
        state="failed",
        filename=newest.filename,
        archive_bytes=len(archive_bytes),
        assertions=assertions,
    )

    # 2. Parse it, and prove the stored passphrase opens it.
    try:
        manifest, db_bytes, dump_format, secrets_enc = extract_archive_members(archive_bytes)
    except BackupArchiveError as exc:
        assertions.append(Assertion("archive_readable", FAIL, str(exc)))
        return base
    base.manifest = manifest
    # The real restore path refuses an archive whose format_version this
    # build doesn't support, so a drill that waved it through would
    # report "restorable" for something restore would reject outright —
    # the one failure mode this whole feature exists to catch. Checked
    # against the same constant restore.apply_backup_restore uses.
    fmt_version = manifest.get("format_version")
    if fmt_version not in SUPPORTED_FORMAT_VERSIONS:
        assertions.append(
            Assertion(
                "archive_readable",
                FAIL,
                f"unsupported backup format_version {fmt_version!r} — this build "
                f"restores {sorted(SUPPORTED_FORMAT_VERSIONS)}. The archive was "
                f"written by a newer SpatiumDDI; a restore would refuse it.",
            )
        )
        return base
    assertions.append(
        Assertion(
            "archive_readable",
            PASS,
            f"format_version={fmt_version} dump_format={dump_format}",
        )
    )

    try:
        passphrase = decrypt_str(target.passphrase_encrypted)
    except Exception as exc:  # noqa: BLE001
        # The stored passphrase itself is unreadable — that's this
        # install's key management, not the archive.
        return DrillOutcome(
            state="error",
            filename=newest.filename,
            archive_bytes=len(archive_bytes),
            manifest=manifest,
            assertions=assertions,
            error=f"could not decrypt the target's stored passphrase: {exc}",
        )

    try:
        payload = decrypt_secrets(secrets_enc, passphrase=passphrase)
    except BackupCryptoError as exc:
        assertions.append(
            Assertion(
                "passphrase_opens_secrets",
                FAIL,
                f"the passphrase stored on this target does not open the archive's "
                f"secrets.enc — a restore from it would be impossible ({exc})",
            )
        )
        return base
    assertions.append(
        Assertion(
            "passphrase_opens_secrets",
            PASS,
            f"{len(payload)} secret key(s) recovered",
        )
    )

    # 3. Replay into a throwaway database and assert against it.
    try:
        _pg_env, live_dbname = _pg_env_from_url(live_db_url)
        scratch_db = _scratch_db_name(live_dbname)
    except (BackupArchiveError, DrillError) as exc:
        return DrillOutcome(
            state="error",
            filename=newest.filename,
            archive_bytes=len(archive_bytes),
            manifest=manifest,
            assertions=assertions,
            error=str(exc),
        )
    base.scratch_db = scratch_db

    try:
        await _create_scratch_db(scratch_db, live_db_url=live_db_url)
    except DrillError as exc:
        return DrillOutcome(
            state="error",
            filename=newest.filename,
            archive_bytes=len(archive_bytes),
            manifest=manifest,
            scratch_db=scratch_db,
            assertions=assertions,
            error=f"could not create the scratch database: {exc}",
        )

    try:
        try:
            await _replay_into_scratch(
                db_bytes,
                dump_format=dump_format,
                scratch_db=scratch_db,
                live_db_url=live_db_url,
            )
        except BackupArchiveError as exc:
            assertions.append(Assertion("dump_replays_cleanly", FAIL, str(exc)))
            return base
        assertions.append(Assertion("dump_replays_cleanly", PASS, f"replayed into {scratch_db}"))

        try:
            assertions.extend(
                await asyncio.wait_for(
                    _assert_against_scratch(_scratch_url(live_db_url, scratch_db)),
                    timeout=_ASSERT_TIMEOUT_SECONDS,
                )
            )
        except TimeoutError:
            return DrillOutcome(
                state="error",
                filename=newest.filename,
                archive_bytes=len(archive_bytes),
                manifest=manifest,
                scratch_db=scratch_db,
                assertions=assertions,
                error=f"post-replay assertions exceeded {_ASSERT_TIMEOUT_SECONDS}s",
            )
        except Exception as exc:  # noqa: BLE001
            return DrillOutcome(
                state="error",
                filename=newest.filename,
                archive_bytes=len(archive_bytes),
                manifest=manifest,
                scratch_db=scratch_db,
                assertions=assertions,
                error=f"post-replay assertions could not run: {exc}",
            )
    finally:
        await _drop_scratch_db(scratch_db, live_db_url=live_db_url)

    base.state = "failed" if any(a.status == FAIL for a in assertions) else "passed"
    return base
