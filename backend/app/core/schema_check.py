"""Shared DB-schema-at-head check (#299 / #565).

The api / worker / migrate images all bundle the same fixed set of
Alembic revisions, so the "expected head" is a constant for the
lifetime of a process. Comparing that bundled head against
``SELECT version_num FROM alembic_version`` tells us whether the
running code is *ahead* of the DB schema — the "code deployed before
migrate ran" footgun:

* On the **api** it's the #299 cold-boot case — the pod serves 500s
  against missing tables until the migrate Job lands head. Guarded by
  ``/health/ready`` keeping the pod out of the Service endpoint set.
* On the **Celery worker + beat** (#565) there is no readiness gate —
  they start on whatever schema is present and fail tasks silently in
  the background. An operator's env logged the same
  ``UndefinedColumnError`` ~2440× in a tight retry loop because the
  DHCP config long-poll hammers ``db.get(PlatformSettings, 1)`` while
  the DB was still on the old schema.

The opposite mismatch, the DB *ahead* of the code, is normal for a
while (#2777): on a rolling upgrade the new release's migration commits
while the previous release's pods still serve, and each of them then
finds a revision its image does not know. ``SchemaCheck.ahead`` tells
the two apart. With a single head, every revision in this image's tree
is the head or an ancestor of it, so a known revision that is not the
head is behind; one the tree does not contain was written by a newer
release. ``ok`` still means "exactly at head" for every caller.

``ahead`` is only what the tree says: a revision it lacks may also be a
forked or squashed head, a mistyped ``alembic stamp`` or a restore made
with ``allow_newer_schema``. So readiness admits a newer schema only after
``missing_from_database`` finds every table and column this image's models
map present in it (#2777).

This module holds the framework-agnostic core so ``app/api/health.py``
and the Celery startup / periodic checks share one implementation. It
does pure DB + bundled-migration-file introspection — **no docker /
k8s-specific code** — so it behaves identically in docker-compose and
k8s (an explicit requirement of #565).

Known limitation (scoped out for v1, per #565): a ``version_num``-vs-
head comparison catches "DB behind code" but NOT the rarer
"stamped-forward, DDL never ran" drift (``alembic_version`` == head
but a column is actually missing). That needs real schema
introspection (``alembic check`` / ``information_schema`` diff), which
is heavier and false-positive-prone; tracked separately.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

import structlog
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

logger = structlog.get_logger(__name__)


class SchemaCheck(NamedTuple):
    """Result of a schema-at-head comparison.

    * ``ok`` — ``True`` only when the DB's ``alembic_version`` matches
      the bundled head.
    * ``expected`` — the bundled head revision (``None`` if the
      migration files couldn't be read).
    * ``actual`` — the DB's current ``version_num`` (``None`` if the
      table / row is missing or the read failed).
    * ``detail`` — an operator-actionable one-liner describing the
      state ("schema at head …", "migrate not run", "schema at X,
      image expects Y", …).
    * ``ahead`` — ``True`` only when ``actual`` is a revision this
      image's migrations do not contain: a NEWER release migrated the
      database (the mixed-version window of a rolling upgrade, or a
      rollback onto a newer database, #1227). ``False`` at head, when
      the DB is behind, and whenever that cannot be told, so a caller
      keying on it fails closed (#2777).
    """

    ok: bool
    expected: str | None
    actual: str | None
    detail: str
    ahead: bool = False


# ── Bundled-head cache ─────────────────────────────────────────────
#
# The bundled revisions are fixed for the process lifetime, so read
# the head once and cache it. Single dataclass instance instead of
# parallel scalars so the linter sees one used global. ``head`` is set
# once on success; ``error`` is set on persistent config bugs ("no
# head revision"); transient exceptions are NOT cached (re-tried on
# the next call).
@dataclass(slots=True)
class _SchemaHeadCache:
    head: str | None = None
    error: str | None = None
    # Every revision id in the bundled tree, read with the head (#2777).
    revisions: frozenset[str] = frozenset()


_head_cache = _SchemaHeadCache()


def _locate_alembic_ini() -> Path | None:
    """Find ``alembic.ini`` for the running process.

    Two production deployments + the test path each put the file in a
    different place:

    * **Container image** (api / worker / migrate) — baked at
      ``/app/alembic.ini`` by the Dockerfile's ``COPY``.
    * **CI ``Backend — Tests`` / dev host venv** — pytest runs from
      ``backend/`` so the file is at ``./alembic.ini``.

    Search order: container path → relative to this module → cwd.
    Returns ``None`` if no candidate exists.
    """
    candidates = [
        Path("/app/alembic.ini"),
        # ``app/core/schema_check.py`` → ``app/core`` → ``app`` →
        # ``backend``, where alembic.ini lives.
        Path(__file__).resolve().parent.parent.parent / "alembic.ini",
        Path.cwd() / "alembic.ini",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def expected_alembic_head() -> tuple[str | None, str | None]:
    """Read + cache the bundled alembic head.

    Returns ``(head, None)`` on success, ``(None, error_str)`` if the
    alembic.ini / scripts directory is missing or malformed.
    """
    if _head_cache.head is not None or _head_cache.error is not None:
        return _head_cache.head, _head_cache.error
    ini_path = _locate_alembic_ini()
    if ini_path is None:
        # Don't cache — the absence may be a packaging bug operators
        # need to see, but tests / dev swap in a fresh working dir
        # between fixtures and we want the next call to re-find it.
        msg = "alembic.ini not found (looked in /app, source tree, cwd)"
        logger.warning("schema_head_read_failed", error=msg)
        return None, msg
    try:
        from alembic.config import Config  # noqa: PLC0415
        from alembic.script import ScriptDirectory  # noqa: PLC0415

        cfg = Config(str(ini_path))
        script = ScriptDirectory.from_config(cfg)
        head = script.get_current_head()
        if head is None:
            _head_cache.error = "no head revision in script directory"
            return None, _head_cache.error
        _head_cache.revisions = frozenset(rev.revision for rev in script.walk_revisions())
        _head_cache.head = head
        logger.info("schema_head_cached", expected_head=head, ini_path=str(ini_path))
        return head, None
    except Exception as exc:  # noqa: BLE001 — surface ANY exception
        # Don't cache transient errors — genuinely-missing alembic
        # files are a config bug operators need to see; a one-off blip
        # re-reads on the next call.
        msg = f"could not read alembic head: {exc}"
        logger.warning("schema_head_read_failed", error=str(exc))
        return None, msg


async def schema_at_head(session_factory=None) -> SchemaCheck:
    """Compare the DB's ``alembic_version`` against the bundled head.

    ``session_factory`` defaults to ``app.db.AsyncSessionLocal``;
    callers may pass an alternative for testing. Pure DB +
    bundled-file introspection — identical behaviour under
    docker-compose and k8s.

    Failure modes (each gets a distinct operator-actionable detail so
    the cause isn't ambiguous):

    * ``alembic_version`` table doesn't exist — migrate hasn't created
      the schema at all → ``schema not initialised: …``.
    * Other ``ProgrammingError`` shapes (permission denied, malformed
      schema) → ``schema check failed: …`` so operators aren't misled
      into thinking migrations need to run.
    * ``alembic_version`` row missing — stamp/upgrade interrupted →
      ``alembic_version row missing — migrate not stamped``.
    * ``version_num != head`` — reports both revisions; ``ahead`` says
      whether a newer release wrote it (#2777) or the schema is behind.
    * Any other exception → ``schema check failed: …``.
    """
    if session_factory is None:
        from app.db import AsyncSessionLocal  # noqa: PLC0415

        session_factory = AsyncSessionLocal

    expected, head_err = expected_alembic_head()
    if head_err is not None:
        return SchemaCheck(False, None, None, head_err)
    try:
        async with session_factory() as session:
            result = await session.execute(text("SELECT version_num FROM alembic_version"))
            row = result.fetchone()
    except ProgrammingError as exc:
        # asyncpg UndefinedTableError → "relation 'alembic_version'
        # does not exist". Other ProgrammingError shapes are real
        # config bugs — don't lump them into the cold-boot case.
        logger.warning("schema_check_failed", error=str(exc), expected_head=expected)
        short = str(exc).splitlines()[0][:160]
        if "does not exist" in short:
            return SchemaCheck(False, expected, None, f"schema not initialised: {short}")
        return SchemaCheck(False, expected, None, f"schema check failed: {short}")
    except Exception as exc:  # noqa: BLE001 — surface ANY exception
        logger.warning("schema_check_failed", error=str(exc), expected_head=expected)
        short = str(exc).splitlines()[0][:160]
        return SchemaCheck(False, expected, None, f"schema check failed: {short}")
    if row is None:
        return SchemaCheck(
            False, expected, None, "alembic_version row missing — migrate not stamped"
        )
    actual = row[0]
    if actual != expected:
        # #2777 — a revision this image's tree knows is behind its head; one
        # it does not know was written by a newer release. An empty set (the
        # tree never read) says neither, so ``ahead`` stays False.
        known = _head_cache.revisions
        return SchemaCheck(
            False,
            expected,
            actual,
            f"schema at {actual}, image expects {expected}",
            ahead=bool(known) and actual not in known,
        )
    return SchemaCheck(True, expected, actual, f"schema at head {expected}")


# Every table of one schema (when :schema is NULL, every table visible on the
# search_path, as the SQLAlchemy inspector read them: a name resolves to the
# one table the search_path reaches first, so it is never counted twice, and
# an empty schema earlier on the path, such as "$user", does not hide the
# tables, which current_schema() would) and its live columns, from the
# catalog alone. Not the SQLAlchemy inspector: its
# column reflection deparses each column default with pg_get_expr(), which
# opens the table with ACCESS SHARE, so it waits behind the ACCESS EXCLUSIVE
# lock a migration holds on a table it alters until its revision commits.
# Readiness reads this while a newer release migrates (#2777); the catalog
# rows are read under MVCC and take no lock on the tables themselves.
_TABLES_AND_COLUMNS = text(
    "SELECT c.relname, a.attname"
    " FROM pg_catalog.pg_class c"
    " JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace"
    " LEFT JOIN pg_catalog.pg_attribute a"
    "   ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped"
    " WHERE c.relkind IN ('r', 'p')"
    "   AND CASE WHEN CAST(:schema AS text) IS NULL"
    "     THEN pg_catalog.pg_table_is_visible(c.oid)"
    "       AND n.nspname NOT IN ('pg_catalog', 'information_schema')"
    "     ELSE n.nspname = CAST(:schema AS text) END"
)


def missing_objects(sync_conn, metadata) -> tuple[list[str], list[str]]:
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

    Two callers: the restore's drift recovery stamps head only when this
    finds nothing (#1233), and readiness keeps a pod serving on a newer
    schema only when it finds nothing this image uses missing (#2777).
    Names come from the catalog (``_TABLES_AND_COLUMNS``), so the read
    never waits on a lock a migration holds.
    """
    missing_tables: list[str] = []
    missing_columns: list[str] = []
    by_schema: dict[str | None, list] = {}
    for table in metadata.tables.values():
        by_schema.setdefault(table.schema, []).append(table)
    for schema, tables in by_schema.items():
        present: dict[str, set[str]] = {}
        for relname, attname in sync_conn.execute(_TABLES_AND_COLUMNS, {"schema": schema}):
            columns = present.setdefault(relname, set())
            if attname is not None:
                columns.add(attname)
        for table in sorted(tables, key=lambda t: t.name):
            label = f"{schema}.{table.name}" if schema else table.name
            if table.name not in present:
                missing_tables.append(label)
                continue
            have = present[table.name]
            missing_columns.extend(
                f"{label}.{col.name}" for col in table.columns if col.name not in have
            )
    return missing_tables, missing_columns


async def missing_from_database(session_factory=None) -> tuple[list[str], list[str]]:
    """``missing_objects`` for every table this image's models map, read
    from the live database (#2777).

    ``session_factory`` defaults to ``app.db.AsyncSessionLocal``. Raises
    whatever the read raised: what a check that could not run means is the
    caller's to decide.
    """
    if session_factory is None:
        from app.db import AsyncSessionLocal  # noqa: PLC0415

        session_factory = AsyncSessionLocal
    # Importing the models package registers every mapped table.
    from app.models import Base  # noqa: PLC0415

    async with session_factory() as session:
        conn = await session.connection()
        return await conn.run_sync(missing_objects, Base.metadata)


# Alembic's own wording when a revision id is not in the script directory.
# Matched rather than typed: alembic raises it as a plain ``CommandError``.
_UNKNOWN_REVISION = re.compile(r"Can't locate revision identified by '([^']+)'")

UNKNOWN_REVISION_HINT = (
    "The database was migrated by a NEWER SpatiumDDI release than this one "
    "(#1227). This release's migrations stop before that revision, so it "
    "cannot run on this database and its api, worker and beat will wait for "
    "migrate forever. Re-apply the newer release, or restore a copy of the "
    "database taken before the upgrade. See 'Rolling back' in "
    "docs/deployment/APPLIANCE.md."
)


def explain_unknown_revision(message: str, database_revisions: Iterable[str]) -> str | None:
    """The migrate-step error for a database a newer release migrated, or None.

    Alembic's ``Can't locate revision identified by 'x'`` is accurate and
    useless: it reads like a corrupt install, while the real cause is almost
    always a rollback, an auto-revert or a downgrade onto a database the
    newer release had already migrated. Only when ``x`` is the revision the
    DATABASE is at: the same error for a mistyped command-line target is the
    operator's typo, and saying "a newer release migrated this" there would
    send them the wrong way. None for every other error, which is left exactly
    as alembic raised it.
    """
    match = _UNKNOWN_REVISION.search(message)
    if match is None or match.group(1) not in set(database_revisions):
        return None
    return f"{message}\n\n{UNKNOWN_REVISION_HINT}"
