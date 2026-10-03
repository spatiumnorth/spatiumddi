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
    """

    ok: bool
    expected: str | None
    actual: str | None
    detail: str


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
    * ``version_num != head`` — schema behind → reports both revisions.
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
        return SchemaCheck(False, expected, actual, f"schema at {actual}, image expects {expected}")
    return SchemaCheck(True, expected, actual, f"schema at head {expected}")


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
