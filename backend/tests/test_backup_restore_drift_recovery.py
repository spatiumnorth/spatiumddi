"""Restore's "already exists" drift recovery stamps head only on evidence (#1233).

After a restore, ``alembic upgrade head`` failing with "already exists" is
the signature of a stale ``alembic_version`` over a schema already at head,
and the restore recovers by stamping head. But the signature is not proof:
any revision that meets one object it would create fails the same way, and
with one transaction per revision (#1204) the revisions before it stay
committed while those after it never run. Stamping on the signature alone
records that partially migrated schema as current.

These pin that head is stamped only when every table and column the models
declare is present, that a check which cannot run refuses rather than
stamps, and that the refusal names what is missing and where the upgrade
stopped.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Column, Integer, MetaData, Table
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Base
from app.services.backup import migrations
from app.services.backup.migrations import (
    SchemaVerdict,
    _error_excerpt,
    _failing_revision,
    _missing_objects,
    _verify_schema_at_head,
    maybe_upgrade_after_restore,
)

_DB_URL = os.environ["DATABASE_URL"]

_UPGRADE_STDERR = (
    "INFO  [alembic.runtime.migration] Running upgrade a1a1 -> b2b2, first\n"
    "INFO  [alembic.runtime.migration] Running upgrade b2b2 -> c3c3, second\n"
    "sqlalchemy.exc.ProgrammingError: (sqlalchemy.dialects.postgresql.asyncpg."
    "ProgrammingError) <class 'asyncpg.exceptions.DuplicateTableError'>: relation \"widget\" "
    "already exists\n"
)


class _FakeProc:
    def __init__(self, returncode: int, stderr: str) -> None:
        self.returncode = returncode
        self._stderr = stderr.encode()

    async def communicate(self) -> tuple[bytes, bytes]:
        return b"", self._stderr

    def kill(self) -> None:  # pragma: no cover — only on timeout
        pass

    async def wait(self) -> int:  # pragma: no cover — only on timeout
        return self.returncode


def _older_head() -> tuple[str, str]:
    """(an ancestor of the local head, the local head) from the real tree."""
    ini = migrations._alembic_ini()
    assert ini is not None
    script = ScriptDirectory.from_config(Config(str(ini)))
    head = script.get_current_head()
    assert head is not None
    down = script.get_revision(head).down_revision
    # A merge head has a tuple of parents; any one of them is an ancestor.
    if isinstance(down, tuple):
        down = down[0]
    assert isinstance(down, str)
    return down, head


@pytest.fixture
def failed_upgrade(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """An ``alembic upgrade`` that stops on "already exists", with the
    verification and the stamp replaced by recorders."""
    state: dict[str, Any] = {"stamped": 0, "verdict": None}

    async def fake_exec(*_args: Any, **_kwargs: Any) -> _FakeProc:
        return _FakeProc(1, _UPGRADE_STDERR)

    async def fake_verify(_db_url: str) -> SchemaVerdict:
        return state["verdict"]

    async def fake_stamp(_db_url: str) -> tuple[bool, str | None]:
        state["stamped"] += 1
        return True, None

    monkeypatch.setattr(migrations.asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(migrations, "_verify_schema_at_head", fake_verify)
    monkeypatch.setattr(migrations, "_try_alembic_stamp_head", fake_stamp)
    return state


# ── the gate on the stamp ─────────────────────────────────────────


async def test_missing_objects_refuse_the_stamp(failed_upgrade: dict[str, Any]) -> None:
    failed_upgrade["verdict"] = SchemaVerdict(
        ok=False,
        missing_tables=["widget_audit"],
        missing_columns=["subnet.widget_id"],
        version_num="b2b2",
    )
    source, head = _older_head()

    outcome = await maybe_upgrade_after_restore(manifest_schema_version=source, db_url=_DB_URL)

    assert failed_upgrade["stamped"] == 0, "head was stamped over a partially migrated schema"
    assert outcome.state == "failed"
    assert outcome.error is not None
    assert "widget_audit" in outcome.error
    assert "subnet.widget_id" in outcome.error
    assert "'c3c3'" in outcome.error, "the refusal should name the revision that failed"
    assert "'b2b2'" in outcome.error, "the refusal should say where alembic_version stopped"
    assert head in outcome.error
    # One transaction per revision (#1204): b2b2 committed before c3c3 failed.
    assert outcome.migrations_applied == ["b2b2"]


async def test_a_check_that_cannot_run_refuses_the_stamp(
    failed_upgrade: dict[str, Any],
) -> None:
    failed_upgrade["verdict"] = SchemaVerdict(
        ok=False, missing_tables=[], missing_columns=[], error="OSError: connection refused"
    )
    source, _head = _older_head()

    outcome = await maybe_upgrade_after_restore(manifest_schema_version=source, db_url=_DB_URL)

    assert failed_upgrade["stamped"] == 0, "no evidence is not evidence the schema is at head"
    assert outcome.state == "failed"
    assert outcome.error is not None
    assert "could not be checked" in outcome.error
    assert "connection refused" in outcome.error


async def test_a_verified_schema_is_stamped(failed_upgrade: dict[str, Any]) -> None:
    failed_upgrade["verdict"] = SchemaVerdict(
        ok=True, missing_tables=[], missing_columns=[], version_num="b2b2"
    )
    source, _head = _older_head()

    outcome = await maybe_upgrade_after_restore(manifest_schema_version=source, db_url=_DB_URL)

    assert failed_upgrade["stamped"] == 1
    assert outcome.state == "auto_recovered"
    # b2b2 committed before c3c3 stopped on "already exists" (#1204), so
    # the outcome must not claim nothing ran.
    assert outcome.migrations_applied == ["b2b2"]
    assert outcome.error is not None
    assert "No migrations actually ran" not in outcome.error


async def test_other_failures_never_reach_the_recovery(
    failed_upgrade: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_exec(*_args: Any, **_kwargs: Any) -> _FakeProc:
        return _FakeProc(1, 'column "x" does not exist\n')

    async def verify_must_not_run(_db_url: str) -> SchemaVerdict:
        raise AssertionError("verification ran for a failure that is not drift")

    monkeypatch.setattr(migrations.asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(migrations, "_verify_schema_at_head", verify_must_not_run)
    source, _head = _older_head()

    outcome = await maybe_upgrade_after_restore(manifest_schema_version=source, db_url=_DB_URL)

    assert failed_upgrade["stamped"] == 0
    assert outcome.state == "failed"


# ── the verification itself, against a real database ─────────────


async def test_the_models_schema_verifies(db_session: AsyncSession) -> None:
    """The test database is built from the models, so nothing is missing.
    This is the evidence the real drift case produces."""
    verdict = await _verify_schema_at_head(_DB_URL)

    assert verdict.error is None
    assert verdict.missing_tables == []
    assert verdict.missing_columns == []
    assert verdict.ok is True


async def test_missing_tables_and_columns_are_found(db_session: AsyncSession) -> None:
    """A table and a column the metadata declares but the database lacks
    are both reported; ones that exist are not."""
    md = MetaData()
    Table("subnet", md, Column("id", Integer, primary_key=True), Column("no_such_column", Integer))
    Table("no_such_table_1233", md, Column("id", Integer, primary_key=True))

    conn = await db_session.connection()
    tables, columns = await conn.run_sync(_missing_objects, md)

    assert tables == ["no_such_table_1233"]
    assert columns == ["subnet.no_such_column"]


async def test_an_unreachable_database_is_not_verified() -> None:
    verdict = await _verify_schema_at_head("postgresql+asyncpg://nobody:x@127.0.0.1:1/nope")

    assert verdict.ok is False
    assert verdict.error


def test_the_metadata_is_the_whole_model_set() -> None:
    """The check is only as good as the metadata it reads; an empty one
    would verify anything."""
    assert len(Base.metadata.tables) > 100


# ── reading where the upgrade stopped ─────────────────────────────


def test_failing_revision_is_the_last_one_announced() -> None:
    assert _failing_revision(_UPGRADE_STDERR) == "c3c3"


def test_failing_revision_handles_base_and_merge_lines() -> None:
    out = (
        "INFO  [alembic.runtime.migration] Running upgrade  -> 1a48e694db0b, initial\n"
        "INFO  [alembic.runtime.migration] Running upgrade aa, bb -> cc01, merge heads\n"
    )
    assert _failing_revision(out) == "cc01"
    assert _failing_revision("ERROR: relation already exists") is None


async def test_a_long_ladder_still_reaches_the_recovery(
    failed_upgrade: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """alembic logs a line per revision before the traceback; with enough
    of them the exception sat past the 1500 characters kept, so the
    "already exists" match never fired and the error shown was INFO noise."""
    ladder = "".join(
        f"INFO  [alembic.runtime.migration] Running upgrade r{i:04d} -> r{i + 1:04d}, "
        "a revision with a reasonably long message\n"
        for i in range(60)
    )

    async def fake_exec(*_args: Any, **_kwargs: Any) -> _FakeProc:
        return _FakeProc(1, ladder + _UPGRADE_STDERR)

    monkeypatch.setattr(migrations.asyncio, "create_subprocess_exec", fake_exec)
    failed_upgrade["verdict"] = SchemaVerdict(
        ok=False, missing_tables=["widget_audit"], missing_columns=[], version_num="b2b2"
    )
    source, _head = _older_head()

    outcome = await maybe_upgrade_after_restore(manifest_schema_version=source, db_url=_DB_URL)

    assert outcome.state == "failed"
    assert outcome.error is not None
    assert "widget_audit" in outcome.error, "the drift branch was never reached"
    assert "DuplicateTableError" in outcome.error, "the exception was truncated away"


def test_error_excerpt_leads_with_the_exception_not_the_sql() -> None:
    """SQLAlchemy puts the whole statement after the exception line; a wide
    CREATE TABLE must not push the exception out of what is shown."""
    sql = "CREATE TABLE widget (" + ", ".join(f"col_{i} INTEGER" for i in range(200)) + ")"
    output = (
        "INFO  [alembic.runtime.migration] Running upgrade b2b2 -> c3c3, second\n"
        "Traceback (most recent call last):\n"
        '  File "x.py", line 1, in <module>\n'
        "    op.create_table(...)\n"
        "sqlalchemy.exc.ProgrammingError: (asyncpg.exceptions.DuplicateTableError) "
        'relation "widget" already exists\n'
        f"[SQL: {sql}]\n"
        "(Background on this error at: https://sqlalche.me/e/20/f405)\n"
    )
    excerpt = _error_excerpt(output)

    assert excerpt.startswith("sqlalchemy.exc.ProgrammingError")
    assert "DuplicateTableError" in excerpt
    assert len(excerpt) <= 1500
    assert _error_excerpt("no traceback here") == "no traceback here"
