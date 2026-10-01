"""A full restore replays over a cleared schema, in one transaction (#1363).

``pg_restore --clean`` drops only the objects the ARCHIVE contains, so the
tables a later migration added survived the replay with their constraints.
Restoring an archive older than ``dns_agent_bundle`` (every 2026.09.04-1
archive) therefore failed with a 400: ``--clean`` could not drop
``dns_server_pkey`` while ``dns_agent_bundle_server_id_fkey`` depended on it.

These run the real replay (``pg_restore`` / ``psql``) against scratch
databases holding the same shape: an archive of an "old" schema with a parent
table, replayed over a "new" one where a later table holds a foreign key into
it. They pin that the replay lands exactly the archive's schema, and that any
failure, including a ``pg_restore`` that dies part way through its output,
leaves the destination untouched rather than half cleared.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest

from app.services.backup import restore
from app.services.backup.archive import _pg_env_from_url

pytestmark = pytest.mark.skipif(
    not all(shutil.which(tool) for tool in ("pg_dump", "pg_restore", "psql")),
    reason="needs the PostgreSQL client tools",
)

_URL = os.environ["DATABASE_URL"]

# The archive's schema: what an older release had.
_OLD_SCHEMA = """
CREATE TABLE dns_server (id integer PRIMARY KEY, name text NOT NULL);
CREATE TABLE alembic_version (version_num varchar(32) PRIMARY KEY);
INSERT INTO dns_server VALUES (1, 'from-the-archive');
INSERT INTO alembic_version VALUES ('old_revision');
"""

# The destination's schema: a later migration added a table whose foreign key
# blocks ``--clean`` from dropping the archive's primary key, plus the other
# kinds of object the clearing step must handle.
_NEW_SCHEMA = """
CREATE TABLE dns_server (id integer PRIMARY KEY, name text NOT NULL, added_later text);
CREATE TABLE alembic_version (version_num varchar(32) PRIMARY KEY);
CREATE TABLE dns_agent_bundle (
    id serial PRIMARY KEY,
    server_id integer REFERENCES dns_server(id) ON DELETE CASCADE
);
CREATE TYPE added_later_kind AS ENUM ('a', 'b');
-- A range brings a multirange that cannot be dropped on its own. The rename
-- rewrites the range's pg_type row past its multirange's, so a catalog scan
-- meets the multirange first, which is the order that used to fail.
CREATE TYPE added_later_tmp AS RANGE (
    subtype = float8, multirange_type_name = added_later_range_multirange
);
ALTER TYPE added_later_tmp RENAME TO added_later_range;
CREATE VIEW added_later_view AS SELECT id FROM dns_server;
CREATE FUNCTION added_later_fn() RETURNS integer LANGUAGE sql AS 'SELECT 1';
INSERT INTO dns_server VALUES (1, 'live', 'x'), (2, 'live-only', 'y');
INSERT INTO dns_agent_bundle (server_id) VALUES (1), (2);
INSERT INTO alembic_version VALUES ('new_revision');
"""


def _url_for(dbname: str) -> str:
    parts = urlsplit(_URL)
    return urlunsplit(parts._replace(path=f"/{dbname}"))


def _dsn(url: str) -> str:
    return url.replace("+asyncpg", "")


async def _admin() -> asyncpg.Connection:
    return await asyncpg.connect(_dsn(_url_for("postgres")))


async def _create_db(sql: str) -> str:
    name = f"spatiumddi_test_r1363_{uuid.uuid4().hex[:10]}"
    admin = await _admin()
    try:
        await admin.execute(f'CREATE DATABASE "{name}"')
    finally:
        await admin.close()
    conn = await asyncpg.connect(_dsn(_url_for(name)))
    try:
        await conn.execute(sql)
    finally:
        await conn.close()
    return name


async def _drop_db(name: str) -> None:
    admin = await _admin()
    try:
        await admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
    finally:
        await admin.close()


async def _pg_dump(dbname: str, out: Path, fmt: str) -> None:
    pg_env, _ = _pg_env_from_url(_url_for(dbname))
    proc = await asyncio.create_subprocess_exec(
        "pg_dump",
        f"--format={fmt}",
        "--no-owner",
        "--no-privileges",
        "--quote-all-identifiers",
        f"--file={out}",
        env={**os.environ, **pg_env},
        stderr=asyncio.subprocess.PIPE,
    )
    _, err = await proc.communicate()
    assert proc.returncode == 0, err.decode()


async def _state(dbname: str) -> dict[str, object]:
    conn = await asyncpg.connect(_dsn(_url_for(dbname)))
    try:
        tables = await conn.fetch(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY 1"
        )
        names = [r["tablename"] for r in tables]
        return {
            "tables": names,
            "servers": [
                r["name"] for r in await conn.fetch("SELECT name FROM dns_server ORDER BY id")
            ],
            "version": await conn.fetchval("SELECT version_num FROM alembic_version"),
            "view": await conn.fetchval("SELECT to_regclass('public.added_later_view')::text"),
            "enum": await conn.fetchval(
                "SELECT count(*) FROM pg_type WHERE typname = 'added_later_kind'"
            ),
            "function": await conn.fetchval(
                "SELECT count(*) FROM pg_proc WHERE proname = 'added_later_fn'"
            ),
            "range": await conn.fetchval(
                "SELECT count(*) FROM pg_type WHERE typname LIKE 'added_later_range%'"
            ),
        }
    finally:
        await conn.close()


@pytest.fixture
async def dbs(tmp_path: Path) -> AsyncIterator[tuple[str, Path, Path]]:
    """(destination db at the new schema, custom archive, plain archive) of
    the old schema."""
    source = await _create_db(_OLD_SCHEMA)
    dest = await _create_db(_NEW_SCHEMA)
    custom, plain = tmp_path / "old.dump", tmp_path / "old.sql"
    try:
        await _pg_dump(source, custom, "custom")
        await _pg_dump(source, plain, "plain")
        yield dest, custom, plain
    finally:
        await _drop_db(source)
        await _drop_db(dest)


_OLD_STATE = {
    "tables": ["alembic_version", "dns_server"],
    "servers": ["from-the-archive"],
    "version": "old_revision",
    "view": None,
    "enum": 0,
    "function": 0,
    "range": 0,
}


async def test_an_older_custom_archive_restores_exactly_its_schema(dbs) -> None:
    dest, custom, _ = dbs
    await restore._run_pg_restore(custom, _url_for(dest))
    assert await _state(dest) == _OLD_STATE


async def test_an_older_plain_archive_restores_exactly_its_schema(dbs) -> None:
    dest, _, plain = dbs
    await restore._run_psql(plain, _url_for(dest))
    assert await _state(dest) == _OLD_STATE


async def test_the_old_replay_fails_on_this_shape(dbs) -> None:
    """Negative control: the fixture reproduces the reported failure under
    the previous ``pg_restore --clean`` replay, so the tests above prove the
    fix rather than an easier fixture."""
    dest, custom, _ = dbs
    pg_env, dbname = _pg_env_from_url(_url_for(dest))
    proc = await asyncio.create_subprocess_exec(
        "pg_restore",
        "--dbname",
        dbname,
        "--clean",
        "--if-exists",
        "--no-owner",
        "--no-acl",
        "--single-transaction",
        "--exit-on-error",
        str(custom),
        env={**os.environ, **pg_env},
        stderr=asyncio.subprocess.PIPE,
    )
    _, err = await proc.communicate()
    assert proc.returncode != 0
    assert "dns_agent_bundle_server_id_fkey" in err.decode()


async def test_a_truncated_archive_changes_nothing(dbs, tmp_path: Path) -> None:
    """pg_restore dies after emitting part of the script. psql must not reach
    end of input and commit what it has: the clearing included."""
    dest, custom, _ = dbs
    before = await _state(dest)
    truncated = tmp_path / "truncated.dump"
    truncated.write_bytes(custom.read_bytes()[: len(custom.read_bytes()) * 2 // 3])
    with pytest.raises(restore.BackupRestoreError, match="nothing was applied"):
        await restore._run_pg_restore(truncated, _url_for(dest))
    assert await _state(dest) == before


async def test_a_failing_statement_changes_nothing_and_says_why(dbs, tmp_path: Path) -> None:
    dest, _, plain = dbs
    before = await _state(dest)
    bad = tmp_path / "bad.sql"
    bad.write_bytes(plain.read_bytes() + b"\nSELECT no_such_column FROM dns_server;\n")
    with pytest.raises(restore.BackupRestoreError) as exc:
        await restore._run_psql(bad, _url_for(dest))
    assert await _state(dest) == before
    # The reason leads, not the clearing's notices.
    assert str(exc.value).split(": ", 1)[1].lstrip().startswith(("psql:", "ERROR:"))
    assert "no_such_column" in str(exc.value)
    assert "drop cascades" not in str(exc.value)


async def test_psql_stopping_early_does_not_wait_on_the_producer(dbs) -> None:
    """A producer with far more output than a pipe holds, and a script that
    fails on its first statement: psql stops reading, and the replay must
    stop the producer rather than wait on its full pipe until the timeout."""
    dest, _, _ = dbs
    producer = await asyncio.create_subprocess_exec(
        "sh",
        "-c",
        "echo 'SELECT no_such_function();'; while :; do echo 'SELECT 1;'; done",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    async def script():
        while chunk := await producer.stdout.read(65536):
            yield chunk

    with pytest.raises(restore.BackupRestoreError, match="no_such_function"):
        await asyncio.wait_for(
            restore._replay_clean(script(), _url_for(dest), producer=producer), timeout=60
        )
    assert producer.returncode is not None


async def test_extension_members_survive(dbs) -> None:
    """Extension objects are not ours to drop: the dump's CREATE EXTENSION IF
    NOT EXISTS is then a no-op, and no extension needs re-creating by a role
    that may not be allowed to."""
    dest, custom, _ = dbs
    conn = await asyncpg.connect(_dsn(_url_for(dest)))
    try:
        try:
            await conn.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
        except asyncpg.PostgresError:
            pytest.skip("pg_trgm is not creatable here")
    finally:
        await conn.close()
    await restore._run_pg_restore(custom, _url_for(dest))
    conn = await asyncpg.connect(_dsn(_url_for(dest)))
    try:
        assert await conn.fetchval("SELECT count(*) FROM pg_extension WHERE extname = 'pg_trgm'")
        assert await conn.fetchval("SELECT similarity('abc', 'abd')") is not None
    finally:
        await conn.close()


async def test_a_plain_archive_restores_from_memory(dbs) -> None:
    """The restore hands the plain dump over as the bytes it unzipped."""
    dest, _, plain = dbs
    await restore._run_psql(plain.read_bytes(), _url_for(dest))
    assert await _state(dest) == _OLD_STATE
