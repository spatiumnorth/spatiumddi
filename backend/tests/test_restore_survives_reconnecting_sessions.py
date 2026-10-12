"""A full restore must not deadlock against the appliance's own sessions.

``_replay_clean`` terminates every other session on the database, then clears
``public`` and replays the archive in ONE transaction (#1363). The clearing
drops the tables in name order, locking each as it goes and holding every lock
to commit, while the api, worker and agents reconnect at once. On a QA
appliance a session that opened after the terminate held a table the drops had
not reached yet and waited for one they had already dropped. When the drops got
to the held table, PostgreSQL aborted the replay and the restore answered 400
``deadlock detected``, at the clearing block's last line.

The interleaving, built deterministically against the real replay:

  1. right after the terminate, a request opens and reads ``zz_settings`` (late
     in name order), and another session holds ``mm_middle`` so the drops pause
     after they have taken ``aa_hub``;
  2. the request now reads ``aa_hub`` and waits past ``deadlock_timeout``, so
     its own single deadlock check finds no cycle;
  3. the other session lets go, and the drops go on to ``zz_settings``.

The drops alone close the cycle in step 3 and the replay is the victim (the
negative control below). The lock block that now runs first ends the sessions
of the restore's role that hold a table, takes every table in one statement,
and retries the attempt if a session of another role still closes a cycle.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest

from app.services.backup import restore
from app.services.backup.archive import _pg_env_from_url

pytestmark = pytest.mark.skipif(
    not all(shutil.which(tool) for tool in ("pg_dump", "psql")),
    reason="needs the PostgreSQL client tools",
)

_URL = os.environ["DATABASE_URL"]

# Three tables in name order: the request holds the last and later reads the
# first; the middle one is where another session holds the drops up.
_SCHEMA = """
CREATE TABLE aa_hub (id integer PRIMARY KEY, name text NOT NULL);
CREATE TABLE mm_middle (id integer PRIMARY KEY);
CREATE TABLE zz_settings (id integer PRIMARY KEY);
INSERT INTO aa_hub VALUES (1, '{name}');
INSERT INTO mm_middle VALUES (1);
INSERT INTO zz_settings VALUES (1);
"""

# What the clearing was before the lock block: the drops alone.
_DROPS_ONLY = "SET client_min_messages = warning;\n" + restore._DROP_PUBLIC_SCHEMA_SQL


def _url_for(dbname: str, user: str = "", password: str = "") -> str:
    parts = urlsplit(_URL)
    if user:
        host = parts.hostname or "localhost"
        port = f":{parts.port}" if parts.port else ""
        parts = parts._replace(netloc=f"{user}:{password}@{host}{port}")
    return urlunsplit(parts._replace(path=f"/{dbname}"))


def _dsn(url: str) -> str:
    return url.replace("+asyncpg", "")


async def _admin() -> asyncpg.Connection:
    return await asyncpg.connect(_dsn(_url_for("postgres")))


async def _create_db(sql: str) -> str:
    name = f"spatiumddi_test_rdl_{uuid.uuid4().hex[:10]}"
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


async def _pg_dump_plain(dbname: str, out: Path) -> None:
    pg_env, _ = _pg_env_from_url(_url_for(dbname))
    proc = await asyncio.create_subprocess_exec(
        "pg_dump",
        "--format=plain",
        "--no-owner",
        "--no-privileges",
        f"--file={out}",
        env={**os.environ, **pg_env},
        stderr=asyncio.subprocess.PIPE,
    )
    _, err = await proc.communicate()
    assert proc.returncode == 0, err.decode()


async def _wait_until_waiting(conn: asyncpg.Connection, table: str, timeout: float = 30) -> None:
    """Until some backend waits for ACCESS EXCLUSIVE on `table`."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        waiting = await conn.fetchval(
            "SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation "
            "WHERE c.relname = $1 AND l.mode = 'AccessExclusiveLock' AND NOT l.granted",
            table,
        )
        if waiting:
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"the clearing never waited for {table}")


@pytest.fixture
async def dbs(tmp_path: Path):
    """(destination db, plain archive whose aa_hub row reads 'from-the-archive')."""
    source = await _create_db(_SCHEMA.format(name="from-the-archive"))
    dest = await _create_db(_SCHEMA.format(name="live"))
    archive = tmp_path / "archive.sql"
    try:
        await _pg_dump_plain(source, archive)
        yield dest, archive
    finally:
        await _drop_db(source)
        await _drop_db(dest)


def _reconnect_after_terminate(monkeypatch, dest: str, sessions: dict, url_for):
    """Make the replay's own terminate followed by what the appliance does next:
    a request reads ``zz_settings`` and another session holds ``mm_middle``,
    both mid-transaction, plus an idle watcher. Returns an Event set once they
    are in place."""
    ready = asyncio.Event()
    terminate = restore._terminate_other_db_connections

    async def terminate_then_reconnect(pg_env: dict[str, str]) -> None:
        await terminate(pg_env)
        for name in ("request", "holder", "watch"):
            sessions[name] = await asyncpg.connect(_dsn(url_for(dest, name)))
        await sessions["request"].execute("BEGIN")
        await sessions["request"].fetch("SELECT * FROM zz_settings")
        await sessions["holder"].execute("BEGIN")
        await sessions["holder"].fetch("SELECT * FROM mm_middle")
        ready.set()

    monkeypatch.setattr(restore, "_terminate_other_db_connections", terminate_then_reconnect)
    return ready


async def _close(sessions: dict) -> None:
    for conn in sessions.values():
        with contextlib.suppress(Exception):
            await conn.close()


async def test_the_drops_alone_deadlock_on_this_interleaving(dbs, monkeypatch) -> None:
    """Negative control: the clearing as it was before the lock block is the
    deadlock victim, with the error the appliance returned."""
    dest, archive = dbs
    monkeypatch.setattr(restore, "_CLEAR_PUBLIC_SCHEMA_SQL", _DROPS_ONLY)
    sessions: dict[str, asyncpg.Connection] = {}
    ready = _reconnect_after_terminate(monkeypatch, dest, sessions, lambda db, _n: _url_for(db))
    try:
        replay = asyncio.create_task(restore._run_psql(archive, _url_for(dest)))
        await asyncio.wait_for(ready.wait(), 30)
        await _wait_until_waiting(sessions["watch"], "mm_middle")
        read = asyncio.create_task(sessions["request"].fetch("SELECT * FROM aa_hub"))
        await asyncio.sleep(1.5)  # past deadlock_timeout (1 s): its one check sees no cycle
        await sessions["holder"].execute("COMMIT")  # the drops go on to zz_settings
        await asyncio.wait_for(read, 30)
        await sessions["request"].execute("COMMIT")
        with pytest.raises(restore.BackupRestoreError, match="deadlock detected"):
            await asyncio.wait_for(replay, 60)
    finally:
        await _close(sessions)


async def test_sessions_that_came_back_after_the_terminate_do_not_kill_the_restore(
    dbs, monkeypatch
) -> None:
    dest, archive = dbs
    sessions: dict[str, asyncpg.Connection] = {}
    ready = _reconnect_after_terminate(monkeypatch, dest, sessions, lambda db, _n: _url_for(db))
    try:
        replay = asyncio.create_task(restore._run_psql(archive, _url_for(dest)))
        await asyncio.wait_for(ready.wait(), 30)
        await asyncio.wait_for(replay, 60)
        restored = await sessions["watch"].fetchval("SELECT name FROM aa_hub WHERE id = 1")
        # The two sessions holding tables were ended; the idle watcher was not.
        for name in ("request", "holder"):
            with pytest.raises((asyncpg.PostgresError, asyncpg.InterfaceError, OSError)):
                await sessions[name].fetchval("SELECT 1")
    finally:
        await _close(sessions)
    assert restored == "from-the-archive"


@pytest.fixture
async def other_role():
    """(name, password) of a superuser role that is not the restore's: the lock
    block does not end its sessions (ending a superuser's is refused)."""
    role, password = f"rdl_other_{uuid.uuid4().hex[:8]}", uuid.uuid4().hex
    admin = await _admin()
    try:
        await admin.execute(f"CREATE ROLE {role} LOGIN SUPERUSER PASSWORD '{password}'")
    finally:
        await admin.close()
    try:
        yield role, password
    finally:
        admin = await _admin()
        try:
            await admin.execute(f"DROP ROLE IF EXISTS {role}")
        finally:
            await admin.close()


async def _cycle_with_another_role(
    dest, archive, monkeypatch, sessions, other_role, request_timeout
):
    """Start the replay with the other role's request holding zz_settings, wait
    until the lock block (holding aa_hub and mm_middle) waits for zz_settings,
    then have the request read aa_hub: the cycle. Returns (replay, read).

    PostgreSQL rolls back whichever side's deadlock check runs first, and each
    side checks once, ``deadlock_timeout`` after it began to wait. With both at
    the server's 1 s, the request starts waiting only a poll interval after the
    lock block, so the two checks land within a scheduler tick of each other
    and either side can lose: the request did in 4 of 16 runs (2026-10-03).
    The request's own ``deadlock_timeout`` (a superuser may set it) decides the
    order instead: ``request_timeout`` well above the server's makes the lock
    block check first, well below makes the request check first."""
    role, password = other_role

    def url_for(db: str, name: str) -> str:
        return _url_for(db, role, password) if name == "request" else _url_for(db)

    ready = _reconnect_after_terminate(monkeypatch, dest, sessions, url_for)
    replay = asyncio.create_task(restore._run_psql(archive, _url_for(dest)))
    await asyncio.wait_for(ready.wait(), 30)
    await sessions["request"].execute(f"SET deadlock_timeout = '{request_timeout}'")
    # The lock block ended the holder (this role) and took aa_hub and
    # mm_middle; the request's role is spared, so it waits on zz_settings.
    await _wait_until_waiting(sessions["watch"], "zz_settings")
    read = asyncio.create_task(sessions["request"].fetch("SELECT * FROM aa_hub"))
    return replay, read


async def test_a_deadlock_while_taking_the_locks_is_retried_not_fatal(
    dbs, monkeypatch, other_role
) -> None:
    """A session of another role is not ended (that would be refused for a
    superuser's), so it can still close a cycle with the lock block. When
    PostgreSQL picks the lock block, only its attempt is rolled back: the
    request gets its table, finishes, and the retried attempt takes every table
    and the restore completes."""
    dest, archive = dbs
    sessions: dict[str, asyncpg.Connection] = {}
    try:
        # The request checks after 10 s, so the lock block's check (1 s) is the
        # one that finds the cycle: its attempt is the side rolled back.
        replay, read = await _cycle_with_another_role(
            dest, archive, monkeypatch, sessions, other_role, "10s"
        )
        await asyncio.wait_for(read, 30)
        await sessions["request"].execute("COMMIT")
        await asyncio.wait_for(replay, 60)
        restored = await sessions["watch"].fetchval("SELECT name FROM aa_hub WHERE id = 1")
    finally:
        await _close(sessions)
    assert restored == "from-the-archive"


async def test_a_deadlock_the_other_session_loses_leaves_the_restore_to_finish(
    dbs, monkeypatch, other_role
) -> None:
    """The cycle's other outcome: the other role's session checks first and is
    the one rolled back. The lock block keeps its attempt, gets zz_settings once
    that session ends its transaction, and the restore completes."""
    dest, archive = dbs
    sessions: dict[str, asyncpg.Connection] = {}
    try:
        # The request checks after 100 ms, long before the lock block's 1 s.
        replay, read = await _cycle_with_another_role(
            dest, archive, monkeypatch, sessions, other_role, "100ms"
        )
        with pytest.raises(asyncpg.exceptions.DeadlockDetectedError):
            await asyncio.wait_for(read, 30)
        await sessions["request"].execute("ROLLBACK")
        await asyncio.wait_for(replay, 60)
        restored = await sessions["watch"].fetchval("SELECT name FROM aa_hub WHERE id = 1")
    finally:
        await _close(sessions)
    assert restored == "from-the-archive"


def test_the_lock_block_runs_before_the_drops() -> None:
    sql = restore._CLEAR_PUBLIC_SCHEMA_SQL
    assert sql.index("LOCK TABLE") < sql.index("DROP %s IF EXISTS")
    assert "EXCEPTION WHEN deadlock_detected" in restore._LOCK_PUBLIC_TABLES_SQL
