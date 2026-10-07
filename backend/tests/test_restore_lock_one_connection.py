"""The install-wide restore lock is held on one connection for the whole restore (#1648).

``apply_backup_restore`` (#1571) took its session-level advisory lock on the
request session's connection, then committed, which hands that connection back
to the pool. The rest of the restore, the ``pg_advisory_unlock`` in its
``finally`` included, ran on whatever connection the session checked out next.
With other connections idle in the pool (first in, first out) that was a
different one: the unlock returned false, unread, and the lock stayed behind on
an idle pooled connection. Every later restore whose session started on another
connection was refused as "already in progress". The other way round, a restore
whose session checked out the holder got in while one was running (a session
lock is re-entrant), and Phase 4's pool dispose closed the holder, so the replay
itself ran unlocked.

The contract pinned here: a restore that ends, however it ends (refused,
raising, cancelled or done), leaves no restore lock behind, so the next one is
refused for its own reason; and while one runs, through its own pool dispose and
terminate step, a second one is refused as "already in progress", whichever
pooled connection either request's session lands on.

These use the product's own engine and sessions (``app.db``: ``QueuePool``,
first in, first out), not the suite's ``db_session`` fixture: its ``NullPool``
closes the connection at every commit, which drops the lock the moment it is
taken and hides the pool this defect lives in. The tests that run the restore's
terminate step and a real replay do it in scratch databases.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import shutil
import uuid
import zipfile
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest
from sqlalchemy import text

from app.config import settings
from app.db import AsyncSessionLocal, engine
from app.services.backup import restore
from app.services.backup.archive import _pg_env_from_url
from app.services.backup.crypto import encrypt_secrets
from app.services.backup.restore import BackupRestoreError

_URL = os.environ["DATABASE_URL"]
_IN_PROGRESS = "another restore is already in progress"

_needs_pg_tools = pytest.mark.skipif(
    not all(shutil.which(tool) for tool in ("pg_dump", "pg_restore", "psql")),
    reason="needs the PostgreSQL client tools",
)


def _url_for(dbname: str) -> str:
    return urlunsplit(urlsplit(_URL)._replace(path=f"/{dbname}"))


def _dsn(url: str) -> str:
    return url.replace("+asyncpg", "")


async def _holders(url: str = _URL) -> list[tuple[int, str]]:
    """(pid, state) of each backend holding the restore lock in ``url``'s database.

    Read on a connection of its own, never through ``app.db``'s pool, so that
    looking does not move the pool's queue."""
    conn = await asyncpg.connect(_dsn(url))
    try:
        rows = await conn.fetch(
            "SELECT l.pid, a.state FROM pg_locks l JOIN pg_stat_activity a USING (pid) "
            "WHERE l.locktype = 'advisory' AND l.granted AND l.objsubid = 1 "
            "AND ((l.classid::bigint << 32) | l.objid::bigint) = $1 "
            "AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database())",
            restore._RESTORE_LOCK_KEY,
        )
    finally:
        await conn.close()
    return [(r["pid"], r["state"]) for r in rows]


async def _settled(read: Callable[[], Awaitable[Any]], done: Callable[[Any], bool]) -> Any:
    """``read()`` again until ``done`` holds, for up to five seconds.

    A backend that was terminated, or whose client went away, takes the
    server a moment to end; its locks go with it."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 5
    value = await read()
    while not done(value) and loop.time() < deadline:
        await asyncio.sleep(0.05)
        value = await read()
    return value


async def _pids(url: str) -> set[int]:
    conn = await asyncpg.connect(_dsn(url))
    try:
        rows = await conn.fetch(
            "SELECT pid FROM pg_stat_activity WHERE datname = current_database()"
        )
    finally:
        await conn.close()
    return {r["pid"] for r in rows}


def _kwargs(passphrase: str, **overrides: Any) -> dict[str, Any]:
    return {
        "archive_bytes": b"zip",
        "passphrase": passphrase,
        "confirmation_phrase": restore.CONFIRM_PHRASE,
        "db_url": _URL,
        **overrides,
    }


async def _refuse(db: Any, **kwargs: Any) -> Any:
    """What an archive the restore rejects does ("secrets.enc is not a valid
    JSON envelope", a wrong passphrase, a damaged dump)."""
    raise BackupRestoreError(f"refused: {kwargs['passphrase']}")


@pytest.fixture
async def pool() -> AsyncIterator[Callable[[int], Awaitable[None]]]:
    """``app.db``'s own pool, emptied, and a way to leave ``n`` connections idle
    in it, as a busy api's concurrent requests do. Emptied again afterwards."""
    await engine.dispose()

    async def warm(n: int) -> None:
        conns = [await engine.connect() for _ in range(n)]
        for conn in conns:
            await conn.execute(text("SELECT 1"))
        for conn in conns:
            await conn.close()
        assert engine.pool.checkedin() == n

    try:
        yield warm
    finally:
        await engine.dispose()


async def _create_db(sql: str | None = None) -> str:
    name = f"spatiumddi_test_r1648_{uuid.uuid4().hex[:10]}"
    admin = await asyncpg.connect(_dsn(_url_for("postgres")))
    try:
        await admin.execute(f'CREATE DATABASE "{name}"')
    finally:
        await admin.close()
    if sql:
        conn = await asyncpg.connect(_dsn(_url_for(name)))
        try:
            await conn.execute(sql)
        finally:
            await conn.close()
    return name


async def _drop_db(name: str) -> None:
    admin = await asyncpg.connect(_dsn(_url_for("postgres")))
    try:
        await admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
    finally:
        await admin.close()


# ══════════════════════════════════════════════════════════════════════
# A restore that ends leaves no lock behind
# ══════════════════════════════════════════════════════════════════════


async def test_a_refused_restore_leaves_no_lock_behind(monkeypatch, pool) -> None:
    """The reported case: refused restores one after another, each through its
    own session, while the api's pool holds idle connections. Each is refused
    for its own reason, never as "already in progress", and none leaves the
    lock behind."""
    monkeypatch.setattr(restore, "_apply_backup_restore_inner", _refuse)
    await pool(3)

    seen = []
    for n in range(4):
        async with AsyncSessionLocal() as db:
            with pytest.raises(BackupRestoreError) as exc:
                await restore.apply_backup_restore(db, **_kwargs(f"archive {n}"))
        seen.append((str(exc.value), await _holders()))

    assert seen == [(f"refused: archive {n}", []) for n in range(4)]


async def test_a_restore_that_raises_releases_the_lock(monkeypatch, pool) -> None:
    async def _inner(db: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the replay's subprocess vanished")

    monkeypatch.setattr(restore, "_apply_backup_restore_inner", _inner)
    await pool(3)

    async with AsyncSessionLocal() as db:
        with pytest.raises(RuntimeError, match="vanished"):
            await restore.apply_backup_restore(db, **_kwargs("archive"))

    assert await _holders() == []


@pytest.mark.parametrize("cancel", ["once", "at_every_await"])
async def test_a_cancelled_restore_releases_the_lock(monkeypatch, pool, cancel) -> None:
    """A request cancelled mid-restore. ``at_every_await`` cancels again at each
    await, as an anyio cancel scope does: the unlock never gets to run, and
    closing the connection has to release the lock on its own."""
    started = asyncio.Event()

    async def _inner(db: Any, **kwargs: Any) -> Any:
        started.set()
        await asyncio.Event().wait()  # a replay that does not end by itself

    monkeypatch.setattr(restore, "_apply_backup_restore_inner", _inner)
    await pool(3)

    async def request() -> None:
        async with AsyncSessionLocal() as db:
            await restore.apply_backup_restore(db, **_kwargs("archive"))

    task = asyncio.create_task(request())
    await asyncio.wait_for(started.wait(), 10)
    assert len(await _holders()) == 1
    task.cancel()
    if cancel == "at_every_await":
        while not task.done():
            task.cancel()
            await asyncio.sleep(0)
    with pytest.raises(asyncio.CancelledError):
        await task

    assert await _settled(_holders, lambda held: held == []) == []


# ══════════════════════════════════════════════════════════════════════
# A restore that runs keeps the lock (#1571)
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("idle", [1, 3])
async def test_a_second_restore_is_refused_while_one_runs(monkeypatch, pool, idle) -> None:
    """#1571's guard, whichever pooled connection either request's session
    lands on. With one idle connection the second request's session checks out
    the first one's: the lock is re-entrant within a session, so it got in."""
    started, finish = asyncio.Event(), asyncio.Event()

    async def _inner(db: Any, **kwargs: Any) -> Any:
        if kwargs["passphrase"] != "first":
            raise AssertionError("a second restore ran while the first was running")
        started.set()
        await finish.wait()
        return "restored"

    monkeypatch.setattr(restore, "_apply_backup_restore_inner", _inner)
    await pool(idle)

    async def first() -> Any:
        async with AsyncSessionLocal() as db:
            return await restore.apply_backup_restore(db, **_kwargs("first"))

    task = asyncio.create_task(first())
    try:
        await asyncio.wait_for(started.wait(), 10)
        async with AsyncSessionLocal() as db:
            with pytest.raises(BackupRestoreError, match=_IN_PROGRESS):
                await restore.apply_backup_restore(db, **_kwargs("second"))
    finally:
        finish.set()
        result = await task

    assert result == "restored"
    assert await _holders() == []


@_needs_pg_tools
async def test_the_restores_own_terminate_step_spares_the_lock_holder() -> None:
    """Phase 5 ends every other session on the database before it replays.
    Ending the restore lock's own connection would release the lock in the
    middle of the replay and let a second restore in (#1571)."""
    name = await _create_db()
    url = _url_for(name)
    holder = await asyncpg.connect(_dsn(url))
    bystander = await asyncpg.connect(_dsn(url))  # a worker / agent session
    try:
        assert await holder.fetchval("SELECT pg_try_advisory_lock($1)", restore._RESTORE_LOCK_KEY)
        holder_pid = await holder.fetchval("SELECT pg_backend_pid()")
        bystander_pid = await bystander.fetchval("SELECT pg_backend_pid()")

        pg_env, _ = _pg_env_from_url(url)
        await restore._terminate_other_db_connections(pg_env)

        # The step ran: the bystander is gone. The lock's holder is not.
        left = await _settled(lambda: _pids(url), lambda pids: bystander_pid not in pids)
        assert bystander_pid not in left
        assert holder_pid in left
        assert await holder.fetchval("SELECT pg_backend_pid()") == holder_pid
        assert await _holders(url) == [(holder_pid, "idle")]
    finally:
        holder.terminate()
        bystander.terminate()
        await _drop_db(name)


_ARCHIVE_SCHEMA = """
CREATE TABLE restored_row (id integer PRIMARY KEY, name text NOT NULL);
INSERT INTO restored_row VALUES (1, 'from-the-archive');
"""

_LIVE_SCHEMA = """
CREATE TABLE restored_row (id integer PRIMARY KEY, name text NOT NULL);
INSERT INTO restored_row VALUES (1, 'live');
"""


async def _archive_of(dbname: str, tmp_path: Path, passphrase: str) -> bytes:
    """A backup archive of ``dbname`` in the shape ``build_backup_archive``
    writes (manifest, custom-format dump, secrets.enc), keyed with this
    install's own secret so the post-restore rewrap is a no-op."""
    dump = tmp_path / "database.dump"
    pg_env, _ = _pg_env_from_url(_url_for(dbname))
    proc = await asyncio.create_subprocess_exec(
        "pg_dump",
        "--format=custom",
        "--no-owner",
        "--no-privileges",
        f"--file={dump}",
        env={**os.environ, **pg_env},
        stderr=asyncio.subprocess.PIPE,
    )
    _, err = await proc.communicate()
    assert proc.returncode == 0, err.decode()
    manifest = {
        "format": "spatiumddi-backup",
        "format_version": 2,
        "dump_format": "custom",
        "schema_version": None,
    }
    secrets_enc = encrypt_secrets(
        {
            "platform_secret_key": settings.secret_key,
            "platform_credential_encryption_key": settings.credential_encryption_key or "",
        },
        passphrase=passphrase,
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest))
        zf.write(dump, arcname="database.dump")
        zf.writestr("secrets.enc", secrets_enc)
    return buf.getvalue()


@_needs_pg_tools
async def test_the_lock_holds_through_a_real_restore_and_is_released_after(
    monkeypatch, pool, tmp_path
) -> None:
    """A real full restore (pg_restore into psql) of a scratch database through
    ``apply_backup_restore``, with Phase 4's pool dispose and Phase 5's
    terminate step as they are. A second restore is refused as "already in
    progress" as the replay starts (right after the terminate step) and again
    once it has ended; after the restore returns, nothing holds the lock."""
    source = await _create_db(_ARCHIVE_SCHEMA)
    dest = await _create_db(_LIVE_SCHEMA)
    dest_url = _url_for(dest)
    passphrase = "correct horse battery staple"
    seen: dict[str, Any] = {}
    bystander = None
    try:
        archive = await _archive_of(source, tmp_path, passphrase)

        async def second_restore() -> str:
            # The wrong phrase: refused before it touches anything, should it get in.
            async with AsyncSessionLocal() as db:
                with pytest.raises(BackupRestoreError) as exc:
                    await restore.apply_backup_restore(
                        db,
                        archive_bytes=archive,
                        passphrase=passphrase,
                        confirmation_phrase="not the phrase",
                        db_url=dest_url,
                    )
            return str(exc.value)

        real_terminate = restore._terminate_other_db_connections
        real_upgrade = restore.maybe_upgrade_after_restore

        async def terminate(pg_env: dict[str, str]) -> None:
            await real_terminate(pg_env)
            seen["bystander_left"] = await _settled(
                lambda: _pids(dest_url), lambda pids: bystander_pid not in pids
            )
            seen["replay_start"] = (len(await _holders(dest_url)), await second_restore())

        async def upgrade(**kwargs: Any) -> Any:
            seen["replay_end"] = (len(await _holders(dest_url)), await second_restore())
            return await real_upgrade(**kwargs)

        async def safety_dump(db: Any) -> None:
            # The session does work here, as the real dump's head read does;
            # the dump itself (pg_dump of the whole install) is not the point.
            await db.execute(text("SELECT 1"))

        monkeypatch.setattr(restore, "_terminate_other_db_connections", terminate)
        monkeypatch.setattr(restore, "maybe_upgrade_after_restore", upgrade)
        monkeypatch.setattr(restore, "_write_pre_restore_safety_dump", safety_dump)
        await pool(3)
        bystander = await asyncpg.connect(_dsn(dest_url))
        bystander_pid = await bystander.fetchval("SELECT pg_backend_pid()")

        async with AsyncSessionLocal() as db:
            outcome = await restore.apply_backup_restore(
                db,
                archive_bytes=archive,
                passphrase=passphrase,
                confirmation_phrase=restore.CONFIRM_PHRASE,
                db_url=dest_url,
            )

        assert seen["replay_start"][1].startswith(_IN_PROGRESS), seen
        assert seen["replay_end"][1].startswith(_IN_PROGRESS), seen
        assert seen["replay_start"][0] == seen["replay_end"][0] == 1, seen
        assert bystander_pid not in seen["bystander_left"]
        assert await _holders(dest_url) == []
        assert outcome.rewrap is not None and outcome.rewrap.same_install
        conn = await asyncpg.connect(_dsn(dest_url))
        try:
            names = [r["name"] for r in await conn.fetch("SELECT name FROM restored_row")]
        finally:
            await conn.close()
        assert names == ["from-the-archive"]
    finally:
        if bystander is not None:
            bystander.terminate()
        await _drop_db(source)
        await _drop_db(dest)
