"""The migrate command must not hang behind a dead client's session (#3932).

A session left idle in transaction by an api pod that is gone held the 1.0.0
migration's ``ALTER TABLE`` for 2 h+, with every pod waiting on it. These run
the REAL ``alembic/env.py`` against a throwaway database with a real second
connection holding a real lock:

* after a timed-out lock wait, the reaper ends only a stale ``idle in
  transaction`` session of the migrator's own role, and leaves a young one, a
  plain idle one and another role's alone;
* only a session the migration WAITS ON is ended (``pg_blocking_pids``): an
  active ``pg_dump``-like holder is waited out, and an unrelated stale
  idle-in-transaction session (a backup's own) survives;
* an upgrade that is never blocked ends nothing, however stale;
* with the reaper off, ``lock_timeout`` turns the silent wait into a logged
  retry that succeeds once the blocker goes, without limit by default (a
  legitimate long holder, a backup's pg_dump, must be waited out as before),
  and into an error only when the operator bounded the retries.
"""

from __future__ import annotations

import asyncio
import os
import pathlib
import shutil
import threading
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest
from alembic.config import Config

from alembic import command
from app.core import migrate_guard

_REAL_ENV = pathlib.Path(__file__).resolve().parents[1] / "alembic" / "env.py"

_REVISION = '''"""synthetic #3932 revision"""
import sqlalchemy as sa
from alembic import op

revision = "mg1"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("mg_target", sa.Column("x", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("mg_target", "x")
'''


def _urls() -> tuple[str, str, str, str]:
    base = urlsplit(os.environ["DATABASE_URL"])
    name = base.path.lstrip("/") + "_migguard"
    sa_url = urlunsplit(base._replace(path=f"/{name}"))
    raw = base._replace(scheme=base.scheme.replace("postgresql+asyncpg", "postgresql"))
    return (
        sa_url,
        urlunsplit(raw._replace(path=f"/{name}")),
        urlunsplit(raw._replace(path="/postgres")),
        name,
    )


@pytest.fixture
async def rig(tmp_path, monkeypatch):
    sa_url, raw_url, maintenance_url, name = _urls()
    admin = await asyncpg.connect(maintenance_url)
    try:
        await admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        await admin.execute(f'CREATE DATABASE "{name}"')
    finally:
        await admin.close()
    setup = await asyncpg.connect(raw_url)
    try:
        await setup.execute("CREATE TABLE mg_target (id integer PRIMARY KEY)")
        await setup.execute("CREATE TABLE mg_other (id integer PRIMARY KEY)")
    finally:
        await setup.close()

    d = tmp_path / "alembic"
    (d / "versions").mkdir(parents=True)
    shutil.copy(_REAL_ENV, d / "env.py")
    (d / "versions" / "mg1_x.py").write_text(_REVISION, encoding="utf-8")
    cfg = Config()
    cfg.set_main_option("script_location", str(d))
    monkeypatch.setenv("DATABASE_URL", sa_url)
    yield cfg, raw_url, maintenance_url
    admin = await asyncpg.connect(maintenance_url)
    try:
        await admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
    finally:
        await admin.close()


def _start_upgrade(cfg: Config) -> tuple[threading.Thread, dict[str, BaseException]]:
    outcome: dict[str, BaseException] = {}

    def run() -> None:
        try:
            command.upgrade(cfg, "head")
        except BaseException as exc:  # noqa: BLE001 — reported by the assertions
            outcome["error"] = exc

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t, outcome


async def _alive(watch: asyncpg.Connection, pid: int) -> bool:
    return bool(await watch.fetchval("SELECT count(*) FROM pg_stat_activity WHERE pid = $1", pid))


async def test_reaper_ends_only_stale_idle_in_transaction_sessions_of_the_migrator_role(
    rig, monkeypatch
) -> None:
    cfg, raw_url, maintenance_url = rig
    # The young session must still be under the threshold after the 1 s lock
    # wait that has to time out before the reaper runs.
    monkeypatch.setenv(migrate_guard.STALE_IDLE_ENV, "3")
    monkeypatch.setenv(migrate_guard.LOCK_TIMEOUT_ENV, "1")
    monkeypatch.setattr(migrate_guard, "backoff_seconds", lambda attempt: 0.1)

    stale = await asyncpg.connect(raw_url)  # the dead api pod's session
    young = await asyncpg.connect(raw_url)
    plain_idle = await asyncpg.connect(raw_url)
    other_role = None
    watch = await asyncpg.connect(raw_url)
    admin = await asyncpg.connect(maintenance_url)
    try:
        try:
            await admin.execute("DROP ROLE IF EXISTS mg_other_role")
            await admin.execute("CREATE ROLE mg_other_role LOGIN PASSWORD 'x' SUPERUSER")
            parts = urlsplit(raw_url)
            other_role = await asyncpg.connect(
                urlunsplit(
                    parts._replace(
                        netloc=f"mg_other_role:x@{parts.hostname}"
                        + (f":{parts.port}" if parts.port else "")
                    )
                )
            )
        except Exception:  # noqa: BLE001 — cannot create a role here: skip that arm
            other_role = None

        await stale.execute("BEGIN")
        await stale.fetch("SELECT * FROM mg_target")  # holds a lock the ALTER needs
        stale_pid = await stale.fetchval("SELECT pg_backend_pid()")
        if other_role is not None:
            await other_role.execute("BEGIN")
            await other_role.fetch("SELECT * FROM mg_other")
            other_pid = await other_role.fetchval("SELECT pg_backend_pid()")
            # Backdate nothing: it just has to be as old as the stale one.
        plain_pid = await plain_idle.fetchval("SELECT pg_backend_pid()")
        await asyncio.sleep(3.6)  # stale + other_role are now older than 3 s
        await young.execute("BEGIN")
        await young.fetch("SELECT * FROM mg_other")
        young_pid = await young.fetchval("SELECT pg_backend_pid()")

        t, outcome = _start_upgrade(cfg)
        await asyncio.to_thread(t.join, 60)
        assert not t.is_alive(), "the migration hung behind the idle session"
        assert "error" not in outcome, repr(outcome.get("error"))

        assert not await _alive(watch, stale_pid), "the stale session was not ended"
        assert await _alive(watch, young_pid), "a young idle-in-transaction session was killed"
        assert await _alive(watch, plain_pid), "a plain idle session was killed"
        if other_role is not None:
            assert await _alive(watch, other_pid), "another role's session was killed"
        assert await watch.fetchval("SELECT version_num FROM alembic_version") == "mg1"
    finally:
        for conn in (stale, young, plain_idle, watch, other_role):
            if conn is not None:
                await conn.close()
        try:
            await admin.execute("DROP ROLE IF EXISTS mg_other_role")
        finally:
            await admin.close()


async def test_an_active_holder_is_waited_out_and_a_non_blocking_stale_session_survives(
    rig, monkeypatch
) -> None:
    """The #3933 regression: a backup's own idle-in-transaction session (a lock
    the ALTER does not wait on) was ended while the migration waited on
    pg_dump. Only the sessions the migration waits on may be ended."""
    cfg, raw_url, _ = rig
    monkeypatch.setenv(migrate_guard.STALE_IDLE_ENV, "1")
    monkeypatch.setenv(migrate_guard.LOCK_TIMEOUT_ENV, "1")
    monkeypatch.setattr(migrate_guard, "backoff_seconds", lambda attempt: 0.1)

    dump = await asyncpg.connect(raw_url)  # pg_dump: active, holds a conflicting lock
    backup_session = await asyncpg.connect(raw_url)  # idle, holds only unrelated locks
    watch = await asyncpg.connect(raw_url)
    try:
        await backup_session.execute("BEGIN")
        await backup_session.fetch("SELECT * FROM mg_other")
        backup_pid = await backup_session.fetchval("SELECT pg_backend_pid()")
        await dump.execute("BEGIN")
        await dump.fetch("SELECT * FROM mg_target")
        dump_pid = await dump.fetchval("SELECT pg_backend_pid()")
        await asyncio.sleep(1.6)  # backup_session is now past the 1 s threshold
        sleeping = asyncio.ensure_future(dump.execute("SELECT pg_sleep(6)"))

        t, outcome = _start_upgrade(cfg)
        await asyncio.sleep(4)  # several timed-out waits, all while the dump is active
        assert t.is_alive() and "error" not in outcome, repr(outcome.get("error"))
        assert await _alive(watch, dump_pid), "the active holder was ended"
        assert await _alive(watch, backup_pid), "a session that blocks nothing was ended"
        await sleeping
        await dump.execute("COMMIT")
        await asyncio.to_thread(t.join, 60)
        assert not t.is_alive() and "error" not in outcome, repr(outcome.get("error"))
        assert await watch.fetchval("SELECT version_num FROM alembic_version") == "mg1"
        assert await _alive(watch, backup_pid), "the bystander did not survive the upgrade"
    finally:
        for conn in (dump, backup_session, watch):
            await conn.close()


async def test_lock_timeout_logs_the_holder_retries_and_succeeds_once_it_goes(
    rig, monkeypatch
) -> None:
    cfg, raw_url, _ = rig
    monkeypatch.setenv(migrate_guard.STALE_IDLE_ENV, "0")  # reaper off: only lock_timeout acts
    monkeypatch.setenv(migrate_guard.LOCK_TIMEOUT_ENV, "1")
    monkeypatch.setenv(migrate_guard.LOCK_RETRIES_ENV, "20")
    monkeypatch.setattr(migrate_guard, "backoff_seconds", lambda attempt: 0.1)
    reports: list[list[dict]] = []
    real_log = migrate_guard.log_blockers

    def recording(blockers, **kw):
        reports.append(blockers)
        real_log(blockers, **kw)

    monkeypatch.setattr(migrate_guard, "log_blockers", recording)

    holder = await asyncpg.connect(raw_url)
    watch = await asyncpg.connect(raw_url)
    try:
        await holder.execute("BEGIN")
        await holder.fetch("SELECT * FROM mg_target")
        holder_pid = await holder.fetchval("SELECT pg_backend_pid()")
        t, outcome = _start_upgrade(cfg)
        await asyncio.sleep(3.5)  # at least two 1 s lock waits time out
        assert t.is_alive() and "error" not in outcome
        await holder.execute("COMMIT")
        await asyncio.to_thread(t.join, 60)
        assert not t.is_alive()
        assert "error" not in outcome, repr(outcome.get("error"))
        assert await watch.fetchval("SELECT version_num FROM alembic_version") == "mg1"
    finally:
        await holder.close()
        await watch.close()

    assert len(reports) >= 2, "a timed-out lock wait must be retried, not abandoned"
    assert any(b["pid"] == holder_pid for r in reports for b in r), "the holder was not named"
    assert any(b["state"] == "idle in transaction" for r in reports for b in r)


async def test_lock_timeout_gives_up_after_the_bounded_retries(rig, monkeypatch) -> None:
    cfg, raw_url, _ = rig
    monkeypatch.setenv(migrate_guard.STALE_IDLE_ENV, "0")
    monkeypatch.setenv(migrate_guard.LOCK_TIMEOUT_ENV, "1")
    monkeypatch.setenv(migrate_guard.LOCK_RETRIES_ENV, "1")
    monkeypatch.setattr(migrate_guard, "backoff_seconds", lambda attempt: 0.1)

    holder = await asyncpg.connect(raw_url)
    try:
        await holder.execute("BEGIN")
        await holder.fetch("SELECT * FROM mg_target")
        t, outcome = _start_upgrade(cfg)
        await asyncio.to_thread(t.join, 60)
        assert not t.is_alive()
        assert migrate_guard.is_lock_timeout(outcome.get("error")), repr(outcome.get("error"))
    finally:
        await holder.close()


async def test_an_unblocked_upgrade_ends_no_session_however_stale(rig, monkeypatch) -> None:
    """The reaper is reactive: nothing is ended unless a lock wait timed out."""
    cfg, raw_url, _ = rig
    monkeypatch.setenv(migrate_guard.STALE_IDLE_ENV, "1")
    monkeypatch.setenv(migrate_guard.LOCK_TIMEOUT_ENV, "1")

    stale = await asyncpg.connect(raw_url)  # e.g. a backup session, not in the way
    watch = await asyncpg.connect(raw_url)
    try:
        await stale.execute("BEGIN")
        await stale.fetch("SELECT * FROM mg_other")  # a lock the ALTER does not need
        stale_pid = await stale.fetchval("SELECT pg_backend_pid()")
        await asyncio.sleep(1.6)
        t, outcome = _start_upgrade(cfg)
        await asyncio.to_thread(t.join, 60)
        assert not t.is_alive() and "error" not in outcome, repr(outcome.get("error"))
        assert await watch.fetchval("SELECT version_num FROM alembic_version") == "mg1"
        assert await _alive(watch, stale_pid), "a session that blocked nothing was ended"
    finally:
        await stale.close()
        await watch.close()


async def test_retries_are_unlimited_by_default(rig, monkeypatch) -> None:
    """A legitimate long holder (a backup's pg_dump) is waited out, as it was
    before #3932, rather than failing the migrate Job and stranding the api."""
    cfg, raw_url, _ = rig
    monkeypatch.setenv(migrate_guard.STALE_IDLE_ENV, "0")
    monkeypatch.setenv(migrate_guard.LOCK_TIMEOUT_ENV, "1")
    monkeypatch.delenv(migrate_guard.LOCK_RETRIES_ENV, raising=False)
    monkeypatch.setattr(migrate_guard, "backoff_seconds", lambda attempt: 0.05)
    attempts: list[int] = []
    real_log = migrate_guard.log_blockers

    def recording(blockers, **kw):
        attempts.append(kw["attempt"])
        real_log(blockers, **kw)

    monkeypatch.setattr(migrate_guard, "log_blockers", recording)

    holder = await asyncpg.connect(raw_url)
    try:
        await holder.execute("BEGIN")
        await holder.fetch("SELECT * FROM mg_target")
        t, outcome = _start_upgrade(cfg)
        # Well past the old default budget of 10 retries.
        deadline = asyncio.get_running_loop().time() + 60
        while len(attempts) < 12 and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.2)
        assert t.is_alive() and "error" not in outcome, repr(outcome.get("error"))
        assert len(attempts) >= 12
        await holder.execute("COMMIT")
        await asyncio.to_thread(t.join, 60)
        assert not t.is_alive()
        assert "error" not in outcome, repr(outcome.get("error"))
    finally:
        await holder.close()


def test_lock_retries_env_parsing(monkeypatch) -> None:
    monkeypatch.delenv(migrate_guard.LOCK_RETRIES_ENV, raising=False)
    assert migrate_guard.lock_retries() is None
    for raw, want in (("", None), ("-1", None), ("junk", None), ("0", 0), ("7", 7)):
        monkeypatch.setenv(migrate_guard.LOCK_RETRIES_ENV, raw)
        assert migrate_guard.lock_retries() == want, raw


def test_lock_timeout_is_recognised_through_the_wrapper_chain() -> None:
    class Pg(Exception):
        sqlstate = "55P03"

    wrapper = RuntimeError("wrapped")
    wrapper.__cause__ = Pg()
    assert migrate_guard.is_lock_timeout(wrapper)
    assert not migrate_guard.is_lock_timeout(RuntimeError("deadlock detected"))
    assert not migrate_guard.is_lock_timeout(None)


def test_the_guard_is_scoped_to_upgrade_and_env_py_is_wired() -> None:
    src = _REAL_ENV.read_text(encoding="utf-8")
    assert "terminate_stale_idle_sessions" in src and "apply_lock_timeout" in src
    assert '== "upgrade"' in src  # never on `alembic current` / stamp / downgrade
