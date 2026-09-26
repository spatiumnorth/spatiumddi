"""The migration must survive the previous release's traffic (#1204).

During an upgrade the previous release keeps serving: the new api, worker and
beat wait on ``wait-for-migrate``, the old pods do not. ``alembic/env.py`` used
to run the whole chain in ONE transaction, so every ACCESS EXCLUSIVE lock a
revision took was held until the last revision committed. On a real
2026.09.04-1 -> 7490f61b upgrade every attempt then died of a deadlock:
``c93f1a72e408`` altered ``dhcp_server_group``; an old-release request holding
``appliance`` blocked on it; three revisions later ``f7c3a91e50b4``'s
``ALTER TABLE appliance`` closed the cycle, and PostgreSQL aborted the
migration. It happened with three different table pairs on one appliance.

This reproduces that order deterministically with three synthetic revisions,
run through the REAL ``env.py``:

  1. a request of the previous release holds ``mt_appliance`` (it read it);
  2. revision 1 alters ``mt_group``; revision 2 is held up behind another
     reader of ``mt_settings``, so the chain pauses mid-way;
  3. the request now reads ``mt_group``, the table revision 1 altered, and
     waits past ``deadlock_timeout`` so its own one deadlock check finds no
     cycle;
  4. revision 2 is let go; revision 3 alters ``mt_appliance``.

With one transaction for the chain, step 3 blocks on revision 1's lock and
step 4 closes the cycle, so the migration is the victim. With one transaction
per revision, revision 1 has committed by step 3, the read returns, and the
chain completes.
"""

from __future__ import annotations

import asyncio
import os
import pathlib
import shutil
import threading
from urllib.parse import urlsplit, urlunsplit

import asyncpg
from alembic.config import Config

from alembic import command

_REAL_ENV = pathlib.Path(__file__).resolve().parents[1] / "alembic" / "env.py"

# (revision, down_revision, table, column): three ALTERs on three tables.
_CHAIN = (
    ("mt1", None, "mt_group", "x"),
    ("mt2", "mt1", "mt_settings", "y"),
    ("mt3", "mt2", "mt_appliance", "z"),
)

_REVISION = '''"""synthetic #1204 revision {rev}"""
import sqlalchemy as sa
from alembic import op

revision = "{rev}"
down_revision = {down!r}
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("{table}", sa.Column("{column}", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("{table}", "{column}")
'''


def _urls() -> tuple[str, str, str, str]:
    """(env.py's SQLAlchemy URL, a raw asyncpg URL, the maintenance URL, the
    database name) for a throwaway database next to this worker's test DB."""
    base = urlsplit(os.environ["DATABASE_URL"])
    name = base.path.lstrip("/") + "_migtx"
    sa_url = urlunsplit(base._replace(path=f"/{name}"))
    raw = base._replace(scheme=base.scheme.replace("postgresql+asyncpg", "postgresql"))
    return (
        sa_url,
        urlunsplit(raw._replace(path=f"/{name}")),
        urlunsplit(raw._replace(path="/postgres")),
        name,
    )


def _script_dir(root: pathlib.Path) -> pathlib.Path:
    """A script directory holding the real env.py and the synthetic chain."""
    d = root / "alembic"
    (d / "versions").mkdir(parents=True)
    shutil.copy(_REAL_ENV, d / "env.py")
    for rev, down, table, column in _CHAIN:
        (d / "versions" / f"{rev}_{table}.py").write_text(
            _REVISION.format(rev=rev, down=down, table=table, column=column),
            encoding="utf-8",
        )
    return d


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
        await asyncio.sleep(0.05)
    raise AssertionError(f"the migration never reached {table}")


async def test_a_previous_release_request_blocked_on_an_altered_table_does_not_kill_the_migration(
    tmp_path, monkeypatch
) -> None:
    sa_url, raw_url, maintenance_url, name = _urls()
    admin = await asyncpg.connect(maintenance_url)
    try:
        await admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        await admin.execute(f'CREATE DATABASE "{name}"')
    finally:
        await admin.close()
    setup = await asyncpg.connect(raw_url)
    try:
        for _rev, _down, table, _column in _CHAIN:
            await setup.execute(f"CREATE TABLE {table} (id integer PRIMARY KEY)")
            await setup.execute(f"INSERT INTO {table} VALUES (1)")
    finally:
        await setup.close()

    cfg = Config()
    cfg.set_main_option("script_location", str(_script_dir(tmp_path)))
    # env.py takes the URL from DATABASE_URL, exactly as the migrate Job does.
    monkeypatch.setenv("DATABASE_URL", sa_url)

    outcome: dict[str, BaseException] = {}

    def upgrade() -> None:
        try:
            command.upgrade(cfg, "head")
        except BaseException as exc:  # noqa: BLE001 — reported by the assertion
            outcome["error"] = exc

    request = await asyncpg.connect(raw_url)  # the previous release's request
    holder = await asyncpg.connect(raw_url)  # holds revision 2 up mid-chain
    watch = await asyncpg.connect(raw_url)
    try:
        await request.execute("BEGIN")
        await request.fetch("SELECT * FROM mt_appliance")
        await holder.execute("BEGIN")
        await holder.fetch("SELECT * FROM mt_settings")

        migration = threading.Thread(target=upgrade, daemon=True)
        migration.start()
        await _wait_until_waiting(watch, "mt_settings")  # revision 1 is done

        read = asyncio.create_task(request.fetch("SELECT * FROM mt_group"))
        await asyncio.sleep(1.5)  # past deadlock_timeout (1 s): its one check sees no cycle
        await holder.execute("COMMIT")  # revision 2 goes; revision 3 wants mt_appliance
        await asyncio.wait_for(read, 30)
        await request.execute("COMMIT")
        await asyncio.to_thread(migration.join, 60)
        assert not migration.is_alive(), "the migration did not finish"
        assert "error" not in outcome, f"the migration was aborted: {outcome.get('error')!r}"
        version = await watch.fetchval("SELECT version_num FROM alembic_version")
    finally:
        for conn in (request, holder, watch):
            await conn.close()
        admin = await asyncpg.connect(maintenance_url)
        try:
            await admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        finally:
            await admin.close()

    assert version == "mt3"


def test_env_runs_one_transaction_per_revision_in_both_modes() -> None:
    """Offline SQL scripts must commit per revision too, so a DBA replaying
    one hits the same lock behaviour as the migrate Job."""
    src = _REAL_ENV.read_text(encoding="utf-8")
    assert "TRANSACTION_PER_MIGRATION = True" in src
    assert src.count("transaction_per_migration=TRANSACTION_PER_MIGRATION") == 2
