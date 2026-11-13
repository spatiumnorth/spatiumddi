"""A scheduled backup whose session is ended mid-run is stamped on the sweep's loop (#3939).

The Celery sweep runs ``asyncio.run(_sweep())`` once per tick, so each tick
has its own event loop. The end stamp (#2353) used the module-level
``AsyncSessionLocal`` pool, which can hold a connection made under an earlier
tick's (closed) loop: the stamp then failed with "Event loop is closed" and the
row stayed ``in_progress`` for 2 h although the archive was written.
"""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.core.crypto import encrypt_str
from app.models.backup import BackupTarget
from app.services.backup import runner as runner_mod
from app.tasks import backup_sweep

NAME = "spatiumddi-backup-h-20261112-020000-ab12cd.zip"


def test_sweep_stamp_survives_a_pool_connection_from_an_earlier_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.db as app_db

    db_url = os.environ["DATABASE_URL"]

    async def _make_target() -> object:
        async with app_db.AsyncSessionLocal() as s:
            # Wipe leftovers from earlier tests, then add a due target.
            await s.execute(text("DELETE FROM backup_target"))
            t = BackupTarget(
                name="loopy",
                kind="webdav",
                config={},
                enabled=True,
                schedule_cron="* * * * *",
                next_run_at=datetime.now(UTC) - timedelta(minutes=1),
                last_run_status="never",
                passphrase_encrypted=encrypt_str("hunter2hunter2"),
            )
            s.add(t)
            await s.commit()
            loop1_pid[0] = (await s.execute(text("SELECT pg_backend_pid()"))).scalar_one()
            return t.id

    loop1_pid = [0]

    # Loop 1: leaves a connection in the SHARED pool, bound to this loop.
    target_id = asyncio.run(_make_target())

    try:
        pid_box: dict[str, int] = {}

        class _Driver:
            def validate_config(self, config) -> None:
                return None

            async def write(self, *, config, filename, archive_bytes) -> None:
                eng = create_async_engine(db_url, poolclass=NullPool)
                try:
                    async with eng.connect() as other:
                        await other.execute(
                            text("SELECT pg_terminate_backend(:p)"), {"p": pid_box["pid"]}
                        )
                        await other.commit()
                finally:
                    await eng.dispose()

        async def _build(db, **kw):
            pid_box["pid"] = (await db.execute(text("SELECT pg_backend_pid()"))).scalar_one()
            return b"zip", NAME

        monkeypatch.setattr(runner_mod, "get_destination", lambda kind: _Driver())
        monkeypatch.setattr(runner_mod, "decrypt_config_secrets", lambda d, c: c)
        monkeypatch.setattr(runner_mod, "build_backup_archive", _build)

        # Loop 2: the sweep fires the run; the run's session is ended mid-run.
        result = asyncio.run(backup_sweep._sweep())
        assert result["fired"] == 1

        async def _read():
            async with app_db.task_session() as s:
                return (
                    await s.execute(select(BackupTarget).where(BackupTarget.id == target_id))
                ).scalar_one()

        row = asyncio.run(_read())
        assert row.last_run_status == "success"
        assert row.last_run_filename == NAME

    finally:
        # Leave nothing behind for the next test on this worker/Postgres
        # (#3939 CI shard 9): the loop-1 pooled connection is bound to a
        # closed loop and cannot be closed gracefully, so end its backend
        # server-side and drop the dead pool without touching the loop.
        async def _reap() -> None:
            eng = create_async_engine(db_url, poolclass=NullPool)
            try:
                async with eng.connect() as c:
                    await c.execute(text("DELETE FROM backup_target"))
                    await c.execute(text("SELECT pg_terminate_backend(:p)"), {"p": loop1_pid[0]})
                    await c.commit()
            finally:
                await eng.dispose()

        asyncio.run(_reap())
        app_db.engine.sync_engine.dispose(close=False)
