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
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.crypto import encrypt_str
from app.models.backup import BackupTarget
from app.services.backup import runner as runner_mod
from app.tasks import backup_sweep

NAME = "spatiumddi-backup-h-20261112-020000-ab12cd.zip"


def test_sweep_stamp_survives_a_pool_connection_from_an_earlier_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Never touches the shared app engine: a test-local one-connection pool
    stands in for ``app.db.AsyncSessionLocal`` for this test only, so the
    cross-loop connection reuse is real but cannot leak into other tests."""
    import app.db as app_db

    db_url = os.environ["DATABASE_URL"]
    app_name = f"t3939-{uuid.uuid4().hex[:12]}"
    test_engine = create_async_engine(
        db_url,
        pool_size=1,
        max_overflow=0,
        connect_args={"server_settings": {"application_name": app_name}},
    )
    test_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    # The runner resolves the shared pool lazily from app.db.
    monkeypatch.setattr(app_db, "AsyncSessionLocal", test_factory)
    monkeypatch.setattr(app_db, "engine", test_engine)

    def _plain_engine():
        return create_async_engine(db_url, poolclass=NullPool)

    async def _make_target() -> object:
        async with test_factory() as s:
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
            return t.id

    try:
        # Loop 1: leaves a connection in the test pool, bound to this loop.
        target_id = asyncio.run(_make_target())

        pid_box: dict[str, int] = {}

        class _Driver:
            def validate_config(self, config) -> None:
                return None

            async def write(self, *, config, filename, archive_bytes) -> None:
                eng = _plain_engine()
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
            eng = _plain_engine()
            try:
                async with eng.connect() as c:
                    return (
                        await c.execute(
                            select(
                                BackupTarget.last_run_status, BackupTarget.last_run_filename
                            ).where(BackupTarget.id == target_id)
                        )
                    ).one()
            finally:
                await eng.dispose()

        row = asyncio.run(_read())
        assert row.last_run_status == "success"
        assert row.last_run_filename == NAME

    finally:
        # Drop the dead-loop pool without awaiting it, then end every backend
        # this test opened server-side (filtered by its unique application_name).
        test_engine.sync_engine.dispose(close=False)

        async def _reap() -> None:
            eng = _plain_engine()
            try:
                async with eng.connect() as c:
                    await c.execute(text("DELETE FROM backup_target"))
                    await c.execute(
                        text(
                            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                            "WHERE application_name = :n AND pid <> pg_backend_pid()"
                        ),
                        {"n": app_name},
                    )
                    await c.commit()
            finally:
                await eng.dispose()

        asyncio.run(_reap())
