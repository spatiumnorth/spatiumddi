"""The plaintext webhook forward-target columns are dropped, and their values
survive it (migration ``c2b203844c95``).

``e51ab0dede3e`` moved ``audit_forward_target.url`` / ``auth_header`` and the
legacy single-webhook pair on ``platform_settings`` into ``*_encrypted``
columns and kept the plaintext ones, unread, for one release. Dropping them
must not lose a value that never reached the encrypted column, must not
overwrite one that did, and must not stop an archive taken before the drop
from restoring — fully or selectively.
"""

from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import shutil
import uuid
import zipfile
from collections.abc import AsyncIterator
from typing import Any

import asyncpg
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.config import settings
from app.core.crypto import decrypt_str, encrypt_str
from app.models.audit_forward import AuditForwardTarget
from app.models.base import Base
from app.models.settings import PlatformSettings
from app.services.backup import restore
from app.services.backup.crypto import encrypt_secrets
from app.services.backup.legacy_columns import DROPPED_PLAINTEXT_SECRET_COLUMNS
from tests.test_selective_restore_app_role_1693 import _admin, _dsn, _pg_dump, _url_for

_MIGRATION = (
    pathlib.Path(__file__).resolve().parents[1]
    / "alembic"
    / "versions"
    / "c2b203844c95_drop_plaintext_forward_webhook_columns.py"
)
_PREVIOUS_HEAD = "e7b3d19a4c26"
_HEAD = "c2b203844c95"

# Fixtures only; nothing here is ever contacted.
_OLD_URL = "https://hooks.chat.example/services/T0/B0/oldPlaintextOnly"
_NEW_URL = "https://hooks.chat.example/services/T0/B0/alreadyEncrypted"
_AUTH = "Bearer legacy-hdr-fixture"
_GENERIC = "https://collector.example.test/ingest/legacyPath"


def _load_migration() -> Any:
    spec = importlib.util.spec_from_file_location("m_c2b203844c95", _MIGRATION)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_restore_helper_and_the_migration_agree_on_the_columns() -> None:
    module = _load_migration()
    assert [(t, p, e) for t, p, e, _ in DROPPED_PLAINTEXT_SECRET_COLUMNS] == list(
        module._PAIRS  # noqa: SLF001
    )


def test_the_migration_follows_the_current_head() -> None:
    assert _load_migration().down_revision == _PREVIOUS_HEAD


async def _columns(db: AsyncSession, table: str) -> set[str]:
    rows = await db.execute(
        text("SELECT column_name FROM information_schema.columns WHERE table_name = :t"),
        {"t": table},
    )
    return {r[0] for r in rows}


async def test_the_migration_encrypts_what_is_left_and_drops_the_columns(
    db_session: AsyncSession,
) -> None:
    """Upgrade then downgrade, in the test's transaction (rolled back)."""
    module = _load_migration()
    plaintext_only = AuditForwardTarget(name=f"p-{uuid.uuid4().hex[:6]}", kind="webhook")
    already = AuditForwardTarget(
        name=f"e-{uuid.uuid4().hex[:6]}",
        kind="webhook",
        url_encrypted=encrypt_str(_NEW_URL),
    )
    blanked = AuditForwardTarget(
        name=f"b-{uuid.uuid4().hex[:6]}", kind="webhook", url_encrypted=b""
    )
    db_session.add_all([plaintext_only, already, blanked])
    if await db_session.get(PlatformSettings, 1) is None:
        db_session.add(PlatformSettings(id=1))
    await db_session.flush()

    # The shape e51ab0dede3e left an upgraded install in.
    for table, plain, _enc in module._PAIRS:  # noqa: SLF001
        await db_session.execute(
            text(f"ALTER TABLE {table} ADD COLUMN {plain} VARCHAR(1024) DEFAULT ''")
        )
    for row in (plaintext_only, already, blanked):
        await db_session.execute(
            text("UPDATE audit_forward_target SET url = :u, auth_header = :a WHERE id = :id"),
            {"u": _OLD_URL, "a": _AUTH, "id": row.id},
        )
    await db_session.execute(
        text(
            "UPDATE platform_settings SET audit_forward_webhook_url = :u, "
            "audit_forward_webhook_auth_header = NULL, "
            "audit_forward_webhook_url_encrypted = NULL WHERE id = 1"
        ),
        {"u": _GENERIC},
    )

    def _run(fn_name: str):  # noqa: ANN202
        def _inner(sync_conn) -> None:  # noqa: ANN001
            from alembic.migration import MigrationContext
            from alembic.operations import Operations

            ctx = MigrationContext.configure(sync_conn)
            with Operations.context(ctx):
                getattr(module, fn_name)()

        return _inner

    conn = await db_session.connection()
    await conn.run_sync(_run("upgrade"))

    for table, plain, _enc in module._PAIRS:  # noqa: SLF001
        assert plain not in await _columns(db_session, table)

    async def _target(row_id: uuid.UUID) -> tuple[bytes | None, bytes | None]:
        r = (
            await db_session.execute(
                text(
                    "SELECT url_encrypted, auth_header_encrypted "
                    "FROM audit_forward_target WHERE id = :id"
                ),
                {"id": row_id},
            )
        ).one()
        return r[0], r[1]

    url, hdr = await _target(plaintext_only.id)
    assert decrypt_str(bytes(url)) == _OLD_URL and decrypt_str(bytes(hdr)) == _AUTH
    # An encrypted value is what the application reads; the plaintext copy
    # does not replace it.
    url, _hdr = await _target(already.id)
    assert decrypt_str(bytes(url)) == _NEW_URL
    # An empty bytea (an "exclude secrets" restore) counts as empty.
    url, _hdr = await _target(blanked.id)
    assert decrypt_str(bytes(url)) == _OLD_URL
    ps = (
        await db_session.execute(
            text(
                "SELECT audit_forward_webhook_url_encrypted, "
                "audit_forward_webhook_auth_header_encrypted FROM platform_settings WHERE id = 1"
            )
        )
    ).one()
    assert decrypt_str(bytes(ps[0])) == _GENERIC and ps[1] is None

    # A second run is a no-op, not an error.
    await conn.run_sync(_run("upgrade"))

    await conn.run_sync(_run("downgrade"))
    for table, plain, _enc in module._PAIRS:  # noqa: SLF001
        assert plain in await _columns(db_session, table)
    back = (
        await db_session.execute(
            text("SELECT url, url_encrypted FROM audit_forward_target WHERE id = :id"),
            {"id": plaintext_only.id},
        )
    ).one()
    # Re-added empty; the value stays encrypted.
    assert back[0] == "" and decrypt_str(bytes(back[1])) == _OLD_URL


# ── restoring an archive taken before the drop ─────────────────────

pg_tools = pytest.mark.skipif(
    not all(shutil.which(tool) for tool in ("pg_dump", "pg_restore", "psql")),
    reason="needs the PostgreSQL client tools",
)

_PASSPHRASE = "drop-plaintext-forward-passphrase"


def _archive(dump: bytes, schema_version: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "manifest.json",
            json.dumps(
                {
                    "format": "spatiumddi-backup",
                    "format_version": 2,
                    "dump_format": "custom",
                    "schema_version": schema_version,
                }
            ),
        )
        zf.writestr("database.dump", dump)
        zf.writestr(
            "secrets.enc",
            encrypt_secrets(
                {
                    "platform_secret_key": settings.secret_key,
                    "platform_credential_encryption_key": settings.credential_encryption_key or "",
                },
                passphrase=_PASSPHRASE,
            ),
        )
    return buf.getvalue()


class _RequestSession:
    async def close(self) -> None:
        return None


@pytest.fixture
async def scratch_db() -> AsyncIterator[str]:
    dbname = f"spatiumddi_test_dropfwd_{uuid.uuid4().hex[:10]}"
    admin = await _admin()
    try:
        await admin.execute(f'CREATE DATABASE "{dbname}"')
    finally:
        await admin.close()
    url = _url_for(dbname)
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        yield url
    finally:
        await engine.dispose()
        admin = await _admin()
        try:
            await admin.execute(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)')
        finally:
            await admin.close()


async def _seed_pre_drop_archive(url: str, schema_version: str) -> bytes:
    """An archive of an install that still had the plaintext columns, with a
    value in each that never reached its encrypted column."""
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with AsyncSession(engine) as db:
            db.add_all(
                [
                    PlatformSettings(id=1),
                    AuditForwardTarget(name="archived", kind="webhook", enabled=True),
                ]
            )
            await db.commit()
    finally:
        await engine.dispose()
    conn = await asyncpg.connect(_dsn(url))
    try:
        await conn.execute(
            "CREATE TABLE alembic_version (version_num varchar(32) NOT NULL, "
            "CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))"
        )
        await conn.execute("INSERT INTO alembic_version VALUES ($1)", schema_version)
        for table, plain, _enc, sql_type in DROPPED_PLAINTEXT_SECRET_COLUMNS:
            await conn.execute(f"ALTER TABLE {table} ADD COLUMN {plain} {sql_type} DEFAULT ''")
        await conn.execute(
            "UPDATE audit_forward_target SET url = $1, auth_header = $2 WHERE name = 'archived'",
            _OLD_URL,
            _AUTH,
        )
        await conn.execute(
            "UPDATE platform_settings SET audit_forward_webhook_url = $1 WHERE id = 1", _GENERIC
        )
    finally:
        await conn.close()
    return _archive(await _pg_dump(url), schema_version)


async def _upgrade_in_place(url: str) -> None:
    """The install the archive is restored onto: already past the drop, with
    different data."""
    conn = await asyncpg.connect(_dsn(url))
    try:
        for table, plain, _enc, _type in DROPPED_PLAINTEXT_SECRET_COLUMNS:
            await conn.execute(f"ALTER TABLE {table} DROP COLUMN {plain}")
        await conn.execute("UPDATE alembic_version SET version_num = $1", _HEAD)
        await conn.execute("DELETE FROM audit_forward_target")
        await conn.execute("DELETE FROM platform_settings")
    finally:
        await conn.close()


async def _restored(url: str) -> dict[str, Any]:
    conn = await asyncpg.connect(_dsn(url))
    try:
        cols = {
            (r[0], r[1])
            for r in await conn.fetch(
                "SELECT table_name, column_name FROM information_schema.columns "
                "WHERE table_schema = 'public'"
            )
        }
        target = await conn.fetchrow(
            "SELECT url_encrypted, auth_header_encrypted FROM audit_forward_target "
            "WHERE name = 'archived'"
        )
        ps = await conn.fetchval(
            "SELECT audit_forward_webhook_url_encrypted FROM platform_settings WHERE id = 1"
        )
    finally:
        await conn.close()
    return {
        "leftover_columns": sorted(
            (t, p) for t, p, _e, _ty in DROPPED_PLAINTEXT_SECRET_COLUMNS if (t, p) in cols
        ),
        "target_url": decrypt_str(bytes(target[0])) if target and target[0] else None,
        "target_auth": decrypt_str(bytes(target[1])) if target and target[1] else None,
        "settings_url": decrypt_str(bytes(ps)) if ps else None,
    }


_EXPECTED = {
    "leftover_columns": [],
    "target_url": _OLD_URL,
    "target_auth": _AUTH,
    "settings_url": _GENERIC,
}


async def _restore(url: str, archive: bytes, monkeypatch, sections=None) -> Any:  # noqa: ANN001
    async def _no_safety_dump(_db: object) -> None:
        return None

    monkeypatch.setattr(restore, "_write_pre_restore_safety_dump", _no_safety_dump)
    return await restore.apply_backup_restore(
        _RequestSession(),
        archive_bytes=archive,
        passphrase=_PASSPHRASE,
        confirmation_phrase=restore.CONFIRM_PHRASE,
        db_url=url,
        sections=list(sections) if sections else None,
    )


@pg_tools
@pytest.mark.parametrize("archive_head", [_PREVIOUS_HEAD, _HEAD])
async def test_a_selective_restore_of_a_pre_drop_archive_loads_and_encrypts(
    scratch_db: str, monkeypatch: pytest.MonkeyPatch, archive_head: str
) -> None:
    """Without the re-added columns the archive's COPY names a column that no
    longer exists and the whole selective restore rolls back."""
    archive = await _seed_pre_drop_archive(scratch_db, archive_head)
    await _upgrade_in_place(scratch_db)

    outcome = await _restore(scratch_db, archive, monkeypatch, sections=("settings", "audit"))

    assert outcome.selective
    assert not [w for w in outcome.warnings if "Plaintext columns" in w], outcome.warnings
    assert await _restored(scratch_db) == _EXPECTED


@pg_tools
async def test_a_full_restore_of_a_pre_drop_archive_migrates_it(
    scratch_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = await _seed_pre_drop_archive(scratch_db, _PREVIOUS_HEAD)
    await _upgrade_in_place(scratch_db)

    outcome = await _restore(scratch_db, archive, monkeypatch)

    assert outcome.migration is not None
    assert outcome.migration.state == "upgraded", outcome.migration
    assert await _restored(scratch_db) == _EXPECTED
