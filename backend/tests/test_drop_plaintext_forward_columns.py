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

import asyncio
import importlib.util
import io
import json
import os
import pathlib
import re
import shutil
import uuid
import zipfile
from collections.abc import AsyncIterator
from typing import Any

import asyncpg
import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.config import settings
from app.core.crypto import decrypt_str, encrypt_str
from app.models.audit_forward import AuditForwardTarget
from app.models.base import Base
from app.models.settings import PlatformSettings
from app.services.backup import migrations, restore
from app.services.backup.archive import _pg_env_from_url
from app.services.backup.crypto import encrypt_secrets
from app.services.backup.legacy_columns import (
    DROPPED_PLAINTEXT_SECRET_COLUMNS,
    FOLDED_DISABLED_REASON,
)
from tests.test_selective_restore_app_role_1693 import _admin, _dsn, _pg_dump, _url_for

_MIGRATION = (
    pathlib.Path(__file__).resolve().parents[1]
    / "alembic"
    / "versions"
    / "c2b203844c95_drop_plaintext_forward_webhook_columns.py"
)
# The contract migration and the revision it follows. Neither is assumed to be
# the head: migrations land after this one, and a test that equates "the drop"
# with "head" fails the moment one does (see ``_local_head``).
_BEFORE_DROP = "c8d3a1f47e92"
_DROP = "c2b203844c95"

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


def test_the_migration_follows_the_revision_it_was_written_against() -> None:
    assert _load_migration().down_revision == _BEFORE_DROP


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
        auth_header_encrypted=encrypt_str("Bearer already-encrypted"),
    )
    blanked = AuditForwardTarget(
        name=f"b-{uuid.uuid4().hex[:6]}", kind="webhook", url_encrypted=b""
    )
    for row in (plaintext_only, already, blanked):
        row.enabled = True
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
            "audit_forward_webhook_url_encrypted = NULL, "
            "audit_forward_webhook_enabled = true WHERE id = 1"
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

    # A target the fold wrote into is left disabled; one that already had a
    # ciphertext is untouched and stays enabled.
    async def _enabled(row_id: uuid.UUID) -> bool:
        return bool(
            (
                await db_session.execute(
                    text("SELECT enabled FROM audit_forward_target WHERE id = :id"),
                    {"id": row_id},
                )
            ).scalar_one()
        )

    assert await _enabled(plaintext_only.id) is False
    assert await _enabled(blanked.id) is False
    assert await _enabled(already.id) is True
    assert (
        await db_session.execute(
            text("SELECT audit_forward_webhook_enabled FROM platform_settings WHERE id = 1")
        )
    ).scalar_one() is False

    # Each target left disabled has an audit row saying so; the one with a
    # ciphertext already present has none.
    recorded = (
        await db_session.execute(
            text(
                "SELECT resource_type, resource_id, COALESCE(new_value->>'enabled', "
                "new_value->>'audit_forward_webhook_enabled') FROM audit_log "
                "WHERE new_value->>'reason' = :r"
            ),
            {"r": FOLDED_DISABLED_REASON},
        )
    ).all()
    assert sorted((r[0], r[1], r[2]) for r in recorded) == sorted(
        [
            ("audit_forward_target", str(plaintext_only.id), "false"),
            ("audit_forward_target", str(blanked.id), "false"),
            ("platform_settings", "1", "false"),
        ]
    )

    # A second run is a no-op, not an error.
    await conn.run_sync(_run("upgrade"))
    # ...so a target re-enabled after the first run stays enabled.
    await db_session.execute(
        text("UPDATE audit_forward_target SET enabled = true WHERE id = :id"),
        {"id": plaintext_only.id},
    )
    await conn.run_sync(_run("upgrade"))
    assert await _enabled(plaintext_only.id) is True

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
_ENCRYPTED_URL_CT = encrypt_str(_NEW_URL)
_ENCRYPTED_AUTH_CT = encrypt_str("Bearer already-encrypted")


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


def _local_head() -> str:
    """This build's head, read from the alembic script directory the restore
    itself reads (``migrations._alembic_ini``), never assumed to be the drop."""
    head = migrations._local_head()  # noqa: SLF001
    assert head is not None, "the alembic script directory has no single head"
    return head


def _alembic_env(url: str) -> dict[str, str]:
    pg_env, _dbname = _pg_env_from_url(url)
    return {**os.environ, **pg_env, "DATABASE_URL": url}


async def _alembic(url: str, *args: str) -> None:
    """``alembic`` against ``url``, through the ini the restore uses."""
    proc = await asyncio.create_subprocess_exec(
        "alembic",
        "-c",
        str(migrations._alembic_ini() or "alembic.ini"),  # noqa: SLF001
        *args,
        env=_alembic_env(url),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate()
    assert proc.returncode == 0, (err or out).decode(errors="replace")[-3000:]


@pytest.fixture
async def pre_drop_db() -> AsyncIterator[str]:
    """A database migrated by the REAL migrations to the revision before the
    drop — the schema an archive taken on that build actually has.

    Not ``Base.metadata.create_all`` relabelled with an older revision: that
    schema already carries every object a migration after the drop creates,
    so the post-restore upgrade collides with the first of them and the
    restore reports ``auto_recovered`` — a fixture artefact, and one that
    appears only once a migration lands after the drop.
    """
    dbname = f"spatiumddi_test_predrop_{uuid.uuid4().hex[:10]}"
    admin = await _admin()
    try:
        await admin.execute(f'CREATE DATABASE "{dbname}"')
    finally:
        await admin.close()
    url = _url_for(dbname)
    try:
        await _alembic(url, "upgrade", _BEFORE_DROP)
        yield url
    finally:
        admin = await _admin()
        try:
            await admin.execute(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)')
        finally:
            await admin.close()


async def _seed_migrated_pre_drop_archive(url: str) -> bytes:
    """The archive of a real install at ``_BEFORE_DROP``: the plaintext
    columns exist because the migrations put them there, and hold a value
    that never reached its encrypted column. Raw SQL, because the models
    describe head, not this schema."""
    conn = await asyncpg.connect(_dsn(url))
    try:
        assert await conn.fetchval("SELECT version_num FROM alembic_version") == _BEFORE_DROP
        await conn.execute(
            "INSERT INTO platform_settings (id, audit_forward_webhook_enabled, "
            "audit_forward_webhook_url) VALUES (1, true, $1)",
            _GENERIC,
        )
        await conn.execute(
            "INSERT INTO audit_forward_target (name, kind, enabled, url, auth_header) "
            "VALUES ('archived', 'webhook', true, $1, $2)",
            _OLD_URL,
            _AUTH,
        )
        await conn.execute(
            "INSERT INTO audit_forward_target (name, kind, enabled, url, auth_header, "
            "url_encrypted, auth_header_encrypted) "
            "VALUES ('encrypted', 'webhook', true, $1, $2, $3, $4)",
            _OLD_URL,
            _AUTH,
            _ENCRYPTED_URL_CT,
            _ENCRYPTED_AUTH_CT,
        )
    finally:
        await conn.close()
    return _archive(await _pg_dump(url), _BEFORE_DROP)


async def _schema_version(url: str) -> str | None:
    conn = await asyncpg.connect(_dsn(url))
    try:
        return await conn.fetchval("SELECT version_num FROM alembic_version")
    finally:
        await conn.close()


async def _seed_pre_drop_archive(url: str, schema_version: str) -> bytes:
    """An archive of an install that still had the plaintext columns, with a
    value in each that never reached its encrypted column."""
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with AsyncSession(engine) as db:
            db.add_all(
                [
                    PlatformSettings(id=1, audit_forward_webhook_enabled=True),
                    AuditForwardTarget(name="archived", kind="webhook", enabled=True),
                    # Already encrypted, with an older plaintext copy beside it.
                    AuditForwardTarget(
                        name="encrypted",
                        kind="webhook",
                        enabled=True,
                        url_encrypted=_ENCRYPTED_URL_CT,
                        auth_header_encrypted=_ENCRYPTED_AUTH_CT,
                    ),
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
            "UPDATE audit_forward_target SET url = $1, auth_header = $2 "
            "WHERE name IN ('archived', 'encrypted')",
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
    """The install the archive is restored onto: at this build's head (past
    the drop), with different data."""
    conn = await asyncpg.connect(_dsn(url))
    try:
        for table, plain, _enc, _type in DROPPED_PLAINTEXT_SECRET_COLUMNS:
            await conn.execute(f"ALTER TABLE {table} DROP COLUMN IF EXISTS {plain}")
        await conn.execute(
            "CREATE TABLE IF NOT EXISTS alembic_version (version_num varchar(32) NOT NULL, "
            "CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))"
        )
        await conn.execute("DELETE FROM alembic_version")
        await conn.execute("INSERT INTO alembic_version VALUES ($1)", _local_head())
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
@pytest.mark.parametrize("archive_head", [_BEFORE_DROP, _DROP])
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
    pre_drop_db: str, scratch_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The upgrade step runs the drop and EVERY migration after it, to this
    build's head, whatever that is — and the schema it leaves is head's."""
    archive = await _seed_migrated_pre_drop_archive(pre_drop_db)
    await _upgrade_in_place(scratch_db)
    head = _local_head()

    outcome = await _restore(scratch_db, archive, monkeypatch)

    assert outcome.migration is not None
    assert outcome.migration.state == "upgraded", outcome.migration
    assert outcome.migration.local_head == head
    applied = outcome.migration.migrations_applied
    assert applied[0] == _DROP and applied[-1] == head, applied
    assert await _schema_version(scratch_db) == head
    verdict = await migrations._verify_schema_at_head(scratch_db)  # noqa: SLF001
    assert verdict.ok, verdict
    assert await _restored(scratch_db) == _EXPECTED


_SYNTHETIC = "ffff0000restoreguard"
_SYNTHETIC_TABLE = "zz_restore_later_migration_guard"


def _alembic_tree_ending_after_the_drop(tmp_path: pathlib.Path) -> pathlib.Path:
    """An alembic tree holding the real chain up to the drop and one synthetic
    migration after it, which creates a table no model declares. Returns its
    ini. Built here, not committed, so the drop is never the head of it —
    whatever ``main`` happens to carry."""
    backend = pathlib.Path(__file__).resolve().parents[1]
    real_ini = migrations._alembic_ini()  # noqa: SLF001
    assert real_ini is not None
    script = ScriptDirectory.from_config(Config(str(real_ini)))
    tree = tmp_path / "alembic"
    versions = tree / "versions"
    versions.mkdir(parents=True)
    for name in ("env.py", "script.py.mako"):
        shutil.copy(backend / "alembic" / name, tree / name)
    for rev in script.iterate_revisions(_DROP, "base"):
        shutil.copy(rev.path, versions / pathlib.Path(rev.path).name)
    (versions / f"{_SYNTHETIC}_guard.py").write_text(
        f'''"""synthetic: a migration after the drop (test only)

Revision ID: {_SYNTHETIC}
Revises: {_DROP}
"""
import sqlalchemy as sa
from alembic import op

revision = "{_SYNTHETIC}"
down_revision = "{_DROP}"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("{_SYNTHETIC_TABLE}", sa.Column("id", sa.Integer, primary_key=True))


def downgrade() -> None:
    op.drop_table("{_SYNTHETIC_TABLE}")
'''
    )
    ini = tmp_path / "alembic.ini"
    text_ = real_ini.read_text()
    text_ = re.sub(r"(?m)^script_location\s*=.*$", f"script_location = {tree}", text_)
    text_ = re.sub(r"(?m)^prepend_sys_path\s*=.*$", f"prepend_sys_path = {backend}", text_)
    ini.write_text(text_)
    return ini


@pg_tools
async def test_a_full_restore_runs_the_migrations_after_the_drop(
    pre_drop_db: str, scratch_db: str, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """With a migration after the drop, the restore must run the drop AND it
    and report ``upgraded`` — not stop on a collision and stamp head. Holds
    even while the drop is ``main``'s head, so the full-restore test above
    cannot pass only because nothing follows it."""
    ini = _alembic_tree_ending_after_the_drop(tmp_path)
    monkeypatch.setattr(migrations, "_alembic_ini", lambda: ini)
    assert _local_head() == _SYNTHETIC

    archive = await _seed_migrated_pre_drop_archive(pre_drop_db)
    await _upgrade_in_place(scratch_db)

    outcome = await _restore(scratch_db, archive, monkeypatch)

    assert outcome.migration is not None
    assert outcome.migration.state == "upgraded", outcome.migration
    assert outcome.migration.migrations_applied == [_DROP, _SYNTHETIC]
    assert await _schema_version(scratch_db) == _SYNTHETIC
    conn = await asyncpg.connect(_dsn(scratch_db))
    try:
        assert await conn.fetchval("SELECT to_regclass($1) IS NOT NULL", _SYNTHETIC_TABLE)
    finally:
        await conn.close()
    assert await _restored(scratch_db) == _EXPECTED


async def _enabled_state(url: str) -> dict[str, Any]:
    conn = await asyncpg.connect(_dsn(url))
    try:
        targets = {
            r["name"]: (r["enabled"], bytes(r["url_encrypted"]), bytes(r["auth_header_encrypted"]))
            for r in await conn.fetch(
                "SELECT name, enabled, url_encrypted, auth_header_encrypted "
                "FROM audit_forward_target"
            )
        }
        settings_enabled = await conn.fetchval(
            "SELECT audit_forward_webhook_enabled FROM platform_settings WHERE id = 1"
        )
        audit = [
            (r["resource_type"], r["resource_display"], r["source"])
            for r in await conn.fetch(
                "SELECT resource_type, resource_display, new_value->>'source' AS source "
                "FROM audit_log WHERE new_value->>'reason' = $1",
                FOLDED_DISABLED_REASON,
            )
        ]
    finally:
        await conn.close()
    return {"targets": targets, "settings_enabled": settings_enabled, "audit": sorted(audit)}


@pg_tools
@pytest.mark.parametrize(
    ("archive_head", "folded_by"),
    [
        # The archive's schema is past the drop yet carries the columns, so
        # the upgrade step runs nothing and the restore's own fold does it.
        (_DROP, "backup_restore"),
        # The upgrade step runs the contract migration over the archive.
        (_BEFORE_DROP, f"schema upgrade {_DROP}"),
    ],
)
async def test_a_selective_restore_leaves_a_target_filled_from_plaintext_disabled(
    scratch_db: str, monkeypatch: pytest.MonkeyPatch, archive_head: str, folded_by: str
) -> None:
    """The archive's target and Settings webhook were enabled with only a
    plaintext URL and header (unconfigured on that build); the destination
    has them cleared. Restoring the archive fills them from the plaintext and
    must leave them disabled, with an audit row, as the upgrade does."""
    archive = await _seed_pre_drop_archive(scratch_db, archive_head)
    await _upgrade_in_place(scratch_db)

    outcome = await _restore(scratch_db, archive, monkeypatch, sections=("settings", "audit"))

    assert outcome.selective
    assert await _restored(scratch_db) == _EXPECTED
    state = await _enabled_state(scratch_db)
    assert state["targets"]["archived"][0] is False
    assert state["settings_enabled"] is False
    # A target whose ciphertext was already there keeps its enabled state and
    # its ciphertext, byte for byte.
    assert state["targets"]["encrypted"] == (True, _ENCRYPTED_URL_CT, _ENCRYPTED_AUTH_CT)
    assert state["audit"] == [
        ("audit_forward_target", "archived", folded_by),
        ("platform_settings", "Settings webhook", folded_by),
    ]
    disabled_notes = [w for w in outcome.warnings if "left disabled" in w]
    assert len(disabled_notes) == 1, outcome.warnings
    assert "archived" in disabled_notes[0] and "Settings webhook" in disabled_notes[0]
    assert "encrypted" not in disabled_notes[0].split(":", 1)[1]


@pg_tools
async def test_a_full_restore_of_a_pre_drop_archive_leaves_folded_targets_disabled(
    pre_drop_db: str, scratch_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The full restore's upgrade runs the migration, which records the same
    audit rows."""
    archive = await _seed_migrated_pre_drop_archive(pre_drop_db)
    await _upgrade_in_place(scratch_db)

    outcome = await _restore(scratch_db, archive, monkeypatch)

    assert [w for w in outcome.warnings if "left disabled" in w and "archived" in w]
    state = await _enabled_state(scratch_db)
    assert state["targets"]["archived"][0] is False
    assert state["settings_enabled"] is False
    assert state["targets"]["encrypted"] == (True, _ENCRYPTED_URL_CT, _ENCRYPTED_AUTH_CT)
    assert state["audit"] == [
        ("audit_forward_target", "archived", f"schema upgrade {_DROP}"),
        ("platform_settings", "Settings webhook", f"schema upgrade {_DROP}"),
    ]
