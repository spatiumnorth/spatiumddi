"""#1362 — whole-archive encryption: the database dump is sealed, not only secrets.enc."""

from __future__ import annotations

import io
import json
import os
import zipfile
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.backup import BackupTarget
from app.services.backup import archive as archive_mod
from app.services.backup import restore
from app.services.backup.archive import (
    build_backup_archive,
    extract_archive_members,
    manifest_preview_payload,
    open_dump_member,
)
from app.services.backup.crypto import (
    BackupCryptoError,
    DumpStreamEncryptor,
    decrypt_dump_stream,
    decrypt_secrets,
)
from tests.test_backup_target_update_bounds import _headers, _target

PASSPHRASE = "correct horse battery staple"
# Incompressible bytes, more than one chunk, with a marker that must not
# appear in the archive when it is encrypted.
MARKER = b"SUBNET-10.77.0.0-MARKER-"
DUMP = MARKER + os.urandom(2_500_000) + MARKER


@pytest.fixture(autouse=True)
def _fake_pg_dump(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _dump(out_path: Path, *, snapshot_id: str | None = None) -> None:
        out_path.write_bytes(DUMP)

    monkeypatch.setattr(archive_mod, "_run_pg_dump", _dump)


async def _build(db: AsyncSession, *, encrypt: bool, passphrase: str = PASSPHRASE) -> bytes:
    data, _name = await build_backup_archive(db, passphrase=passphrase, encrypt_archive=encrypt)
    return data


def _seal(plain: bytes, chunk: int = 1000) -> bytes:
    enc = DumpStreamEncryptor(PASSPHRASE, chunk_bytes=chunk)
    return enc.header() + enc.write(plain) + enc.finish()


@pytest.mark.asyncio
async def test_round_trip_encrypts_the_dump(db_session: AsyncSession) -> None:
    data = await _build(db_session, encrypt=True)
    assert MARKER not in data  # not in the zip as a stored or a deflated member either
    manifest, db_bytes, fmt, secrets_enc = extract_archive_members(data)
    assert manifest["format_version"] == 3
    assert manifest["archive_encryption"]["scope"] == "whole-archive"
    assert fmt == "custom"
    assert db_bytes != DUMP and MARKER not in db_bytes
    assert open_dump_member(manifest, db_bytes, PASSPHRASE) == DUMP
    assert decrypt_secrets(secrets_enc, passphrase=PASSPHRASE)  # same passphrase opens both
    preview = manifest_preview_payload(data)
    assert preview["archive_encrypted"] is True
    assert preview["restorable"] is True
    assert preview["selective_restore_supported"] is True


@pytest.mark.asyncio
async def test_wrong_passphrase_is_refused(db_session: AsyncSession) -> None:
    data = await _build(db_session, encrypt=True)
    manifest, db_bytes, _fmt, _s = extract_archive_members(data)
    with pytest.raises(BackupCryptoError, match="passphrase mismatch"):
        open_dump_member(manifest, db_bytes, "not the passphrase")


@pytest.mark.asyncio
async def test_a_manifest_stripped_of_its_flag_still_does_not_reach_pg_restore(
    db_session: AsyncSession,
) -> None:
    data = await _build(db_session, encrypt=True)
    manifest, db_bytes, _fmt, _s = extract_archive_members(data)
    manifest.pop("archive_encryption")
    assert open_dump_member(manifest, db_bytes, PASSPHRASE) == DUMP
    with pytest.raises(BackupCryptoError):
        open_dump_member(manifest, db_bytes, "wrong passphrase")


@pytest.mark.asyncio
async def test_legacy_archive_still_restores(db_session: AsyncSession) -> None:
    data = await _build(db_session, encrypt=False)
    manifest, db_bytes, fmt, _s = extract_archive_members(data)
    assert manifest["format_version"] == 2
    assert "archive_encryption" not in manifest
    assert db_bytes == DUMP and fmt == "custom"
    assert open_dump_member(manifest, db_bytes, PASSPHRASE) == DUMP
    assert manifest_preview_payload(data)["archive_encrypted"] is False


@pytest.mark.asyncio
async def test_tampered_archive_is_refused(db_session: AsyncSession) -> None:
    data = await _build(db_session, encrypt=True)
    manifest, db_bytes, _fmt, _s = extract_archive_members(data)
    flipped = bytearray(db_bytes)
    flipped[len(flipped) // 2] ^= 0x01
    with pytest.raises(BackupCryptoError):
        open_dump_member(manifest, bytes(flipped), PASSPHRASE)


def test_stream_tampering_truncation_and_reordering_are_refused() -> None:
    plain = os.urandom(5000)
    sealed = _seal(plain)
    assert decrypt_dump_stream(sealed, passphrase=PASSPHRASE, max_bytes=10**6) == plain

    flipped = bytearray(sealed)
    flipped[-5] ^= 0xFF
    with pytest.raises(BackupCryptoError):
        decrypt_dump_stream(bytes(flipped), passphrase=PASSPHRASE, max_bytes=10**6)

    # Cut at a chunk boundary: every remaining chunk is intact, the final one is gone.
    header_len = 8 + 1 + 4 + 16 + 4 + 4
    first_len = int.from_bytes(sealed[header_len : header_len + 4], "big")
    cut = sealed[: header_len + 4 + first_len]
    with pytest.raises(BackupCryptoError):
        decrypt_dump_stream(cut, passphrase=PASSPHRASE, max_bytes=10**6)

    # Header edited (chunk size): bound into every chunk's AAD.
    edited = bytearray(sealed)
    edited[header_len - 1] ^= 0x01
    with pytest.raises(BackupCryptoError):
        decrypt_dump_stream(bytes(edited), passphrase=PASSPHRASE, max_bytes=10**6)

    with pytest.raises(BackupCryptoError):
        decrypt_dump_stream(sealed + b"\x00" * 3, passphrase=PASSPHRASE, max_bytes=10**6)


def test_inflated_size_is_capped() -> None:
    sealed = _seal(b"\x00" * 1_000_000)
    with pytest.raises(BackupCryptoError, match="size cap"):
        decrypt_dump_stream(sealed, passphrase=PASSPHRASE, max_bytes=10_000)


@pytest.mark.asyncio
async def test_restore_refuses_a_wrong_passphrase_before_any_destructive_step(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = await _build(db_session, encrypt=True)
    calls: list[str] = []

    async def _safety(_db):  # pragma: no cover — tripwire
        calls.append("safety")

    monkeypatch.setattr(restore, "_write_pre_restore_safety_dump", _safety)
    with pytest.raises(restore.BackupRestoreError, match="passphrase mismatch"):
        await restore._apply_backup_restore_inner(
            db_session,
            archive_bytes=data,
            passphrase="some other passphrase",
            confirmation_phrase=restore.CONFIRM_PHRASE,
            db_url="postgresql+asyncpg://u:p@h:5432/db",
        )
    assert calls == []


@pytest.mark.asyncio
async def test_restore_replays_the_decrypted_dump(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = await _build(db_session, encrypt=True)
    seen: dict[str, bytes] = {}

    async def _stop(_db):
        # The dump handed on is the plaintext; stop here, nothing destructive ran.
        raise restore.BackupRestoreError("stop")

    real_open = restore.open_dump_member

    def _spy(manifest, db_bytes, passphrase):
        seen["dump"] = real_open(manifest, db_bytes, passphrase)
        return seen["dump"]

    monkeypatch.setattr(restore, "open_dump_member", _spy)
    monkeypatch.setattr(restore, "_write_pre_restore_safety_dump", _stop)
    with pytest.raises(restore.BackupRestoreError, match="stop"):
        await restore._apply_backup_restore_inner(
            db_session,
            archive_bytes=data,
            passphrase=PASSPHRASE,
            confirmation_phrase=restore.CONFIRM_PHRASE,
            db_url="postgresql+asyncpg://u:p@h:5432/db",
            allow_newer_schema=True,
        )
    assert seen["dump"] == DUMP


@pytest.mark.asyncio
async def test_new_target_defaults_to_unencrypted_and_changes_are_audited(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    res = await client.post(
        "/api/v1/backup/targets",
        json={
            "name": "enc-default",
            "kind": "local_volume",
            "config": {"path": "/var/lib/spatiumddi/backups"},
            "passphrase": PASSPHRASE,
        },
        headers=headers,
    )
    assert res.status_code in (200, 201), res.text
    body = res.json()
    assert body["encrypt_archive"] is False

    res = await client.post(
        "/api/v1/backup/targets",
        json={
            "name": "enc-explicit",
            "kind": "local_volume",
            "config": {"path": "/var/lib/spatiumddi/backups"},
            "passphrase": PASSPHRASE,
            "encrypt_archive": True,
        },
        headers=headers,
    )
    assert res.status_code in (200, 201), res.text
    assert res.json()["encrypt_archive"] is True

    res = await client.patch(
        f"/api/v1/backup/targets/{body['id']}", json={"encrypt_archive": True}, headers=headers
    )
    assert res.status_code == 200, res.text
    assert res.json()["encrypt_archive"] is True
    rows = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_type == "backup_target", AuditLog.action == "update"
            )
        )
    ).scalars()
    (row,) = list(rows)
    assert row.changed_fields == ["encrypt_archive"]
    assert row.old_value == {"encrypt_archive": False}
    assert PASSPHRASE not in json.dumps(row.new_value)


@pytest.mark.asyncio
async def test_existing_target_row_is_unencrypted(db_session: AsyncSession) -> None:
    t = await _target(db_session, "azure_blob", {"container": "c"})
    assert isinstance(t, BackupTarget) and t.encrypt_archive is False


def test_zip_member_is_stored_ciphertext() -> None:
    # The member is a real zip entry a stock tool can list.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        archive_mod._write_encrypted_member(zf, _tmp(DUMP[:5000]), "database.dump", PASSPHRASE)
    with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
        assert zf.getinfo("database.dump").compress_type == zipfile.ZIP_STORED


def _tmp(data: bytes) -> Path:
    import tempfile

    p = Path(tempfile.mkdtemp()) / "d"
    p.write_bytes(data)
    return p
