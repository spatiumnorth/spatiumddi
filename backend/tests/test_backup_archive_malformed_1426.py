"""#1426 — a damaged or foreign backup archive is refused as malformed, never a 500.

``extract_archive_members`` (restore, the restore drill) and
``read_backup_manifest`` (the restore pre-flight) caught only ``BadZipFile``
and ``JSONDecodeError``. A ``database.dump`` corrupt inside its first deflate
block raised ``zlib.error`` from ``zipfile``, which escaped
``POST /backup/restore`` as a bare 500 instead of the 400 "archive is
malformed" every other damaged archive gets. The same held for the other ways
a zip member fails to decode: a corrupt bzip2 or LZMA member, an unsupported
compression method, an encrypted member, a manifest that is not UTF-8.
"""

from __future__ import annotations

import io
import json
import struct
import uuid
import zipfile
from collections.abc import Callable

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.services.backup.archive import (
    BackupArchiveError,
    extract_archive_members,
    read_backup_manifest,
)

MANIFEST = json.dumps({"format_version": 2, "dump_format": "custom"}).encode()
DUMP = b"".join(b"COPY public.subnet row %d\n" % i for i in range(3000))


def _archive(*, manifest: bytes = MANIFEST, dump_method: int = zipfile.ZIP_DEFLATED) -> bytes:
    """A backup archive's members, as ``build_backup_archive`` lays them out."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(zipfile.ZipInfo("manifest.json"), manifest, zipfile.ZIP_DEFLATED)
        zf.writestr(zipfile.ZipInfo("database.dump"), DUMP, dump_method)
        zf.writestr(zipfile.ZipInfo("secrets.enc"), b"s" * 64, zipfile.ZIP_DEFLATED)
    return buf.getvalue()


def _data_offset(archive: bytes, member: str) -> int:
    """Where ``member``'s compressed bytes start."""
    info = zipfile.ZipFile(io.BytesIO(archive)).getinfo(member)
    name_len, extra_len = struct.unpack_from("<HH", archive, info.header_offset + 26)
    return info.header_offset + 30 + name_len + extra_len


def _damage(archive: bytes, member: str, at: int, data: bytes) -> bytes:
    buf = bytearray(archive)
    start = _data_offset(archive, member) + at
    buf[start : start + len(data)] = data
    return bytes(buf)


def _central(archive: bytes, member: str, *, flag_or: int = 0, method: int | None = None) -> bytes:
    """Rewrite ``member``'s central-directory entry, the one zipfile trusts."""
    buf = bytearray(archive)
    pos = struct.unpack_from("<I", buf, buf.rfind(b"PK\x05\x06") + 16)[0]
    while buf[pos : pos + 4] == b"PK\x01\x02":
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", buf, pos + 28)
        if bytes(buf[pos + 46 : pos + 46 + name_len]).decode() == member:
            flags = struct.unpack_from("<H", buf, pos + 8)[0]
            struct.pack_into("<H", buf, pos + 8, flags | flag_or)
            if method is not None:
                struct.pack_into("<H", buf, pos + 10, method)
            return bytes(buf)
        pos += 46 + name_len + extra_len + comment_len
    raise KeyError(member)


# A first deflate byte with BTYPE=11, the reserved block type: what the
# issue's flipped bytes in the dump's first deflate block amount to.
_BAD_BLOCK = b"\x07"

DAMAGED: dict[str, Callable[[], bytes]] = {
    "dump-first-deflate-block": lambda: _damage(_archive(), "database.dump", 0, _BAD_BLOCK),
    "manifest-first-deflate-block": lambda: _damage(_archive(), "manifest.json", 0, _BAD_BLOCK),
    "dump-bzip2-corrupt": lambda: _damage(
        _archive(dump_method=zipfile.ZIP_BZIP2), "database.dump", 20, b"\xff" * 16
    ),
    "dump-lzma-corrupt": lambda: _damage(
        _archive(dump_method=zipfile.ZIP_LZMA), "database.dump", 20, b"\xff" * 16
    ),
    "dump-unknown-compression": lambda: _central(_archive(), "database.dump", method=99),
    "dump-encrypted": lambda: _central(_archive(), "database.dump", flag_or=0x1),
    "manifest-encrypted": lambda: _central(_archive(), "manifest.json", flag_or=0x1),
    "manifest-unknown-compression": lambda: _central(_archive(), "manifest.json", method=99),
    "manifest-not-utf8": lambda: _archive(manifest=b"\xff\xfe{}"),
}
# The pre-flight reads only manifest.json, so only its damage reaches it.
MANIFEST_DAMAGED = [k for k in DAMAGED if k.startswith("manifest-")]


def test_an_undamaged_archive_reads() -> None:
    manifest, db_bytes, dump_format, secrets_enc = extract_archive_members(_archive())
    assert (manifest["dump_format"], db_bytes, dump_format, secrets_enc) == (
        "custom",
        DUMP,
        "custom",
        b"s" * 64,
    )
    assert read_backup_manifest(_archive())["format_version"] == 2


@pytest.mark.parametrize("damage", list(DAMAGED))
def test_extract_refuses_a_damaged_archive_as_malformed(damage: str) -> None:
    with pytest.raises(BackupArchiveError, match="^archive is malformed: "):
        extract_archive_members(DAMAGED[damage]())


@pytest.mark.parametrize("damage", MANIFEST_DAMAGED)
def test_the_preflight_refuses_a_damaged_manifest_as_malformed(damage: str) -> None:
    with pytest.raises(BackupArchiveError, match="^archive is malformed: "):
        read_backup_manifest(DAMAGED[damage]())


@pytest.mark.asyncio
async def test_restore_answers_400_for_a_dump_corrupt_in_its_first_deflate_block(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The issue's case over the API: 400 with the reason, not a 500. The
    archive is refused before anything is applied (and before the passphrase
    is even checked)."""
    admin = User(
        username=f"bk-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="bk",
        hashed_password=hash_password("x" * 12),
        is_superadmin=True,
    )
    db_session.add(admin)
    await db_session.commit()

    resp = await client.post(
        "/api/v1/backup/restore",
        headers={"Authorization": f"Bearer {create_access_token(str(admin.id))}"},
        files={"archive": ("backup.zip", DAMAGED["dump-first-deflate-block"](), "application/zip")},
        data={"passphrase": "not-the-passphrase", "confirmation_phrase": "RESTORE-FROM-BACKUP"},
    )

    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"].startswith("archive is malformed: "), resp.text


@pytest.mark.asyncio
async def test_the_restore_drill_reports_a_damaged_archive_as_unreadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The drill's ``archive_readable`` check fails with the reason; the
    decompression error used to raise out of the run instead."""
    from app.models.backup import BackupTarget
    from app.services.backup import drill as drill_mod
    from tests.test_restore_drills import _FakeDriver, _wire_drill

    _wire_drill(
        monkeypatch,
        assertions=[],
        driver=_FakeDriver(payload=DAMAGED["dump-first-deflate-block"]()),
    )
    # The real reader, not the stub _wire_drill installs: it is what is under test.
    monkeypatch.setattr(drill_mod, "extract_archive_members", extract_archive_members)
    target = BackupTarget(name="t", kind="local_volume", config={}, passphrase_encrypted=b"x")

    outcome = await drill_mod._execute(target, live_db_url="postgresql+asyncpg://u:p@h:5432/live")

    readable = {a.name: a for a in outcome.assertions}["archive_readable"]
    assert outcome.state == "failed"
    assert readable.status == drill_mod.FAIL
    assert readable.detail.startswith("archive is malformed: "), readable.detail
