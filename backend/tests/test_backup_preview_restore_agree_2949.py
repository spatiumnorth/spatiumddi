"""The restore card's verdict covers what the restore refuses (#2949).

The manifest preview said "recognised" for an archive whose manifest was
fine, and the console then enabled a Full restore the restore refuses
outright: no database dump, no ``secrets.enc``, a newer ``format_version``.
The preview now answers ``restorable`` / ``restore_refusal`` from the same
helpers the restore uses, so these tests build each archive and check the
preview and the real restore agree.
"""

from __future__ import annotations

import io
import json
import zipfile

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.services.backup.archive import BackupArchiveError, extract_archive_members
from app.services.backup.restore import BackupRestoreError, _apply_backup_restore_inner

_PASS = "correct horse battery"
_PHRASE = "RESTORE-FROM-BACKUP"


def _zip(manifest: dict, members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("manifest.json", json.dumps(manifest))
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


_BASE = {"format": "spatiumddi-backup", "format_version": 2}
_GOOD = {"database.dump": b"PGDMP", "secrets.enc": b"x"}

CASES = {
    "good": (_zip({**_BASE, "dump_format": "custom"}, _GOOD), True, None),
    "no_dump": (
        _zip(_BASE, {"secrets.enc": b"x"}),
        False,
        "neither database.dump nor database.sql",
    ),
    "declared_dump_missing": (
        _zip({**_BASE, "dump_format": "custom"}, {"secrets.enc": b"x"}),
        False,
        "member 'database.dump' is missing",
    ),
    "no_secrets": (
        _zip({**_BASE, "dump_format": "custom"}, {"database.dump": b"PGDMP"}),
        False,
        "secrets.enc",
    ),
    "newer_format": (
        _zip({**_BASE, "format_version": 3, "dump_format": "custom"}, _GOOD),
        False,
        "unsupported backup format_version: 3",
    ),
}


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username="p2949",
        email="p2949@example.com",
        display_name="p2949",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.mark.asyncio
@pytest.mark.parametrize("case", sorted(CASES))
async def test_preview_verdict_matches_the_restore(
    client: AsyncClient, db_session: AsyncSession, case: str
) -> None:
    data, restorable, reason = CASES[case]
    headers = await _superadmin(db_session)
    resp = await client.post(
        "/api/v1/backup/manifest-preview",
        headers=headers,
        files={"archive": ("a.zip", io.BytesIO(data), "application/zip")},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["restorable"] is restorable
    if restorable:
        assert body["restore_refusal"] is None
        return
    assert reason in body["restore_refusal"]
    # The restore's own answer is the same sentence.
    with pytest.raises((BackupArchiveError, BackupRestoreError)) as exc:
        await _apply_backup_restore_inner(
            db_session,
            archive_bytes=data,
            passphrase=_PASS,
            confirmation_phrase=_PHRASE,
            db_url="postgresql://unused",
        )
    assert str(exc.value) == body["restore_refusal"]


def test_extract_and_preview_share_the_member_rule() -> None:
    data, _, _ = CASES["no_dump"]
    with pytest.raises(BackupArchiveError, match="neither database.dump"):
        extract_archive_members(data)
