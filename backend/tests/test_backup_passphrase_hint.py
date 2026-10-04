"""A passphrase hint that contains the passphrase is refused.

The hint is written in clear into ``manifest.json`` and the
``secrets.enc`` header of every archive — on purpose, so archives can be
told apart without the passphrase. The form puts the hint field directly
under the passphrase field, and nothing stopped the passphrase landing in
it: every archive then carried its own key next to the ciphertext, and the
update path copied it into the append-only audit log.

The tests that matter:

* every write path answers 422 and stores nothing (the audit log is the
  part that cannot be undone);
* a PATCH that changes only ONE half of the pair is still checked against
  the stored other half — the form re-sends the hint on every save;
* a target saved before the check existed keeps backing up, with the
  hint dropped from both places it would have been written.
"""

from __future__ import annotations

import importlib
import io
import json
import zipfile
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.backup import BackupTarget
from app.services.backup import archive as archive_mod
from app.services.backup.crypto import (
    HINT_REVEALS_PASSPHRASE,
    decrypt_secrets,
    encrypt_secrets,
    hint_reveals_passphrase,
)

_PASS = "Correct-Horse-Battery-9"

# ── the predicate ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "hint",
    [_PASS, f"vault: {_PASS}", _PASS.upper(), f"  {_PASS.lower()}  "],
    ids=["equal", "embedded", "re-cased", "padded"],
)
def test_a_hint_containing_the_passphrase_reveals_it(hint: str):
    assert hint_reveals_passphrase(_PASS, hint)


@pytest.mark.parametrize(
    "hint",
    ["", None, "password manager: backup NAS", "Correct-Horse", "battery"],
    ids=["empty", "none", "label", "prefix-only", "shared-word"],
)
def test_an_ordinary_hint_does_not(hint: str | None):
    # A hint may share words with the passphrase; only the whole
    # passphrase inside it gives the archive away.
    assert not hint_reveals_passphrase(_PASS, hint)


def test_no_passphrase_means_nothing_to_reveal():
    assert not hint_reveals_passphrase(None, _PASS)
    assert not hint_reveals_passphrase("", _PASS)


# ── the envelope and the manifest ─────────────────────────────────────


def test_envelope_drops_a_revealing_hint_but_still_encrypts():
    env = json.loads(encrypt_secrets({"k": "v"}, passphrase=_PASS, hint=f"pw={_PASS}"))
    assert env["hint"] == ""
    assert _PASS.casefold() not in json.dumps(env).casefold()
    assert decrypt_secrets(json.dumps(env).encode(), passphrase=_PASS) == {"k": "v"}


def test_envelope_keeps_an_ordinary_hint():
    env = json.loads(encrypt_secrets({"k": "v"}, passphrase=_PASS, hint="vault entry 7"))
    assert env["hint"] == "vault entry 7"


@pytest.fixture
def no_pg_dump(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _head(_db) -> str:
        return "head"

    async def _dump(path: Path) -> None:
        path.write_bytes(b"PGDMP-stub")

    monkeypatch.setattr(archive_mod, "_read_alembic_head", _head)
    monkeypatch.setattr(archive_mod, "_run_pg_dump", _dump)


@pytest.mark.asyncio
async def test_archive_of_a_legacy_target_carries_no_hint_anywhere(no_pg_dump: None):
    """A row saved before the API refused this must keep producing
    backups — but neither member that would carry the hint may carry it."""
    data, _name = await archive_mod.build_backup_archive(
        None, passphrase=_PASS, passphrase_hint=_PASS  # type: ignore[arg-type]
    )
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        manifest = json.loads(zf.read("manifest.json"))
        envelope = json.loads(zf.read("secrets.enc"))
        readme = zf.read("README.txt").decode()
    assert manifest["secret_passphrase_hint"] == ""
    assert envelope["hint"] == ""
    assert _PASS not in readme
    assert decrypt_secrets(json.dumps(envelope).encode(), passphrase=_PASS)


@pytest.mark.asyncio
async def test_archive_keeps_an_ordinary_hint(no_pg_dump: None):
    data, _name = await archive_mod.build_backup_archive(
        None, passphrase=_PASS, passphrase_hint="vault entry 7"  # type: ignore[arg-type]
    )
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        assert json.loads(zf.read("manifest.json"))["secret_passphrase_hint"] == "vault entry 7"
        assert json.loads(zf.read("secrets.enc"))["hint"] == "vault entry 7"


# ── API ───────────────────────────────────────────────────────────────


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username="hintcheck",
        email="hintcheck@example.com",
        display_name="hintcheck",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _target(db: AsyncSession, *, hint: str = "") -> BackupTarget:
    target = BackupTarget(
        name="nas",
        description="",
        kind="webdav",
        enabled=True,
        config={"url": "https://192.0.2.1/dav", "username": "u", "password": "p"},
        passphrase_encrypted=encrypt_str(_PASS),
        passphrase_hint=hint,
    )
    db.add(target)
    await db.flush()
    return target


async def _audit_rows(db: AsyncSession) -> int:
    return (
        await db.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.resource_type == "backup_target")
        )
    ).scalar_one()


@pytest.mark.asyncio
async def test_create_refuses_a_revealing_hint(client: AsyncClient, db_session: AsyncSession):
    headers = await _superadmin(db_session)
    res = await client.post(
        "/api/v1/backup/targets",
        headers=headers,
        json={
            "name": "nas",
            "kind": "webdav",
            "config": {"url": "https://192.0.2.1/dav", "username": "u", "password": "p"},
            "passphrase": _PASS,
            "passphrase_hint": _PASS,
        },
    )
    assert res.status_code == 422, res.text
    assert res.json()["detail"] == HINT_REVEALS_PASSPHRASE
    assert _PASS not in res.text
    assert (
        await db_session.execute(select(func.count()).select_from(BackupTarget))
    ).scalar_one() == 0


@pytest.mark.asyncio
async def test_patch_of_the_hint_alone_is_checked_against_the_stored_passphrase(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _superadmin(db_session)
    target = await _target(db_session)
    before = await _audit_rows(db_session)
    res = await client.patch(
        f"/api/v1/backup/targets/{target.id}",
        headers=headers,
        json={"passphrase_hint": f"it is {_PASS.lower()}"},
    )
    assert res.status_code == 422, res.text
    assert _PASS.casefold() not in res.text.casefold()
    await db_session.refresh(target)
    assert target.passphrase_hint == ""
    # The update path audits its payload; a refused hint must not get there.
    assert await _audit_rows(db_session) == before


@pytest.mark.asyncio
async def test_patch_of_the_passphrase_alone_is_checked_against_the_stored_hint(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _superadmin(db_session)
    target = await _target(db_session, hint="Another-Long-Secret-42 (old)")
    res = await client.patch(
        f"/api/v1/backup/targets/{target.id}",
        headers=headers,
        json={"passphrase": "Another-Long-Secret-42"},
    )
    assert res.status_code == 422, res.text


@pytest.mark.asyncio
async def test_patch_with_an_ordinary_hint_still_works(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _superadmin(db_session)
    target = await _target(db_session)
    res = await client.patch(
        f"/api/v1/backup/targets/{target.id}",
        headers=headers,
        json={"passphrase_hint": "password manager: backup NAS"},
    )
    assert res.status_code == 200, res.text
    assert res.json()["passphrase_hint"] == "password manager: backup NAS"


@pytest.mark.asyncio
async def test_create_and_download_refuses_before_dumping(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
):
    async def _must_not_run(*_a, **_k):
        raise AssertionError("archive built despite a revealing hint")

    # By module object: the package re-exports its APIRouter as ``router``,
    # so the dotted string resolves to that rather than to the module.
    router_mod = importlib.import_module("app.api.v1.backup.router")
    monkeypatch.setattr(router_mod, "build_backup_archive", _must_not_run)
    headers = await _superadmin(db_session)
    res = await client.post(
        "/api/v1/backup/create-and-download",
        headers=headers,
        data={"passphrase": _PASS, "passphrase_hint": f"[{_PASS}]"},
    )
    assert res.status_code == 422, res.text
    assert res.json()["detail"] == HINT_REVEALS_PASSPHRASE
