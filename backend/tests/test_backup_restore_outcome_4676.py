"""The restore outcome survives the session revocation the restore causes (#4676).

A restore replaces the auth tables, so the browser that applied it is
signed out before the POST response can be shown. The audit row written
after the replay carries the outcome; ``GET /backup/restore/last`` serves
it to a freshly signed-in superadmin.
"""

from __future__ import annotations

import sys
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.api.v1.backup.router  # noqa: F401  (loads the module; the package attr is the APIRouter)
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.services.backup.restore import RestoreOutcome

backup_router = sys.modules["app.api.v1.backup.router"]

SAFETY = "/var/lib/spatiumddi/backups/pre-restore-20261121-100000.zip"


async def _user(db: AsyncSession, *, superadmin: bool) -> dict[str, str]:
    user = User(
        username=f"r4676-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="r",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=superadmin,
    )
    user.groups = []
    db.add(user)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def test_outcome_readable_after_restore(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.db as app_db

    admin = await _user(db_session, superadmin=True)

    async def _apply(db, **kw):
        return RestoreOutcome(
            manifest={"hostname": "src-host"},
            pre_restore_path=SAFETY,
            secrets_payload_keys=[],
            duration_ms=1234,
            warnings=["re-publish the DS records"],
        )

    monkeypatch.setattr(backup_router, "apply_backup_restore", _apply)
    monkeypatch.setattr(
        app_db, "AsyncSessionLocal", async_sessionmaker(db_session.bind, expire_on_commit=False)
    )
    # Nothing recorded yet.
    assert (await client.get("/api/v1/backup/restore/last", headers=admin)).status_code == 404

    r = await client.post(
        "/api/v1/backup/restore",
        headers=admin,
        files={"archive": ("a.zip", b"zip")},
        data={"passphrase": "hunter2hunter2", "confirmation_phrase": "RESTORE-FROM-BACKUP"},
    )
    assert r.status_code == 200, r.text

    # A fresh login, after the original session was revoked.
    fresh = await _user(db_session, superadmin=True)
    got = await client.get("/api/v1/backup/restore/last", headers=fresh)
    assert got.status_code == 200, got.text
    body = got.json()
    assert body["pre_restore_safety_path"] == SAFETY
    assert body["duration_ms"] == 1234
    assert body["warnings"] == ["re-publish the DS records"]
    assert body["note"] == r.json()["note"]
    assert body["performed_at"]


async def test_outcome_requires_superadmin(client: AsyncClient, db_session: AsyncSession) -> None:
    plain = await _user(db_session, superadmin=False)
    r = await client.get("/api/v1/backup/restore/last", headers=plain)
    assert r.status_code == 403
