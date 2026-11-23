"""The upload restore's answer reports the sessions it ended (#4704).

``POST /backup/restore`` builds its own response model, so the count the
backup-target restore carries has to be added to it separately, and its note
may only say every session was ended when that actually happened.
"""

from __future__ import annotations

import importlib
import io
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.services.backup.restore import RestoreOutcome

backup_router = importlib.import_module("app.api.v1.backup.router")

_NOTE = "Every session was ended; sign in again."


async def _post_restore(
    client: AsyncClient, db_session: AsyncSession, monkeypatch, sessions_ended
) -> dict:
    admin = User(
        username=f"bk-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="bk",
        hashed_password=hash_password("x" * 12),
        is_superadmin=True,
    )
    db_session.add(admin)
    await db_session.commit()

    async def _fake(*_a, **_k):
        return RestoreOutcome(
            manifest={},
            pre_restore_path="/tmp/safety.dump",
            secrets_payload_keys=[],
            duration_ms=1,
            sessions_ended=sessions_ended,
        )

    monkeypatch.setattr(backup_router, "apply_backup_restore", _fake)
    resp = await client.post(
        "/api/v1/backup/restore",
        headers={"Authorization": f"Bearer {create_access_token(str(admin.id))}"},
        files={"archive": ("a.zip", io.BytesIO(b"x"), "application/zip")},
        data={"passphrase": "x" * 12, "confirmation_phrase": "RESTORE-FROM-BACKUP"},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_upload_restore_answers_sessions_ended(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
) -> None:
    body = await _post_restore(client, db_session, monkeypatch, 7)
    assert body["sessions_ended"] == 7
    assert _NOTE in body["note"]


@pytest.mark.asyncio
async def test_zero_live_sessions_still_says_sign_in_again(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
) -> None:
    body = await _post_restore(client, db_session, monkeypatch, 0)
    assert body["sessions_ended"] == 0
    assert _NOTE in body["note"]


@pytest.mark.asyncio
async def test_failed_ending_does_not_claim_every_session_was_ended(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
) -> None:
    body = await _post_restore(client, db_session, monkeypatch, -1)
    assert body["sessions_ended"] == -1
    assert _NOTE not in body["note"]


@pytest.mark.asyncio
async def test_restore_that_missed_the_session_table_has_no_note(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
) -> None:
    body = await _post_restore(client, db_session, monkeypatch, None)
    assert body["sessions_ended"] is None
    assert _NOTE not in body["note"]
