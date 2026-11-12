"""Add refuses the redaction placeholder as a secret (#3846)."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.backup import BackupTarget
from app.services.backup.targets.secrets_config import REDACTED_SENTINEL
from tests.test_backup_target_update_bounds import _headers

_URL = "/api/v1/backup/targets"
_BASE = {"name": "d", "passphrase": "a-passphrase-long-enough", "enabled": False}
_FTP = {"host": "h", "username": "u", "remote_path": "/b"}


@pytest.mark.asyncio
async def test_add_placeholder_secret_is_422(client: AsyncClient, db_session: AsyncSession):
    headers = await _headers(db_session)
    cfg = {**_FTP, "password": REDACTED_SENTINEL}
    r = await client.post(_URL, json={**_BASE, "kind": "ftp", "config": cfg}, headers=headers)
    assert r.status_code == 422, r.text
    assert "'password'" in r.json()["detail"]


@pytest.mark.asyncio
async def test_edit_placeholder_keeps_stored_secret(client: AsyncClient, db_session: AsyncSession):
    headers = await _headers(db_session)
    cfg = {**_FTP, "password": "real-secret"}
    r = await client.post(_URL, json={**_BASE, "kind": "ftp", "config": cfg}, headers=headers)
    assert r.status_code == 201, r.text
    tid = r.json()["id"]
    before = (await db_session.get(BackupTarget, tid)).config["password"]
    r = await client.patch(
        f"{_URL}/{tid}", json={"config": {"password": REDACTED_SENTINEL}}, headers=headers
    )
    assert r.status_code == 200, r.text
    await db_session.refresh(await db_session.get(BackupTarget, tid))
    assert (await db_session.get(BackupTarget, tid)).config["password"] == before
