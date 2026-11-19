"""A non-text backup destination setting answers 422, not 500 (#3845)."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.backup import BackupTarget
from tests.test_backup_target_update_bounds import _headers

_URL = "/api/v1/backup/targets"
_BASE = {"name": "d", "passphrase": "a-passphrase-long-enough", "enabled": False}
_FTP = {"host": "h", "username": "u", "password": "p", "remote_path": "/b"}
_HTTPS = {"url": "https://example.com/up", "auth": "none"}
_S3 = {"bucket": "b", "access_key_id": "a", "secret_access_key": "s", "region": "us-east-1"}
_SCP = {"host": "h", "username": "u", "remote_path": "/b", "password": "p"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind,config,field",
    [
        ("ftp", {**_FTP, "mode": True}, "mode"),
        ("ftp", {**_FTP, "mode": {"a": 1}}, "mode"),
        ("https_put", {**_HTTPS, "auth": ["basic"]}, "auth"),
        ("s3", {**_S3, "object_lock_mode": True}, "object_lock_mode"),
        ("scp", {**_SCP, "host_key_check": False}, "host_key_check"),
    ],
)
async def test_add_non_text_setting_is_422(
    kind: str, config: dict, field: str, client: AsyncClient, db_session: AsyncSession
):
    headers = await _headers(db_session)
    r = await client.post(_URL, json={**_BASE, "kind": kind, "config": config}, headers=headers)
    assert r.status_code == 422, r.text
    assert repr(field) in r.json()["detail"]


@pytest.mark.asyncio
async def test_edit_non_text_setting_is_422(client: AsyncClient, db_session: AsyncSession):
    headers = await _headers(db_session)
    r = await client.post(
        _URL, json={**_BASE, "kind": "ftp", "config": {**_FTP, "mode": "ftp"}}, headers=headers
    )
    assert r.status_code == 201, r.text
    tid = r.json()["id"]
    r = await client.patch(f"{_URL}/{tid}", json={"config": {"mode": True}}, headers=headers)
    assert r.status_code == 422, r.text
    assert "'mode'" in r.json()["detail"]
    row = await db_session.get(BackupTarget, tid)
    assert row is not None and row.config["mode"] == "ftp"


@pytest.mark.asyncio
async def test_add_numeric_port_still_accepted(client: AsyncClient, db_session: AsyncSession):
    headers = await _headers(db_session)
    r = await client.post(
        _URL, json={**_BASE, "kind": "ftp", "config": {**_FTP, "port": 21}}, headers=headers
    )
    assert r.status_code == 201, r.text
