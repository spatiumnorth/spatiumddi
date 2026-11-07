"""A backup destination's Add holds the auth-mode rules its Edit holds (#3696)."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.models.backup import BackupTarget
from app.services.backup.targets.secrets_config import ENC_PREFIX, REDACTED_SENTINEL
from tests.test_backup_target_update_bounds import _headers

_URL = "/api/v1/backup/targets"
_BASE = {"name": "d", "passphrase": "a-passphrase-long-enough", "enabled": False}
_AZ = {"container": "c", "account_name": "acct"}
_SCP = {"host": "h", "username": "u", "remote_path": "/b", "host_key_check": "insecure_skip"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind,config,names",
    [
        (
            "azure_blob",
            {**_AZ, "account_key": "k", "connection_string": "cs"},
            "'account_key' and 'connection_string'",
        ),
        ("scp", {**_SCP, "password": "p", "private_key": "PEM"}, "'password' and 'private_key'"),
    ],
)
async def test_add_refuses_two_auth_modes(
    kind: str, config: dict, names: str, client: AsyncClient, db_session: AsyncSession
):
    headers = await _headers(db_session)
    r = await client.post(_URL, json={**_BASE, "kind": kind, "config": config}, headers=headers)
    assert r.status_code == 422, r.text
    assert f"set ONE of {names}, not both" in r.json()["detail"]


@pytest.mark.asyncio
async def test_add_one_mode_is_stored(client: AsyncClient, db_session: AsyncSession):
    headers = await _headers(db_session)
    r = await client.post(
        _URL,
        json={**_BASE, "kind": "azure_blob", "config": {**_AZ, "account_key": "k"}},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    assert r.json()["config"]["account_key"] == REDACTED_SENTINEL
    assert not r.json()["config"]["connection_string"]


@pytest.mark.asyncio
async def test_add_https_put_auth_none_stores_no_credential(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _headers(db_session)
    cfg = {"url": "https://example.com/up", "auth": "none", "credential": "tok"}
    r = await client.post(_URL, json={**_BASE, "kind": "https_put", "config": cfg}, headers=headers)
    assert r.status_code == 201, r.text
    assert not r.json()["config"]["credential"]


@pytest.mark.asyncio
async def test_stored_row_with_both_modes_stays_editable(
    client: AsyncClient, db_session: AsyncSession
):
    """A row Add stored before this rule holds two modes; an edit that
    supplies no new secret must still save, keeping what is stored."""
    headers = await _headers(db_session)
    t = BackupTarget(
        name="old",
        description="d",
        kind="azure_blob",
        enabled=False,
        config={
            **_AZ,
            "account_key": ENC_PREFIX + encrypt_str("k").decode(),
            "connection_string": ENC_PREFIX + encrypt_str("cs").decode(),
        },
        passphrase_encrypted=encrypt_str("a-passphrase-long-enough"),
        passphrase_hint="",
    )
    db_session.add(t)
    await db_session.flush()
    r = await client.patch(
        f"{_URL}/{t.id}",
        json={"config": {**_AZ, "account_key": "", "connection_string": ""}},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["config"]["account_key"] == REDACTED_SENTINEL
    assert r.json()["config"]["connection_string"] == REDACTED_SENTINEL


@pytest.mark.asyncio
async def test_add_https_put_bearer_keeps_credential(client: AsyncClient, db_session: AsyncSession):
    headers = await _headers(db_session)
    cfg = {"url": "https://example.com/up", "auth": "bearer", "credential": "tok"}
    r = await client.post(_URL, json={**_BASE, "kind": "https_put", "config": cfg}, headers=headers)
    assert r.status_code == 201, r.text
    assert r.json()["config"]["credential"] == REDACTED_SENTINEL


@pytest.mark.asyncio
async def test_add_none_then_edit_to_bearer_has_no_inherited_token(
    client: AsyncClient, db_session: AsyncSession
):
    """The issue's step 4: a token typed under auth none must not become the
    bearer token on a later move to bearer with the credential left blank."""
    headers = await _headers(db_session)
    cfg = {"url": "https://example.com/up", "auth": "none", "credential": "tok"}
    r = await client.post(_URL, json={**_BASE, "kind": "https_put", "config": cfg}, headers=headers)
    assert r.status_code == 201, r.text
    r = await client.patch(
        f"{_URL}/{r.json()['id']}",
        json={"config": {"url": "https://example.com/up", "auth": "bearer", "credential": ""}},
        headers=headers,
    )
    assert r.status_code == 422, r.text
