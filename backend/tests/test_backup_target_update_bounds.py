"""A backup destination's Edit holds Add's bounds and can take a secret away
(#3288, #3289)."""

from __future__ import annotations

import json

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.backup import BackupTarget
from app.services.backup.targets import get_destination
from app.services.backup.targets.base import DestinationConfigError
from app.services.backup.targets.secrets_config import (
    ENC_PREFIX,
    REDACTED_SENTINEL,
    merge_config_for_update,
)


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username="bounds",
        email="bounds@example.com",
        display_name="bounds",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _target(db: AsyncSession, kind: str, config: dict) -> BackupTarget:
    t = BackupTarget(
        name="dest",
        description="d",
        kind=kind,
        enabled=True,
        config=config,
        passphrase_encrypted=encrypt_str("a-passphrase-long-enough"),
        passphrase_hint="",
    )
    db.add(t)
    await db.flush()
    return t


def _enc(v: str) -> str:
    return ENC_PREFIX + encrypt_str(v).decode()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body,field",
    [
        ({"name": ""}, "name"),
        ({"name": "n" * 121}, "name"),
        ({"description": "d" * 501}, "description"),
        ({"passphrase_hint": "h" * 201}, "passphrase_hint"),
    ],
)
async def test_update_refuses_what_create_refuses_naming_the_field(
    body: dict, field: str, client: AsyncClient, db_session: AsyncSession
):
    headers = await _headers(db_session)
    t = await _target(db_session, "local_volume", {"path": "/x"})
    res = await client.patch(f"/api/v1/backup/targets/{t.id}", json=body, headers=headers)
    assert res.status_code == 422, res.text
    assert field in res.json()["detail"][0]["loc"]
    got = await client.get(f"/api/v1/backup/targets/{t.id}", headers=headers)
    assert got.json()["name"] == "dest"


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["name", "description", "passphrase_hint", "enabled"])
async def test_update_null_on_a_required_field_leaves_it_unchanged(
    field: str, client: AsyncClient, db_session: AsyncSession
):
    headers = await _headers(db_session)
    t = await _target(db_session, "local_volume", {"path": "/x"})
    res = await client.patch(f"/api/v1/backup/targets/{t.id}", json={field: None}, headers=headers)
    assert res.status_code == 200, res.text
    assert res.json()["name"] == "dest"
    assert res.json()["description"] == "d"
    assert res.json()["enabled"] is True


@pytest.mark.asyncio
async def test_azure_moved_to_account_key_drops_the_connection_string(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _headers(db_session)
    t = await _target(
        db_session,
        "azure_blob",
        {"container": "c", "connection_string": _enc("DefaultEndpointsProtocol=x")},
    )
    for conn in ("", None):
        res = await client.patch(
            f"/api/v1/backup/targets/{t.id}",
            json={
                "config": {
                    "container": "c",
                    "account_name": "acct",
                    "account_key": "KEY-VALUE",
                    "connection_string": conn,
                }
            },
            headers=headers,
        )
        assert res.status_code == 200, res.text
        cfg = res.json()["config"]
        assert cfg["account_key"] == REDACTED_SENTINEL
        assert cfg["connection_string"] == ""
    await db_session.refresh(t)
    assert not t.config.get("connection_string")


@pytest.mark.asyncio
async def test_azure_update_naming_both_modes_is_refused_naming_both(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _headers(db_session)
    t = await _target(db_session, "azure_blob", {"container": "c", "account_key": _enc("k")})
    res = await client.patch(
        f"/api/v1/backup/targets/{t.id}",
        json={"config": {"account_key": "K2", "connection_string": "CS2"}},
        headers=headers,
    )
    assert res.status_code == 422
    assert "account_key" in res.json()["detail"] and "connection_string" in res.json()["detail"]


def test_unrelated_edit_keeps_the_stored_secret():
    d = get_destination("azure_blob")
    out = merge_config_for_update(
        d,
        incoming={"container": "c2", "connection_string": REDACTED_SENTINEL, "account_key": ""},
        existing={"container": "c", "connection_string": _enc("CS")},
    )
    assert out["connection_string"].startswith(ENC_PREFIX)
    assert out["container"] == "c2"


def test_scp_key_to_password_drops_key_and_passphrase_and_back():
    d = get_destination("scp")
    existing = {
        "private_key": _enc("PEM"),
        "private_key_passphrase": _enc("pp"),
    }
    out = merge_config_for_update(d, incoming={"password": "pw"}, existing=existing)
    assert "private_key" not in out and "private_key_passphrase" not in out
    back = merge_config_for_update(d, incoming={"private_key": "PEM2"}, existing=out)
    assert "password" not in back and back["private_key"] == "PEM2"
    with pytest.raises(DestinationConfigError):
        merge_config_for_update(d, incoming={"password": "p", "private_key": "k"}, existing={})


def test_https_put_auth_none_drops_the_stored_credential():
    d = get_destination("https_put")
    out = merge_config_for_update(
        d,
        incoming={"auth": "none", "credential": REDACTED_SENTINEL},
        existing={"url": "https://h/x", "auth": "bearer", "credential": _enc("tok")},
    )
    assert "credential" not in out
    kept = merge_config_for_update(
        d,
        incoming={"url": "https://h/y"},
        existing={"url": "https://h/x", "auth": "bearer", "credential": _enc("tok")},
    )
    assert kept["credential"].startswith(ENC_PREFIX)


@pytest.mark.asyncio
async def test_update_null_config_leaves_it_unchanged(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _headers(db_session)
    t = await _target(db_session, "local_volume", {"path": "/x"})
    res = await client.patch(
        f"/api/v1/backup/targets/{t.id}", json={"config": None}, headers=headers
    )
    assert res.status_code == 200, res.text
    assert res.json()["config"]["path"] == "/x"


@pytest.mark.asyncio
async def test_null_clears_a_secret_and_empty_string_keeps_it(
    client: AsyncClient, db_session: AsyncSession
):
    """``""`` is what the console sends for a secret left blank, so it must
    keep the stored value; an explicit null is the API's way to clear one
    (#3289). SCP's key passphrase has no other mode to move to."""
    headers = await _headers(db_session)
    base = {
        "host": "h",
        "username": "u",
        "remote_path": "/b",
        "host_key_check": "insecure_skip",
    }
    t = await _target(
        db_session,
        "scp",
        {**base, "private_key": _enc("PEM"), "private_key_passphrase": _enc("PASSPHRASE-OLD")},
    )
    url = f"/api/v1/backup/targets/{t.id}"
    kept = await client.patch(
        url,
        json={"config": {**base, "private_key": "", "private_key_passphrase": ""}},
        headers=headers,
    )
    assert kept.status_code == 200, kept.text
    assert kept.json()["config"]["private_key_passphrase"] == REDACTED_SENTINEL
    assert kept.json()["config"]["private_key"] == REDACTED_SENTINEL

    cleared = await client.patch(
        url, json={"config": {**base, "private_key_passphrase": None}}, headers=headers
    )
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["config"]["private_key_passphrase"] == ""
    assert cleared.json()["config"]["private_key"] == REDACTED_SENTINEL
    await db_session.refresh(t)
    assert not t.config.get("private_key_passphrase")

    # Clearing the only credential is refused, and nothing is stored.
    refused = await client.patch(url, json={"config": {"private_key": None}}, headers=headers)
    assert refused.status_code == 422, refused.text
    await db_session.refresh(t)
    assert t.config["private_key"].startswith(ENC_PREFIX)


@pytest.mark.asyncio
async def test_audit_row_names_the_cleared_secret_never_its_value(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _headers(db_session)
    t = await _target(
        db_session,
        "azure_blob",
        {"container": "c", "connection_string": _enc("CONNSTR-OLD-VALUE")},
    )
    res = await client.patch(
        f"/api/v1/backup/targets/{t.id}",
        json={
            "config": {
                "container": "c",
                "account_name": "acct",
                "account_key": "ACCOUNTKEY-NEW-VALUE",
                "connection_string": "",
            }
        },
        headers=headers,
    )
    assert res.status_code == 200, res.text
    row = (
        (
            await db_session.execute(
                select(AuditLog)
                .where(AuditLog.resource_type == "backup_target", AuditLog.action == "update")
                .order_by(AuditLog.seq.desc())
            )
        )
        .scalars()
        .first()
    )
    assert row is not None
    assert row.new_value["config_secrets_cleared"] == ["connection_string"]
    blob = json.dumps(row.new_value)
    assert "CONNSTR-OLD-VALUE" not in blob and "ACCOUNTKEY-NEW-VALUE" not in blob
    assert ENC_PREFIX not in blob
