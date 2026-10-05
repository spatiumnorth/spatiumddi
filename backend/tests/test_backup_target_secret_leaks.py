"""Backup-target credentials must not reach audit rows or error text.

Two leaks: ``PATCH /backup/targets/{id}`` logged the raw ``config`` in
``audit_log.new_value`` (secrets in clear), and the https_put / webdav
drivers put the full destination URL — presigned query string, userinfo —
into error messages that reach ``last_run_error``, audit and logs.
"""

from __future__ import annotations

import json

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.backup import BackupTarget
from app.services.backup.targets import DESTINATIONS, get_destination
from app.services.backup.targets import https_put as https_mod
from app.services.backup.targets import webdav as webdav_mod
from app.services.backup.targets.base import (
    BackupDestinationError,
    config_field_specs,
    safe_url,
)

SIGNED = "https://bucket.example.com/backups/x.zip?X-Amz-Signature=SIGSECRET123&sig=SIGSECRET456"


def test_safe_url_keeps_only_scheme_host_path():
    out = safe_url("https://user:PWSECRET@host.example:8443/a/b?q=QSECRET#FRAG")
    assert out == "https://host.example:8443/a/b"
    assert safe_url("not a url") == "<unparseable url>"


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username="leakcheck",
        email="leakcheck@example.com",
        display_name="leakcheck",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", sorted(DESTINATIONS))
async def test_patch_config_secrets_never_reach_the_audit_row(
    kind: str, client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
):
    driver = get_destination(kind)

    async def _ok(*_a, **_k):
        return None

    monkeypatch.setattr(type(driver), "validate_config", lambda self, c: None)
    monkeypatch.setattr(type(driver), "validate_config_network", lambda self, c: _ok())

    secret_names = [f.name for f in config_field_specs(driver) if f.secret]
    new_config = {n: f"NEWSECRET-{kind}-{n}" for n in secret_names}
    new_config["url"] = SIGNED  # a non-secret-flagged field that can still be a credential

    headers = await _superadmin(db_session)
    target = BackupTarget(
        name=f"t-{kind}",
        description="",
        kind=kind,
        enabled=True,
        config={},
        passphrase_encrypted=encrypt_str("a-passphrase-long-enough"),
        passphrase_hint="",
    )
    db_session.add(target)
    await db_session.flush()

    res = await client.patch(
        f"/api/v1/backup/targets/{target.id}", json={"config": new_config}, headers=headers
    )
    assert res.status_code == 200, res.text

    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "backup_target", AuditLog.action == "update"
                )
            )
        )
        .scalars()
        .all()
    )
    assert rows
    blob = json.dumps([r.new_value for r in rows])
    for value in new_config.values():
        assert value not in blob
    assert "SIGSECRET" not in blob and "NEWSECRET" not in blob
    assert set(rows[-1].new_value["config_keys_changed"]) == set(new_config)


def _patch_client(monkeypatch, mod, cls, handler):
    monkeypatch.setattr(
        cls,
        "_client",
        lambda self, config: httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["status", "transport"])
async def test_https_put_error_omits_presigned_query(mode: str, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if mode == "transport":
            raise httpx.ConnectError(f"boom talking to {request.url}")
        return httpx.Response(403, text="denied")

    _patch_client(monkeypatch, https_mod, https_mod.HttpsPutDestination, handler)
    with pytest.raises(BackupDestinationError) as ei:
        await get_destination("https_put").write(
            config={"url": SIGNED}, filename="a.zip", archive_bytes=b"x"
        )
    msg = str(ei.value)
    assert "SIGSECRET" not in msg and "X-Amz-Signature" not in msg
    assert "bucket.example.com/backups/x.zip" in msg


@pytest.mark.asyncio
async def test_https_put_redirect_location_omits_query(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": SIGNED})

    _patch_client(monkeypatch, https_mod, https_mod.HttpsPutDestination, handler)
    with pytest.raises(BackupDestinationError) as ei:
        await get_destination("https_put").write(
            config={"url": "https://r.example.com/{filename}"}, filename="a.zip", archive_bytes=b"x"
        )
    assert "SIGSECRET" not in str(ei.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["404", "transport"])
async def test_webdav_error_omits_userinfo_and_query(mode: str, monkeypatch):
    url = "https://user:PWSECRET@dav.example.com/dav/backups?token=QSECRET"

    def handler(request: httpx.Request) -> httpx.Response:
        if mode == "transport":
            raise httpx.ConnectError(f"boom talking to {url}")
        return httpx.Response(404)

    _patch_client(monkeypatch, webdav_mod, webdav_mod.WebDAVDestination, handler)
    with pytest.raises(BackupDestinationError) as ei:
        await get_destination("webdav").list_archives(
            config={"url": url, "username": "u", "password": "p"}
        )
    msg = str(ei.value)
    assert "PWSECRET" not in msg and "QSECRET" not in msg
    assert "dav.example.com/dav/backups" in msg
