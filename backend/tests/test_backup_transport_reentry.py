"""An edit that makes a backup destination's transport weaker asks for the
stored credential again, as an edit of its host does."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_backup_target_update_bounds import _enc, _headers, _target

_FTP = {
    "host": "h",
    "username": "u",
    "remote_path": "/b",
    "password": _enc("p"),
    "mode": "ftps_explicit",
    "verify_tls": "true",
}
_SCP = {
    "host": "h",
    "username": "u",
    "remote_path": "/b",
    "password": _enc("p"),
    "host_key_check": "known_hosts",
    "known_hosts": "h ssh-ed25519 AAAA",
}
_HTTPS = {"url": "https://h/x", "username": "u", "password": _enc("p"), "verify_tls": "true"}

_PUT = {
    "url": "https://h/x",
    "auth": "bearer",
    "credential": _enc("t"),
    "verify_tls": "true",
}

# (kind, stored config, edit, the same edit with the credential re-entered)
_WEAKENING = [
    ("ftp", _FTP, {"mode": "ftp"}),
    ("ftp", _FTP, {"verify_tls": "false"}),
    ("ftp", _FTP, {"mode": "ftp", "verify_tls": "false"}),
    ("scp", _SCP, {"host_key_check": "insecure_skip"}),
    ("scp", _SCP, {"known_hosts": "other ssh-ed25519 BBBB"}),
    ("webdav", _HTTPS, {"verify_tls": "false"}),
    ("https_put", _PUT, {"verify_tls": "false"}),
]
_SAFE = [
    ("ftp", {**_FTP, "mode": "ftp"}, {"mode": "ftps_explicit"}),
    ("ftp", {**_FTP, "verify_tls": "false"}, {"verify_tls": "true"}),
    ("ftp", _FTP, {"mode": "ftps_implicit"}),
    ("ftp", {**_FTP, "mode": "ftp"}, {"verify_tls": "false"}),  # plain FTP stays plain
    ("scp", {**_SCP, "host_key_check": "insecure_skip"}, {"host_key_check": "known_hosts"}),
    ("scp", _SCP, {"host_key_check": "strict"}),
    ("webdav", {**_HTTPS, "verify_tls": "false"}, {"verify_tls": "true"}),
]


async def _patch(client, db, kind, stored, edit):
    headers = await _headers(db)
    t = await _target(db, kind, dict(stored))
    return (
        t,
        headers,
        await client.patch(
            f"/api/v1/backup/targets/{t.id}", json={"config": edit}, headers=headers
        ),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,stored,edit", _WEAKENING)
async def test_weaker_transport_without_credential_is_refused(
    kind, stored, edit, client: AsyncClient, db_session: AsyncSession
):
    t, headers, res = await _patch(client, db_session, kind, stored, edit)
    assert res.status_code == 422, res.text
    assert "less protected transport" in res.json()["detail"]
    assert "re-enter" in res.json()["detail"]
    await db_session.refresh(t)
    for k in edit:
        assert t.config.get(k) == stored[k]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,stored,edit", _WEAKENING)
async def test_weaker_transport_with_credential_is_saved(
    kind, stored, edit, client: AsyncClient, db_session: AsyncSession
):
    _, _, res = await _patch(
        client,
        db_session,
        kind,
        stored,
        {**edit, ("credential" if kind == "https_put" else "password"): "new-pw"},
    )
    assert res.status_code == 200, res.text


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,stored,edit", _SAFE)
async def test_stronger_or_equal_transport_needs_no_credential(
    kind, stored, edit, client: AsyncClient, db_session: AsyncSession
):
    _, _, res = await _patch(client, db_session, kind, stored, edit)
    assert res.status_code == 200, res.text


@pytest.mark.asyncio
async def test_unrelated_edit_needs_no_credential(client: AsyncClient, db_session: AsyncSession):
    headers = await _headers(db_session)
    t = await _target(db_session, "ftp", dict(_FTP))
    res = await client.patch(
        f"/api/v1/backup/targets/{t.id}",
        json={"name": "renamed", "config": {"remote_path": "/c", "mode": "ftps_explicit"}},
        headers=headers,
    )
    assert res.status_code == 200, res.text
