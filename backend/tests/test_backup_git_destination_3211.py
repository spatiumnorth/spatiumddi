"""The ``git`` backup destination (#3211), against a local bare repository."""

from __future__ import annotations

import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.backup import BackupTarget
from app.services.backup.targets import git_repo
from app.services.backup.targets.base import (
    ArchiveNotFoundError,
    ArchiveTooLargeError,
    BackupDestinationError,
    DestinationConfigError,
)
from app.services.backup.targets.git_repo import GitRepoDestination
from app.services.backup.targets.secrets_config import REDACTED_SENTINEL

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git binary not installed")

_NAME = "spatiumddi-backup-host-20260101-120000-abc123.zip"
_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"
_HOSTS = "git.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBogus"


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout


@pytest.fixture(autouse=True)
def _local_urls(monkeypatch):
    monkeypatch.setattr(git_repo, "_ALLOW_LOCAL_URLS", True)


@pytest.fixture
def remote(tmp_path: Path) -> Path:
    path = tmp_path / "remote.git"
    _git(tmp_path, "init", "-q", "--bare", "--initial-branch=main", str(path))
    return path


def _cfg(remote: Path, **extra) -> dict:
    return {"url": str(remote), "token": "unused-for-file", **extra}


async def test_write_list_download_delete_round_trip(remote: Path):
    d = GitRepoDestination()
    cfg = _cfg(remote)
    d.validate_config(cfg)
    assert await d.list_archives(config=cfg) == []  # empty repository

    await d.write(config=cfg, filename=_NAME, archive_bytes=b"first")
    listing = await d.list_archives(config=cfg)
    assert [r.filename for r in listing] == [_NAME]
    assert listing[0].size_bytes == 5
    assert listing[0].created_at == datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    assert await d.download(config=cfg, filename=_NAME) == b"first"

    # the push is a real commit under the timestamped path, with a clear message
    log = _git(remote, "log", "--format=%s", "main")
    assert log.strip() == f"Backup {_NAME}"
    assert _git(remote, "show", f"main:backups/{_NAME}") == "first"

    await d.delete(config=cfg, filename=_NAME)
    assert await d.list_archives(config=cfg) == []
    assert _git(remote, "log", "--format=%s", "main").splitlines()[0] == f"Prune {_NAME}"
    await d.delete(config=cfg, filename=_NAME)  # idempotent


async def test_each_run_adds_a_commit(remote: Path):
    d = GitRepoDestination()
    cfg = _cfg(remote, subdirectory="x/y")
    for i in range(3):
        await d.write(
            config=cfg,
            filename=f"spatiumddi-backup-h-2026010{i + 1}-000000-a.zip",
            archive_bytes=b"z",
        )
    assert len(_git(remote, "rev-list", "main").split()) == 3
    names = [r.filename for r in await d.list_archives(config=cfg)]
    assert names[0].endswith("a.zip") and "20260103" in names[0]  # newest first


async def test_download_missing_and_too_large(remote: Path):
    d = GitRepoDestination()
    cfg = _cfg(remote)
    with pytest.raises(ArchiveNotFoundError):
        await d.download(config=cfg, filename=_NAME)
    await d.write(config=cfg, filename=_NAME, archive_bytes=b"0123456789")
    with pytest.raises(ArchiveNotFoundError):
        await d.download(config=cfg, filename="spatiumddi-backup-nope.zip")
    with pytest.raises(ArchiveTooLargeError):
        await d.download(config=cfg, filename=_NAME, max_bytes=3)


async def test_oversize_archive_refused_before_push(remote: Path):
    d = GitRepoDestination()
    cfg = _cfg(remote, max_archive_mb=1)
    with pytest.raises(BackupDestinationError, match="max_archive_mb"):
        await d.write(config=cfg, filename=_NAME, archive_bytes=b"x" * (1024 * 1024 + 1))
    assert _git(remote, "branch", "--list").strip() == ""


async def test_failed_push_is_an_error_without_the_token(remote: Path):
    hook = remote / "hooks" / "pre-receive"
    hook.write_text("#!/bin/sh\necho 'denied: secret-token-xyz protected' >&2\nexit 1\n")
    hook.chmod(0o755)
    d = GitRepoDestination()
    cfg = _cfg(remote, token="secret-token-xyz")
    with pytest.raises(BackupDestinationError) as ei:
        await d.write(config=cfg, filename=_NAME, archive_bytes=b"x")
    assert "git push failed" in str(ei.value)
    assert "secret-token-xyz" not in str(ei.value)


async def test_concurrent_push_is_retried(remote: Path, monkeypatch):
    d = GitRepoDestination()
    cfg = _cfg(remote)
    await d.write(config=cfg, filename=_NAME, archive_bytes=b"a")
    real = git_repo._Run.fetch
    calls = {"n": 0}

    def racing_fetch(self):
        got = real(self)
        calls["n"] += 1
        if calls["n"] == 1:  # someone else pushes between our fetch and push
            other = remote.parent / "other"
            _git(remote.parent, "clone", "-q", str(remote), str(other))
            (other / "f").write_text("1")
            _git(other, "add", "f")
            _git(other, "-c", "user.name=o", "-c", "user.email=o@x", "commit", "-q", "-m", "o")
            _git(other, "push", "-q", "origin", "main")
        return got

    monkeypatch.setattr(git_repo._Run, "fetch", racing_fetch)
    await d.write(config=cfg, filename=_NAME.replace("abc", "def"), archive_bytes=b"b")
    assert calls["n"] == 2
    assert len(await d.list_archives(config=cfg)) == 2


async def test_connection_pushes_scratch_ref_and_cleans_up(remote: Path):
    d = GitRepoDestination()
    out = await d.test_connection(config=_cfg(remote))
    assert out["ok"] is True, out
    assert _git(remote, "branch", "--list").strip() == ""  # scratch branch removed


async def test_connection_fails_when_push_is_refused(remote: Path):
    hook = remote / "hooks" / "pre-receive"
    hook.write_text("#!/bin/sh\necho 'read-only key' >&2\nexit 1\n")
    hook.chmod(0o755)
    out = await GitRepoDestination().test_connection(config=_cfg(remote))
    assert out["ok"] is False and "read-only key" in out["error"]


async def test_connection_unreachable_is_reported(tmp_path: Path):
    out = await GitRepoDestination().test_connection(config=_cfg(tmp_path / "missing.git"))
    assert out["ok"] is False and out["error"]


@pytest.mark.parametrize(
    "cfg,needle",
    [
        ({"url": "http://h/r.git", "token": "t"}, "https://"),
        ({"url": "file:///etc", "token": "t"}, "https://"),
        ({"url": "ext::sh -c id", "token": "t"}, "https://"),
        ({"url": "-oProxyCommand=x", "token": "t"}, "https://"),
        ({"url": "https://u:p@h/r.git", "token": "t"}, "credentials"),
        ({"url": "https://h/r.git"}, "'token'"),
        ({"url": "ssh://git@h/r.git"}, "ssh_private_key"),
        ({"url": "ssh://git@h/r.git", "ssh_private_key": _KEY}, "known_hosts"),
        ({"url": "git@h:r.git", "ssh_private_key": _KEY, "known_hosts": " "}, "known_hosts"),
        ({"url": "https://h/r.git", "token": "t", "branch": "a..b"}, "branch"),
        ({"url": "https://h/r.git", "token": "t", "subdirectory": "../x"}, "subdirectory"),
        ({"url": "https://h/r.git", "token": "t", "max_archive_mb": "0"}, "max_archive_mb"),
        ({"url": "", "token": "t"}, "'url'"),
    ],
)
def test_validate_config_refuses(cfg, needle, monkeypatch):
    monkeypatch.setattr(git_repo, "_ALLOW_LOCAL_URLS", False)
    with pytest.raises(DestinationConfigError) as ei:
        GitRepoDestination().validate_config(cfg)
    assert needle in str(ei.value)


def test_validate_config_accepts_both_modes(monkeypatch):
    monkeypatch.setattr(git_repo, "_ALLOW_LOCAL_URLS", False)
    d = GitRepoDestination()
    d.validate_config({"url": "https://git.example.com/o/r.git", "token": "t"})
    d.validate_config(
        {"url": "git@git.example.com:o/r.git", "ssh_private_key": _KEY, "known_hosts": _HOSTS}
    )
    d.validate_config(
        {
            "url": "ssh://git@git.example.com:2222/o/r.git",
            "ssh_private_key": _KEY,
            "known_hosts": _HOSTS,
        }
    )


def test_local_path_refused_without_the_test_switch(monkeypatch, tmp_path):
    monkeypatch.setattr(git_repo, "_ALLOW_LOCAL_URLS", False)
    with pytest.raises(DestinationConfigError):
        GitRepoDestination().validate_config({"url": str(tmp_path), "token": "t"})


def test_ssh_environment_pins_host_keys(tmp_path):
    cfg = {"url": "git@h:r.git", "ssh_private_key": _KEY, "known_hosts": _HOSTS}
    run = git_repo._Run(cfg, tmp_path)
    cmd = run.env["GIT_SSH_COMMAND"]
    assert "StrictHostKeyChecking=yes" in cmd and "BatchMode=yes" in cmd
    assert "GlobalKnownHostsFile=/dev/null" in cmd
    assert (tmp_path / "known_hosts").read_text().strip() == _HOSTS
    assert ((tmp_path / "id_key").stat().st_mode & 0o777) == 0o600


def test_https_token_goes_in_env_not_argv(tmp_path):
    run = git_repo._Run({"url": "https://h/r.git", "token": "tok123"}, tmp_path)
    assert run.env["GIT_CONFIG_KEY_0"] == "http.extraHeader"
    assert run.env["GIT_CONFIG_VALUE_1"] == "false"
    assert "tok123" not in run.scrub("fatal: bad tok123 at https://h/r.git")


# ── API surface ───────────────────────────────────────────────────────

_URL = "/api/v1/backup/targets"


async def _headers(db: AsyncSession, *, superadmin: bool = True) -> dict[str, str]:
    user = User(
        username="gitadmin" if superadmin else "gitplain",
        email=f"{'a' if superadmin else 'p'}@example.com",
        display_name="g",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=superadmin,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


_BODY = {
    "name": "git-dest",
    "kind": "git",
    "passphrase": "a-passphrase-long-enough",
    "enabled": False,
    "config": {"url": "https://git.example.com/o/r.git", "token": "tok-secret-1"},
}


@pytest.mark.asyncio
async def test_kind_is_listed(client: AsyncClient, db_session: AsyncSession):
    h = await _headers(db_session)
    r = await client.get(f"{_URL}/kinds", headers=h)
    assert r.status_code == 200
    kinds = {k["kind"]: k for k in r.json()["kinds"]}
    assert "git" in kinds
    fields = {f["name"]: f for f in kinds["git"]["config_fields"]}
    assert fields["token"]["secret"] and fields["ssh_private_key"]["secret"]
    assert fields["ssh_private_key"]["multiline"] and fields["known_hosts"]["multiline"]


@pytest.mark.asyncio
async def test_create_encrypts_and_never_returns_secrets(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
):
    # the SSRF guard resolves the host; this host is not resolvable offline
    monkeypatch.setattr(git_repo, "assert_safe_target", lambda *a, **k: None)
    h = await _headers(db_session)
    r = await client.post(_URL, json=_BODY, headers=h)
    assert r.status_code == 201, r.text
    assert r.json()["config"]["token"] == REDACTED_SENTINEL
    assert "tok-secret-1" not in r.text
    row = await db_session.get(BackupTarget, r.json()["id"])
    assert row is not None and row.config["token"].startswith("__enc__:")
    assert "tok-secret-1" not in str(row.config)
    listing = await client.get(_URL, headers=h)
    assert "tok-secret-1" not in listing.text
    audit = (await db_session.execute(select(AuditLog))).scalars().all()
    assert audit and all("tok-secret-1" not in str(a.new_value) for a in audit)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "config",
    [
        {"url": "http://git.example.com/r.git", "token": "t"},
        {"url": "https://git.example.com/r.git"},
        {"url": "ssh://git@git.example.com/r.git", "ssh_private_key": _KEY},
        {"url": "https://git.example.com/r.git", "token": "t", "ssh_private_key": _KEY},
        {"url": "https://git.example.com/r.git", "token": "t", "max_archive_mb": 1.5},
    ],
)
async def test_bad_config_is_422(client: AsyncClient, db_session: AsyncSession, config: dict):
    h = await _headers(db_session)
    r = await client.post(_URL, json={**_BODY, "config": config}, headers=h)
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_loopback_url_refused_by_ssrf_guard(client: AsyncClient, db_session: AsyncSession):
    h = await _headers(db_session)
    cfg = {"url": "https://127.0.0.1/r.git", "token": "t"}
    r = await client.post(_URL, json={**_BODY, "config": cfg}, headers=h)
    assert r.status_code == 422 and "refusing" in r.text


@pytest.mark.asyncio
async def test_moving_the_url_requires_the_credential_again(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
):
    monkeypatch.setattr(git_repo, "assert_safe_target", lambda *a, **k: None)
    h = await _headers(db_session)
    r = await client.post(_URL, json=_BODY, headers=h)
    tid = r.json()["id"]
    r = await client.patch(
        f"{_URL}/{tid}", json={"config": {"url": "https://evil.example.com/r.git"}}, headers=h
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_unauthenticated_and_unprivileged_refused(
    client: AsyncClient, db_session: AsyncSession
):
    assert (await client.post(_URL, json=_BODY)).status_code in (401, 403)
    h = await _headers(db_session, superadmin=False)
    assert (await client.post(_URL, json=_BODY, headers=h)).status_code == 403


@pytest.mark.asyncio
async def test_replacing_known_hosts_requires_the_key_again(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
):
    monkeypatch.setattr(git_repo, "assert_safe_target", lambda *a, **k: None)
    h = await _headers(db_session)
    ssh = {
        "url": "git@git.example.com:o/r.git",
        "ssh_private_key": _KEY,
        "known_hosts": _HOSTS,
    }
    r = await client.post(_URL, json={**_BODY, "config": ssh}, headers=h)
    assert r.status_code == 201, r.text
    tid = r.json()["id"]
    r = await client.patch(
        f"{_URL}/{tid}", json={"config": {"known_hosts": _HOSTS + "x"}}, headers=h
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_whole_number_max_archive_mb_accepted(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
):
    monkeypatch.setattr(git_repo, "assert_safe_target", lambda *a, **k: None)
    h = await _headers(db_session)
    cfg = {**_BODY["config"], "max_archive_mb": 500}
    r = await client.post(_URL, json={**_BODY, "config": cfg}, headers=h)
    assert r.status_code == 201, r.text
