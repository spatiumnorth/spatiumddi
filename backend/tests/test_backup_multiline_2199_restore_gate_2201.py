"""Backup target line breaks (#2199) and the restore card's dump-format
gate (#2201).

#2199 — every config field rendered as an ``<input>``, which folds a line
break into a space, so a PEM key, a two-host known_hosts or a second
HTTPS header could not be entered. The catalog now marks the fields whose
value is lines ``multiline`` so the form renders a textarea; these tests
pin that set and prove a multi-line value survives API → Fernet → DB →
driver byte for byte, and that a key which arrives flattened is refused
with a reason rather than paramiko's "not a valid OPENSSH private key".

#2201 — the console decided "can this be restored selectively?" from
``format_version == 2``, which every archive is, an Exclude-secrets one
included, whose dump is plain SQL that the restore refuses to restore
selectively. The refusal is right (a selective restore runs pg_restore
over a custom-format dump; a plain one cannot be filtered by table), so
the preview now reports the dump format the restore resolves, from the
same helper. These tests build real archives with the archive builder and
check the preview and the restore agree.
"""

from __future__ import annotations

import io

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.backup import BackupTarget
from app.services.backup import archive as archive_mod
from app.services.backup import restore as restore_mod
from app.services.backup.migrations import _local_head
from app.services.backup.restore import BackupRestoreError
from app.services.backup.targets import get_destination
from app.services.backup.targets.base import list_destination_kinds
from app.services.backup.targets.https_put import _parse_extra_headers
from app.services.backup.targets.scp import (
    _load_private_key,
    _load_supplied_host_keys,
)
from app.services.backup.targets.secrets_config import decrypt_config_secrets

_PASS = "correct horse battery"


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username="ml2199",
        email="ml2199@example.com",
        display_name="ml2199",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _openssh_key() -> str:
    key = Ed25519PrivateKey.generate()
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode()


def _known_hosts() -> str:
    lines = []
    for host in ("a.example", "b.example"):
        pub = (
            Ed25519PrivateKey.generate()
            .public_key()
            .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
            .decode()
        )
        lines.append(f"{host} {pub}")
    return "\n".join(lines) + "\n"


# ── #2199: the catalog ─────────────────────────────────────────────────


def _catalog() -> dict[tuple[str, str], dict]:
    return {(k["kind"], f["name"]): f for k in list_destination_kinds() for f in k["config_fields"]}


def test_every_field_whose_value_is_lines_is_multiline() -> None:
    multiline = {key for key, f in _catalog().items() if f.get("multiline")}
    assert multiline == {
        ("scp", "private_key"),
        ("scp", "known_hosts"),
        ("https_put", "extra_headers"),
        ("gcs", "service_account_json"),
    }


@pytest.mark.parametrize("hint", ["per line", "PEM", "known_hosts file", "multi-line", "JSON"])
def test_no_single_line_field_asks_for_lines(hint: str) -> None:
    """A field whose help asks for lines, a PEM block or a JSON document
    must be multiline — otherwise the form renders an <input> and the
    value is folded onto one line before it is sent."""
    for (kind, name), f in _catalog().items():
        if f["type"] == "notice":
            continue
        if hint.lower() in (f["description"] or "").lower() or hint in f["label"]:
            assert f.get("multiline"), f"{kind}.{name} asks for {hint!r} but is single-line"


# ── #2199: the round trip ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scp_key_and_known_hosts_round_trip_byte_exact(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    pem = _openssh_key()
    known = _known_hosts()
    resp = await client.post(
        "/api/v1/backup/targets",
        headers=headers,
        json={
            "name": "scp-2199",
            "kind": "scp",
            "passphrase": _PASS,
            "config": {
                "host": "192.0.2.20",
                "username": "backup",
                "remote_path": "/srv/backups",
                "private_key": pem,
                "known_hosts": known,
            },
        },
    )
    assert resp.status_code == 201, resp.text
    # The API never returns the key, and returns the known_hosts as stored.
    assert resp.json()["config"]["private_key"] == "<set>"
    assert resp.json()["config"]["known_hosts"] == known

    row = (
        await db_session.execute(select(BackupTarget).where(BackupTarget.name == "scp-2199"))
    ).scalar_one()
    assert row.config["private_key"] != pem  # Fernet-wrapped at rest
    plain = decrypt_config_secrets(get_destination("scp"), row.config)
    assert plain["private_key"] == pem
    assert plain["known_hosts"] == known

    # And the driver can use both as stored.
    loaded = _load_private_key(plain["private_key"], None)
    assert loaded.get_name() == "ssh-ed25519"

    import paramiko  # noqa: PLC0415

    ssh = paramiko.SSHClient()
    _load_supplied_host_keys(ssh, plain["known_hosts"])
    assert sorted(ssh.get_host_keys().keys()) == ["a.example", "b.example"]


@pytest.mark.asyncio
async def test_edit_without_retyping_keeps_the_stored_key(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    pem = _openssh_key()
    known = _known_hosts()
    created = await client.post(
        "/api/v1/backup/targets",
        headers=headers,
        json={
            "name": "scp-edit-2199",
            "kind": "scp",
            "passphrase": _PASS,
            "config": {
                "host": "192.0.2.21",
                "username": "backup",
                "remote_path": "/srv/backups",
                "private_key": pem,
                "known_hosts": known,
            },
        },
    )
    assert created.status_code == 201, created.text
    tid = created.json()["id"]
    # What the form sends on a save that did not retype the key.
    resp = await client.patch(
        f"/api/v1/backup/targets/{tid}",
        headers=headers,
        json={
            "name": "scp-edit-2199-renamed",
            "config": {**created.json()["config"], "private_key": ""},
        },
    )
    assert resp.status_code == 200, resp.text
    row = await db_session.get(BackupTarget, created.json()["id"])
    await db_session.refresh(row)
    plain = decrypt_config_secrets(get_destination("scp"), row.config)
    assert plain["private_key"] == pem
    assert plain["known_hosts"] == known


@pytest.mark.asyncio
async def test_a_flattened_pem_key_is_refused_with_the_reason(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    flattened = _openssh_key().replace("\n", " ")
    resp = await client.post(
        "/api/v1/backup/targets",
        headers=headers,
        json={
            "name": "scp-flat-2199",
            "kind": "scp",
            "passphrase": _PASS,
            "config": {
                "host": "192.0.2.22",
                "username": "backup",
                "remote_path": "/srv/backups",
                "private_key": flattened,
                "host_key_check": "insecure_skip",
            },
        },
    )
    assert resp.status_code == 422, resp.text
    assert "line breaks" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_https_extra_headers_keep_one_header_per_line(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    extra = "X-One: 1\nX-Two: 2"
    resp = await client.post(
        "/api/v1/backup/targets",
        headers=headers,
        json={
            "name": "https-2199",
            "kind": "https_put",
            "passphrase": _PASS,
            "config": {"url": "https://192.0.2.23/upload", "extra_headers": extra},
        },
    )
    assert resp.status_code == 201, resp.text
    row = (
        await db_session.execute(select(BackupTarget).where(BackupTarget.name == "https-2199"))
    ).scalar_one()
    assert row.config["extra_headers"] == extra
    assert _parse_extra_headers(row.config) == {"X-One": "1", "X-Two": "2"}


# ── #2201: the restore card's gate agrees with the restore ─────────────


@pytest.fixture
def stub_pg_dump(monkeypatch: pytest.MonkeyPatch) -> None:
    """The archive builder, for real, minus the pg_dump subprocess."""

    async def _head(_db) -> str | None:
        return _local_head()

    async def _custom(path, **_kw) -> None:
        path.write_bytes(b"PGDMP-stub")

    async def _plain(path) -> None:
        path.write_text("SELECT 1;\n", encoding="utf-8")

    monkeypatch.setattr(archive_mod, "_read_alembic_head", _head)
    monkeypatch.setattr(archive_mod, "_run_pg_dump", _custom)
    monkeypatch.setattr(archive_mod, "_run_pg_dump_plain", _plain)


@pytest.fixture
def safety_dump_tripwire(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stop a restore that got past the selective checks before it does
    anything, with a message the test can recognise."""

    async def _reached(_db):
        raise BackupRestoreError("reached the safety dump")

    monkeypatch.setattr(restore_mod, "_write_pre_restore_safety_dump", _reached)


async def _build(db: AsyncSession, *, exclude_secrets: bool) -> bytes:
    data, _name = await archive_mod.build_backup_archive(
        db, passphrase=_PASS, exclude_secrets=exclude_secrets
    )
    return data


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("exclude_secrets", "expected_format"), [(True, "plain"), (False, "custom")]
)
async def test_preview_and_restore_agree_on_selective_restore(
    client: AsyncClient,
    db_session: AsyncSession,
    stub_pg_dump: None,
    safety_dump_tripwire: None,
    exclude_secrets: bool,
    expected_format: str,
) -> None:
    headers = await _superadmin(db_session)
    data = await _build(db_session, exclude_secrets=exclude_secrets)

    preview = await client.post(
        "/api/v1/backup/manifest-preview",
        headers=headers,
        files={"archive": ("a.zip", io.BytesIO(data), "application/zip")},
    )
    assert preview.status_code == 200, preview.text
    body = preview.json()
    # Every archive is format_version 2 — that is why it cannot decide this.
    assert body["manifest"]["format_version"] == 2
    assert body["dump_format"] == expected_format
    assert body["selective_restore_supported"] is (expected_format == "custom")

    resp = await client.post(
        "/api/v1/backup/restore",
        headers=headers,
        files={"archive": ("a.zip", io.BytesIO(data), "application/zip")},
        data={
            "passphrase": _PASS,
            "confirmation_phrase": "RESTORE-FROM-BACKUP",
            "sections": "ipam",
        },
    )
    assert resp.status_code == 400, resp.text
    detail = resp.json()["detail"]
    if body["selective_restore_supported"]:
        # Past the selective gate: the restore would have run.
        assert detail == "reached the safety dump"
    else:
        assert "custom format" in detail


def test_resolve_dump_format_ignores_format_version() -> None:
    names_plain = {"manifest.json", "database.sql", "secrets.enc"}
    names_custom = {"manifest.json", "database.dump", "secrets.enc"}
    resolve = archive_mod.resolve_dump_format
    assert resolve({"format_version": 2, "dump_format": "plain"}, names_plain) == "plain"
    assert resolve({"format_version": 2, "dump_format": "custom"}, names_custom) == "custom"
    # Pre-field archives fall back on the member name.
    assert resolve({"format_version": 1}, names_plain) == "plain"
    assert resolve({"format_version": 2}, names_custom) == "custom"
    assert resolve({}, {"manifest.json"}) is None


# ── #2222: a destination archive's format is readable before restore ───


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("exclude_secrets", "expected_format"), [(True, "plain"), (False, "custom")]
)
async def test_destination_archive_preview_reports_the_dump_format(
    client: AsyncClient,
    db_session: AsyncSession,
    stub_pg_dump: None,
    tmp_path,
    exclude_secrets: bool,
    expected_format: str,
) -> None:
    headers = await _superadmin(db_session)
    data = await _build(db_session, exclude_secrets=exclude_secrets)
    name = "spatiumddi-backup-20260101-000000.zip"
    (tmp_path / name).write_bytes(data)
    target = BackupTarget(
        name="t2222",
        kind="local_volume",
        config={"path": str(tmp_path)},
        passphrase_encrypted=b"x",
    )
    db_session.add(target)
    await db_session.flush()

    resp = await client.get(
        f"/api/v1/backup/targets/{target.id}/archives/{name}/manifest-preview",
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["dump_format"] == expected_format
    assert body["selective_restore_supported"] is (expected_format == "custom")
    assert body["restorable"] is True

    missing = await client.get(
        f"/api/v1/backup/targets/{target.id}/archives/spatiumddi-backup-20260101-000001.zip/manifest-preview",
        headers=headers,
    )
    assert missing.status_code in (404, 502), missing.text


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["%2E%2E", "notes.txt", "spatiumddi-backup-x.tar"])
async def test_destination_archive_preview_refuses_a_name_that_is_not_ours(
    client: AsyncClient,
    db_session: AsyncSession,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    """The preview takes its filename through the same ``_archive_name``
    gate as download / restore / delete, so a traversal or a file the
    listing never offered is a 422 before the driver is asked for it."""
    headers = await _superadmin(db_session)
    (tmp_path / "notes.txt").write_bytes(b"not an archive")
    target = BackupTarget(
        name="t2222n",
        kind="local_volume",
        config={"path": str(tmp_path)},
        passphrase_encrypted=b"x",
    )
    db_session.add(target)
    await db_session.flush()

    calls: list[str] = []
    driver = get_destination("local_volume")

    async def _download(**kwargs: object) -> bytes:
        calls.append(str(kwargs.get("filename")))
        return b""

    monkeypatch.setattr(driver, "download", _download)
    resp = await client.get(
        f"/api/v1/backup/targets/{target.id}/archives/{name}/manifest-preview",
        headers=headers,
    )
    assert resp.status_code == 422, resp.text
    assert calls == []


@pytest.mark.asyncio
async def test_destination_archive_preview_is_superadmin_only(
    client: AsyncClient, db_session: AsyncSession, tmp_path
) -> None:
    user = User(
        username="nosa2222",
        email="nosa2222@example.com",
        display_name="nosa2222",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=False,
    )
    user.groups = []
    db_session.add(user)
    target = BackupTarget(
        name="t2222p",
        kind="local_volume",
        config={"path": str(tmp_path)},
        passphrase_encrypted=b"x",
    )
    db_session.add(target)
    await db_session.flush()
    resp = await client.get(
        f"/api/v1/backup/targets/{target.id}/archives/"
        "spatiumddi-backup-20260101-000000.zip/manifest-preview",
        headers={"Authorization": f"Bearer {create_access_token(str(user.id))}"},
    )
    assert resp.status_code == 403, resp.text
