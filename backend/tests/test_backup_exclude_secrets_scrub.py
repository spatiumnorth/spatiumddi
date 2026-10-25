"""An "exclude secrets" diagnostic archive carries no secret at all, and
still restores into a working install.

Every stored secret is covered: the Fernet-encrypted credentials, the
install's machine identity (appliance CA key, k3s join tokens, cluster
kubeconfig, pairing-code reveals, ACME account key), the stored digests of
credentials (local password hashes, API-token / session / pairing-code /
agent-token digests), and the install's own encryption keys in
``secrets.enc``. A normal backup is unchanged.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import uuid
import zipfile
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from sqlalchemy import LargeBinary, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

import app.models  # noqa: F401 — register every model on the metadata
from app.config import settings
from app.core.crypto import decrypt_str, encrypt_str
from app.models.acme_client import ACME_ORDER_PENDING, ACMEClientAccount, ACMEOrder
from app.models.appliance import Appliance, ApplianceCA, PairingCode
from app.models.auth import APIToken, User, UserSession
from app.models.base import Base
from app.services.acme_client import orchestrator
from app.services.backup import archive as archive_mod
from app.services.backup import restore
from app.services.backup.archive import _scrub_dump_text
from app.services.backup.crypto import decrypt_secrets
from app.services.backup.migrations import _local_head
from app.services.backup.rewrap import (
    ENCRYPTED_COLUMNS,
    JSONB_ENCRYPTED_FIELDS,
    LEGACY_PLAINTEXT_SECRET_COLUMNS,
    SCRUB_CREDENTIAL_DIGEST_COLUMNS,
    SCRUB_OMITTED_TABLES,
)

_PASS = "exclude-secrets-passphrase"

# ── every secret-shaped column is either scrubbed or known not to be one ──

# Columns whose NAME looks like a secret but whose content is not one. Each
# needs a reason; anything else matching the pattern must be scrubbed.
_NOT_SECRETS: dict[tuple[str, str], str] = {
    ("acme_http_challenge", "token"): "HTTP-01 token, served publicly by design",
    ("acme_http_challenge", "key_authorization"): "HTTP-01 response, served publicly",
    ("appliance", "public_key_der"): "public key",
    ("appliance", "public_key_fingerprint"): "digest of a public key",
    ("audit_log", "row_hash"): "audit chain digest",
    ("audit_log", "prev_hash"): "audit chain digest",
    ("cutover_checklist_item", "key"): "checklist item identifier",
    ("dhcp_server_scope_state", "config_hash"): "config digest",
    ("dns_ingest_snapshot", "record_keys"): "record name, type and value as served in DNS",
    ("dns_server_group", "tsig_key_name"): "key name, not the secret",
    ("dns_server_group", "tsig_key_algorithm"): "algorithm name",
    ("dns_server_options", "gss_tsig_keytab_path"): "filesystem path",
    ("dns_trust_anchor", "public_key"): "public DNSKEY",
    ("dnssec_key", "key_type"): "KSK / ZSK label",
    ("firewall_apply_state", "rendered_hash"): "ruleset digest",
    ("firewall_apply_state", "applied_hash"): "ruleset digest",
    ("firewall_apply_state", "last_confirmed_hash"): "ruleset digest",
    ("opnsense_router", "api_key"): "key identifier; the secret half is encrypted",
    ("opnsense_router", "block_sync_api_key"): "key identifier; the secret half is encrypted",
    ("overlay_network", "encryption_profile"): "profile name",
    ("platform_settings", "ssh_authorized_keys"): "public keys",
    ("proxmox_node", "token_id"): "token identifier; the secret is encrypted",
    ("tailscale_tenant", "api_key_expiry_source"): "enum label",
    ("tls_cert_probe", "key_algo"): "algorithm name",
    ("tls_cert_target", "key_algo"): "algorithm name",
}

_SECRET_NAME = re.compile(
    r"(encrypt|private|secret|passw|token|psk|key|hash|cred|community|bearer|otp)", re.I
)


def test_every_secret_shaped_column_is_scrubbed_or_known_harmless() -> None:
    scrubbed = {(t.strip('"'), c) for t, _pk, c in ENCRYPTED_COLUMNS}
    scrubbed |= {(s.table.strip('"'), s.column) for s in JSONB_ENCRYPTED_FIELDS}
    scrubbed |= set(LEGACY_PLAINTEXT_SECRET_COLUMNS)
    scrubbed |= set(SCRUB_CREDENTIAL_DIGEST_COLUMNS)

    uncovered = []
    for table in Base.metadata.tables.values():
        if table.name in SCRUB_OMITTED_TABLES:
            continue
        for column in table.columns:
            if not isinstance(column.type, (LargeBinary, String, Text, JSONB)):
                continue
            if not _SECRET_NAME.search(column.name):
                continue
            pair = (table.name, column.name)
            if pair not in scrubbed and pair not in _NOT_SECRETS:
                uncovered.append(pair)
    assert not uncovered, (
        "secret-shaped columns the exclude-secrets scrub does not cover — add "
        "them to a SCRUB_* registry in app/services/backup/rewrap.py, or to "
        f"_NOT_SECRETS here with the reason: {sorted(uncovered)}"
    )


# ── the scrub, on a dump ──────────────────────────────────────────────


def _copy_block(table: str, columns: list[str], rows: list[list[str]]) -> str:
    header = ", ".join(f'"{c}"' for c in columns)
    body = "\n".join("\t".join(r) for r in rows)
    return f'COPY "public"."{table}" ({header}) FROM stdin;\n{body}\n\\.\n'


def _rows(out: str, table: str) -> list[list[str]]:
    lines = out.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(f'COPY "public"."{table}"'))
    end = lines.index(r"\.", start)
    return [line.split("\t") for line in lines[start + 1 : end]]


def test_the_appliance_ca_row_is_left_out() -> None:
    dump = _copy_block(
        "appliance_ca",
        ["id", "subject_cn", "cert_pem", "key_encrypted"],
        [["1", "SpatiumDDI CA", "-----BEGIN CERTIFICATE-----", r"\\xdeadbeef"]],
    )

    out = _scrub_dump_text(dump)

    assert _rows(out, "appliance_ca") == []
    assert "deadbeef" not in out


def test_cluster_credentials_are_nulled() -> None:
    cols = [
        "id",
        "hostname",
        "kubeconfig_encrypted",
        "k3s_join_token_encrypted",
        "desired_k3s_join_token_encrypted",
        "session_token_hash",
    ]
    dump = _copy_block("appliance", cols, [["a1", "ddi1", r"\\x01", r"\\x02", r"\\x03", "f" * 64]])

    (row,) = _rows(_scrub_dump_text(dump), "appliance")

    assert row == ["a1", "ddi1", r"\N", r"\N", r"\N", r"\N"]


def test_credential_digests_no_longer_match_anything() -> None:
    code_digest = hashlib.sha256(b"12345678").hexdigest()
    dump = (
        _copy_block(
            "pairing_code",
            ["id", "code_hash", "code_encrypted"],
            [["p1", code_digest, r"\\x01"], ["p2", "a" * 64, r"\N"]],
        )
        + _copy_block("user", ["id", "username", "hashed_password"], [["u1", "admin", "$2b$12$x"]])
        + _copy_block("api_token", ["id", "token_hash"], [["t1", "b" * 64], ["t2", "c" * 64]])
        + _copy_block("user_session", ["id", "refresh_token_hash"], [["s1", "d" * 64]])
        + _copy_block("acme_account", ["id", "password_hash"], [["a1", "$2b$12$y"]])
        + _copy_block("dns_server", ["id", "agent_jwt_hash"], [["d1", "e" * 64]])
    )

    out = _scrub_dump_text(dump)

    pairing = _rows(out, "pairing_code")
    assert [r[2] for r in pairing] == [r"\N", r"\N"]
    assert pairing[0][1] != code_digest
    assert _rows(out, "user") == [["u1", "admin", r"\N"]]
    tokens = [r[1] for r in _rows(out, "api_token")]
    assert len(set(tokens)) == 2, "a UNIQUE column must stay unique"
    digests = tokens + [r[1] for r in pairing]
    digests += [r[1] for r in _rows(out, "user_session")]
    digests += [r[1] for r in _rows(out, "acme_account")]
    digests += [r[1] for r in _rows(out, "dns_server")]
    for value in digests:
        assert not re.fullmatch(r"[0-9a-f]{64}", value), value
        assert not value.startswith("$2"), value


def test_the_acme_account_key_is_blanked() -> None:
    dump = _copy_block(
        "acme_client_account", ["id", "account_key_encrypted"], [["a1", r"\\xabcdef"]]
    )

    assert _rows(_scrub_dump_text(dump), "acme_client_account") == [["a1", r"\\x"]]


# ── secrets.enc ───────────────────────────────────────────────────────


@pytest.fixture
def stub_dumps(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _head(_db: object) -> str:
        return "head"

    async def _custom(path: Path) -> None:
        path.write_bytes(b"PGDMP-stub")

    async def _plain(path: Path) -> None:
        path.write_text("-- plain\n", encoding="utf-8")

    monkeypatch.setattr(archive_mod, "_read_alembic_head", _head)
    monkeypatch.setattr(archive_mod, "_run_pg_dump", _custom)
    monkeypatch.setattr(archive_mod, "_run_pg_dump_plain", _plain)


async def _payload(exclude_secrets: bool) -> dict[str, object]:
    data, _name = await archive_mod.build_backup_archive(
        None,  # type: ignore[arg-type]
        passphrase=_PASS,
        exclude_secrets=exclude_secrets,
    )
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return decrypt_secrets(zf.read("secrets.enc"), passphrase=_PASS)


@pytest.mark.asyncio
async def test_an_exclude_secrets_archive_carries_no_install_key(stub_dumps: None) -> None:
    payload = await _payload(exclude_secrets=True)

    assert "platform_secret_key" not in payload
    assert "platform_credential_encryption_key" not in payload
    assert settings.secret_key not in json.dumps(payload)
    assert payload["schema_version"] == "head"


@pytest.mark.asyncio
async def test_a_normal_archive_still_carries_the_install_key(stub_dumps: None) -> None:
    payload = await _payload(exclude_secrets=False)

    assert payload["platform_secret_key"] == settings.secret_key
    assert payload["platform_credential_encryption_key"] == (
        settings.credential_encryption_key or ""
    )


# ── end to end: build, inspect, restore, regenerate ───────────────────

_HAVE_PG_TOOLS = all(shutil.which(t) for t in ("pg_dump", "psql"))


def _scratch_url(dbname: str) -> str:
    parts = urlsplit(str(settings.database_url))
    return urlunsplit(parts._replace(path=f"/{dbname}"))


def _dsn(url: str) -> str:
    return url.replace("postgresql+asyncpg://", "postgresql://", 1)


@pytest.fixture
async def scratch_db() -> AsyncIterator[str]:
    """An empty database to restore into."""
    dbname = f"spatiumddi_test_xs_{uuid.uuid4().hex[:10]}"
    admin = await asyncpg.connect(_dsn(_scratch_url("postgres")))
    try:
        await admin.execute(f'CREATE DATABASE "{dbname}"')
    finally:
        await admin.close()
    try:
        yield _scratch_url(dbname)
    finally:
        admin = await asyncpg.connect(_dsn(_scratch_url("postgres")))
        try:
            await admin.execute(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)')
        finally:
            await admin.close()


class _RequestSession:
    async def close(self) -> None:
        return None


@pytest.mark.asyncio
@pytest.mark.skipif(not _HAVE_PG_TOOLS, reason="needs the PostgreSQL client tools")
async def test_an_exclude_secrets_archive_holds_no_secret_and_restores(
    db_session: AsyncSession,
    scratch_db: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    ca_key_ct = encrypt_str("-----BEGIN PRIVATE KEY----- ca -----END PRIVATE KEY-----")
    kubeconfig_ct = encrypt_str("apiVersion: v1\nkind: Config\n")
    join_ct = encrypt_str("K10join::server:token")
    pairing_ct = encrypt_str("12345678")
    acme_key_ct = encrypt_str("-----BEGIN PRIVATE KEY----- acme -----END PRIVATE KEY-----")
    password_hash = "$2b$12$abcdefghijklmnopqrstuuF9yq5V9Pf8Xn3zBq2vWm4n7o5kR2y1W"
    token_hash = hashlib.sha256(b"api-token-value").hexdigest()
    refresh_hash = hashlib.sha256(b"refresh-token-value").hexdigest()
    code_hash = hashlib.sha256(b"12345678").hexdigest()
    session_hash = hashlib.sha256(b"supervisor-session").hexdigest()

    user = User(
        username="opsadmin",
        email="ops@example.com",
        display_name="ops",
        hashed_password=password_hash,
        auth_source="local",
        is_superadmin=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add_all(
        [
            APIToken(
                name="ci",
                token_hash=token_hash,
                prefix="spddi_ci",
                scope="user",
                user_id=user.id,
                created_by_user_id=user.id,
            ),
            UserSession(
                user_id=user.id,
                refresh_token_hash=refresh_hash,
                created_at=now,
                expires_at=now + timedelta(days=1),
            ),
            ApplianceCA(
                id=1,
                subject_cn="SpatiumDDI Appliance CA",
                algorithm="rsa-2048",
                cert_pem="-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
                key_encrypted=ca_key_ct,
                expires_at=now + timedelta(days=3650),
            ),
            PairingCode(
                id=uuid.uuid4(),
                code_hash=code_hash,
                code_last_two="78",
                persistent=True,
                enabled=True,
                code_encrypted=pairing_ct,
            ),
            ACMEClientAccount(
                directory_url="https://acme.example/directory",
                account_url="https://acme.example/acct/1",
                account_key_encrypted=acme_key_ct,
            ),
        ]
    )
    der = os.urandom(32)
    db_session.add(
        Appliance(
            id=uuid.uuid4(),
            hostname="ddi1",
            public_key_der=der,
            public_key_fingerprint=hashlib.sha256(der).hexdigest(),
            session_token_hash=session_hash,
            kubeconfig_encrypted=kubeconfig_ct,
            k3s_join_token_encrypted=join_ct,
            desired_k3s_join_token_encrypted=join_ct,
        )
    )
    await db_session.commit()

    local_head = _local_head()
    assert local_head is not None

    async def _head(_db: object) -> str:
        return local_head

    monkeypatch.setattr(archive_mod, "_read_alembic_head", _head)
    data, _name = await archive_mod.build_backup_archive(
        db_session, passphrase=_PASS, exclude_secrets=True
    )

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        dump = zf.read("database.sql").decode("utf-8")
        payload = decrypt_secrets(zf.read("secrets.enc"), passphrase=_PASS)
    for secret in (ca_key_ct, kubeconfig_ct, join_ct, pairing_ct, acme_key_ct):
        assert secret.hex() not in dump
    for digest in (password_hash, token_hash, refresh_hash, code_hash, session_hash):
        assert digest not in dump
    assert "platform_secret_key" not in payload
    assert "opsadmin" in dump, "non-secret data must survive"

    async def _no_safety_dump(_db: object) -> None:
        return None

    monkeypatch.setattr(restore, "_write_pre_restore_safety_dump", _no_safety_dump)
    outcome = await restore.apply_backup_restore(
        _RequestSession(),
        archive_bytes=data,
        passphrase=_PASS,
        confirmation_phrase=restore.CONFIRM_PHRASE,
        db_url=scratch_db,
    )
    assert outcome.rewrap is not None
    assert not outcome.rewrap.aborted
    assert outcome.rewrap.failed_rows == 0

    conn = await asyncpg.connect(_dsn(scratch_db))
    try:
        assert await conn.fetchval("SELECT count(*) FROM appliance_ca") == 0
        appliance = await conn.fetchrow(
            "SELECT hostname, kubeconfig_encrypted, k3s_join_token_encrypted, "
            "desired_k3s_join_token_encrypted, session_token_hash FROM appliance"
        )
        assert appliance["hostname"] == "ddi1"
        assert appliance["kubeconfig_encrypted"] is None
        assert appliance["k3s_join_token_encrypted"] is None
        assert appliance["desired_k3s_join_token_encrypted"] is None
        assert appliance["session_token_hash"] is None
        restored_user = await conn.fetchrow('SELECT username, hashed_password FROM "user"')
        assert restored_user["username"] == "opsadmin"
        assert restored_user["hashed_password"] is None
        assert await conn.fetchval("SELECT token_hash FROM api_token") != token_hash
        assert await conn.fetchval("SELECT refresh_token_hash FROM user_session") != refresh_hash
        pairing = await conn.fetchrow("SELECT code_hash, code_encrypted FROM pairing_code")
        assert pairing["code_hash"] != code_hash
        assert pairing["code_encrypted"] is None
        assert (
            bytes(await conn.fetchval("SELECT account_key_encrypted FROM acme_client_account"))
            == b""
        )
    finally:
        await conn.close()

    # The machine identity regenerates on the restored install.
    from app.services.appliance.ca import _load_ca_private_key, ensure_ca

    engine = create_async_engine(scratch_db, poolclass=NullPool)
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as scratch:
            ca = await ensure_ca(scratch)
            await scratch.commit()
            assert _load_ca_private_key(ca) is not None
    finally:
        await engine.dispose()


# ── the ACME account key regenerates ──────────────────────────────────


class _RecordingCA:
    """Captures the account key it was handed, then fails to connect."""

    seen: list[tuple[str, str | None]] = []

    def __init__(self, directory_url: str, account_key_pem: str, **kw: object) -> None:
        self._directory_url = directory_url
        type(self).seen.append((account_key_pem, kw.get("account_url")))  # type: ignore[arg-type]

    async def __aenter__(self) -> _RecordingCA:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def ensure_account(self, *, email: object = None) -> str:
        raise httpx.ConnectError("unreachable", request=httpx.Request("GET", self._directory_url))


@pytest.mark.asyncio
async def test_an_empty_acme_account_key_is_regenerated(db_session: AsyncSession) -> None:
    account = ACMEClientAccount(
        directory_url="https://acme.example/directory",
        account_url="https://acme.example/acct/1",
        account_key_encrypted=b"",
    )
    db_session.add(account)
    await db_session.flush()
    order = ACMEOrder(
        account_id=account.id,
        domains=["www.example.com"],
        challenge_type="dns-01",
        status=ACME_ORDER_PENDING,
    )
    db_session.add(order)
    await db_session.flush()
    account_id, order_id = account.id, order.id
    await db_session.commit()
    _RecordingCA.seen = []

    with (
        patch.object(orchestrator, "ACMEClient", _RecordingCA),
        pytest.raises(httpx.ConnectError),
    ):
        await orchestrator.run_order(db_session, order_id)

    ((pem, account_url),) = _RecordingCA.seen
    assert serialization.load_pem_private_key(pem.encode(), password=None) is not None
    assert account_url is None, "a new key must register a new CA account"
    db_session.expire_all()
    stored = await db_session.get(ACMEClientAccount, account_id)
    assert stored is not None
    assert decrypt_str(stored.account_key_encrypted) == pem
    assert stored.account_url is None
