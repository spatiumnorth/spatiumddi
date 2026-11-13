"""The credential key is dedicated, and what was written before it still opens (#1358).

Most installs encrypted stored credentials under a key derived from SECRET_KEY,
which also signs every session token. A dedicated CREDENTIAL_ENCRYPTION_KEY now
does the writing, the derived key stays a read fallback (so an upgrade loses
nothing), and ``rotate_credential_key`` moves the old values across.
"""

from __future__ import annotations

import uuid

import pytest
import structlog
from cryptography.fernet import Fernet
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core import crypto, rotate_credential_key
from app.models.ai import AIProvider
from app.models.audit import AuditLog
from app.services.backup.rewrap import _fernet_from_keys, _keys_identical

_SECRET = "3f" * 32


@pytest.fixture(autouse=True)
def _keys(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "secret_key", _SECRET)
    monkeypatch.setattr(settings, "credential_encryption_key", "")
    crypto._fernet.cache_clear()
    yield
    crypto._fernet.cache_clear()


def _dedicated(monkeypatch: pytest.MonkeyPatch) -> str:
    key = Fernet.generate_key().decode()
    monkeypatch.setattr(settings, "credential_encryption_key", key)
    crypto._fernet.cache_clear()
    return key


def test_new_writes_use_the_dedicated_key(monkeypatch: pytest.MonkeyPatch) -> None:
    key = _dedicated(monkeypatch)
    token = crypto.encrypt_str("hunter2")
    assert Fernet(key.encode()).decrypt(token) == b"hunter2"
    # ...and are NOT readable with the SECRET_KEY-derived key alone.
    with pytest.raises(Exception):  # noqa: B017, PT011
        _fernet_from_keys(_SECRET, "").decrypt(token)
    assert crypto.is_current_key(token)


def test_ciphertext_from_before_the_upgrade_still_decrypts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy = crypto.encrypt_str("ldap-bind-pw")  # no dedicated key yet
    _dedicated(monkeypatch)
    assert crypto.decrypt_str(legacy) == "ldap-bind-pw"
    assert not crypto.is_current_key(legacy)
    assert crypto.encrypted_at(legacy).year >= 2026
    assert crypto.decrypt_dict(crypto.encrypt_dict({"a": 1})) == {"a": 1}


def test_an_unrelated_token_is_still_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _dedicated(monkeypatch)
    with pytest.raises(ValueError):
        crypto.decrypt_str(Fernet(Fernet.generate_key()).encrypt(b"x"))


def test_no_dedicated_key_falls_back_to_derived_with_a_warning() -> None:
    with structlog.testing.capture_logs() as logs:
        token = crypto.encrypt_str("x")
    assert crypto.decrypt_str(token) == "x"
    assert _fernet_from_keys(_SECRET, "").decrypt(token) == b"x"
    assert any(e["event"] == "credential_encryption_key_not_set" for e in logs)
    # The warning never carries key material.
    assert _SECRET not in str(logs)


def test_restore_walk_keeps_the_fallback_when_only_secret_key_differs() -> None:
    cred = Fernet.generate_key().decode()
    # Same dedicated key, different SECRET_KEY: values still under the old
    # derived key would be orphaned if this were treated as "nothing to do".
    assert not _keys_identical("a" * 40, cred, "b" * 40, cred)
    assert _keys_identical("a" * 40, cred, "a" * 40, cred)


async def test_rotation_moves_every_column_and_is_idempotent(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    legacy = _fernet_from_keys(_SECRET, "").encrypt(b"sk-live-secret")
    provider = AIProvider(
        name=f"rot-{uuid.uuid4().hex[:6]}", kind="openai_compat", api_key_encrypted=legacy
    )
    db_session.add(provider)
    await db_session.commit()
    key = _dedicated(monkeypatch)

    assert await rotate_credential_key.rotate() == 0
    await db_session.refresh(provider)
    assert provider.api_key_encrypted is not None
    assert provider.api_key_encrypted != legacy
    assert Fernet(key.encode()).decrypt(provider.api_key_encrypted) == b"sk-live-secret"

    audit = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "rotate_credential_key")
            )
        )
        .scalars()
        .all()
    )
    assert len(audit) == 1 and audit[0].result == "success"
    assert audit[0].new_value is not None and audit[0].new_value["rewrapped_rows"] >= 1
    assert key not in str(audit[0].new_value) and _SECRET not in str(audit[0].new_value)

    # A second run changes nothing: the ciphertext is byte-identical.
    before = provider.api_key_encrypted
    assert await rotate_credential_key.rotate() == 0
    await db_session.refresh(provider)
    assert provider.api_key_encrypted == before


async def test_rotation_requires_a_dedicated_key() -> None:
    assert await rotate_credential_key.rotate() == 2


async def test_replacing_a_dedicated_key_with_old_key_given(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = Fernet.generate_key().decode()
    provider = AIProvider(
        name=f"rot-{uuid.uuid4().hex[:6]}",
        kind="openai_compat",
        api_key_encrypted=Fernet(old.encode()).encrypt(b"sk-x"),
    )
    db_session.add(provider)
    await db_session.commit()
    new = _dedicated(monkeypatch)
    assert await rotate_credential_key.rotate(old) == 0
    await db_session.refresh(provider)
    assert provider.api_key_encrypted is not None
    assert Fernet(new.encode()).decrypt(provider.api_key_encrypted) == b"sk-x"


# ── the rollout that adds the key must not write with it (#1358) ─────────────


def test_writes_stay_on_the_derived_key_during_the_rollout_that_adds_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A pod of the previous image (or one started before the Secret had the
    # key) can only read the derived key; while this process runs the version
    # that introduced the key, nothing it writes may need the dedicated one.
    monkeypatch.setattr(settings, "version", "2026.11.13-1")
    monkeypatch.setattr(settings, "credential_key_since", "2026.11.13-1")
    key = _dedicated(monkeypatch)
    token = crypto.encrypt_str("hunter2")
    assert _fernet_from_keys(_SECRET, "").decrypt(token) == b"hunter2"
    # ...while what a later release wrote under the dedicated key still opens.
    assert crypto.decrypt_str(Fernet(key.encode()).encrypt(b"later")) == "later"


def test_the_next_release_writes_with_the_dedicated_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "version", "2026.12.01-1")
    monkeypatch.setattr(settings, "credential_key_since", "2026.11.13-1")
    key = _dedicated(monkeypatch)
    assert Fernet(key.encode()).decrypt(crypto.encrypt_str("x")) == b"x"


def test_restore_honours_the_deferral() -> None:
    cred = Fernet.generate_key().decode()
    ring = _fernet_from_keys(_SECRET, cred, defer_dedicated_writes=True)
    assert _fernet_from_keys(_SECRET, "").decrypt(ring.encrypt(b"x")) == b"x"
    assert ring.decrypt(Fernet(cred.encode()).encrypt(b"y")) == b"y"


async def test_rotation_refuses_during_the_rollout_that_adds_the_key(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    legacy = _fernet_from_keys(_SECRET, "").encrypt(b"sk-live-secret")
    provider = AIProvider(
        name=f"rot-{uuid.uuid4().hex[:6]}", kind="openai_compat", api_key_encrypted=legacy
    )
    db_session.add(provider)
    await db_session.commit()
    monkeypatch.setattr(settings, "version", "2026.11.13-1")
    monkeypatch.setattr(settings, "credential_key_since", "2026.11.13-1")
    _dedicated(monkeypatch)
    assert await rotate_credential_key.rotate() == 2
    await db_session.refresh(provider)
    assert provider.api_key_encrypted == legacy


# ── a rotation running beside the app never puts an old value back (#1358) ───


class _ConcurrentWriter:
    """asyncpg connection proxy that runs ``sql`` just before the walk's first
    UPDATE — i.e. the app changed the row after the walk read it."""

    def __init__(self, conn, sql: str) -> None:
        self._conn = conn
        self._sql = sql
        self.fired = False

    def __getattr__(self, name):
        return getattr(self._conn, name)

    async def execute(self, query: str, *args):
        if not self.fired and query.lstrip().upper().startswith("UPDATE"):
            self.fired = True
            await self._conn.execute(self._sql)
        return await self._conn.execute(query, *args)


async def _pg(db_session: AsyncSession):
    import asyncpg  # noqa: PLC0415

    url = settings.database_url.replace("postgresql+asyncpg://", "postgresql://", 1)
    return await asyncpg.connect(dsn=url)


async def test_a_column_changed_mid_walk_is_not_overwritten(db_session: AsyncSession) -> None:
    from app.services.backup.rewrap import RewrapOutcome, _rewrap_column  # noqa: PLC0415

    old = _fernet_from_keys(_SECRET, "")
    cred = Fernet.generate_key().decode()
    fresh = _fernet_from_keys(_SECRET, cred).encrypt(b"changed-by-app")
    conn = await _pg(db_session)
    try:
        await conn.execute("CREATE TEMP TABLE rot_t (id int primary key, v bytea)")
        await conn.execute("INSERT INTO rot_t VALUES (1, $1)", old.encrypt(b"original"))
        proxy = _ConcurrentWriter(
            conn, f"UPDATE rot_t SET v = '\\x{fresh.hex()}'::bytea WHERE id = 1"
        )
        outcome = RewrapOutcome()
        await _rewrap_column(
            conn=proxy,  # type: ignore[arg-type]
            table="rot_t",
            pk_col="id",
            enc_col="v",
            source=old,
            dest=_fernet_from_keys(_SECRET, cred),
            outcome=outcome,
        )
        assert proxy.fired
        assert bytes(await conn.fetchval("SELECT v FROM rot_t WHERE id = 1")) == fresh
        assert outcome.rewrapped_rows == 0
    finally:
        await conn.close()


async def test_a_jsonb_document_changed_mid_walk_is_not_overwritten(
    db_session: AsyncSession,
) -> None:
    import json  # noqa: PLC0415

    from app.services.backup.rewrap import (  # noqa: PLC0415
        JsonbSecret,
        RewrapOutcome,
        _rewrap_jsonb_field,
    )

    old = _fernet_from_keys(_SECRET, "")
    cred = Fernet.generate_key().decode()
    spec = JsonbSecret(table="rot_j", pk_col="id", column="doc", shape="dict", prefix="__enc__:")
    doc = {"secret": "__enc__:" + old.encrypt(b"s").decode(), "region": "eu"}
    conn = await _pg(db_session)
    try:
        await conn.execute("CREATE TEMP TABLE rot_j (id int primary key, doc jsonb)")
        await conn.execute("INSERT INTO rot_j VALUES (1, $1::jsonb)", json.dumps(doc))
        # The app edits an unrelated field of the same document meanwhile.
        proxy = _ConcurrentWriter(
            conn, "UPDATE rot_j SET doc = jsonb_set(doc, '{region}', '\"us\"') WHERE id = 1"
        )
        outcome = RewrapOutcome()
        await _rewrap_jsonb_field(
            conn=proxy,  # type: ignore[arg-type]
            spec=spec,
            source=old,
            dest=_fernet_from_keys(_SECRET, cred),
            outcome=outcome,
        )
        assert proxy.fired
        got = json.loads(await conn.fetchval("SELECT doc::text FROM rot_j WHERE id = 1"))
        assert got["region"] == "us"
        assert outcome.rewrapped_jsonb_fields == 0
    finally:
        await conn.close()
