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
