"""Supervisor registration: the registering key is shown to be held.

A supervisor signs its registration with the key it registers with. A
re-registration of an existing row returns a fresh session token, so it must
come from the key's holder; a row whose supervisor has reported that it signs
is not re-registered unsigned, while a supervisor from before the signature
existed keeps working until the operator turns the allowance off.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import supervisor as supervisor_mod
from app.config import settings
from app.models.appliance import Appliance
from app.models.settings import PlatformSettings
from app.services.appliance import cert_auth

from .test_appliance_supervisor_register import (  # noqa: F401
    _make_pairing_code,
    _no_attempt_throttle,
    _no_failure_sleep,
)

URL = "/api/v1/appliance/supervisor/register"


class _FakeRedis:
    def __init__(self, store: dict[str, Any]) -> None:
        self.store = store

    async def set(self, key: str, value: Any, ex: int | None = None, nx: bool = False) -> bool:
        if nx and key in self.store:
            return False
        self.store[key] = value
        return True

    async def aclose(self) -> None:
        return None


@pytest.fixture(autouse=True)
def _redis(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    store: dict[str, Any] = {}
    monkeypatch.setattr(cert_auth, "make_async_redis", lambda *_a, **_k: _FakeRedis(store))
    return store


class _Key:
    def __init__(self) -> None:
        self.priv = Ed25519PrivateKey.generate()
        der = self.priv.public_key().public_bytes(
            encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
        )
        self.fp = hashlib.sha256(der).hexdigest()
        self.b64 = base64.b64encode(der).decode()

    def proof(self, *, key: Ed25519PrivateKey | None = None, age_s: int = 0) -> dict[str, str]:
        ts = (datetime.now(UTC) - timedelta(seconds=age_s)).isoformat(timespec="seconds")
        nonce = secrets.token_hex(16)
        payload = "\n".join(("spatium-register-v1", self.fp, ts, nonce)).encode()
        sig = (key or self.priv).sign(payload)
        return {
            "proof_timestamp": ts,
            "proof_nonce": nonce,
            "proof_signature": base64.b64encode(sig).decode(),
        }

    def body(self, code: str, **extra: Any) -> dict[str, Any]:
        return {
            "pairing_code": code,
            "hostname": "node-a",
            "public_key_der_b64": self.b64,
            **extra,
        }


async def _enable(db: AsyncSession) -> None:
    row = (
        await db.execute(select(PlatformSettings).where(PlatformSettings.id == 1))
    ).scalar_one_or_none()
    if row is None:
        db.add(PlatformSettings(id=1, supervisor_registration_enabled=True))
    else:
        row.supervisor_registration_enabled = True
    await db.flush()


async def _registered(
    db: AsyncSession, client: AsyncClient, *, signed: bool
) -> tuple[_Key, str, str]:
    await _enable(db)
    await _make_pairing_code(db, code="11112222")
    await db.commit()
    k = _Key()
    extra = k.proof() if signed else {}
    r = await client.post(URL, json=k.body("11112222", **extra))
    assert r.status_code == 200, r.text
    return k, r.json()["appliance_id"], r.json()["session_token"]


async def _token_hash(db: AsyncSession, appliance_id: str) -> str | None:
    import uuid

    await db.rollback()
    row = await db.get(Appliance, uuid.UUID(appliance_id))
    assert row is not None
    await db.refresh(row)
    return row.session_token_hash


@pytest.mark.asyncio
async def test_signed_reregister_returns_a_fresh_token(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    k, aid, tok = await _registered(db_session, client, signed=True)
    r = await client.post(URL, json=k.body("00000000", **k.proof()))
    assert r.status_code == 200, r.text
    assert r.json()["appliance_id"] == aid
    assert r.json()["session_token"] != tok


@pytest.mark.asyncio
async def test_unsigned_reregister_of_a_signing_supervisor_is_refused(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    k, aid, _ = await _registered(db_session, client, signed=True)
    before = await _token_hash(db_session, aid)
    r = await client.post(URL, json=k.body("00000000"))
    assert r.status_code == 403
    assert "session_token" not in r.text
    assert await _token_hash(db_session, aid) == before


@pytest.mark.asyncio
async def test_registration_signed_by_another_key_is_refused(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    k, aid, _ = await _registered(db_session, client, signed=True)
    before = await _token_hash(db_session, aid)
    r = await client.post(URL, json=k.body("00000000", **k.proof(key=Ed25519PrivateKey.generate())))
    assert r.status_code == 403
    assert await _token_hash(db_session, aid) == before


@pytest.mark.asyncio
async def test_a_registration_signature_is_accepted_once(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    k, aid, _ = await _registered(db_session, client, signed=True)
    body = k.body("00000000", **k.proof())
    assert (await client.post(URL, json=body)).status_code == 200
    before = await _token_hash(db_session, aid)
    assert (await client.post(URL, json=body)).status_code == 403
    assert await _token_hash(db_session, aid) == before


@pytest.mark.asyncio
async def test_stale_registration_signature_is_refused(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    k, _, _ = await _registered(db_session, client, signed=True)
    r = await client.post(URL, json=k.body("00000000", **k.proof(age_s=3600)))
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_supervisor_without_signing_still_re_registers_during_upgrade(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """A supervisor from before the signature existed keeps working."""
    k, aid, tok = await _registered(db_session, client, signed=False)
    r = await client.post(URL, json=k.body("00000000"))
    assert r.status_code == 200, r.text
    assert r.json()["session_token"] != tok
    # ...and once it upgrades, it is held to signing.
    r = await client.post(URL, json=k.body("00000000", **k.proof()))
    assert r.status_code == 200
    assert (await client.post(URL, json=k.body("00000000"))).status_code == 403


@pytest.mark.asyncio
async def test_unsigned_reregister_refused_once_the_allowance_is_off(
    db_session: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    k, _, _ = await _registered(db_session, client, signed=False)
    monkeypatch.setattr(settings, "appliance_legacy_signature_allowed", False)
    assert (await client.post(URL, json=k.body("00000000"))).status_code == 403
    assert (await client.post(URL, json=k.body("00000000", **k.proof()))).status_code == 200


@pytest.mark.asyncio
async def test_registration_refused_while_nonce_store_is_down(
    db_session: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    k, _, _ = await _registered(db_session, client, signed=True)

    def _boom(*_a: Any, **_k: Any) -> Any:
        raise ConnectionError("down")

    monkeypatch.setattr(cert_auth, "make_async_redis", _boom)
    r = await client.post(URL, json=k.body("00000000", **k.proof()))
    assert r.status_code == 503
    assert supervisor_mod is not None
