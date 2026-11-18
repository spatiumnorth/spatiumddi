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
from app.models.audit import AuditLog
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
    db_session: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the upgrade-window opt-in (``legacy``), an older supervisor keeps working."""
    k, aid, tok = await _registered(db_session, client, signed=False)
    monkeypatch.setattr(settings, "appliance_unsigned_register_allowed", "legacy")
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
    monkeypatch.setattr(settings, "appliance_unsigned_register_allowed", "never")
    r = await client.post(URL, json=k.body("00000000"))
    assert r.status_code == 403
    assert "upgrade" in r.json()["detail"].lower()
    assert (await client.post(URL, json=k.body("00000000", **k.proof()))).status_code == 200


async def _set_version(db: AsyncSession, aid: str, version: str | None) -> None:
    import uuid

    await db.rollback()
    row = await db.get(Appliance, uuid.UUID(aid))
    assert row is not None
    row.supervisor_version = version
    await db.commit()


async def _unsigned_audit_rows(db: AsyncSession) -> list[AuditLog]:
    await db.rollback()
    return list(
        (
            await db.execute(
                select(AuditLog).where(AuditLog.action == "appliance.supervisor_register_unsigned")
            )
        ).scalars()
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("old_version", ["2026.09.04-1", "1.0.0", "1.0.1-rc.1", None, "dev"])
async def test_legacy_unsigned_reregister_of_old_version_is_audited_and_spends_budget(
    db_session: AsyncSession,
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    old_version: str | None,
) -> None:
    k, aid, tok = await _registered(db_session, client, signed=False)
    monkeypatch.setattr(settings, "appliance_unsigned_register_allowed", "legacy")
    await _set_version(db_session, aid, old_version)
    claims: list[str] = []

    async def _claim(ip: str) -> tuple[bool, int, int]:
        claims.append(ip)
        return True, 1, 1

    monkeypatch.setattr(supervisor_mod, "claim_pairing_attempt", _claim)
    r = await client.post(URL, json=k.body("00000000"))
    assert r.status_code == 200, r.text
    assert r.json()["session_token"] != tok
    assert len(claims) == 1
    rows = await _unsigned_audit_rows(db_session)
    assert len(rows) == 1
    assert rows[0].resource_id == aid
    assert rows[0].result == "success"


@pytest.mark.asyncio
@pytest.mark.parametrize("version", ["1.0.1", "1.0.2", "1.1.0", "2.0.0"])
async def test_legacy_unsigned_reregister_of_signing_version_is_refused(
    db_session: AsyncSession, client: AsyncClient, version: str
) -> None:
    k, aid, _ = await _registered(db_session, client, signed=False)
    await _set_version(db_session, aid, version)
    before = await _token_hash(db_session, aid)
    r = await client.post(URL, json=k.body("00000000"))
    assert r.status_code == 403
    detail = r.json()["detail"]
    assert "upgrade" in detail.lower() and "Fleet" in detail
    assert "APPLIANCE_UNSIGNED_REGISTER_ALLOWED" in detail
    assert await _token_hash(db_session, aid) == before
    assert await _unsigned_audit_rows(db_session) == []


@pytest.mark.asyncio
async def test_unsigned_reregister_stops_when_the_attempt_budget_is_spent(
    db_session: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    k, aid, _ = await _registered(db_session, client, signed=False)
    monkeypatch.setattr(settings, "appliance_unsigned_register_allowed", "legacy")
    await _set_version(db_session, aid, "1.0.0")

    async def _claim(_ip: str) -> tuple[bool, int, int]:
        return False, 99, 99

    monkeypatch.setattr(supervisor_mod, "claim_pairing_attempt", _claim)
    before = await _token_hash(db_session, aid)
    assert (await client.post(URL, json=k.body("00000000"))).status_code == 429
    assert await _token_hash(db_session, aid) == before


@pytest.mark.asyncio
async def test_register_setting_leaves_the_heartbeat_legacy_flag_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The two settings are independent: one default, one flag, each its own."""
    assert settings.appliance_legacy_signature_allowed is True
    monkeypatch.setattr(settings, "appliance_unsigned_register_allowed", "never")
    assert settings.appliance_legacy_signature_allowed is True


def test_unsigned_register_default_is_never() -> None:
    """1.1.0 refuses unsigned re-registration unless an operator opts back in."""
    from app.config import Settings

    assert Settings.model_fields["appliance_unsigned_register_allowed"].default == "never"


@pytest.mark.asyncio
@pytest.mark.parametrize("old_version", ["1.0.0", "2026.09.04-1", None])
async def test_unsigned_reregister_refused_by_default_even_for_an_old_supervisor(
    db_session: AsyncSession, client: AsyncClient, old_version: str | None
) -> None:
    k, aid, _ = await _registered(db_session, client, signed=False)
    await _set_version(db_session, aid, old_version)
    before = await _token_hash(db_session, aid)
    r = await client.post(URL, json=k.body("00000000"))
    assert r.status_code == 403
    assert "APPLIANCE_UNSIGNED_REGISTER_ALLOWED" in r.json()["detail"]
    assert await _token_hash(db_session, aid) == before
    assert await _unsigned_audit_rows(db_session) == []


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
