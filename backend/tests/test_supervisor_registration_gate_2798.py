"""Switching appliance registration off refuses new pairings only (#2798).

``platform_settings.supervisor_registration_enabled`` used to gate the
heartbeat and poll of every appliance that was already registered: with it
off, each heartbeat was answered 404, every supervisor read two of those as a
revocation and took its DNS and DHCP down. The flag now gates
``/supervisor/register`` only, and a deliberate heartbeat refusal (revoked
row, or no row the credential opens) carries the ``X-Spatium-Revocation``
header the supervisor keys its teardown on.
"""

from __future__ import annotations

import base64
import hashlib
import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import supervisor as supervisor_mod
from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    APPLIANCE_STATE_PENDING_APPROVAL,
    APPLIANCE_STATE_REVOKED,
    Appliance,
    PairingClaim,
    PairingCode,
)
from app.models.settings import PlatformSettings
from app.services.appliance.ca import generate_session_token

_HEARTBEAT = "/api/v1/appliance/supervisor/heartbeat"
_POLL = "/api/v1/appliance/supervisor/poll"
_REGISTER = "/api/v1/appliance/supervisor/register"


@pytest.fixture(autouse=True)
def _no_failure_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(supervisor_mod, "_CONSUME_FAILURE_DELAY_S", 0.0)


async def _registration(db: AsyncSession, enabled: bool) -> None:
    s = await db.get(PlatformSettings, 1)
    if s is None:
        s = PlatformSettings(id=1)
        db.add(s)
    s.supervisor_registration_enabled = enabled
    await db.flush()


async def _appliance(db: AsyncSession, state: str) -> tuple[Appliance, str]:
    token, token_hash = generate_session_token()
    der = os.urandom(32)
    row = Appliance(
        id=uuid.uuid4(),
        hostname=f"node-{state}",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=state,
        deployment_kind="appliance",
        appliance_variant="control-plane",
        session_token_hash=token_hash,
    )
    db.add(row)
    await db.flush()
    return row, token


async def test_heartbeat_of_a_registered_appliance_is_accepted_with_registration_off(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """REGRESSION (#2798): this answered 404, which revoked the node."""
    await _registration(db_session, False)
    row, token = await _appliance(db_session, APPLIANCE_STATE_APPROVED)
    await db_session.commit()

    r = await client.post(_HEARTBEAT, json={"appliance_id": str(row.id), "session_token": token})
    assert r.status_code == 200, r.text
    assert supervisor_mod.REVOCATION_HEADER not in r.headers


async def test_poll_of_a_registered_appliance_is_accepted_with_registration_off(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _registration(db_session, False)
    row, token = await _appliance(db_session, APPLIANCE_STATE_PENDING_APPROVAL)
    await db_session.commit()

    r = await client.post(_POLL, json={"appliance_id": str(row.id), "session_token": token})
    assert r.status_code == 200, r.text
    assert r.json()["state"] == APPLIANCE_STATE_PENDING_APPROVAL


async def test_new_registration_is_still_refused_with_registration_off(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _registration(db_session, False)
    code = "31415926"
    db_session.add(
        PairingCode(
            code_hash=hashlib.sha256(code.encode()).hexdigest(),
            code_last_two=code[-2:],
            persistent=False,
            enabled=True,
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
        )
    )
    await db_session.commit()
    der = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)
    )

    r = await client.post(
        _REGISTER,
        json={
            "pairing_code": code,
            "hostname": "newcomer",
            "public_key_der_b64": base64.b64encode(der).decode("ascii"),
            "supervisor_version": "2026.10.25-1",
        },
    )
    assert r.status_code == 404, r.text
    assert (await db_session.execute(select(PairingClaim))).scalars().first() is None
    assert (await db_session.execute(select(Appliance))).scalars().first() is None


async def test_a_revoked_row_is_refused_with_the_revocation_marker(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The supervisor tears down only on a marked 403; a revoked row must
    still carry the marker, whatever the registration flag says."""
    await _registration(db_session, False)
    row, token = await _appliance(db_session, APPLIANCE_STATE_REVOKED)
    await db_session.commit()

    r = await client.post(_HEARTBEAT, json={"appliance_id": str(row.id), "session_token": token})
    assert r.status_code == 403, r.text
    assert r.headers[supervisor_mod.REVOCATION_HEADER] == "revoked"


async def test_a_deleted_row_is_refused_with_the_revocation_marker(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A deleted row (#2696 / #2786: the control-plane node re-registers once
    it reads revoked) answers 403 ``unknown``, never a bare 404."""
    await _registration(db_session, True)
    await db_session.commit()

    r = await client.post(
        _HEARTBEAT, json={"appliance_id": str(uuid.uuid4()), "session_token": "gone"}
    )
    assert r.status_code == 403, r.text
    assert r.headers[supervisor_mod.REVOCATION_HEADER] == "unknown"
