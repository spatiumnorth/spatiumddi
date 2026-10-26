"""Regression tests for the supervisor /heartbeat authentication gate
(GHSA-mj4g-hw3m-62rm / #400 C1).

The vulnerability: the no-cert fallback validity check was
``row.state == APPROVED or (session_token and verify(...))``. Python ``or``
short-circuits, so any APPROVED appliance was accepted with NO cert AND NO
session token — anyone who knew an appliance UUID could drive the heartbeat,
read the decrypted k3s cluster-join token, and overwrite control-plane state.

The fix: every no-cert heartbeat now REQUIRES a valid session token (UUID
alone is insufficient), and the cluster-admin join token is only returned over
a cert-authenticated (mTLS) request.
"""

from __future__ import annotations

import hashlib
import os
import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    DESIRED_CLUSTER_ROLE_MEMBER,
    Appliance,
)
from app.models.settings import PlatformSettings
from app.services.appliance.ca import generate_session_token


async def _approved_appliance(
    db: AsyncSession, *, member_join: bool = False
) -> tuple[Appliance, str]:
    s = await db.get(PlatformSettings, 1)
    if s is None:
        s = PlatformSettings(id=1)
        db.add(s)
    s.supervisor_registration_enabled = True
    token, token_hash = generate_session_token()
    der = os.urandom(32)
    row = Appliance(
        id=uuid.uuid4(),
        hostname="cp-1",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        appliance_variant="control-plane",
        session_token_hash=token_hash,
    )
    if member_join:
        row.desired_cluster_role = DESIRED_CLUSTER_ROLE_MEMBER
        row.desired_k3s_join_token_encrypted = encrypt_str("K10deadbeef::node:abc123")
    db.add(row)
    await db.flush()
    await db.commit()
    return row, token


async def test_heartbeat_with_valid_session_token_succeeds(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The legitimate non-mTLS path: an approved appliance heartbeating with
    its valid session token is accepted (this is the path the host-config
    delivery tests rely on)."""
    row, token = await _approved_appliance(db_session)
    r = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={"appliance_id": str(row.id), "session_token": token},
    )
    assert r.status_code == 200, r.text


async def test_heartbeat_uuid_only_is_rejected(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """C1: an APPROVED appliance UUID with NO cert and NO session token must
    be rejected — the credential-less short-circuit is gone."""
    row, _token = await _approved_appliance(db_session)
    r = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={"appliance_id": str(row.id)},
    )
    assert r.status_code == 403, r.text


async def test_heartbeat_wrong_session_token_is_rejected(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    row, _token = await _approved_appliance(db_session)
    r = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={"appliance_id": str(row.id), "session_token": "not-the-real-token"},
    )
    assert r.status_code == 403, r.text


async def test_unknown_appliance_uuid_is_rejected(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _approved_appliance(db_session)
    r = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={"appliance_id": str(uuid.uuid4()), "session_token": "x"},
    )
    assert r.status_code == 403, r.text


async def test_join_token_not_returned_over_session_token_path(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """C1 defence-in-depth: the cluster-admin k3s join token must NOT be
    handed back over the credential-but-non-cert (session-token) path — only
    over an mTLS (cert-authenticated) heartbeat."""
    row, token = await _approved_appliance(db_session, member_join=True)
    r = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={"appliance_id": str(row.id), "session_token": token},
    )
    assert r.status_code == 200, r.text
    assert r.json()["desired_k3s_join_token"] is None


# ── #411 — cert-auth failure falls back to the session-token path ──────────
# Cert headers PRESENT but failing to validate (the field condition where the
# cert pipeline isn't proven yet) must not hard-403 an approved supervisor —
# it falls back to its valid session token so reboot / upgrade / role delivery
# keep working. This is NOT the C1 bypass: the token is still required.

_GARBAGE_CERT_HEADERS = {
    "X-Appliance-Cert": "not-a-real-base64-cert",
    "X-Appliance-Signature": "x",
    "X-Appliance-Timestamp": "2026-06-13T00:00:00Z",
}


async def test_heartbeat_cert_failure_falls_back_to_valid_session_token(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#411 — invalid cert headers + a VALID session token → accepted (the
    cert-auth fallback). Pre-#411 this hard-403'd on the cert failure."""
    row, token = await _approved_appliance(db_session)
    r = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        headers=_GARBAGE_CERT_HEADERS,
        json={"appliance_id": str(row.id), "session_token": token},
    )
    assert r.status_code == 200, r.text


async def test_heartbeat_cert_failure_without_valid_token_still_rejected(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#411 — the fallback does NOT open a hole: invalid cert headers + no
    valid session token is still rejected (a real credential is still
    required — the C1 invariant holds)."""
    row, _token = await _approved_appliance(db_session)
    r = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        headers=_GARBAGE_CERT_HEADERS,
        json={"appliance_id": str(row.id), "session_token": "wrong-token"},
    )
    assert r.status_code == 403, r.text
