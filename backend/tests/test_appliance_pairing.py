"""Integration tests for the pairing-code admin surface
(#169 + #170 Wave A3 reshape).

Covers create / list / revoke / enable / disable / reveal across both
ephemeral and persistent flavours, plus the MCP read tool. The
consume side (``/supervisor/register``) is exercised in
``test_appliance_supervisor_register.py``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.appliance import PairingCode
from app.models.auth import User
from app.services.ai.tools.pairing import (
    FindPairingCodesArgs,
    find_pairing_codes,
)

# ── Fixtures ──────────────────────────────────────────────────────────


async def _make_user(
    db: AsyncSession,
    *,
    superadmin: bool = True,
    username: str = "pcadmin",
    auth_source: str = "local",
    password: str = "password123",
) -> tuple[User, str]:
    user = User(
        username=username,
        email=f"{username}@example.com",
        display_name=username,
        hashed_password=hash_password(password),
        auth_source=auth_source,
        is_superadmin=superadmin,
    )
    user.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(user)
    await db.flush()
    token = create_access_token(str(user.id))
    return user, token


# ── Create ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_ephemeral_pairing_code_happy_path(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_user(db_session, username="pccreate")
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.post(
        "/api/v1/appliance/pairing-codes",
        headers=headers,
        json={"persistent": False, "note": "for dns-west-2"},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert len(body["code"]) == 8 and body["code"].isdigit()
    assert body["persistent"] is False
    assert body["enabled"] is True
    assert body["max_claims"] is None
    assert body["note"] == "for dns-west-2"
    assert body["expires_at"] is not None  # ephemeral always has expiry

    rows = (await db_session.execute(select(PairingCode))).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert row.persistent is False
    assert row.code_last_two == body["code"][-2:]
    assert row.code_hash != body["code"]  # cleartext is never persisted


@pytest.mark.asyncio
async def test_create_persistent_pairing_code_defaults_to_30_days(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """#1356 — an 8-digit code that never expires is a standing fleet-join
    credential, so "never" has to be asked for (``expires_in_minutes: 0``)."""
    _, token = await _make_user(db_session, username="pcpersistent")
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.post(
        "/api/v1/appliance/pairing-codes",
        headers=headers,
        json={"persistent": True, "max_claims": 50, "note": "staging fleet"},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["persistent"] is True
    assert body["max_claims"] == 50
    expires = datetime.fromisoformat(body["expires_at"].replace("Z", "+00:00"))
    assert timedelta(days=29) < expires - datetime.now(UTC) <= timedelta(days=30)

    resp = await client.post(
        "/api/v1/appliance/pairing-codes",
        headers=headers,
        json={"persistent": True, "expires_in_minutes": 0},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["expires_at"] is None


@pytest.mark.asyncio
async def test_create_persistent_pairing_code_accepts_explicit_expiry(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_user(db_session, username="pcpersistexp")
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.post(
        "/api/v1/appliance/pairing-codes",
        headers=headers,
        json={"persistent": True, "expires_in_minutes": 60},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["expires_at"] is not None


@pytest.mark.asyncio
async def test_create_rejects_max_claims_on_ephemeral(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_user(db_session, username="pcrejectmax")
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.post(
        "/api/v1/appliance/pairing-codes",
        headers=headers,
        json={"persistent": False, "max_claims": 5},
    )
    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_create_non_superadmin_403(db_session: AsyncSession, client: AsyncClient) -> None:
    _, token = await _make_user(db_session, superadmin=False, username="regular")
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.post(
        "/api/v1/appliance/pairing-codes",
        headers=headers,
        json={"persistent": False},
    )
    assert resp.status_code == 403, resp.text


# ── List ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_redacts_cleartext_and_carries_claim_count(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_user(db_session, username="pclist")
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    create_a = await client.post(
        "/api/v1/appliance/pairing-codes",
        headers=headers,
        json={"persistent": False, "note": "alpha"},
    )
    create_b = await client.post(
        "/api/v1/appliance/pairing-codes",
        headers=headers,
        json={"persistent": True, "max_claims": 3, "note": "beta"},
    )
    assert create_a.status_code == 201 and create_b.status_code == 201

    resp = await client.get("/api/v1/appliance/pairing-codes", headers=headers)
    assert resp.status_code == 200, resp.text
    codes = resp.json()["codes"]
    assert len(codes) == 2
    for row in codes:
        assert "code" not in row
        assert "code_hash" not in row
        assert "code_last_two" in row
        assert "claim_count" in row
        assert row["state"] == "pending"


# ── Revoke ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_revoke_pairing_code_is_idempotent(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_user(db_session, username="pcrevoke")
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    created = await client.post(
        "/api/v1/appliance/pairing-codes",
        headers=headers,
        json={"persistent": False},
    )
    code_id = created.json()["id"]

    r1 = await client.delete(f"/api/v1/appliance/pairing-codes/{code_id}", headers=headers)
    r2 = await client.delete(f"/api/v1/appliance/pairing-codes/{code_id}", headers=headers)
    assert r1.status_code == 204
    assert r2.status_code == 204  # idempotent on already-revoked

    row = (await db_session.execute(select(PairingCode))).scalars().one()
    assert row.revoked_at is not None


# ── Enable / Disable ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_disable_then_enable_persistent_code(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_user(db_session, username="pctoggle")
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    created = await client.post(
        "/api/v1/appliance/pairing-codes",
        headers=headers,
        json={"persistent": True},
    )
    code_id = created.json()["id"]

    r = await client.post(f"/api/v1/appliance/pairing-codes/{code_id}/disable", headers=headers)
    assert r.status_code == 204
    row = (await db_session.execute(select(PairingCode))).scalars().one()
    await db_session.refresh(row)
    assert row.enabled is False

    r = await client.post(f"/api/v1/appliance/pairing-codes/{code_id}/enable", headers=headers)
    assert r.status_code == 204
    await db_session.refresh(row)
    assert row.enabled is True


@pytest.mark.asyncio
async def test_disable_rejects_ephemeral_code(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_user(db_session, username="pctoggleeph")
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    created = await client.post(
        "/api/v1/appliance/pairing-codes",
        headers=headers,
        json={"persistent": False},
    )
    code_id = created.json()["id"]

    r = await client.post(f"/api/v1/appliance/pairing-codes/{code_id}/disable", headers=headers)
    assert r.status_code == 422


# ── Reveal ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_reveal_persistent_code_returns_original_cleartext(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """Persistent codes carry a Fernet-encrypted cleartext on the
    row. Reveal decrypts + returns the same 8 digits the operator
    saw at create time — no rotation. Operators who shared the code
    with colleagues earlier don't get invalidated by a reveal."""
    _, token = await _make_user(db_session, username="pcreveal", password="reveal-secret")
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    created = await client.post(
        "/api/v1/appliance/pairing-codes",
        headers=headers,
        json={"persistent": True},
    )
    code_id = created.json()["id"]
    original_code = created.json()["code"]

    resp = await client.post(
        f"/api/v1/appliance/pairing-codes/{code_id}/reveal",
        headers=headers,
        json={"password": "reveal-secret"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["code"] == original_code

    # Second reveal returns the same cleartext (no rotation).
    resp2 = await client.post(
        f"/api/v1/appliance/pairing-codes/{code_id}/reveal",
        headers=headers,
        json={"password": "reveal-secret"},
    )
    assert resp2.json()["code"] == original_code


@pytest.mark.asyncio
async def test_reveal_rejects_wrong_password(db_session: AsyncSession, client: AsyncClient) -> None:
    _, token = await _make_user(db_session, username="pcrevealbad", password="correct-password")
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    created = await client.post(
        "/api/v1/appliance/pairing-codes",
        headers=headers,
        json={"persistent": True},
    )
    code_id = created.json()["id"]

    resp = await client.post(
        f"/api/v1/appliance/pairing-codes/{code_id}/reveal",
        headers=headers,
        json={"password": "wrong-password"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_reveal_rejects_ephemeral_code(db_session: AsyncSession, client: AsyncClient) -> None:
    _, token = await _make_user(db_session, username="pcrevealeph", password="pw")
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    created = await client.post(
        "/api/v1/appliance/pairing-codes",
        headers=headers,
        json={"persistent": False},
    )
    code_id = created.json()["id"]

    resp = await client.post(
        f"/api/v1/appliance/pairing-codes/{code_id}/reveal",
        headers=headers,
        json={"password": "pw"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_reveal_external_auth_without_mfa_must_enrol(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """#408 — external-auth users (LDAP / OIDC / SAML) have no local
    password, so reveal re-confirmation requires TOTP. A user who hasn't
    enrolled MFA gets a clear 'enrol MFA' 403 (not a confusing password
    rejection); enrolling + supplying a TOTP code is covered in
    test_reveal_mfa_reauth.py."""
    _, token = await _make_user(
        db_session,
        username="pcldap",
        auth_source="ldap",
        password="anything",
    )
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    created = await client.post(
        "/api/v1/appliance/pairing-codes",
        headers=headers,
        json={"persistent": True},
    )
    code_id = created.json()["id"]

    resp = await client.post(
        f"/api/v1/appliance/pairing-codes/{code_id}/reveal",
        headers=headers,
        json={"password": "anything"},
    )
    assert resp.status_code == 403
    assert "mfa" in resp.json()["detail"].lower()


# ── MCP tool ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mcp_find_pairing_codes_returns_redacted_shape(
    db_session: AsyncSession,
) -> None:
    user, _ = await _make_user(db_session, username="pcmcp")
    db_session.add(
        PairingCode(
            id=uuid.uuid4(),
            code_hash="a" * 64,
            code_last_two="99",
            persistent=False,
            enabled=True,
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
        )
    )
    await db_session.commit()

    result = await find_pairing_codes(db_session, user, FindPairingCodesArgs())
    assert "codes" in result
    assert result["count"] == 1
    row = result["codes"][0]
    assert row["code_last_two"] == "99"
    assert "code" not in row
    assert "code_hash" not in row


@pytest.mark.asyncio
async def test_mcp_find_pairing_codes_filters_by_persistent(
    db_session: AsyncSession,
) -> None:
    user, _ = await _make_user(db_session, username="pcmcppersist")
    db_session.add_all(
        [
            PairingCode(
                id=uuid.uuid4(),
                code_hash="b" * 64,
                code_last_two="01",
                persistent=False,
                enabled=True,
                expires_at=datetime.now(UTC) + timedelta(minutes=15),
            ),
            PairingCode(
                id=uuid.uuid4(),
                code_hash="c" * 64,
                code_last_two="02",
                persistent=True,
                enabled=True,
                expires_at=None,
            ),
        ]
    )
    await db_session.commit()

    only_persist = await find_pairing_codes(db_session, user, FindPairingCodesArgs(persistent=True))
    assert only_persist["count"] == 1
    assert only_persist["codes"][0]["persistent"] is True

    only_eph = await find_pairing_codes(db_session, user, FindPairingCodesArgs(persistent=False))
    assert only_eph["count"] == 1
    assert only_eph["codes"][0]["persistent"] is False


@pytest.mark.asyncio
async def test_mcp_find_pairing_codes_blocks_non_superadmin(
    db_session: AsyncSession,
) -> None:
    user, _ = await _make_user(db_session, superadmin=False, username="regular")
    await db_session.commit()
    result = await find_pairing_codes(db_session, user, FindPairingCodesArgs())
    assert "error" in result
