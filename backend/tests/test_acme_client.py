"""Tests for the embedded ACME *client* (issue #438 Phase 1).

Distinct from ``test_acme.py`` (the ACME *provider* surface — an
acme-dns-compatible HTTP endpoint external clients use). This file
covers the *client* side: SpatiumDDI acting as an ACME client against a
public CA (Let's Encrypt), driving the RFC 8555 DNS-01 flow to issue a
CA-trusted Web UI TLS cert.

Three deterministic, offline buckets:

(a) ``engine.py`` pure helpers — the RFC 7638 JWK thumbprint, the
    key-authorization (``token.thumbprint``), and the DNS-01 TXT value
    (``base64url(sha256(key_authorization))``) checked against an
    independently-derived value + the RFC 7638 §3.1 worked example.
    No network — keys are synthesised in-process.

(b) API — ``PUT/GET /account`` asserting NO secret leakage (account
    key + EAB HMAC never appear in any response), ``POST /issue``
    creates a ``pending`` ``ACMEOrder`` + enqueues the Celery task
    (``.delay`` monkeypatched), ``GET /orders`` + ``/orders/{id}``,
    the ``security.certificates`` module gate 404, and the
    permission gate 403 for a non-admin.

(c) ``orchestrator.run_order`` failure path — a mocked engine raising
    ``ACMEProtocolError`` lands the order in ``invalid`` with
    ``last_error`` set (and never re-raises).

Nothing here touches the CA or a live DNS agent: the Celery dispatch is
patched and the orchestrator's CA client is mocked.
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.acme_client import (
    ACME_ORDER_INVALID,
    ACME_ORDER_PENDING,
    ACME_ORDER_PROCESSING,
    ACMEClientAccount,
    ACMEOrder,
)
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.feature_module import FeatureModule
from app.models.settings import PlatformSettings
from app.services import feature_modules
from app.services.acme_client import orchestrator
from app.services.acme_client.engine import (
    ACMEClient,
    ACMEProtocolError,
    DNS01Challenge,
    _jwk_thumbprint,
    _public_jwk,
    b64url,
)

# ── Cache reset (mirror test_pcap_api.py) ───────────────────────────


@pytest.fixture(autouse=True)
def _reset_module_cache() -> None:
    feature_modules.invalidate_cache()
    yield
    feature_modules.invalidate_cache()


# ── Auth helpers ────────────────────────────────────────────────────


async def _superadmin(db: AsyncSession) -> tuple[User, str]:
    u = User(
        username=f"admin-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@x.com",
        display_name="Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return u, create_access_token(str(u.id))


async def _user_with_perm(db: AsyncSession, perm: dict | None) -> tuple[User, str]:
    u = User(
        username=f"user-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@x.com",
        display_name="User",
        hashed_password=hash_password("x"),
        is_superadmin=False,
    )
    db.add(u)
    await db.flush()
    if perm is not None:
        role = Role(name=f"r-{uuid.uuid4().hex[:6]}", description="", permissions=[perm])
        db.add(role)
        await db.flush()
        group = Group(name=f"g-{uuid.uuid4().hex[:6]}", description="")
        group.roles = [role]
        group.users = [u]
        db.add(group)
        await db.flush()
    return u, create_access_token(str(u.id))


def _hdr(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _seed_account(db: AsyncSession) -> ACMEClientAccount:
    """A minimal ACME account row (locally generated EC account key)."""
    key = ec.generate_private_key(ec.SECP256R1())
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    row = ACMEClientAccount(
        directory_url="https://acme-staging-v02.api.letsencrypt.org/directory",
        email="ops@example.com",
        account_key_encrypted=encrypt_str(key_pem),
    )
    db.add(row)
    await db.flush()
    return row


async def _enable_acme(db: AsyncSession) -> None:
    """Flip the ``acme_enabled`` issuance gate on (mirrors what
    ``PUT /account`` does), creating the settings singleton if absent."""
    settings = await db.get(PlatformSettings, 1)
    if settings is None:
        settings = PlatformSettings(id=1)
        db.add(settings)
    settings.acme_enabled = True
    await db.flush()


# ── (a) engine.py pure helpers ──────────────────────────────────────


def test_jwk_thumbprint_matches_rfc7638_worked_example() -> None:
    """RFC 7638 §3.1 worked example — the canonical RSA JWK must hash to
    the published thumbprint. Pins the member-ordering + no-whitespace
    canonicalisation the rest of the dns-01 computation rides on."""
    jwk = {
        "kty": "RSA",
        "n": (
            "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4"
            "cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs"
            "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW"
            "2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOp"
            "bISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBni"
            "Iqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
        ),
        "e": "AQAB",
    }
    assert _jwk_thumbprint(jwk) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


def test_jwk_thumbprint_canonicalisation_is_member_order_independent() -> None:
    """The thumbprint is over a sorted, whitespace-free re-serialisation
    of the *required* members only — wire member order can't change it."""
    a = {"kty": "EC", "crv": "P-256", "x": "AAA", "y": "BBB"}
    b = {"y": "BBB", "kty": "EC", "x": "AAA", "crv": "P-256"}
    assert _jwk_thumbprint(a) == _jwk_thumbprint(b)


def test_key_authorization_and_txt_value_against_independent_derivation() -> None:
    """``get_dns01_challenge`` returns ``(challenge, key_auth, txt)`` where
    ``key_auth = token + "." + thumbprint`` and ``txt = b64url(sha256(
    key_auth))``. Re-derive both independently and assert equality so a
    silent change to the formula gets caught offline (no CA needed)."""
    key = ec.generate_private_key(ec.SECP256R1())
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    client = ACMEClient("https://example/directory", key_pem)

    token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"
    authz = {
        "identifier": {"type": "dns", "value": "example.com"},
        "challenges": [
            {"type": "http-01", "url": "https://ca/http", "token": "ignored"},
            {"type": "dns-01", "url": "https://ca/dns", "token": token},
        ],
    }

    challenge, key_auth, txt = client.get_dns01_challenge(authz)

    # The challenge surfaces the bare identifier (orchestrator prefixes
    # _acme-challenge) + the dns-01 URL/token.
    assert isinstance(challenge, DNS01Challenge)
    assert challenge.identifier == "example.com"
    assert challenge.url == "https://ca/dns"
    assert challenge.token == token

    # Independent derivation.
    thumb = _jwk_thumbprint(_public_jwk(key))
    expected_key_auth = f"{token}.{thumb}"
    expected_txt = (
        base64.urlsafe_b64encode(hashlib.sha256(expected_key_auth.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    assert key_auth == expected_key_auth
    assert txt == expected_txt
    # The TXT value is unpadded base64url of a 32-byte digest → 43 chars.
    assert len(txt) == 43
    assert "=" not in txt


def test_get_dns01_challenge_raises_when_no_dns01_offered() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    client = ACMEClient("https://example/directory", key_pem)
    authz = {
        "identifier": {"type": "dns", "value": "example.com"},
        "challenges": [{"type": "http-01", "url": "https://ca/http", "token": "t"}],
    }
    with pytest.raises(ACMEProtocolError):
        client.get_dns01_challenge(authz)


def test_b64url_is_unpadded_urlsafe() -> None:
    # 0xFB 0xFF would produce '+/' under standard b64 and a '=' pad.
    assert b64url(b"\xfb\xff") == "-_8"
    assert "=" not in b64url(b"\x00")


def test_public_jwk_rsa_and_ec_shapes() -> None:
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_jwk = _public_jwk(rsa_key)
    assert rsa_jwk["kty"] == "RSA"
    assert set(rsa_jwk) == {"kty", "n", "e"}

    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_jwk = _public_jwk(ec_key)
    assert ec_jwk["kty"] == "EC"
    assert ec_jwk["crv"] == "P-256"
    assert set(ec_jwk) == {"kty", "crv", "x", "y"}


# ── (b) API: account ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_account_returns_null_when_unconfigured(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _superadmin(db_session)
    await db_session.commit()
    r = await client.get("/api/v1/appliance/acme/account", headers=_hdr(token))
    assert r.status_code == 200
    assert r.json() is None


@pytest.mark.asyncio
async def test_put_account_creates_and_leaks_no_secrets(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _superadmin(db_session)
    await db_session.commit()
    r = await client.put(
        "/api/v1/appliance/acme/account",
        json={
            "directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
            "email": "ops@example.com",
            "eab_kid": "kid-123",
            "eab_hmac_b64": "c2VjcmV0LWhtYWMta2V5",
        },
        headers=_hdr(token),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["directory_url"].startswith("https://")
    assert body["email"] == "ops@example.com"
    assert body["eab_kid"] == "kid-123"
    # EAB presence surfaces as a boolean — never the HMAC itself.
    assert body["eab_hmac_set"] is True
    assert body["account_url"] is None

    # No secret material in the response under ANY key.
    blob = json.dumps(body)
    assert "account_key" not in blob
    assert "eab_hmac_b64" not in blob
    assert "c2VjcmV0LWhtYWMta2V5" not in blob

    # The account-key + EAB HMAC are encrypted at rest, not plaintext.
    row = (await db_session.execute(select(ACMEClientAccount))).scalar_one()
    assert row.account_key_encrypted is not None
    assert b"BEGIN" not in row.account_key_encrypted  # not raw PEM
    assert row.eab_hmac_encrypted is not None

    # Audited.
    audits = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.resource_type == "acme_client_account")
            )
        )
        .scalars()
        .all()
    )
    assert any(a.action == "create" for a in audits)


@pytest.mark.asyncio
async def test_get_account_after_put_hides_secrets(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _superadmin(db_session)
    await db_session.commit()
    await client.put(
        "/api/v1/appliance/acme/account",
        json={"directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory"},
        headers=_hdr(token),
    )
    r = await client.get("/api/v1/appliance/acme/account", headers=_hdr(token))
    assert r.status_code == 200
    body = r.json()
    assert body is not None
    assert body["eab_hmac_set"] is False
    assert "account_key" not in json.dumps(body)
    # The ONLY key referencing the HMAC is the boolean presence flag —
    # never a key/value carrying the secret (e.g. eab_hmac / eab_hmac_b64).
    hmac_keys = [k for k in body if "hmac" in k.lower()]
    assert hmac_keys == ["eab_hmac_set"]


@pytest.mark.asyncio
async def test_put_account_rejects_non_https_directory(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _superadmin(db_session)
    await db_session.commit()
    for bad in ["http://acme.example/directory", "acme.example/directory", "ftp://x/y"]:
        r = await client.put(
            "/api/v1/appliance/acme/account",
            json={"directory_url": bad},
            headers=_hdr(token),
        )
        assert r.status_code == 422, bad


@pytest.mark.asyncio
async def test_put_account_update_preserves_hmac_when_omitted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _superadmin(db_session)
    await db_session.commit()
    # Create with an EAB HMAC.
    await client.put(
        "/api/v1/appliance/acme/account",
        json={
            "directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
            "eab_kid": "kid",
            "eab_hmac_b64": "c2VjcmV0",
        },
        headers=_hdr(token),
    )
    # Update without re-supplying the HMAC — it must persist (write-only).
    r = await client.put(
        "/api/v1/appliance/acme/account",
        json={
            "directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
            "email": "new@example.com",
        },
        headers=_hdr(token),
    )
    assert r.status_code == 200
    assert r.json()["email"] == "new@example.com"
    assert r.json()["eab_hmac_set"] is True


@pytest.mark.asyncio
async def test_delete_account(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _superadmin(db_session)
    await db_session.commit()
    await client.put(
        "/api/v1/appliance/acme/account",
        json={"directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory"},
        headers=_hdr(token),
    )
    r = await client.delete("/api/v1/appliance/acme/account", headers=_hdr(token))
    assert r.status_code == 204
    # Now GET → null again.
    again = await client.get("/api/v1/appliance/acme/account", headers=_hdr(token))
    assert again.json() is None


# ── (b) API: issue + orders ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_issue_creates_pending_order_and_enqueues(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _superadmin(db_session)
    await _seed_account(db_session)
    await _enable_acme(db_session)
    await db_session.commit()

    with patch("app.tasks.acme.run_acme_order.delay") as delay:
        r = await client.post(
            "/api/v1/appliance/acme/issue",
            json={"domains": ["www.example.com", "example.com"]},
            headers=_hdr(token),
        )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == ACME_ORDER_PENDING
    assert body["domains"] == ["www.example.com", "example.com"]
    assert body["challenge_type"] == "dns-01"
    assert body["certificate_id"] is None
    assert body["last_error"] is None

    # Task enqueued with the order id.
    delay.assert_called_once_with(body["id"])

    # Row persisted in pending.
    row = await db_session.get(ACMEOrder, uuid.UUID(body["id"]))
    assert row is not None
    assert row.status == ACME_ORDER_PENDING

    # Audited.
    audits = (
        (await db_session.execute(select(AuditLog).where(AuditLog.resource_type == "acme_order")))
        .scalars()
        .all()
    )
    assert any(a.action == "acme_issue" for a in audits)


@pytest.mark.asyncio
async def test_issue_requires_account(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _superadmin(db_session)
    await db_session.commit()
    with patch("app.tasks.acme.run_acme_order.delay") as delay:
        r = await client.post(
            "/api/v1/appliance/acme/issue",
            json={"domains": ["example.com"]},
            headers=_hdr(token),
        )
    assert r.status_code == 422
    delay.assert_not_called()


@pytest.mark.asyncio
async def test_issue_disabled_when_acme_not_enabled(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An account exists but acme_enabled is False (e.g. seeded directly,
    never opted in) → POST /issue is gated with 409 and no task fires."""
    _, token = await _superadmin(db_session)
    await _seed_account(db_session)  # NB: does NOT flip acme_enabled
    await db_session.commit()
    with patch("app.tasks.acme.run_acme_order.delay") as delay:
        r = await client.post(
            "/api/v1/appliance/acme/issue",
            json={"domains": ["example.com"]},
            headers=_hdr(token),
        )
    assert r.status_code == 409, r.text
    delay.assert_not_called()


@pytest.mark.asyncio
async def test_issue_rejects_unknown_challenge_type(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """dns-01 + http-01 are accepted (Phases 1/4); an unknown challenge
    type is rejected with 422 and no task fires. (tls-alpn-01 has its own
    422 test; this covers the catch-all unsupported branch.)"""
    _, token = await _superadmin(db_session)
    await _seed_account(db_session)
    await _enable_acme(db_session)
    await db_session.commit()
    with patch("app.tasks.acme.run_acme_order.delay") as delay:
        r = await client.post(
            "/api/v1/appliance/acme/issue",
            json={"domains": ["example.com"], "challenge_type": "dns-99"},
            headers=_hdr(token),
        )
    assert r.status_code == 422
    delay.assert_not_called()


@pytest.mark.asyncio
async def test_list_and_get_orders(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _superadmin(db_session)
    account = await _seed_account(db_session)
    order = ACMEOrder(
        account_id=account.id,
        domains=["example.com"],
        challenge_type="dns-01",
        status=ACME_ORDER_PENDING,
    )
    db_session.add(order)
    await db_session.commit()

    lst = await client.get("/api/v1/appliance/acme/orders", headers=_hdr(token))
    assert lst.status_code == 200
    assert any(i["id"] == str(order.id) for i in lst.json())

    one = await client.get(f"/api/v1/appliance/acme/orders/{order.id}", headers=_hdr(token))
    assert one.status_code == 200
    assert one.json()["domains"] == ["example.com"]


@pytest.mark.asyncio
async def test_get_unknown_order_404(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _superadmin(db_session)
    await db_session.commit()
    r = await client.get(f"/api/v1/appliance/acme/orders/{uuid.uuid4()}", headers=_hdr(token))
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_cancel_pending_order(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _superadmin(db_session)
    account = await _seed_account(db_session)
    order = ACMEOrder(
        account_id=account.id,
        domains=["example.com"],
        challenge_type="dns-01",
        status=ACME_ORDER_PENDING,
    )
    db_session.add(order)
    await db_session.commit()
    r = await client.post(f"/api/v1/appliance/acme/orders/{order.id}/cancel", headers=_hdr(token))
    assert r.status_code == 200
    assert r.json()["status"] == ACME_ORDER_INVALID
    assert "cancelled" in r.json()["last_error"].lower()


# ── (b) API: gating ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_unauthenticated_401(client: AsyncClient) -> None:
    r = await client.get("/api/v1/appliance/acme/account")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_module_disabled_404(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _superadmin(db_session)
    db_session.add(FeatureModule(id="security.certificates", enabled=False))
    await db_session.commit()
    feature_modules.invalidate_cache()
    r = await client.get("/api/v1/appliance/acme/account", headers=_hdr(token))
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_read_allowed_with_read_perm(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _user_with_perm(db_session, {"action": "read", "resource_type": "appliance"})
    await db_session.commit()
    r = await client.get("/api/v1/appliance/acme/account", headers=_hdr(token))
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_issue_forbidden_without_admin(client: AsyncClient, db_session: AsyncSession) -> None:
    # read-only perm: can list, but POST /issue (admin) is 403.
    _, token = await _user_with_perm(db_session, {"action": "read", "resource_type": "appliance"})
    await db_session.commit()
    with patch("app.tasks.acme.run_acme_order.delay") as delay:
        r = await client.post(
            "/api/v1/appliance/acme/issue",
            json={"domains": ["example.com"]},
            headers=_hdr(token),
        )
    assert r.status_code == 403
    delay.assert_not_called()


@pytest.mark.asyncio
async def test_put_account_forbidden_without_perm(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _user_with_perm(db_session, None)
    await db_session.commit()
    r = await client.put(
        "/api/v1/appliance/acme/account",
        json={"directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory"},
        headers=_hdr(token),
    )
    assert r.status_code == 403


# ── (c) orchestrator failure path ───────────────────────────────────


@pytest.mark.asyncio
async def test_run_order_records_invalid_on_protocol_error(
    db_session: AsyncSession,
) -> None:
    """A CA protocol failure (here at ``ensure_account``) lands the order
    in ``invalid`` with ``last_error`` populated — and ``run_order`` does
    NOT re-raise (only genuinely unexpected exceptions propagate so Celery
    can retry; protocol/DNS failures are recorded on the row)."""
    account = await _seed_account(db_session)
    order = ACMEOrder(
        account_id=account.id,
        domains=["example.com"],
        challenge_type="dns-01",
        status=ACME_ORDER_PENDING,
    )
    db_session.add(order)
    await db_session.commit()

    class _FakeClient:
        def __init__(self, *a: object, **kw: object) -> None:  # noqa: D401
            pass

        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def ensure_account(self, *, email: object = None) -> str:
            raise ACMEProtocolError(
                "newAccount rejected",
                problem={"type": "urn:ietf:params:acme:error:unauthorized"},
            )

    with patch.object(orchestrator, "ACMEClient", _FakeClient):
        status = await orchestrator.run_order(db_session, order.id)

    assert status == ACME_ORDER_INVALID
    refreshed = await db_session.get(ACMEOrder, order.id)
    assert refreshed is not None
    assert refreshed.status == ACME_ORDER_INVALID
    assert refreshed.last_error is not None
    assert "newAccount rejected" in refreshed.last_error
    assert refreshed.certificate_id is None


@pytest.mark.asyncio
async def test_run_order_robust_when_account_cascade_deleted(db_session: AsyncSession) -> None:
    """Deleting the account cascade-deletes its orders; run_order is robust.

    ``acme_order.account_id`` is ``ON DELETE CASCADE``, so an order can
    never outlive its account — deleting the account removes the order
    row too. run_order must therefore handle a now-missing order without
    crashing and return ``invalid``.
    """
    account = await _seed_account(db_session)
    order = ACMEOrder(
        account_id=account.id,
        domains=["example.com"],
        challenge_type="dns-01",
        status=ACME_ORDER_PENDING,
    )
    db_session.add(order)
    await db_session.flush()
    # Capture the id as a plain value before the cascade delete removes it.
    order_id = order.id
    await db_session.delete(account)
    await db_session.commit()  # ON DELETE CASCADE removes the order too

    status = await orchestrator.run_order(db_session, order_id)
    assert status == ACME_ORDER_INVALID
    # The order was cascade-deleted along with its account — gone, not crashed.
    refreshed = await db_session.get(ACMEOrder, order_id)
    assert refreshed is None


@pytest.mark.asyncio
async def test_run_order_idempotent_on_already_valid(db_session: AsyncSession) -> None:
    """A re-dispatched task against an already-``valid`` order is a no-op."""
    from app.models.acme_client import ACME_ORDER_VALID

    account = await _seed_account(db_session)
    order = ACMEOrder(
        account_id=account.id,
        domains=["example.com"],
        challenge_type="dns-01",
        status=ACME_ORDER_VALID,
    )
    db_session.add(order)
    await db_session.commit()

    # No engine patch needed — the early-return must fire before any CA
    # round-trip. If it didn't, the real ACMEClient would try to hit the
    # network and the test would hang/fail.
    status = await orchestrator.run_order(db_session, order.id)
    assert status == ACME_ORDER_VALID


# ── (d) Phase 3 preview ─────────────────────────────────────────────


async def _seed_managed_zone(db: AsyncSession, zone_name: str, *, driver: str = "bind9") -> None:
    """Seed a minimal managed primary zone (group + zone + primary server)
    that covers ``zone_name`` so ``resolve_managed`` reports ``managed=True``.

    ``zone_name`` is stored with the trailing dot (the FQDN form DNSZone
    uses); the resolver rstrips it before the suffix match.
    """
    from app.models.dns import DNSServer, DNSServerGroup, DNSZone

    group = DNSServerGroup(name=f"grp-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    db.add(
        DNSZone(
            group_id=group.id,
            name=zone_name,
            zone_type="primary",
            kind="forward",
        )
    )
    db.add(
        DNSServer(
            group_id=group.id,
            name=f"ns-{uuid.uuid4().hex[:6]}",
            driver=driver,
            host="ns.example.test",
            is_primary=True,
            is_enabled=True,
        )
    )
    await db.flush()


@pytest.mark.asyncio
async def test_preview_unmanaged_domain_reports_not_managed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """No managed zone covers the domain → ``managed`` False, ``zone_name``
    + ``record_name`` + ``driver`` all null, but the ``challenge_fqdn`` is
    still computed (``_acme-challenge.<domain>``)."""
    _, token = await _superadmin(db_session)
    await db_session.commit()
    r = await client.post(
        "/api/v1/appliance/acme/preview",
        json={"domains": ["nothing.unmanaged.test"]},
        headers=_hdr(token),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body) == 1
    row = body[0]
    assert row["domain"] == "nothing.unmanaged.test"
    assert row["challenge_fqdn"] == "_acme-challenge.nothing.unmanaged.test"
    assert row["managed"] is False
    assert row["zone_name"] is None
    assert row["record_name"] is None
    assert row["driver"] is None


@pytest.mark.asyncio
async def test_preview_managed_domain_reports_zone_and_driver(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A SpatiumDDI-managed primary zone covering the domain → ``managed``
    True with the covering zone name + relative TXT label + the primary
    server's driver, so the UI shows the challenge will auto-solve."""
    _, token = await _superadmin(db_session)
    await _seed_managed_zone(db_session, "example.com.", driver="powerdns")
    await db_session.commit()
    r = await client.post(
        "/api/v1/appliance/acme/preview",
        json={"domains": ["www.example.com"]},
        headers=_hdr(token),
    )
    assert r.status_code == 200, r.text
    row = r.json()[0]
    assert row["domain"] == "www.example.com"
    assert row["challenge_fqdn"] == "_acme-challenge.www.example.com"
    assert row["managed"] is True
    assert row["zone_name"] == "example.com."
    # Relative label inside the zone (challenge FQDN minus the zone suffix).
    assert row["record_name"] == "_acme-challenge.www"
    assert row["driver"] == "powerdns"


# ── (e) Phase 3 manual + Phase 4 http-01 issue ──────────────────────


@pytest.mark.asyncio
async def test_issue_allow_manual_persists_and_defaults_empty_challenges(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """``allow_manual=true`` lets an unmanaged domain be solved by the
    operator adding the TXT — the persisted order carries ``allow_manual``
    True and ``manual_challenges`` defaults to ``[]`` (the orchestrator
    populates it once it computes the records)."""
    _, token = await _superadmin(db_session)
    await _seed_account(db_session)
    await _enable_acme(db_session)
    await db_session.commit()

    with patch("app.tasks.acme.run_acme_order.delay") as delay:
        r = await client.post(
            "/api/v1/appliance/acme/issue",
            json={"domains": ["unmanaged.example.org"], "allow_manual": True},
            headers=_hdr(token),
        )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["allow_manual"] is True
    assert body["manual_challenges"] == []
    delay.assert_called_once_with(body["id"])

    row = await db_session.get(ACMEOrder, uuid.UUID(body["id"]))
    assert row is not None
    assert row.allow_manual is True
    assert list(row.manual_challenges or []) == []


@pytest.mark.asyncio
async def test_issue_http01_is_accepted(client: AsyncClient, db_session: AsyncSession) -> None:
    """Phase 4 — ``challenge_type='http-01'`` is accepted (201) and the
    persisted order records it; the CA fetches the well-known path."""
    _, token = await _superadmin(db_session)
    await _seed_account(db_session)
    await _enable_acme(db_session)
    await db_session.commit()

    with patch("app.tasks.acme.run_acme_order.delay") as delay:
        r = await client.post(
            "/api/v1/appliance/acme/issue",
            json={"domains": ["app.example.com"], "challenge_type": "http-01"},
            headers=_hdr(token),
        )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["challenge_type"] == "http-01"
    assert body["status"] == ACME_ORDER_PENDING
    delay.assert_called_once_with(body["id"])

    row = await db_session.get(ACMEOrder, uuid.UUID(body["id"]))
    assert row is not None
    assert row.challenge_type == "http-01"


@pytest.mark.asyncio
async def test_issue_tls_alpn01_rejected_422_and_no_task(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Phase 5 — ``tls-alpn-01`` is unsupported on the nginx/k3s topology;
    ``POST /issue`` returns 422 and enqueues NO task."""
    _, token = await _superadmin(db_session)
    await _seed_account(db_session)
    await _enable_acme(db_session)
    await db_session.commit()

    with patch("app.tasks.acme.run_acme_order.delay") as delay:
        r = await client.post(
            "/api/v1/appliance/acme/issue",
            json={"domains": ["app.example.com"], "challenge_type": "tls-alpn-01"},
            headers=_hdr(token),
        )
    assert r.status_code == 422, r.text
    assert "tls-alpn-01" in r.text
    delay.assert_not_called()


# ── (f) Phase 4 http-01 well-known endpoint ─────────────────────────


@pytest.mark.asyncio
async def test_http01_well_known_serves_published_keyauth(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The unauthenticated root well-known endpoint returns the exact
    key-authorization the orchestrator published for a live http-01
    challenge; an unknown token is 404 (no secret/data leakage)."""
    from app.services.acme_client import http01

    account = await _seed_account(db_session)
    order = ACMEOrder(
        account_id=account.id,
        domains=["app.example.com"],
        challenge_type="http-01",
        status=ACME_ORDER_PROCESSING,
    )
    db_session.add(order)
    await db_session.flush()

    token = "tok-" + uuid.uuid4().hex
    key_auth = f"{token}.thumbprint-stand-in"
    await http01.publish(db_session, order.id, token, key_auth)
    await db_session.commit()

    # Mounted at the app root (not under /api/v1) — hit it directly.
    ok = await client.get(f"/.well-known/acme-challenge/{token}")
    assert ok.status_code == 200, ok.text
    assert ok.text == key_auth
    # text/plain so the CA reads it verbatim.
    assert ok.headers["content-type"].startswith("text/plain")

    miss = await client.get("/.well-known/acme-challenge/does-not-exist")
    assert miss.status_code == 404


# ── (g) Phase 2 renewal beat task ───────────────────────────────────


async def _seed_le_cert(db: AsyncSession, *, days_to_expiry: int, sans: list[str]):
    """Seed an active letsencrypt ApplianceCertificate expiring within
    ``days_to_expiry`` days. Returns the row (flushed, not committed)."""
    from datetime import UTC, datetime, timedelta

    from app.models.appliance import CERT_SOURCE_LETSENCRYPT, ApplianceCertificate

    cert = ApplianceCertificate(
        name=f"le-{uuid.uuid4().hex[:8]}",
        source=CERT_SOURCE_LETSENCRYPT,
        key_encrypted=encrypt_str("-stub-key-"),
        subject_cn=sans[0],
        sans_json=list(sans),
        is_active=True,
        valid_to=datetime.now(UTC) + timedelta(days=days_to_expiry),
    )
    db.add(cert)
    await db.flush()
    return cert


@pytest.mark.asyncio
async def test_renew_due_creates_order_and_is_idempotent(
    db_session: AsyncSession,
) -> None:
    """``_renew`` re-issues an active LE cert within the 30 d window: it
    creates exactly one ``pending`` ACMEOrder for the due cert's SANs and
    enqueues ``run_acme_order``. A second sweep (the order now pending) is
    a no-op — no duplicate order, no second enqueue."""
    from app.tasks import acme as acme_tasks

    # acme_enabled + acme_auto_renew (auto_renew defaults True; set both
    # explicitly so the gate is unambiguous), an account, and a due cert.
    settings = await db_session.get(PlatformSettings, 1)
    if settings is None:
        settings = PlatformSettings(id=1)
        db_session.add(settings)
    settings.acme_enabled = True
    settings.acme_auto_renew = True
    settings.acme_domains = []  # force the fall-back to the cert's own SANs
    await _seed_account(db_session)
    await _seed_le_cert(db_session, days_to_expiry=10, sans=["x.example.com"])
    # The renewal task runs in its own task_session — commit the seed so
    # that separate session sees it.
    await db_session.commit()

    with patch.object(acme_tasks.run_acme_order, "delay") as delay:
        result = await acme_tasks._renew()
        assert result == "renewed=1", result
        assert delay.call_count == 1
        enqueued_id = delay.call_args.args[0]

        # Exactly one pending order for the due cert's SANs.
        db_session.expire_all()
        orders = (
            (
                await db_session.execute(
                    select(ACMEOrder).where(ACMEOrder.status == ACME_ORDER_PENDING)
                )
            )
            .scalars()
            .all()
        )
        assert len(orders) == 1
        assert orders[0].domains == ["x.example.com"]
        assert orders[0].challenge_type == "dns-01"
        assert orders[0].allow_manual is False
        assert str(orders[0].id) == enqueued_id

        # Idempotent: the order is now in-flight (pending) → second sweep
        # skips it, creating no duplicate and enqueuing nothing more.
        delay.reset_mock()
        result2 = await acme_tasks._renew()
        assert result2 == "renewed=0", result2
        delay.assert_not_called()

    db_session.expire_all()
    still_one = (
        (await db_session.execute(select(ACMEOrder).where(ACMEOrder.status == ACME_ORDER_PENDING)))
        .scalars()
        .all()
    )
    assert len(still_one) == 1


@pytest.mark.asyncio
async def test_renew_skips_when_auto_renew_disabled(
    db_session: AsyncSession,
) -> None:
    """``acme_auto_renew=False`` short-circuits the sweep even with a due
    cert + account present (the operator opted out of auto-renewal)."""
    from app.tasks import acme as acme_tasks

    settings = await db_session.get(PlatformSettings, 1)
    if settings is None:
        settings = PlatformSettings(id=1)
        db_session.add(settings)
    settings.acme_enabled = True
    settings.acme_auto_renew = False
    await _seed_account(db_session)
    await _seed_le_cert(db_session, days_to_expiry=5, sans=["y.example.com"])
    await db_session.commit()

    with patch.object(acme_tasks.run_acme_order, "delay") as delay:
        result = await acme_tasks._renew()
    assert result == "disabled"
    delay.assert_not_called()


# ── (h) Phase 2 secret_expiring alert covers the LE Web-UI cert ──────


@pytest.mark.asyncio
async def test_secret_expiring_covers_letsencrypt_web_cert(
    db_session: AsyncSession,
) -> None:
    """The shipped ``secret_expiring`` matcher surfaces a near-expiry active
    LE cert under an ``appliance_cert_tls:<id>`` subject (distinct from the
    supervisor ``appliance_cert:`` prefix), so a stuck auto-renewal pages."""
    from datetime import UTC, datetime

    from app.models.alerts import AlertRule
    from app.services.alerts import _matching_secret_expiring_subjects

    now = datetime.now(UTC)
    rule = AlertRule(
        name="Secret expiry",
        rule_type="secret_expiring",
        severity="warning",
        threshold_days=30,
        enabled=True,
    )
    db_session.add(rule)
    near = await _seed_le_cert(db_session, days_to_expiry=5, sans=["ui.example.com"])
    far = await _seed_le_cert(db_session, days_to_expiry=365, sans=["far.example.com"])
    await db_session.commit()

    subjects = await _matching_secret_expiring_subjects(db_session, rule, now)
    ids = {sid for sid, _disp, _msg, _sev in subjects}
    assert f"appliance_cert_tls:{near.id}" in ids
    assert f"appliance_cert_tls:{far.id}" not in ids


# ── (i) Manual DNS-01 propagation check queries authoritative NS ─────


@pytest.mark.asyncio
async def test_poll_public_txt_requires_every_authoritative_ns() -> None:
    """#1532 — the manual-fallback propagation gate requires the TXT on
    EVERY authoritative nameserver, queried directly — not on the
    worker's own resolver, which can serve the record (split-horizon /
    cache) while the servers the CA queries don't have it yet."""
    from unittest.mock import AsyncMock

    from app.services.acme_client import dns01

    fqdn = "_acme-challenge.www.example.com"

    async def _ips(host: str) -> list[str]:
        return {"ns1.example.com": ["192.0.2.1"], "ns2.example.com": ["192.0.2.2"]}[host]

    async def _txt_complete(ip: str, name: str) -> set[str]:
        return {"expected-token"}

    with (
        patch.object(
            dns01,
            "_authoritative_ns_hosts",
            new=AsyncMock(return_value=["ns1.example.com", "ns2.example.com"]),
        ),
        patch.object(dns01, "_ns_host_ips", new=_ips),
        patch.object(dns01, "_txt_values_at", new=_txt_complete) as txt_at,
    ):
        assert await dns01.poll_public_txt(fqdn, "expected-token", timeout=5, interval=0) is True
    # Both authoritative servers were asked directly.
    assert {c.args[0] for c in txt_at.call_args_list} == {"192.0.2.1", "192.0.2.2"}

    async def _txt_missing_on_one(ip: str, name: str) -> set[str]:
        return {"expected-token"} if ip == "192.0.2.1" else set()

    with (
        patch.object(
            dns01,
            "_authoritative_ns_hosts",
            new=AsyncMock(return_value=["ns1.example.com", "ns2.example.com"]),
        ),
        patch.object(dns01, "_ns_host_ips", new=_ips),
        patch.object(dns01, "_txt_values_at", new=_txt_missing_on_one),
    ):
        # One authoritative server lacks the record → keep waiting
        # (here: until the short timeout) instead of signalling ready.
        assert (
            await dns01.poll_public_txt(fqdn, "expected-token", timeout=0.2, interval=0.01) is False
        )


@pytest.mark.asyncio
async def test_authoritative_ns_hosts_walks_up_to_the_zone() -> None:
    """#1532 — the NS set is found by walking up from the challenge FQDN
    to the first level that answers NS (the zone apex)."""
    from types import SimpleNamespace

    from app.services.acme_client import dns01

    class _FakeResolver:
        lifetime: float = 0.0

        async def resolve(self, name: str, rdtype: str):  # noqa: ANN202
            assert rdtype == "NS"
            if name == "example.com":
                return [
                    SimpleNamespace(target="ns1.example.com."),
                    SimpleNamespace(target="ns2.example.com."),
                ]
            raise RuntimeError("no NS here")

    with patch("dns.asyncresolver.Resolver", _FakeResolver):
        hosts = await dns01._authoritative_ns_hosts("_acme-challenge.www.example.com")
    assert hosts == ["ns1.example.com", "ns2.example.com"]
