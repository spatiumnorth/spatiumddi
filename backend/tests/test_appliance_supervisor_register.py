"""Integration tests for ``POST /api/v1/appliance/supervisor/register`` (#170 A2).

Covers:

* Feature flag — disabled returns 404 (the "shape an attacker probing
  for the path would see if it didn't exist").
* Happy path — claims the pairing code, creates an Appliance row in
  pending_approval, emits the two audit rows.
* Re-register from cache (same pubkey) — idempotent; doesn't burn a
  fresh pairing code; updates last_seen.
* Invalid pubkey — 422 BEFORE the pairing code is consumed.
* Pairing-code failure modes — all collapse to a single generic 403
  (unknown / expired / claimed / revoked).
* Pairing-code from a different agent kind (today's dns/dhcp/both)
  works for the supervisor too — the supervisor register flow is
  kind-agnostic.

The 500 ms failure friction is patched to 0 s in tests where it'd
just pad runtime.
"""

from __future__ import annotations

import base64
import hashlib
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
    APPLIANCE_STATE_PENDING_APPROVAL,
    Appliance,
    PairingClaim,
    PairingCode,
)
from app.models.audit import AuditLog
from app.models.settings import PlatformSettings

# ── Helpers ────────────────────────────────────────────────────────


def _new_keypair() -> tuple[Ed25519PrivateKey, bytes, str, str]:
    """Return (priv, der, fingerprint_hex, b64-encoded-der)."""
    priv = Ed25519PrivateKey.generate()
    der = priv.public_key().public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    fp = hashlib.sha256(der).hexdigest()
    b64 = base64.b64encode(der).decode("ascii")
    return priv, der, fp, b64


async def _make_pairing_code(
    db: AsyncSession,
    *,
    code: str = "12345678",
    expires_in_minutes: int = 15,
    persistent: bool = False,
    enabled: bool = True,
    max_claims: int | None = None,
    used: bool = False,
    revoked: bool = False,
) -> PairingCode:
    row = PairingCode(
        id=uuid.uuid4(),
        code_hash=hashlib.sha256(code.encode("ascii")).hexdigest(),
        code_last_two=code[-2:],
        persistent=persistent,
        enabled=enabled,
        max_claims=max_claims,
        expires_at=datetime.now(UTC) + timedelta(minutes=expires_in_minutes),
        revoked_at=datetime.now(UTC) if revoked else None,
    )
    db.add(row)
    await db.flush()
    if used:
        # Wave A3 — single-use status is derived from any
        # ``pairing_claim`` row, not a column on pairing_code. Plant a
        # fake appliance + claim row so the code reads as already-used.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        fake_priv = Ed25519PrivateKey.generate()
        fake_der = fake_priv.public_key().public_bytes(
            encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
        )
        fake_fp = hashlib.sha256(fake_der).hexdigest()
        fake_appliance = Appliance(
            id=uuid.uuid4(),
            hostname="prior-supervisor",
            public_key_der=fake_der,
            public_key_fingerprint=fake_fp,
            paired_via_code_id=row.id,
            state=APPLIANCE_STATE_PENDING_APPROVAL,
        )
        db.add(fake_appliance)
        db.add(
            PairingClaim(
                pairing_code_id=row.id,
                appliance_id=fake_appliance.id,
                hostname="prior-supervisor",
            )
        )
        await db.flush()
    return row


async def _enable_supervisor_registration(db: AsyncSession) -> None:
    stmt = select(PlatformSettings).where(PlatformSettings.id == 1)
    row = (await db.execute(stmt)).scalar_one_or_none()
    if row is None:
        row = PlatformSettings(id=1, supervisor_registration_enabled=True)
        db.add(row)
    else:
        row.supervisor_registration_enabled = True
    await db.flush()


# ── Fixtures ───────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _no_failure_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(supervisor_mod, "_CONSUME_FAILURE_DELAY_S", 0.0)


@pytest.fixture(autouse=True)
def _no_attempt_throttle(monkeypatch: pytest.MonkeyPatch) -> None:
    """These tests are about the code checks, not the attempt budget (#1356),
    which ``test_supervisor_register_throttle_1356.py`` covers. Real Redis
    counters would carry failures from one test into the next."""

    async def _claim(_ip: object) -> tuple[bool, int]:
        return True, 1

    async def _refund(_ip: object) -> None:
        return None

    monkeypatch.setattr(supervisor_mod, "claim_pairing_attempt", _claim)
    monkeypatch.setattr(supervisor_mod, "refund_pairing_attempt", _refund)


# ── Tests ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_register_404s_while_flag_disabled(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """Default state — flag is FALSE on a fresh install. Even with a
    valid pairing code + pubkey, the endpoint must return 404, same
    shape as "endpoint does not exist"."""
    await _make_pairing_code(db_session, code="11111111")
    await db_session.commit()
    _, _, _, pubkey_b64 = _new_keypair()

    resp = await client.post(
        "/api/v1/appliance/supervisor/register",
        json={
            "pairing_code": "11111111",
            "hostname": "dns-east-1",
            "public_key_der_b64": pubkey_b64,
            "supervisor_version": "2026.05.14-1",
        },
    )
    assert resp.status_code == 404, resp.text

    # Pairing code untouched — no claim row written.
    claim_count = (await db_session.execute(select(PairingClaim))).scalars().first()
    assert claim_count is None
    assert (await db_session.execute(select(Appliance))).scalars().first() is None


@pytest.mark.asyncio
async def test_register_happy_path(db_session: AsyncSession, client: AsyncClient) -> None:
    await _enable_supervisor_registration(db_session)
    code_row = await _make_pairing_code(db_session, code="22222222")
    await db_session.commit()

    _, _, fingerprint, pubkey_b64 = _new_keypair()

    resp = await client.post(
        "/api/v1/appliance/supervisor/register",
        json={
            "pairing_code": "22222222",
            "hostname": "dns-east-1",
            "public_key_der_b64": pubkey_b64,
            "supervisor_version": "2026.05.14-1",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    appliance_id = uuid.UUID(body["appliance_id"])
    assert body["state"] == APPLIANCE_STATE_PENDING_APPROVAL
    assert body["public_key_fingerprint"] == fingerprint

    # Pairing claim row written (replaces #169's used_at columns).
    claim = (
        (
            await db_session.execute(
                select(PairingClaim).where(PairingClaim.pairing_code_id == code_row.id)
            )
        )
        .scalars()
        .one()
    )
    assert claim.hostname == "dns-east-1"
    assert claim.appliance_id == appliance_id

    # Appliance row written.
    appliance = await db_session.get(Appliance, appliance_id)
    assert appliance is not None
    assert appliance.hostname == "dns-east-1"
    assert appliance.public_key_fingerprint == fingerprint
    assert appliance.supervisor_version == "2026.05.14-1"
    assert appliance.state == APPLIANCE_STATE_PENDING_APPROVAL
    assert appliance.paired_via_code_id == code_row.id

    # Both audit rows present (claim + registration_pending).
    audit_actions = {
        row.action
        for row in (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_id.in_([str(code_row.id), str(appliance_id)])
                )
            )
        ).scalars()
    }
    assert "appliance.pairing_code_claimed" in audit_actions
    assert "appliance.registration_pending" in audit_actions


@pytest.mark.asyncio
async def test_register_capabilities_round_trip_every_known_flag(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """Regression test (bug caught live testing the Technitium driver,
    2026-07): ``SupervisorCapabilities`` is a STRICT Pydantic model, not
    a passthrough dict — despite the class docstring's "ignores keys it
    doesn't recognise" framing, Pydantic v2 silently DROPS any field the
    model doesn't explicitly declare. A capability the supervisor sends
    but this model doesn't list never reaches the stored
    ``Appliance.capabilities`` JSONB, which makes the Fleet UI's role
    picker report "supervisor doesn't advertise can_run_X=true" even
    though the real supervisor is sending it. Every ``can_run_dns_*``
    flag must be explicitly declared here — this test locks the full
    set so adding a fourth DNS driver without updating the model fails
    loudly instead of silently misreporting capabilities in the field.
    """
    await _enable_supervisor_registration(db_session)
    code_row = await _make_pairing_code(db_session, code="33333333")
    await db_session.commit()

    _, _, _, pubkey_b64 = _new_keypair()

    resp = await client.post(
        "/api/v1/appliance/supervisor/register",
        json={
            "pairing_code": "33333333",
            "hostname": "dns-cap-test",
            "public_key_der_b64": pubkey_b64,
            "supervisor_version": "2026.07.28-1",
            "capabilities": {
                "can_run_dns_bind9": True,
                "can_run_dns_powerdns": True,
                "can_run_dns_technitium": True,
                "can_run_dhcp": True,
                "can_run_looking_glass": True,
                "can_run_observer": True,
                "has_baked_images": True,
            },
        },
    )
    assert resp.status_code == 200, resp.text
    appliance_id = uuid.UUID(resp.json()["appliance_id"])
    del code_row

    appliance = await db_session.get(Appliance, appliance_id)
    assert appliance is not None
    caps = appliance.capabilities
    for flag in (
        "can_run_dns_bind9",
        "can_run_dns_powerdns",
        "can_run_dns_technitium",
        "can_run_dhcp",
        "can_run_looking_glass",
        "can_run_observer",
        "has_baked_images",
    ):
        assert caps.get(flag) is True, f"{flag} did not survive SupervisorCapabilities round-trip"


@pytest.mark.asyncio
async def test_register_is_idempotent_for_same_pubkey(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """Crash-recovery shape — supervisor restarts before persisting
    its appliance_id, retries with the SAME pubkey. Endpoint must
    short-circuit to "you already exist" rather than refusing
    (because the code is now ``used_at != None``)."""
    await _enable_supervisor_registration(db_session)
    await _make_pairing_code(db_session, code="33333333")
    await db_session.commit()

    _, _, _, pubkey_b64 = _new_keypair()

    first = await client.post(
        "/api/v1/appliance/supervisor/register",
        json={
            "pairing_code": "33333333",
            "hostname": "dns-east-2",
            "public_key_der_b64": pubkey_b64,
            "supervisor_version": "2026.05.14-1",
        },
    )
    assert first.status_code == 200, first.text
    first_id = first.json()["appliance_id"]

    # Same pubkey, fresh code (but doesn't matter — flow shouldn't
    # touch the code at all on the idempotent path).
    await _make_pairing_code(db_session, code="44444444")
    await db_session.commit()

    second = await client.post(
        "/api/v1/appliance/supervisor/register",
        json={
            "pairing_code": "44444444",
            "hostname": "dns-east-2-renamed",  # ignored on idempotent path
            "public_key_der_b64": pubkey_b64,
            "supervisor_version": "2026.05.14-2",
        },
    )
    assert second.status_code == 200, second.text
    assert second.json()["appliance_id"] == first_id

    # The SECOND pairing code is still unused — no claim row written
    # against it (idempotent path short-circuits before touching).
    stmt = select(PairingCode).where(
        PairingCode.code_hash == hashlib.sha256(b"44444444").hexdigest()
    )
    second_code = (await db_session.execute(stmt)).scalar_one()
    second_claims = (
        (
            await db_session.execute(
                select(PairingClaim).where(PairingClaim.pairing_code_id == second_code.id)
            )
        )
        .scalars()
        .all()
    )
    assert second_claims == []

    # Version was updated on the existing row.
    appliance = await db_session.get(Appliance, uuid.UUID(first_id))
    assert appliance is not None
    assert appliance.supervisor_version == "2026.05.14-2"


@pytest.mark.asyncio
async def test_reregister_mints_token_for_certd_row(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """#411 — re-register-from-cache returns a FRESH session token even after
    the row has a cert (post-approval), so an approved supervisor that lost
    its token can recover it. Pre-#411 this returned "" for cert'd rows, which
    — once #400 C1 removed the approved-state heartbeat bypass — left such a
    box with no usable credential and 403'd every heartbeat."""
    await _enable_supervisor_registration(db_session)
    await _make_pairing_code(db_session, code="55555555")
    await db_session.commit()

    _, _, _, pubkey_b64 = _new_keypair()
    first = await client.post(
        "/api/v1/appliance/supervisor/register",
        json={
            "pairing_code": "55555555",
            "hostname": "cp-recover",
            "public_key_der_b64": pubkey_b64,
        },
    )
    assert first.status_code == 200, first.text

    # Simulate approval having issued a cert on the row.
    appliance = await db_session.get(Appliance, uuid.UUID(first.json()["appliance_id"]))
    assert appliance is not None
    appliance.cert_pem = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"
    await db_session.commit()

    # Re-register the SAME pubkey — must hand back a usable (non-empty) token.
    second = await client.post(
        "/api/v1/appliance/supervisor/register",
        json={
            "pairing_code": "55555555",
            "hostname": "cp-recover",
            "public_key_der_b64": pubkey_b64,
        },
    )
    assert second.status_code == 200, second.text
    assert second.json()["session_token"], "re-register must mint a fresh token for a cert'd row"


@pytest.mark.asyncio
async def test_register_rejects_malformed_pubkey_without_burning_code(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    await _enable_supervisor_registration(db_session)
    code_row = await _make_pairing_code(db_session, code="55555555")
    await db_session.commit()

    resp = await client.post(
        "/api/v1/appliance/supervisor/register",
        json={
            "pairing_code": "55555555",
            "hostname": "dns-east-3",
            "public_key_der_b64": "not-base64-at-all-$$$",
        },
    )
    assert resp.status_code == 422, resp.text

    # No claim row written — 422 hits before the pairing-code touch.
    claims = (
        (
            await db_session.execute(
                select(PairingClaim).where(PairingClaim.pairing_code_id == code_row.id)
            )
        )
        .scalars()
        .all()
    )
    assert claims == []


@pytest.mark.asyncio
async def test_register_rejects_non_ed25519_pubkey(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """An RSA pubkey is parseable DER but the wrong algorithm —
    must 422."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    await _enable_supervisor_registration(db_session)
    await _make_pairing_code(db_session, code="66666666")
    await db_session.commit()

    rsa_pub = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    rsa_der = rsa_pub.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)
    rsa_b64 = base64.b64encode(rsa_der).decode("ascii")

    resp = await client.post(
        "/api/v1/appliance/supervisor/register",
        json={
            "pairing_code": "66666666",
            "hostname": "dns-east-4",
            "public_key_der_b64": rsa_b64,
        },
    )
    assert resp.status_code == 422
    assert "Ed25519" in resp.text


@pytest.mark.parametrize(
    "state",
    [
        pytest.param("unknown", id="unknown_code"),
        pytest.param("used", id="already_used"),
        pytest.param("revoked", id="revoked"),
        pytest.param("expired", id="expired"),
    ],
)
@pytest.mark.asyncio
async def test_register_collapses_pairing_failure_modes_to_403(
    db_session: AsyncSession, client: AsyncClient, state: str
) -> None:
    await _enable_supervisor_registration(db_session)

    if state == "unknown":
        code = "99999999"
        # no row inserted
    elif state == "used":
        await _make_pairing_code(db_session, code="77777771", used=True)
        code = "77777771"
    elif state == "revoked":
        await _make_pairing_code(db_session, code="77777772", revoked=True)
        code = "77777772"
    else:  # expired
        await _make_pairing_code(db_session, code="77777773", expires_in_minutes=-5)
        code = "77777773"
    await db_session.commit()

    _, _, _, pubkey_b64 = _new_keypair()
    resp = await client.post(
        "/api/v1/appliance/supervisor/register",
        json={
            "pairing_code": code,
            "hostname": f"dns-{state}",
            "public_key_der_b64": pubkey_b64,
        },
    )
    assert resp.status_code == 403, resp.text
    # All four reasons return the same generic message so timing-
    # invariant + shape-invariant.
    assert "invalid, expired, or already used" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_register_persistent_code_admits_multiple_supervisors(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """A3 persistent-code semantics — same code can be claimed by N
    distinct supervisors; the pairing_claim child table accumulates
    one row per claim."""
    await _enable_supervisor_registration(db_session)
    code_row = await _make_pairing_code(db_session, code="88888888", persistent=True, max_claims=3)
    await db_session.commit()

    # Three distinct supervisors all claim the same persistent code.
    appliance_ids: list[str] = []
    for n in range(3):
        _, _, _, pubkey_b64 = _new_keypair()
        resp = await client.post(
            "/api/v1/appliance/supervisor/register",
            json={
                "pairing_code": "88888888",
                "hostname": f"dns-edge-{n}",
                "public_key_der_b64": pubkey_b64,
            },
        )
        assert resp.status_code == 200, resp.text
        appliance_ids.append(resp.json()["appliance_id"])

    # Three claim rows + three appliance rows, all distinct.
    claims = (
        (
            await db_session.execute(
                select(PairingClaim).where(PairingClaim.pairing_code_id == code_row.id)
            )
        )
        .scalars()
        .all()
    )
    assert len(claims) == 3
    assert {str(c.appliance_id) for c in claims} == set(appliance_ids)

    # Fourth claim hits max_claims → 403 (exhausted).
    _, _, _, pubkey_b64 = _new_keypair()
    resp = await client.post(
        "/api/v1/appliance/supervisor/register",
        json={
            "pairing_code": "88888888",
            "hostname": "dns-edge-overflow",
            "public_key_der_b64": pubkey_b64,
        },
    )
    assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_register_persistent_disabled_code_rejects_new_claims(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """Persistent code with enabled=False — new claims get 403; the
    audit_log denial reason carries 'disabled'."""
    await _enable_supervisor_registration(db_session)
    await _make_pairing_code(db_session, code="55555555", persistent=True, enabled=False)
    await db_session.commit()
    _, _, _, pubkey_b64 = _new_keypair()

    resp = await client.post(
        "/api/v1/appliance/supervisor/register",
        json={
            "pairing_code": "55555555",
            "hostname": "dns-paused-fleet",
            "public_key_der_b64": pubkey_b64,
        },
    )
    assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_register_with_auto_approve_code_signs_cert_inline(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """#272 Phase 1 — codes minted via /self-register-bootstrap carry
    ``auto_approve=True``. The register endpoint signs the cert + flips
    state to ``approved`` inline so the operator doesn't have to manually
    approve their own local supervisor."""
    await _enable_supervisor_registration(db_session)
    code_row = await _make_pairing_code(db_session, code="77777777")
    code_row.auto_approve = True
    await db_session.commit()

    _, _, _, pubkey_b64 = _new_keypair()
    resp = await client.post(
        "/api/v1/appliance/supervisor/register",
        json={
            "pairing_code": "77777777",
            "hostname": "test1",
            "public_key_der_b64": pubkey_b64,
            "appliance_variant": "full-stack",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["state"] == "approved"

    appliance = await db_session.get(Appliance, uuid.UUID(body["appliance_id"]))
    assert appliance is not None
    assert appliance.state == "approved"
    assert appliance.cert_pem is not None  # cert signed inline
    assert appliance.cert_serial is not None
    assert appliance.cert_expires_at is not None
    assert appliance.approved_at is not None
    assert appliance.approved_by_user_id is None  # auto-approved (no admin)
    # Variant stamped. #272 — DNS/DHCP are no longer auto-assigned at
    # register; the operator enables them per node via the Fleet role
    # toggle, so a fresh control-plane node starts with no roles.
    assert appliance.appliance_variant == "full-stack"
    assert appliance.assigned_roles == []


@pytest.mark.asyncio
async def test_register_operator_typed_code_does_not_auto_approve(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """Codes minted via the Fleet → Pairing tab default to
    ``auto_approve=False``. The register endpoint keeps the manual
    approve flow for any remote pairing."""
    await _enable_supervisor_registration(db_session)
    await _make_pairing_code(db_session, code="88888888")
    await db_session.commit()

    _, _, _, pubkey_b64 = _new_keypair()
    resp = await client.post(
        "/api/v1/appliance/supervisor/register",
        json={
            "pairing_code": "88888888",
            "hostname": "dns-east-1",
            "public_key_der_b64": pubkey_b64,
            "appliance_variant": "application",
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == APPLIANCE_STATE_PENDING_APPROVAL

    appliance = await db_session.get(Appliance, uuid.UUID(resp.json()["appliance_id"]))
    assert appliance is not None
    assert appliance.cert_pem is None  # NOT auto-approved
    assert appliance.appliance_variant == "application"
    # application variant has no fixed roles — operator picks.
    assert appliance.assigned_roles == []


@pytest.mark.asyncio
async def test_register_no_expiry_persistent_code_accepts(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """A3 lets persistent codes carry expires_at=NULL ('no expiry').
    The endpoint must not 403 such a code as 'expired'."""
    await _enable_supervisor_registration(db_session)
    row = PairingCode(
        id=uuid.uuid4(),
        code_hash=hashlib.sha256(b"66666660").hexdigest(),
        code_last_two="60",
        persistent=True,
        enabled=True,
        expires_at=None,
    )
    db_session.add(row)
    await db_session.commit()

    _, _, _, pubkey_b64 = _new_keypair()
    resp = await client.post(
        "/api/v1/appliance/supervisor/register",
        json={
            "pairing_code": "66666660",
            "hostname": "dns-no-expiry",
            "public_key_der_b64": pubkey_b64,
        },
    )
    assert resp.status_code == 200, resp.text
