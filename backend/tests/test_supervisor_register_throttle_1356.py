"""Supervisor registration has an attempt budget, and stops flooding the audit log (#1356).

``POST /appliance/supervisor/register`` is unauthenticated: an 8-digit
pairing code is the credential. Nothing limited the guesses beyond a fixed
0.5 s delay, persistent codes defaulted to no expiry, and every wrong guess
committed its own audit row.
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

import app.core.auth_throttle as throttle
from app.api.v1.appliance import supervisor as supervisor_mod
from app.models.appliance import PairingCode
from app.models.audit import AuditLog
from app.models.settings import PlatformSettings

_URL = "/api/v1/appliance/supervisor/register"


def _body(code: str) -> dict[str, str]:
    der = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)
    )
    return {
        "pairing_code": code,
        "hostname": f"sup-{uuid.uuid4().hex[:6]}",
        "public_key_der_b64": base64.b64encode(der).decode("ascii"),
    }


async def _enable(db: AsyncSession) -> None:
    row = (
        await db.execute(select(PlatformSettings).where(PlatformSettings.id == 1))
    ).scalar_one_or_none()
    if row is None:
        db.add(PlatformSettings(id=1, supervisor_registration_enabled=True))
    else:
        row.supervisor_registration_enabled = True
    await db.commit()


async def _code(db: AsyncSession, code: str, *, revoked: bool = False) -> PairingCode:
    row = PairingCode(
        id=uuid.uuid4(),
        code_hash=hashlib.sha256(code.encode("ascii")).hexdigest(),
        code_last_two=code[-2:],
        persistent=False,
        enabled=True,
        expires_at=datetime.now(UTC) + timedelta(minutes=15),
        revoked_at=datetime.now(UTC) if revoked else None,
    )
    db.add(row)
    await db.commit()
    return row


@pytest.fixture
def budget(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """Drive the handler's view of the attempt budget."""
    monkeypatch.setattr(supervisor_mod, "_CONSUME_FAILURE_DELAY_S", 0.0)
    state: dict[str, object] = {"claim": (True, 1, 1), "refunds": 0, "down": False}

    async def _claim(_ip: object) -> tuple[bool, int, int]:
        if state["down"]:
            raise throttle.PairingThrottleUnavailable
        return state["claim"]  # type: ignore[return-value]

    async def _refund(_ip: object) -> None:
        state["refunds"] = int(state["refunds"]) + 1  # type: ignore[arg-type]

    monkeypatch.setattr(supervisor_mod, "claim_pairing_attempt", _claim)
    monkeypatch.setattr(supervisor_mod, "refund_pairing_attempt", _refund)
    return state


async def _audits(db: AsyncSession, action: str) -> list[AuditLog]:
    return list(
        (await db.execute(select(AuditLog).where(AuditLog.action == action))).scalars().all()
    )


@pytest.mark.asyncio
async def test_a_spent_budget_is_429_and_audited_once(
    client: AsyncClient, db_session: AsyncSession, budget: dict[str, object]
) -> None:
    await _enable(db_session)
    budget["claim"] = (False, throttle.PAIRING_FAIL_MAX_PER_IP + 1, -1)
    r = await client.post(_URL, json=_body("11112222"))
    assert r.status_code == 429, r.text
    budget["claim"] = (False, throttle.PAIRING_FAIL_MAX_PER_IP + 2, -1)
    r = await client.post(_URL, json=_body("11112223"))
    assert r.status_code == 429, r.text
    rows = await _audits(db_session, "appliance.supervisor_register_throttled")
    assert len(rows) == 1
    assert rows[0].new_value == {
        "scope": "address",
        "failures_in_window": throttle.PAIRING_FAIL_MAX_PER_IP,
    }


@pytest.mark.asyncio
async def test_the_install_wide_limit_tripping_is_audited_once(
    client: AsyncClient, db_session: AsyncSession, budget: dict[str, object]
) -> None:
    """Spreading guesses over many addresses trips the global budget with no
    address ever reaching its own, so that trip needs its own audit row."""
    await _enable(db_session)
    for g in (throttle.PAIRING_FAIL_MAX_GLOBAL + 1, throttle.PAIRING_FAIL_MAX_GLOBAL + 2):
        budget["claim"] = (False, 0, g)
        r = await client.post(_URL, json=_body("11112224"))
        assert r.status_code == 429, r.text
    [row] = await _audits(db_session, "appliance.supervisor_register_throttled")
    assert row.new_value == {
        "scope": "install",
        "failures_in_window": throttle.PAIRING_FAIL_MAX_GLOBAL,
    }


@pytest.mark.asyncio
async def test_an_unreadable_budget_refuses(
    client: AsyncClient, db_session: AsyncSession, budget: dict[str, object]
) -> None:
    await _enable(db_session)
    await _code(db_session, "33334444")
    budget["down"] = True
    r = await client.post(_URL, json=_body("33334444"))
    assert r.status_code == 503, r.text


@pytest.mark.asyncio
async def test_only_the_first_unknown_guess_per_window_is_audited(
    client: AsyncClient, db_session: AsyncSession, budget: dict[str, object]
) -> None:
    await _enable(db_session)
    for n in (1, 2, 3):
        budget["claim"] = (True, n, n)
        r = await client.post(_URL, json=_body(f"9999000{n}"))
        assert r.status_code == 403, r.text
    assert len(await _audits(db_session, "appliance.supervisor_register_denied")) == 1


@pytest.mark.asyncio
async def test_a_known_code_failing_is_always_audited(
    client: AsyncClient, db_session: AsyncSession, budget: dict[str, object]
) -> None:
    """A revoked code being used is an event, not a guess."""
    await _enable(db_session)
    await _code(db_session, "55556666", revoked=True)
    budget["claim"] = (True, 7, 7)
    r = await client.post(_URL, json=_body("55556666"))
    assert r.status_code == 403, r.text
    [row] = await _audits(db_session, "appliance.supervisor_register_denied")
    assert row.new_value["reason"] == "revoked"


@pytest.mark.asyncio
async def test_a_right_code_refunds_its_attempt(
    client: AsyncClient, db_session: AsyncSession, budget: dict[str, object]
) -> None:
    await _enable(db_session)
    await _code(db_session, "77778888")
    r = await client.post(_URL, json=_body("77778888"))
    assert r.status_code == 200, r.text
    assert budget["refunds"] == 1


# ── The budget itself, against Redis ────────────────────────────────────────


@pytest.fixture
async def redis_keys(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    from app.config import settings
    from app.core.redis_client import make_async_redis

    tag = uuid.uuid4().hex
    ip_key, global_key = f"pair_rl_test:ip:{tag}", f"pair_rl_test:global:{tag}"
    monkeypatch.setattr(throttle, "_pairing_keys", lambda _ip: (ip_key, global_key))
    r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
    try:
        yield r, ip_key, global_key
        await r.delete(ip_key, global_key)
    finally:
        await r.aclose()


@pytest.mark.asyncio
async def test_claim_and_refund_against_redis(redis_keys) -> None:  # type: ignore[no-untyped-def]
    r, ip_key, global_key = redis_keys

    results = [await throttle.claim_pairing_attempt("192.0.2.9") for _ in range(11)]
    assert [ok for ok, _, _ in results] == [True] * 10 + [False]
    assert results[-1][1] == 11
    assert results[-1][2] == -1  # an address over its budget isn't charged globally

    await throttle.refund_pairing_attempt("192.0.2.9")
    ok, count, _ = await throttle.claim_pairing_attempt("192.0.2.9")
    assert (ok, count) == (False, 11)  # 11 - 1 refunded + 1 claimed

    for key in (ip_key, global_key):
        assert 0 < await r.ttl(key) <= 15 * 60  # never left without expiry


@pytest.mark.asyncio
async def test_one_address_cannot_spend_the_install_budget(redis_keys) -> None:  # type: ignore[no-untyped-def]
    """Refused requests check no code. Charging them globally would let one
    address lock every registration out, right codes included."""
    r, _ip_key, global_key = redis_keys
    for _ in range(throttle.PAIRING_FAIL_MAX_GLOBAL + 5):
        await throttle.claim_pairing_attempt("192.0.2.10")
    assert int(await r.get(global_key)) == throttle.PAIRING_FAIL_MAX_PER_IP


@pytest.mark.asyncio
async def test_a_global_refusal_gives_the_address_its_attempt_back(redis_keys) -> None:  # type: ignore[no-untyped-def]
    r, ip_key, global_key = redis_keys
    await r.set(global_key, throttle.PAIRING_FAIL_MAX_GLOBAL, ex=900)
    ok, ip_count, global_count = await throttle.claim_pairing_attempt("192.0.2.11")
    assert not ok
    assert global_count == throttle.PAIRING_FAIL_MAX_GLOBAL + 1
    assert ip_count == 0
    assert int(await r.get(ip_key)) == 0


@pytest.mark.asyncio
async def test_a_counter_that_lost_its_expiry_gets_one_back(redis_keys) -> None:  # type: ignore[no-untyped-def]
    """``SET NX EX`` then ``INCR`` could recreate an expired key with no TTL,
    throttling that address forever. The claim repairs a missing expiry."""
    r, ip_key, global_key = redis_keys
    await r.set(ip_key, 3)  # no TTL
    await throttle.claim_pairing_attempt("192.0.2.12")
    for key in (ip_key, global_key):
        assert 0 < await r.ttl(key) <= 15 * 60
