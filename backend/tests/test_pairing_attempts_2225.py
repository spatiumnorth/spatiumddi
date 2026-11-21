"""Fleet shows who used a pairing code and every refused join (#2225).

The register endpoint's 403 is generic on purpose (a specific one would be a
guessing oracle for 8-digit codes), so the reason is kept for the superadmin
pairing tab instead.
"""

from __future__ import annotations

import base64
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import supervisor as supervisor_mod
from app.core.security import create_access_token, hash_password
from app.models.appliance import PairingAttempt
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services.appliance import pairing_attempts

_REG = "/api/v1/appliance/supervisor/register"
_API = "/api/v1/appliance"


@pytest.fixture(autouse=True)
def _no_throttle(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(supervisor_mod, "_CONSUME_FAILURE_DELAY_S", 0.0)

    async def _claim(_ip: object) -> tuple[bool, int, int]:
        return True, 1, 1

    async def _refund(_ip: object) -> None:
        return None

    monkeypatch.setattr(supervisor_mod, "claim_pairing_attempt", _claim)
    monkeypatch.setattr(supervisor_mod, "refund_pairing_attempt", _refund)


async def _admin(db: AsyncSession, *, superadmin: bool = True) -> dict[str, str]:
    user = User(
        username=f"pa{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="pa",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=superadmin,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    row = (
        await db.execute(select(PlatformSettings).where(PlatformSettings.id == 1))
    ).scalar_one_or_none()
    if row is None:
        db.add(PlatformSettings(id=1, supervisor_registration_enabled=True))
    else:
        row.supervisor_registration_enabled = True
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _join(code: str, hostname: str) -> dict[str, str]:
    der = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)
    )
    return {
        "pairing_code": code,
        "hostname": hostname,
        "public_key_der_b64": base64.b64encode(der).decode("ascii"),
    }


async def _mint(client: AsyncClient, headers: dict[str, str], **body: object) -> dict:
    resp = await client.post(f"{_API}/pairing-codes", headers=headers, json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_a_code_for_two_admits_two_and_the_third_is_explained(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    h = await _admin(db_session)
    code = await _mint(client, h, persistent=True, max_claims=2)
    for host in ("node2", "node3"):
        assert (await client.post(_REG, json=_join(code["code"], host))).status_code == 200
    refused = await client.post(_REG, json=_join(code["code"], "node4"))
    assert refused.status_code == 403

    rows = (await client.get(f"{_API}/pairing-attempts", headers=h)).json()["attempts"]
    assert len(rows) == 1
    assert rows[0]["reason"] == "exhausted"
    assert rows[0]["hostname"] == "node4"
    assert rows[0]["code_last_two"] == code["code"][-2:]
    assert rows[0]["used_by"] == ["node2", "node3"]

    listed = (await client.get(f"{_API}/pairing-codes", headers=h)).json()["codes"][0]
    assert listed["claim_count"] == 2
    assert [c["hostname"] for c in listed["claims"]] == ["node3", "node2"]
    assert all(c["claimed_at"] and c["appliance_id"] for c in listed["claims"])


@pytest.mark.asyncio
async def test_single_use_second_joiner_is_recorded_as_already_used(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    h = await _admin(db_session)
    code = await _mint(client, h, persistent=False)
    assert (await client.post(_REG, json=_join(code["code"], "node2"))).status_code == 200
    for _ in range(3):  # an appliance retries on a timer
        assert (await client.post(_REG, json=_join(code["code"], "node3"))).status_code == 403

    rows = (await client.get(f"{_API}/pairing-attempts", headers=h)).json()["attempts"]
    assert len(rows) == 1
    assert (rows[0]["reason"], rows[0]["hostname"], rows[0]["attempts"]) == (
        "already_used",
        "node3",
        3,
    )
    assert rows[0]["used_by"] == ["node2"]


@pytest.mark.asyncio
async def test_the_wire_answer_is_the_same_for_a_known_and_an_unknown_code(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    h = await _admin(db_session)
    code = await _mint(client, h, persistent=False)
    assert (await client.post(_REG, json=_join(code["code"], "a"))).status_code == 200
    used = await client.post(_REG, json=_join(code["code"], "b"))
    unknown = await client.post(_REG, json=_join("00000000", "c"))
    assert (used.status_code, used.json()) == (unknown.status_code, unknown.json())


@pytest.mark.asyncio
async def test_an_unknown_code_is_recorded_without_the_code(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    h = await _admin(db_session)
    await client.post(_REG, json=_join("13572468", "guesser"))
    rows = (await client.get(f"{_API}/pairing-attempts", headers=h)).json()["attempts"]
    assert [(r["reason"], r["pairing_code_id"], r["code_last_two"]) for r in rows] == [
        ("unknown_code", None, None)
    ]
    assert "13572468" not in str(rows)


@pytest.mark.asyncio
async def test_unauthenticated_floods_are_bounded(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pairing_attempts, "MAX_UNKNOWN_ROWS", 5)
    for i in range(12):
        await pairing_attempts.record_pairing_attempt(
            db_session, code_id=None, reason="unknown_code", hostname=f"h{i}", source_ip=None
        )
    await db_session.commit()
    n = (await db_session.execute(select(func.count()).select_from(PairingAttempt))).scalar_one()
    assert n == 5
    hosts = set((await db_session.execute(select(PairingAttempt.hostname))).scalars())
    assert hosts == {f"h{i}" for i in range(7, 12)}  # newest kept


@pytest.mark.asyncio
async def test_dismiss_deletes_and_audits_and_is_superadmin_only(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    h = await _admin(db_session)
    await client.post(_REG, json=_join("24681357", "node9"))
    attempt_id = (await client.get(f"{_API}/pairing-attempts", headers=h)).json()["attempts"][0][
        "id"
    ]
    plain = await _admin(db_session, superadmin=False)
    assert (await client.get(f"{_API}/pairing-attempts", headers=plain)).status_code == 403
    assert (
        await client.delete(f"{_API}/pairing-attempts/{attempt_id}", headers=plain)
    ).status_code == 403

    assert (
        await client.delete(f"{_API}/pairing-attempts/{attempt_id}", headers=h)
    ).status_code == 204
    assert (await client.get(f"{_API}/pairing-attempts", headers=h)).json()["attempts"] == []
    audits = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "appliance.pairing_attempt_dismissed")
            )
        )
        .scalars()
        .all()
    )
    assert len(audits) == 1
