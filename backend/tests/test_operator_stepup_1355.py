"""Actions that mint or expose a credential need the operator step-up (#1355).

#408's reveal step-up only protects anything if a stolen session cannot mint
itself a fresh credential without one. So reading an auth provider's secrets,
creating or promoting a superadmin, resetting a superadmin's password and
minting an API token all re-confirm the caller.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_dict
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.auth_provider import AuthProvider

_PW = "Admin-pw-1355!"
_NEW_PW = "Target-pw-1355-Xyz!"


@pytest.fixture(autouse=True)
def _budget(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """Stand in for the Redis-backed step-up budget."""
    import app.api.stepup as stepup

    state: dict[str, object] = {"blocked": False, "failures": []}

    async def _blocked(_user_id: object) -> bool:
        return bool(state["blocked"])

    async def _record(user_id: object) -> None:
        state["failures"].append(user_id)  # type: ignore[union-attr]

    monkeypatch.setattr(stepup, "stepup_password_blocked", _blocked)
    monkeypatch.setattr(stepup, "record_stepup_password_failure", _record)
    return state


async def _admin(db: AsyncSession, *, auth_source: str = "local") -> tuple[User, dict[str, str]]:
    user = User(
        username=f"a-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="admin",
        hashed_password=hash_password(_PW) if auth_source == "local" else None,
        auth_source=auth_source,
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.commit()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _user(db: AsyncSession, *, superadmin: bool) -> User:
    user = User(
        username=f"t-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="target",
        hashed_password=hash_password("Old-pw-1355-Abc!"),
        auth_source="local",
        is_superadmin=superadmin,
    )
    user.groups = []
    db.add(user)
    await db.commit()
    return user


# ── Auth provider secrets ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_provider_secrets_need_the_step_up(
    client: AsyncClient, db_session: AsyncSession, _budget: dict[str, object]
) -> None:
    admin, headers = await _admin(db_session)
    provider = AuthProvider(
        name=f"ldap-{uuid.uuid4().hex[:6]}",
        type="ldap",
        is_enabled=True,
        config={},
        secrets_encrypted=encrypt_dict({"bind_password": "s3cret"}),
    )
    db_session.add(provider)
    await db_session.commit()
    url = f"/api/v1/auth-providers/{provider.id}/secrets"

    assert (await client.get(url, headers=headers)).status_code == 405
    r = await client.post(url, headers=headers, json={"password": "wrong"})
    assert r.status_code == 403, r.text
    assert "s3cret" not in r.text
    assert _budget["failures"] == [admin.id]

    r = await client.post(url, headers=headers, json={"password": _PW})
    assert r.status_code == 200, r.text
    assert r.json() == {"bind_password": "s3cret"}
    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.resource_type == "auth_provider_secret")
            )
        )
        .scalars()
        .all()
    )
    assert sorted(r.result for r in rows) == ["denied", "success"]
    assert next(r for r in rows if r.result == "success").new_value["stepup_method"] == "password"


@pytest.mark.asyncio
async def test_a_spent_budget_refuses_before_checking(
    client: AsyncClient, db_session: AsyncSession, _budget: dict[str, object]
) -> None:
    _, headers = await _admin(db_session)
    _budget["blocked"] = True
    r = await client.post(
        "/api/v1/api-tokens", headers=headers, json={"name": "t", "stepup_password": _PW}
    )
    assert r.status_code == 429, r.text


# ── Superadmin creation, promotion, password reset ──────────────────────────


def _new_user(superadmin: bool, **extra: object) -> dict[str, object]:
    return {
        "username": f"n-{uuid.uuid4().hex[:6]}",
        "email": f"{uuid.uuid4().hex[:6]}@example.test",
        "display_name": "new",
        "password": _NEW_PW,
        "is_superadmin": superadmin,
        **extra,
    }


@pytest.mark.asyncio
async def test_creating_a_superadmin_needs_the_step_up(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    r = await client.post("/api/v1/users", headers=headers, json=_new_user(True))
    assert r.status_code == 403, r.text
    r = await client.post(
        "/api/v1/users", headers=headers, json=_new_user(True, stepup_password=_PW)
    )
    assert r.status_code == 201, r.text
    # An ordinary account needs none.
    r = await client.post("/api/v1/users", headers=headers, json=_new_user(False))
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_promoting_to_superadmin_needs_the_step_up(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    target = await _user(db_session, superadmin=False)
    url = f"/api/v1/users/{target.id}"
    r = await client.put(url, headers=headers, json={"is_superadmin": True})
    assert r.status_code == 403, r.text
    # Other edits do not.
    r = await client.put(url, headers=headers, json={"display_name": "renamed"})
    assert r.status_code == 200, r.text
    r = await client.put(url, headers=headers, json={"is_superadmin": True, "stepup_password": _PW})
    assert r.status_code == 200, r.text
    assert r.json()["is_superadmin"] is True


@pytest.mark.asyncio
async def test_resetting_a_superadmins_password_needs_the_step_up(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    target = await _user(db_session, superadmin=True)
    url = f"/api/v1/users/{target.id}/reset-password"
    r = await client.post(url, headers=headers, json={"new_password": _NEW_PW})
    assert r.status_code == 403, r.text
    r = await client.post(
        url, headers=headers, json={"new_password": _NEW_PW, "stepup_password": _PW}
    )
    assert r.status_code == 204, r.text

    plain = await _user(db_session, superadmin=False)
    r = await client.post(
        f"/api/v1/users/{plain.id}/reset-password", headers=headers, json={"new_password": _NEW_PW}
    )
    assert r.status_code == 204, r.text


# ── API tokens ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_minting_a_token_needs_the_step_up(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    r = await client.post("/api/v1/api-tokens", headers=headers, json={"name": "t"})
    assert r.status_code == 403, r.text
    r = await client.post(
        "/api/v1/api-tokens", headers=headers, json={"name": "t", "stepup_password": _PW}
    )
    assert r.status_code == 201, r.text
    assert r.json()["token"]


@pytest.mark.asyncio
async def test_an_sso_account_without_mfa_is_told_to_enrol(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session, auth_source="oidc")
    r = await client.post("/api/v1/api-tokens", headers=headers, json={"name": "t"})
    assert r.status_code == 403, r.text
    assert "enrol" in r.json()["detail"]
