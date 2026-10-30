"""Updating an API token: what needs a superadmin, what needs the step-up.

An inactive token was revoked by someone, and a token outlives the session
that edits it. So re-enabling one is superadmin-only and needs the operator
step-up, and widening a token's scopes needs the step-up. Renaming, narrowing
scopes and revoking need neither.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.api_tokens.router import scopes_widen
from app.core.security import create_access_token, generate_api_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import APIToken, User

_PW = "Owner-pw-tok-1!"


@pytest.fixture(autouse=True)
def _budget(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """Stand in for the Redis-backed step-up budget."""
    import app.api.stepup as stepup

    state: dict[str, object] = {"failures": []}

    async def _blocked(_user_id: object) -> bool:
        return False

    async def _record(user_id: object) -> None:
        state["failures"].append(user_id)  # type: ignore[union-attr]

    monkeypatch.setattr(stepup, "stepup_password_blocked", _blocked)
    monkeypatch.setattr(stepup, "record_stepup_password_failure", _record)
    return state


async def _user(db: AsyncSession, *, superadmin: bool) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="user",
        hashed_password=hash_password(_PW),
        auth_source="local",
        is_superadmin=superadmin,
        force_password_change=False,
    )
    user.groups = []
    db.add(user)
    await db.commit()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _token(
    db: AsyncSession, owner: User, *, active: bool = True, scopes: list[str] | None = None
) -> APIToken:
    raw, _p, h = generate_api_token()
    t = APIToken(
        name="tok",
        token_hash=h,
        prefix=raw[:10],
        scope="user",
        scopes=scopes or [],
        user_id=owner.id,
        created_by_user_id=owner.id,
        is_active=active,
    )
    db.add(t)
    await db.commit()
    return t


async def _state(db: AsyncSession, token_id: uuid.UUID) -> APIToken:
    db.expire_all()
    t = await db.get(APIToken, token_id)
    assert t is not None
    return t


# ── Re-enable ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_expired_token_cannot_be_reenabled(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from datetime import UTC, datetime, timedelta

    owner, _ = await _user(db_session, superadmin=False)
    _admin, headers = await _user(db_session, superadmin=True)
    tok = await _token(db_session, owner, active=False)
    tok.expires_at = datetime.now(UTC) - timedelta(days=1)
    await db_session.commit()
    r = await client.patch(
        f"/api/v1/api-tokens/{tok.id}",
        headers=headers,
        json={"is_active": True, "stepup_password": _PW},
    )
    assert r.status_code == 422, r.text
    assert "expired" in r.json()["detail"]
    assert (await _state(db_session, tok.id)).is_active is False


@pytest.mark.asyncio
async def test_expired_token_can_still_be_renamed_and_revoked(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The #3120 refusal is for re-enabling only: a no-op is_active, a rename
    and a revoke of an expired token go through as before."""
    from datetime import UTC, datetime, timedelta

    owner, _ = await _user(db_session, superadmin=False)
    _admin, headers = await _user(db_session, superadmin=True)
    tok = await _token(db_session, owner, active=True)
    tok.expires_at = datetime.now(UTC) - timedelta(days=1)
    await db_session.commit()
    r = await client.patch(
        f"/api/v1/api-tokens/{tok.id}",
        headers=headers,
        json={"is_active": True, "name": "renamed"},
    )
    assert r.status_code == 200, r.text
    r = await client.patch(
        f"/api/v1/api-tokens/{tok.id}", headers=headers, json={"is_active": False}
    )
    assert r.status_code == 200, r.text
    assert (await _state(db_session, tok.id)).is_active is False


@pytest.mark.asyncio
async def test_owner_reenabling_an_expired_token_is_refused_as_non_superadmin(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The superadmin gate still answers first, so the expiry check tells an
    owner nothing the 403 would not."""
    from datetime import UTC, datetime, timedelta

    owner, headers = await _user(db_session, superadmin=False)
    tok = await _token(db_session, owner, active=False)
    tok.expires_at = datetime.now(UTC) - timedelta(days=1)
    await db_session.commit()
    r = await client.patch(
        f"/api/v1/api-tokens/{tok.id}",
        headers=headers,
        json={"is_active": True, "stepup_password": _PW},
    )
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_owner_cannot_reenable_an_inactive_token(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    owner, headers = await _user(db_session, superadmin=False)
    tok = await _token(db_session, owner, active=False)
    # Even with a correct step-up: re-enabling is a superadmin decision.
    r = await client.patch(
        f"/api/v1/api-tokens/{tok.id}",
        headers=headers,
        json={"is_active": True, "stepup_password": _PW},
    )
    assert r.status_code == 403, r.text
    assert (await _state(db_session, tok.id)).is_active is False
    denied = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_id == str(tok.id), AuditLog.result == "denied"
                )
            )
        )
        .scalars()
        .all()
    )
    assert [d.error_detail for d in denied] == ["reenable_requires_superadmin"]


@pytest.mark.asyncio
async def test_superadmin_reenable_needs_the_step_up(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    owner, _ = await _user(db_session, superadmin=False)
    _admin, headers = await _user(db_session, superadmin=True)
    tok = await _token(db_session, owner, active=False)
    url = f"/api/v1/api-tokens/{tok.id}"

    r = await client.patch(url, headers=headers, json={"is_active": True})
    assert r.status_code == 403, r.text
    assert r.headers.get("X-Stepup-Required") == "true"
    assert (await _state(db_session, tok.id)).is_active is False

    r = await client.patch(
        url, headers=headers, json={"is_active": True, "stepup_password": "wrong-pw"}
    )
    assert r.status_code == 403, r.text
    assert (await _state(db_session, tok.id)).is_active is False

    r = await client.patch(url, headers=headers, json={"is_active": True, "stepup_password": _PW})
    assert r.status_code == 200, r.text
    assert r.json()["is_active"] is True
    ok = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_id == str(tok.id), AuditLog.result == "success"
            )
        )
    ).scalar_one()
    # The password never reaches the audit row.
    assert "stepup_password" not in (ok.new_value or {})
    assert _PW not in str(ok.new_value)
    assert ok.new_value["stepup_method"] == "password"


# ── Scopes ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("old", "new"),
    [
        (["read"], []),  # clearing the list removes every restriction
        (["read"], ["read", "dns:write"]),
        (["dns:write"], ["ipam:write"]),
    ],
)
async def test_widening_scopes_needs_the_step_up(
    client: AsyncClient, db_session: AsyncSession, old: list[str], new: list[str]
) -> None:
    owner, headers = await _user(db_session, superadmin=False)
    tok = await _token(db_session, owner, scopes=old)
    url = f"/api/v1/api-tokens/{tok.id}"

    r = await client.patch(url, headers=headers, json={"scopes": new})
    assert r.status_code == 403, r.text
    assert (await _state(db_session, tok.id)).scopes == old

    r = await client.patch(url, headers=headers, json={"scopes": new, "stepup_password": _PW})
    assert r.status_code == 200, r.text
    assert (await _state(db_session, tok.id)).scopes == new


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("old", "new"),
    [
        ([], ["read"]),  # restricting an unrestricted token
        (["read", "dns:write"], ["read"]),
        (["dns:write"], ["dns:write"]),
    ],
)
async def test_narrowing_scopes_needs_no_step_up(
    client: AsyncClient, db_session: AsyncSession, old: list[str], new: list[str]
) -> None:
    owner, headers = await _user(db_session, superadmin=False)
    tok = await _token(db_session, owner, scopes=old)
    r = await client.patch(f"/api/v1/api-tokens/{tok.id}", headers=headers, json={"scopes": new})
    assert r.status_code == 200, r.text
    assert (await _state(db_session, tok.id)).scopes == new


@pytest.mark.asyncio
async def test_rename_and_revoke_need_no_step_up(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    owner, headers = await _user(db_session, superadmin=False)
    tok = await _token(db_session, owner)
    tok2_url = f"/api/v1/api-tokens/{(await _token(db_session, owner)).id}"
    url = f"/api/v1/api-tokens/{tok.id}"

    r = await client.patch(url, headers=headers, json={"name": "renamed", "description": "d"})
    assert r.status_code == 200, r.text
    r = await client.patch(url, headers=headers, json={"is_active": False})
    assert r.status_code == 200, r.text
    t = await _state(db_session, tok.id)
    assert (t.name, t.is_active) == ("renamed", False)
    # Sending is_active=true on an already-active token is not a re-enable.
    r = await client.patch(tok2_url, headers=headers, json={"is_active": True})
    assert r.status_code == 200, r.text


def test_scopes_widen() -> None:
    assert scopes_widen(["read"], []) is True
    assert scopes_widen(["read"], ["agent"]) is True
    assert scopes_widen(None, ["read"]) is False
    assert scopes_widen([], []) is False
    assert scopes_widen(["read", "agent"], ["agent"]) is False
