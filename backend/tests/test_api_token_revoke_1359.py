"""API tokens and a password change / admin reset (#1359).

A password change and an admin reset revoke the account's sessions and, by
design, not its API tokens. The responses now say how many live tokens the
account holds, ``revoke_api_tokens`` opts in to revoking them, and two
"revoke all" actions do it without a password change. Each new or changed
route is exercised as a Viewer, as a user managing only themselves, as a
non-wildcard user-admin role, as a read-scoped token, and as a superadmin;
a refusal must leave every token as it was.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from httpx import AsyncClient
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import generate_api_token
from app.models.audit import AuditLog
from app.models.auth import APIToken, Group, Role, User
from tests.test_fix_m3_m4_auth_session import _bearer, _ensure_settings, _user

_OLD = "OldPass123!"
_NEW = "BrandNewPass1!"


async def _token(
    db: AsyncSession,
    owner: User,
    *,
    scopes: list[str] | None = None,
    expires_at: datetime | None = None,
) -> APIToken:
    raw, _prefix, token_hash = generate_api_token()
    tok = APIToken(
        name=f"t-{uuid.uuid4().hex[:6]}",
        token_hash=token_hash,
        prefix=raw[:10],
        scope="user",
        scopes=scopes or [],
        user_id=owner.id,
        created_by_user_id=owner.id,
        is_active=True,
        expires_at=expires_at,
    )
    db.add(tok)
    await db.flush()
    tok._raw = raw  # type: ignore[attr-defined]
    return tok


async def _with_role(db: AsyncSession, user: User, permissions: list[dict]) -> User:
    role = Role(name=f"r-{uuid.uuid4().hex[:6]}", description="", permissions=permissions)
    db.add(role)
    await db.flush()
    group = Group(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    group.roles = [role]
    group.users = [user]
    db.add(group)
    await db.flush()
    return user


async def _live(db: AsyncSession, owner: User) -> int:
    await db.commit()
    rows = (
        await db.execute(
            select(APIToken.id).where(
                APIToken.user_id == owner.id,
                APIToken.is_active.is_(True),
                or_(APIToken.expires_at.is_(None), APIToken.expires_at > datetime.now(UTC)),
            )
        )
    ).all()
    return len(rows)


def _tok(t: APIToken) -> dict[str, str]:
    return {"Authorization": f"Bearer {t._raw}"}  # type: ignore[attr-defined]


async def _world(db: AsyncSession):
    """A target with two live tokens (+ one expired, which is not live) and a bystander."""
    await _ensure_settings(db)
    target = await _user(db, password=_OLD)
    other = await _user(db)
    await _token(db, target)
    await _token(db, target)
    await _token(db, target, expires_at=datetime.now(UTC) - timedelta(days=1))
    await _token(db, other)
    await db.commit()
    return target, other


async def _revoke_audits(db: AsyncSession) -> list[AuditLog]:
    await db.commit()
    return list(
        (
            await db.execute(
                select(AuditLog).where(
                    AuditLog.action
                    == "revoke_api_tokens"
                    # a refusal must not have audited a success
                )
            )
        )
        .scalars()
        .all()
    )


# ── POST /api-tokens/revoke-all (own tokens) ────────────────────────────────


async def test_self_revoke_all_revokes_only_own_tokens_for_every_role(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    for perms in ([{"action": "read", "resource_type": "*"}], None):  # Viewer, plain self-user
        target, other = await _world(db_session)
        if perms:
            await _with_role(db_session, target, perms)
        r = await client.post("/api/v1/api-tokens/revoke-all", headers=_bearer(target))
        assert r.status_code == 200, r.text
        assert r.json() == {"api_tokens_revoked": 2}
        assert await _live(db_session, target) == 0
        assert await _live(db_session, other) == 1, "revoke-all reached another user's token"
    audits = await _revoke_audits(db_session)
    assert audits and all(a.new_value == {"api_tokens_revoked": 2} for a in audits)


async def test_superadmin_self_revoke_all_still_only_its_own(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    target, other = await _world(db_session)
    admin = await _user(db_session, is_superadmin=True)
    await _token(db_session, admin)
    await db_session.commit()
    r = await client.post("/api/v1/api-tokens/revoke-all", headers=_bearer(admin))
    assert r.status_code == 200 and r.json() == {"api_tokens_revoked": 1}
    assert await _live(db_session, target) == 2
    assert await _live(db_session, other) == 1


async def test_read_scoped_token_cannot_revoke_all(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    target, _ = await _world(db_session)
    ro = await _token(db_session, target, scopes=["read"])
    await db_session.commit()
    r = await client.post("/api/v1/api-tokens/revoke-all", headers=_tok(ro))
    assert r.status_code == 403, r.text
    assert await _live(db_session, target) == 3
    assert await _revoke_audits(db_session) == []


# ── POST /users/{id}/revoke-api-tokens (admin) ──────────────────────────────


async def test_admin_revoke_refused_for_every_non_superadmin_role(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    target, _ = await _world(db_session)
    viewer = await _with_role(
        db_session, await _user(db_session), [{"action": "read", "resource_type": "*"}]
    )
    user_admin = await _with_role(
        db_session, await _user(db_session), [{"action": "admin", "resource_type": "user"}]
    )
    plain = await _user(db_session)
    await db_session.commit()
    url = f"/api/v1/users/{target.id}/revoke-api-tokens"
    for caller, name in ((viewer, "viewer"), (user_admin, "user-admin"), (plain, "self-only")):
        r = await client.post(url, headers=_bearer(caller))
        assert r.status_code == 403, f"{name}: {r.status_code} {r.text}"
    # a user managing only themselves cannot revoke their own via the admin route either
    r = await client.post(f"/api/v1/users/{plain.id}/revoke-api-tokens", headers=_bearer(plain))
    assert r.status_code == 403
    assert await _live(db_session, target) == 2
    assert await _revoke_audits(db_session) == []


async def test_admin_revoke_refused_for_read_scoped_superadmin_token(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    target, _ = await _world(db_session)
    admin = await _user(db_session, is_superadmin=True)
    ro = await _token(db_session, admin, scopes=["read"])
    await db_session.commit()
    r = await client.post(f"/api/v1/users/{target.id}/revoke-api-tokens", headers=_tok(ro))
    assert r.status_code == 403, r.text
    assert await _live(db_session, target) == 2
    assert await _revoke_audits(db_session) == []


async def test_superadmin_revokes_a_users_tokens_audited_and_account_stays_active(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    target, other = await _world(db_session)
    admin = await _user(db_session, is_superadmin=True)
    await db_session.commit()
    r = await client.post(f"/api/v1/users/{target.id}/revoke-api-tokens", headers=_bearer(admin))
    assert r.status_code == 200, r.text
    assert r.json() == {"api_tokens_revoked": 2, "api_token_count": 0}
    assert await _live(db_session, target) == 0
    assert await _live(db_session, other) == 1
    await db_session.refresh(target)
    assert target.is_active is True
    audits = await _revoke_audits(db_session)
    assert [a.resource_id for a in audits] == [str(target.id)]
    per_token = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "api_token",
                    AuditLog.new_value["reason"].astext == "admin_revoke_all",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(per_token) == 2
    missing = await client.post(
        f"/api/v1/users/{uuid.uuid4()}/revoke-api-tokens", headers=_bearer(admin)
    )
    assert missing.status_code == 404


# ── change-password ─────────────────────────────────────────────────────────


async def test_change_password_reports_live_tokens_and_leaves_them(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    target, _ = await _world(db_session)
    r = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": _OLD, "new_password": _NEW},
        headers=_bearer(target),
    )
    assert r.status_code == 200, r.text
    assert r.json() == {"api_tokens_revoked": 0, "api_token_count": 2}
    assert await _live(db_session, target) == 2


async def test_change_password_opt_in_revokes_tokens_and_audits(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    target, other = await _world(db_session)
    r = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": _OLD, "new_password": _NEW, "revoke_api_tokens": True},
        headers=_bearer(target),
    )
    assert r.status_code == 200, r.text
    assert r.json() == {"api_tokens_revoked": 2, "api_token_count": 0}
    assert await _live(db_session, target) == 0
    assert await _live(db_session, other) == 1
    row = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_id == str(target.id), AuditLog.resource_type == "user"
            )
        )
    ).scalar_one()
    assert row.new_value == {"api_tokens_revoked": 2}


async def test_change_password_refused_leaves_tokens_alone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    target, _ = await _world(db_session)
    wrong = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "nope", "new_password": _NEW, "revoke_api_tokens": True},
        headers=_bearer(target),
    )
    assert wrong.status_code == 400
    ro = await _token(db_session, target, scopes=["read"])
    await db_session.commit()
    scoped = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": _OLD, "new_password": _NEW, "revoke_api_tokens": True},
        headers=_tok(ro),
    )
    assert scoped.status_code == 403, scoped.text
    assert await _live(db_session, target) == 3


async def test_viewer_can_change_own_password_and_revoke_own_tokens(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    target, _ = await _world(db_session)
    await _with_role(db_session, target, [{"action": "read", "resource_type": "*"}])
    r = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": _OLD, "new_password": _NEW, "revoke_api_tokens": True},
        headers=_bearer(target),
    )
    assert r.status_code == 200 and r.json()["api_tokens_revoked"] == 2


# ── admin reset ─────────────────────────────────────────────────────────────


async def test_admin_reset_reports_and_opt_in_revokes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    target, other = await _world(db_session)
    admin = await _user(db_session, is_superadmin=True)
    await db_session.commit()
    url = f"/api/v1/users/{target.id}/reset-password"
    plain = await client.post(url, json={"new_password": _NEW}, headers=_bearer(admin))
    assert plain.status_code == 200, plain.text
    assert plain.json() == {"api_tokens_revoked": 0, "api_token_count": 2}
    assert await _live(db_session, target) == 2
    opted = await client.post(
        url,
        json={"new_password": "AnotherNew12!", "revoke_api_tokens": True},
        headers=_bearer(admin),
    )
    assert opted.status_code == 200, opted.text
    assert opted.json() == {"api_tokens_revoked": 2, "api_token_count": 0}
    assert await _live(db_session, target) == 0
    assert await _live(db_session, other) == 1


async def test_admin_reset_refused_roles_change_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    target, _ = await _world(db_session)
    viewer = await _with_role(
        db_session, await _user(db_session), [{"action": "read", "resource_type": "*"}]
    )
    plain = await _user(db_session)
    admin = await _user(db_session, is_superadmin=True)
    ro = await _token(db_session, admin, scopes=["read"])
    await db_session.commit()
    url = f"/api/v1/users/{target.id}/reset-password"
    body = {"new_password": _NEW, "revoke_api_tokens": True}
    for headers in (_bearer(viewer), _bearer(plain), _tok(ro)):
        r = await client.post(url, json=body, headers=headers)
        assert r.status_code == 403, r.text
    assert await _live(db_session, target) == 2
    await db_session.refresh(target)
    assert target.force_password_change is False


# ── GET /users carries the live count ───────────────────────────────────────


async def test_user_list_carries_live_token_count(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    target, _ = await _world(db_session)
    admin = await _user(db_session, is_superadmin=True)
    await db_session.commit()
    rows = (await client.get("/api/v1/users", headers=_bearer(admin))).json()
    by_id = {r["id"]: r for r in rows}
    assert by_id[str(target.id)]["api_token_count"] == 2
    one = (await client.get(f"/api/v1/users/{target.id}", headers=_bearer(admin))).json()
    assert one["api_token_count"] == 2
    # the tool answers the same
    from app.services.ai.tools.admin import ListUsersArgs, list_users

    out = await list_users(db_session, admin, ListUsersArgs())
    assert {r["id"]: r["api_token_count"] for r in out}[str(target.id)] == 2
