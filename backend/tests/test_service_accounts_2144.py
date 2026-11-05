"""Service accounts (#2144): API principals for external systems.

An external system (Home Assistant, Ansible, a monitoring poller) used to need
a fake person: a user with a password, which could sign in to the UI and sat in
the user list. A service account has no password and no sign-in, holds groups
like anyone else, and authenticates only with tokens a superadmin mints.

Pinned here:

* the role matrix on every ``/service-accounts`` route (Viewer, a delegated
  user/group admin who is not a superadmin, a superadmin's read-scoped token,
  the service account's OWN token, a superadmin);
* every sign-in path refuses a service account;
* it is not a person: absent from ``/users``, refused by the user writes, not
  an effective superadmin, no MFA enrolment, no self-minted tokens;
* its token works inside its groups' grants and nowhere else;
* disabling it revokes its tokens; audit rows say ``auth_source=service``;
* the ``find_service_accounts`` copilot tool.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from app.core.auth.user_sync import ExternalAuthResult
from app.core.permissions import is_effective_superadmin
from app.core.security import (
    create_access_token,
    create_refresh_token,
    generate_api_token,
    hash_password,
)
from app.main import _BUILTIN_ROLES
from app.models.audit import AuditLog
from app.models.auth import APIToken, Group, Role, User, UserSession
from app.models.auth_provider import AuthGroupMapping, AuthProvider
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.models.settings import PlatformSettings

_PW = "Admin-pw-2144-ok!"
SA = "/api/v1/service-accounts"


@pytest.fixture(autouse=True)
def _limits(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stand in for the Redis-backed step-up budget and login limiter."""
    import app.api.stepup as stepup
    from app.api.v1.auth import router as auth_router

    async def _no(*_a: object, **_k: object) -> bool:
        return False

    async def _record(_user_id: object) -> None:
        return None

    monkeypatch.setattr(stepup, "stepup_password_blocked", _no)
    monkeypatch.setattr(stepup, "record_stepup_password_failure", _record)
    monkeypatch.setattr(auth_router, "login_rate_limited", _no)


# ── Fixtures ────────────────────────────────────────────────────────────────


async def _settings(db: AsyncSession) -> None:
    if await db.get(PlatformSettings, 1) is None:
        db.add(PlatformSettings(id=1))
        await db.flush()


async def _group(db: AsyncSession, perms: list[dict[str, Any]]) -> Group:
    tag = uuid.uuid4().hex[:8]
    role = Role(name=f"r-{tag}", description="", permissions=perms)
    group = Group(name=f"g-{tag}", description="")
    group.roles = [role]
    db.add_all([role, group])
    await db.flush()
    return group


async def _person(
    db: AsyncSession,
    *,
    superadmin: bool = False,
    perms: list[dict[str, Any]] | None = None,
) -> tuple[User, dict[str, str]]:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"p-{tag}",
        email=f"{tag}@example.test",
        display_name=f"Person {tag}",
        hashed_password=hash_password(_PW),
        auth_source="local",
        is_superadmin=superadmin,
        force_password_change=False,
    )
    user.groups = [await _group(db, perms)] if perms is not None else []
    db.add(user)
    await db.commit()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _raw_token(db: AsyncSession, owner: User, scopes: list[str] | None = None) -> str:
    raw, _p, digest = generate_api_token()
    db.add(
        APIToken(
            name="t",
            token_hash=digest,
            prefix=raw[:10],
            scope="user",
            scopes=scopes or [],
            user_id=owner.id,
            created_by_user_id=owner.id,
            is_active=True,
        )
    )
    await db.commit()
    return raw


async def _create(
    client: AsyncClient, h: dict[str, str], *, group_ids: list[str] | None = None
) -> dict[str, Any]:
    r = await client.post(
        SA,
        json={
            "username": f"ha-{uuid.uuid4().hex[:6]}",
            "display_name": "Home Assistant on ha.lan",
            "group_ids": group_ids or [],
        },
        headers=h,
    )
    assert r.status_code == 201, r.text
    return r.json()


async def _mint(
    client: AsyncClient, h: dict[str, str], account_id: str, **extra: Any
) -> dict[str, Any]:
    r = await client.post(
        f"{SA}/{account_id}/tokens",
        json={"name": "ha", "stepup_password": _PW, **extra},
        headers=h,
    )
    assert r.status_code == 201, r.text
    return r.json()


def _bearer(raw: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {raw}"}


async def _account(db: AsyncSession, account_id: str) -> User:
    db.expire_all()
    user = await db.get(User, uuid.UUID(account_id))
    assert user is not None
    return user


# ── Create / list / not a person ────────────────────────────────────────────


async def test_a_service_account_is_created_without_a_password_and_listed_apart(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _settings(db_session)
    admin, h = await _person(db_session, superadmin=True)
    group = await _group(db_session, [{"action": "read", "resource_type": "ip_space"}])
    await db_session.commit()
    created = await _create(client, h, group_ids=[str(group.id)])
    assert created["groups"] == [{"id": str(group.id), "name": group.name}]
    assert created["display_name"] == "Home Assistant on ha.lan"
    assert created["active_token_count"] == 0

    row = await _account(db_session, created["id"])
    assert row.auth_source == "service"
    assert row.hashed_password is None
    assert row.is_superadmin is False
    assert row.password_change_required is False

    listed = (await client.get(SA, headers=h)).json()
    assert [a["id"] for a in listed] == [created["id"]]
    users = (await client.get("/api/v1/users", headers=h)).json()
    assert created["id"] not in {u["id"] for u in users}, "a service account is not a person"
    assert str(admin.id) in {u["id"] for u in users}

    audit = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_type == "service_account", AuditLog.action == "create"
            )
        )
    ).scalar_one()
    assert audit.resource_id == created["id"]
    assert audit.user_id == admin.id


async def test_the_name_is_shared_with_users(client: AsyncClient, db_session: AsyncSession) -> None:
    """A person must never be able to sign in as a service account's name, or
    the reverse, so the two share one namespace."""
    await _settings(db_session)
    admin, h = await _person(db_session, superadmin=True)
    r = await client.post(SA, json={"username": admin.username}, headers=h)
    assert r.status_code == 409, r.text
    r = await client.post(SA, json={"username": "has space"}, headers=h)
    assert r.status_code == 422, r.text


async def test_a_superadmin_group_is_refused(client: AsyncClient, db_session: AsyncSession) -> None:
    await _settings(db_session)
    _, h = await _person(db_session, superadmin=True)
    wildcard = await _group(db_session, [{"action": "*", "resource_type": "*"}])
    await db_session.commit()
    r = await client.post(
        SA, json={"username": "ansible", "group_ids": [str(wildcard.id)]}, headers=h
    )
    assert r.status_code == 422, r.text
    assert "cannot be a superadmin" in r.json()["detail"]
    assert (
        await db_session.execute(select(User).where(User.username == "ansible"))
    ).scalar_one_or_none() is None
    denied = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_type == "service_account", AuditLog.result == "denied"
            )
        )
    ).scalar_one()
    assert denied.error_detail == "superadmin_group"


async def test_a_service_account_is_never_an_effective_superadmin(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Refused at assignment, and held if a role it already has is widened
    to ``*`` / ``*`` later: its token still cannot reach a superadmin route."""
    await _settings(db_session)
    _, h = await _person(db_session, superadmin=True)
    group = await _group(db_session, [{"action": "read", "resource_type": "ip_space"}])
    await db_session.commit()
    created = await _create(client, h, group_ids=[str(group.id)])
    group.roles[0].permissions = [{"action": "*", "resource_type": "*"}]
    await db_session.commit()

    account = await _account(db_session, created["id"])
    await db_session.refresh(account, ["groups"])
    assert is_effective_superadmin(account) is False
    raw = (await _mint(client, h, created["id"]))["token"]
    for path in (SA, "/api/v1/users"):
        r = await client.get(path, headers=_bearer(raw))
        assert r.status_code == 403, (path, r.status_code, r.text)


# ── Role matrix ─────────────────────────────────────────────────────────────


def _routes(account_id: str) -> list[tuple[str, str, dict[str, Any] | None]]:
    return [
        ("GET", SA, None),
        ("POST", SA, {"username": f"x-{uuid.uuid4().hex[:6]}"}),
        ("GET", f"{SA}/{account_id}", None),
        ("PATCH", f"{SA}/{account_id}", {"display_name": "renamed"}),
        ("GET", f"{SA}/{account_id}/tokens", None),
        ("POST", f"{SA}/{account_id}/tokens", {"name": "n", "stepup_password": _PW}),
        ("DELETE", f"{SA}/{account_id}", None),
    ]


async def _call(
    client: AsyncClient, method: str, path: str, body: dict[str, Any] | None, h: dict[str, str]
) -> int:
    return (await client.request(method, path, json=body, headers=h)).status_code


async def test_role_matrix(client: AsyncClient, db_session: AsyncSession) -> None:
    await _settings(db_session)
    admin, admin_h = await _person(db_session, superadmin=True)
    _, viewer_h = await _person(db_session, perms=list(_BUILTIN_ROLES["Viewer"][1]))
    # Delegated administration short of superadmin: users, groups, roles,
    # audit, API tokens. Still not allowed to touch service accounts.
    _, delegate_h = await _person(
        db_session,
        perms=[
            {"action": "admin", "resource_type": "user"},
            {"action": "admin", "resource_type": "group"},
            {"action": "admin", "resource_type": "role"},
            {"action": "admin", "resource_type": "api_token"},
            {"action": "read", "resource_type": "audit_log"},
        ],
    )
    read_token_h = _bearer(await _raw_token(db_session, admin, scopes=["read"]))
    # The account's own token, in a group that can administer groups and
    # users: it still must not be able to manage itself or mint itself more.
    strong = await _group(
        db_session,
        [
            {"action": "admin", "resource_type": "group"},
            {"action": "admin", "resource_type": "user"},
        ],
    )
    await db_session.commit()
    target = await _create(client, admin_h, group_ids=[str(strong.id)])
    own_h = _bearer((await _mint(client, admin_h, target["id"]))["token"])

    for method, path, body in _routes(target["id"]):
        for who, h in (("viewer", viewer_h), ("delegate", delegate_h), ("own", own_h)):
            code = await _call(client, method, path, body, h)
            assert code == 403, (who, method, path, code)
        code = await _call(client, method, path, body, read_token_h)
        expected = 200 if method == "GET" else 403
        assert code == expected, ("read-token", method, path, code)

    # Superadmin: every route answers.
    victim = await _create(client, admin_h)
    for method, path, body in _routes(victim["id"]):
        code = await _call(client, method, path, body, admin_h)
        assert code in (200, 201, 204), ("superadmin", method, path, code)

    # Its own token could not mint itself one through /api-tokens either: it
    # has neither a password nor an authenticator to pass the step-up with.
    r = await client.post(
        "/api/v1/api-tokens", json={"name": "self", "stepup_totp_code": "000000"}, headers=own_h
    )
    assert r.status_code == 403, r.text
    count = (
        await db_session.execute(
            select(APIToken).where(APIToken.user_id == uuid.UUID(target["id"]))
        )
    ).all()
    assert len(count) == 1


async def test_minting_needs_the_callers_step_up_and_the_owners_grants(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _settings(db_session)
    _, h = await _person(db_session, superadmin=True)
    created = await _create(client, h)
    r = await client.post(f"{SA}/{created['id']}/tokens", json={"name": "n"}, headers=h)
    assert r.status_code == 403, r.text
    r = await client.post(
        f"{SA}/{created['id']}/tokens",
        json={"name": "n", "stepup_password": "wrong-password"},
        headers=h,
    )
    assert r.status_code == 403, r.text

    # A resource grant the account does not hold would be refused on every
    # use, so it is refused at mint, even though the superadmin holds it.
    space = IPSpace(name=f"s-{uuid.uuid4().hex[:6]}")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.214.0.0/16", name="b")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(
        space_id=space.id, block_id=block.id, network="10.214.4.0/24", name="ha", total_ips=254
    )
    db_session.add(subnet)
    await db_session.commit()
    r = await client.post(
        f"{SA}/{created['id']}/tokens",
        json={
            "name": "n",
            "stepup_password": _PW,
            "resource_grants": [
                {"action": "read", "resource_type": "subnet", "resource_id": str(subnet.id)}
            ],
        },
        headers=h,
    )
    assert r.status_code == 422, r.text
    assert "cannot grant more than its owner" in r.json()["detail"]

    minted = await _mint(client, h, created["id"], scopes=["read"], expires_in_days=30)
    assert minted["token"].startswith("sddi_")
    assert minted["owner_is_service_account"] is True
    assert minted["user_id"] == created["id"]
    tokens = (await client.get("/api/v1/api-tokens", headers=h)).json()
    row = next(t for t in tokens if t["id"] == minted["id"])
    assert row["owner_is_service_account"] is True
    assert row["owner_username"] == created["username"]
    listed = (await client.get(f"{SA}/{created['id']}/tokens", headers=h)).json()
    assert [t["id"] for t in listed] == [minted["id"]]
    summary = (await client.get(f"{SA}/{created['id']}", headers=h)).json()
    assert summary["active_token_count"] == 1
    assert summary["next_token_expiry"] is not None


# ── Its token: within its grants and nowhere else ───────────────────────────


async def test_its_token_works_within_its_groups_grants_only(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _settings(db_session)
    _, h = await _person(db_session, superadmin=True)
    reader = await _group(db_session, [{"action": "read", "resource_type": "ip_space"}])
    await db_session.commit()
    created = await _create(client, h, group_ids=[str(reader.id)])
    raw = (await _mint(client, h, created["id"]))["token"]

    assert (await client.get("/api/v1/ipam/spaces", headers=_bearer(raw))).status_code == 200
    r = await client.post("/api/v1/ipam/spaces", json={"name": "nope"}, headers=_bearer(raw))
    assert r.status_code == 403, r.text

    # Widen the group (the account's grants), and the same token can write.
    writer = await _group(
        db_session,
        [
            {"action": "read", "resource_type": "ip_space"},
            {"action": "write", "resource_type": "ip_space"},
        ],
    )
    await db_session.commit()
    r = await client.patch(f"{SA}/{created['id']}", json={"group_ids": [str(writer.id)]}, headers=h)
    assert r.status_code == 200, r.text
    assert [g["name"] for g in r.json()["groups"]] == [writer.name]
    r = await client.post("/api/v1/ipam/spaces", json={"name": "from-ha"}, headers=_bearer(raw))
    assert r.status_code == 201, r.text

    # The change is attributed to the service account, as one.
    row = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_type == "ip_space", AuditLog.action == "create"
            )
        )
    ).scalar_one()
    assert row.user_id == uuid.UUID(created["id"])
    assert row.auth_source == "service"
    # The refused write above is attributed the same way.
    page = (await client.get("/api/v1/audit", params={"auth_source": "service"}, headers=h)).json()
    assert {i["resource_display"] for i in page["items"]} >= {row.resource_display}
    assert {i["auth_source"] for i in page["items"]} == {"service"}
    page = (await client.get("/api/v1/audit", params={"user_id": created["id"]}, headers=h)).json()
    assert page["total"] == len(page["items"]) >= 2
    assert {i["user_display_name"] for i in page["items"]} == {"Home Assistant on ha.lan"}


async def test_an_audit_row_left_at_the_local_default_names_the_service_account(
    db_session: AsyncSession,
) -> None:
    """Many writers leave ``auth_source`` to its ``local`` default. For a row
    a service account caused, the audit hook records ``service`` instead."""
    tag = uuid.uuid4().hex[:6]
    account = User(
        username=f"svc-{tag}",
        email="",
        display_name="svc",
        auth_source="service",
    )
    person = User(username=f"p-{tag}", email="", display_name="p", auth_source="local")
    db_session.add_all([account, person])
    await db_session.flush()
    for actor in (account, person):
        db_session.add(
            AuditLog(
                user_id=actor.id,
                user_display_name=actor.display_name,
                action="update",
                resource_type="thing",
                resource_id="1",
                resource_display="thing",
            )
        )
    await db_session.commit()
    rows = {
        r.user_id: r.auth_source for r in (await db_session.execute(select(AuditLog))).scalars()
    }
    assert rows[account.id] == "service"
    assert rows[person.id] == "local"


# ── Disable revokes ─────────────────────────────────────────────────────────


async def test_disabling_revokes_its_tokens_and_re_enabling_brings_none_back(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _settings(db_session)
    _, h = await _person(db_session, superadmin=True)
    created = await _create(client, h)
    minted = await _mint(client, h, created["id"])
    me = _bearer(minted["token"])
    assert (await client.get("/api/v1/auth/me", headers=me)).status_code == 200

    r = await client.patch(f"{SA}/{created['id']}", json={"is_active": False}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["active_token_count"] == 0
    db_session.expire_all()
    token = await db_session.get(APIToken, uuid.UUID(minted["id"]))
    assert token is not None and token.is_active is False
    assert (await client.get("/api/v1/auth/me", headers=me)).status_code == 401

    r = await client.patch(f"{SA}/{created['id']}", json={"is_active": True}, headers=h)
    assert r.status_code == 200, r.text
    assert (await client.get("/api/v1/auth/me", headers=me)).status_code == 401
    update = (
        (
            await db_session.execute(
                select(AuditLog)
                .where(AuditLog.resource_type == "service_account", AuditLog.action == "update")
                .order_by(AuditLog.seq)
            )
        )
        .scalars()
        .all()
    )
    assert update[0].new_value == {"is_active": False, "api_tokens_revoked": 1}
    revoke = (
        await db_session.execute(
            select(AuditLog)
            .where(AuditLog.resource_type == "api_token", AuditLog.resource_id == minted["id"])
            .where(AuditLog.action == "update")
        )
    ).scalar_one()
    assert revoke.new_value == {"is_active": False, "reason": "owner_disabled"}


async def test_delete_removes_its_tokens(client: AsyncClient, db_session: AsyncSession) -> None:
    await _settings(db_session)
    _, h = await _person(db_session, superadmin=True)
    created = await _create(client, h)
    minted = await _mint(client, h, created["id"])
    r = await client.delete(f"{SA}/{created['id']}", headers=h)
    assert r.status_code == 204, r.text
    db_session.expire_all()
    assert await db_session.get(APIToken, uuid.UUID(minted["id"])) is None
    assert (await client.get(f"{SA}/{created['id']}", headers=h)).status_code == 404
    r = await client.get("/api/v1/auth/me", headers=_bearer(minted["token"]))
    assert r.status_code == 401


# ── Sign-in refusal ─────────────────────────────────────────────────────────


async def test_password_login_refuses_a_service_account(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Local first, then a directory that would accept any password for the
    name: neither signs a service account in, and no session is created."""
    from app.api.v1.auth import router as auth_router

    await _settings(db_session)
    _, h = await _person(db_session, superadmin=True)
    created = await _create(client, h)
    name = created["username"]

    r = await client.post("/api/v1/auth/login", json={"username": name, "password": "x"})
    assert r.status_code == 401, r.text

    group = await _group(db_session, [{"action": "*", "resource_type": "*"}])
    for ptype in ("ldap", "radius", "tacacs"):
        provider = AuthProvider(
            name=f"{ptype}-{uuid.uuid4().hex[:6]}",
            type=ptype,
            is_enabled=True,
            config={},
            auto_create_users=True,
            auto_update_users=True,
        )
        db_session.add(provider)
        await db_session.flush()
        db_session.add(
            AuthGroupMapping(
                provider_id=provider.id, external_group="staff", internal_group_id=group.id
            )
        )
    await db_session.commit()

    def _accept(provider: AuthProvider, username: str, password: str) -> ExternalAuthResult:
        return ExternalAuthResult(
            external_id=f"{provider.type}:{username}",
            username=username,
            email=None,
            display_name=username,
            groups=["staff"],
        )

    monkeypatch.setattr(
        auth_router,
        "_PASSWORD_AUTH_DISPATCH",
        {t: (_accept, RuntimeError) for t in ("ldap", "radius", "tacacs")},
    )
    r = await client.post("/api/v1/auth/login", json={"username": name, "password": "x"})
    assert r.status_code == 401, r.text
    sessions = (
        await db_session.execute(
            select(UserSession).where(UserSession.user_id == uuid.UUID(created["id"]))
        )
    ).all()
    assert sessions == []


async def test_the_session_minter_refuses_a_service_account(db_session: AsyncSession) -> None:
    """``_issue_tokens`` is where every sign-in ends (local, MFA, LDAP /
    RADIUS / TACACS+, OIDC and SAML callbacks): it refuses one outright, so a
    path that stops refusing earlier still cannot sign one in."""
    from app.api.v1.auth.router import _issue_tokens

    await _settings(db_session)
    account = User(
        username=f"svc-{uuid.uuid4().hex[:6]}", email="", display_name="s", auth_source="service"
    )
    db_session.add(account)
    await db_session.commit()
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/auth/login",
            "headers": [],
            "client": ("127.0.0.1", 1),
        }
    )
    for source in ("local", "oidc-idp", "saml-idp"):
        with pytest.raises(HTTPException) as exc:
            await _issue_tokens(db_session, request, account, auth_source=source)
        assert exc.value.status_code == 401
    assert (
        await db_session.execute(select(UserSession).where(UserSession.user_id == account.id))
    ).all() == []
    reasons = {
        (r.new_value or {}).get("reason")
        for r in (
            await db_session.execute(select(AuditLog).where(AuditLog.user_id == account.id))
        ).scalars()
    }
    assert reasons == {"service_account"}


async def test_no_session_or_jwt_works_for_a_service_account(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Defence in depth for a session that should never exist: a JWT naming
    the account is refused, and so is refreshing a session row for it."""
    await _settings(db_session)
    account = User(
        username=f"svc-{uuid.uuid4().hex[:6]}", email="", display_name="s", auth_source="service"
    )
    db_session.add(account)
    await db_session.flush()
    raw_refresh, digest = create_refresh_token(str(account.id))
    now = datetime.now(UTC)
    db_session.add(
        UserSession(
            user_id=account.id,
            refresh_token_hash=digest,
            created_at=now,
            last_seen_at=now,
            expires_at=now + timedelta(days=1),
        )
    )
    await db_session.commit()
    r = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {create_access_token(str(account.id))}"},
    )
    assert r.status_code == 401, r.text
    from app.api.v1.auth import router as auth_router

    client.cookies.set(auth_router._REFRESH_COOKIE, raw_refresh)
    r = await client.post("/api/v1/auth/refresh")
    assert r.status_code == 401, r.text


async def test_its_token_reaches_no_account_holder_endpoint(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Only ``/auth/me`` and ``/auth/me/permissions``. MFA enrolment above all:
    an authenticator is what every step-up accepts from an account with no
    password, so enrolling one would let a leaked token mint more tokens."""
    await _settings(db_session)
    _, h = await _person(db_session, superadmin=True)
    created = await _create(client, h)
    own = _bearer((await _mint(client, h, created["id"]))["token"])
    me = await client.get("/api/v1/auth/me", headers=own)
    assert me.status_code == 200, me.text
    assert me.json()["auth_source"] == "service"
    assert me.json()["is_superadmin"] is False
    assert (await client.get("/api/v1/auth/me/permissions", headers=own)).status_code == 200
    for method, path, body in (
        ("POST", "/api/v1/auth/mfa/enroll/begin", {}),
        ("GET", "/api/v1/auth/mfa/status", None),
        ("POST", "/api/v1/auth/change-password", {"current_password": "a", "new_password": "b"}),
        ("POST", "/api/v1/auth/logout", None),
    ):
        r = await client.request(method, path, json=body, headers=own)
        assert r.status_code == 403, (path, r.status_code, r.text)
    account = await _account(db_session, created["id"])
    assert account.totp_secret_encrypted is None


# ── The user admin leaves it alone ──────────────────────────────────────────


async def test_the_user_writes_refuse_a_service_account(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _settings(db_session)
    _, h = await _person(db_session, superadmin=True)
    created = await _create(client, h)
    uid = created["id"]
    for method, path, body in (
        ("PUT", f"/api/v1/users/{uid}", {"is_superadmin": True, "stepup_password": _PW}),
        ("POST", f"/api/v1/users/{uid}/reset-password", {"new_password": "Abcdefgh1234!"}),
        ("POST", f"/api/v1/users/{uid}/unlock", None),
        ("POST", f"/api/v1/users/{uid}/link-provider", {"auth_provider_id": str(uuid.uuid4())}),
        ("DELETE", f"/api/v1/users/{uid}", None),
    ):
        r = await client.request(method, path, json=body, headers=h)
        assert r.status_code == 409, (path, r.status_code, r.text)
    account = await _account(db_session, uid)
    assert account.is_superadmin is False
    assert account.hashed_password is None


# ── Copilot tool ────────────────────────────────────────────────────────────


async def test_find_service_accounts_tool(client: AsyncClient, db_session: AsyncSession) -> None:
    from app.services.ai.tools.admin import (
        FindServiceAccountsArgs,
        ListUsersArgs,
        find_service_accounts,
        list_users,
    )

    await _settings(db_session)
    admin, h = await _person(db_session, superadmin=True)
    viewer, _vh = await _person(db_session, perms=list(_BUILTIN_ROLES["Viewer"][1]))
    created = await _create(client, h)
    await _mint(client, h, created["id"])

    rows = await find_service_accounts(db_session, admin, FindServiceAccountsArgs())
    assert len(rows) == 1
    row = rows[0]
    assert row["name"] == created["username"]
    assert row["active_token_count"] == 1
    assert "token" not in row and "token_hash" not in row
    refused = await find_service_accounts(db_session, viewer, FindServiceAccountsArgs())
    assert "error" in refused[0]

    people = await list_users(db_session, admin, ListUsersArgs())
    assert created["username"] not in {p["username"] for p in people}
