"""#1337 — a sign-in through a provider with a long name is stored, not refused.

Every external sign-in writes the provider's NAME into two columns:
``user_session.auth_source`` (the session viewer's "signed in via …") and
``audit_log.auth_source`` (the login row, and every error / refusal row on the
way). A provider name may be 255 characters (``auth_provider.name``), but those
columns were ``VARCHAR(64)`` and ``VARCHAR(20)``. So a provider named with more
than 20 characters broke every sign-in through it: the insert raised
``StringDataRightTruncation``, the request answered
``422 "A supplied value cannot be stored as sent."``, and the session, the audit
row and ``last_login_at`` were all rolled back. An unreachable long-named
provider also stopped the fallthrough to the providers after it, because its
own error row could not be stored. Both columns now hold a full provider name.

The directory is stubbed at the product's own dispatch seam
(``_PASSWORD_AUTH_DISPATCH``); the rest of the path (``sync_external_user``,
``_issue_tokens``, the audit writes) is the real one.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import router as auth_router
from app.core.auth.ldap import LDAPServiceError
from app.core.auth.user_sync import ExternalAuthResult
from app.models.audit import AuditLog
from app.models.auth import Group, User, UserSession
from app.models.auth_provider import AuthGroupMapping, AuthProvider

OPS_DN = "cn=ddi-operators,ou=groups,dc=alpha,dc=example,dc=test"
# The issue's provider (23 characters), and one at the name's own maximum.
NAME_23 = "fx-ldap-alpha-long-name"
NAME_255 = ("ldap-directory-with-a-name-as-long-as-the-product-allows-" * 5)[:255]


async def _never_limited(_ip: str | None) -> bool:
    return False


def _directory(users: dict[str, str]):
    """A password-grant authenticate function over ``{username: password}``,
    shaped like ``authenticate_ldap`` (sync; run on a worker thread)."""

    def _authenticate(
        provider: AuthProvider, username: str, password: str
    ) -> ExternalAuthResult | None:
        if users.get(username) != password:
            return None
        return ExternalAuthResult(
            external_id=f"uid={username},ou=people,dc=alpha,dc=example,dc=test",
            username=username,
            email=f"{username}@alpha.example.test",
            display_name=username.title(),
            groups=[OPS_DN],
        )

    return _authenticate


def _unreachable(provider: AuthProvider, username: str, password: str) -> None:
    raise LDAPServiceError("cannot reach ldap://192.0.2.1:389")


async def _provider(db: AsyncSession, name: str, priority: int = 1) -> AuthProvider:
    grp = Group(name=f"g1337-{uuid.uuid4().hex[:6]}", description="")
    prov = AuthProvider(
        name=name,
        type="ldap",
        is_enabled=True,
        priority=priority,
        config={},
        auto_create_users=True,
        auto_update_users=True,
    )
    db.add_all([grp, prov])
    await db.flush()
    db.add(AuthGroupMapping(provider_id=prov.id, external_group=OPS_DN, internal_group_id=grp.id))
    await db.flush()
    return prov


async def _rows(db: AsyncSession, model: Any, *where: Any) -> list[Any]:
    db.expire_all()
    return list((await db.execute(select(model).where(*where))).scalars().all())


@pytest.fixture
def directory(monkeypatch: pytest.MonkeyPatch):
    """Install a stub directory for every ``ldap`` provider; returns a setter
    so a test can swap in an unreachable one for a given provider name."""
    monkeypatch.setattr(auth_router, "login_rate_limited", _never_limited)
    by_name: dict[str, Any] = {}
    default = _directory({"jsmith": "correct horse"})

    def _dispatch(provider: AuthProvider, username: str, password: str):
        return by_name.get(provider.name, default)(provider, username, password)

    monkeypatch.setitem(auth_router._PASSWORD_AUTH_DISPATCH, "ldap", (_dispatch, LDAPServiceError))
    return by_name


@pytest.mark.asyncio
@pytest.mark.parametrize("name", [NAME_23, NAME_255], ids=["23-chars", "255-chars"])
async def test_a_sign_in_through_a_long_named_provider_is_stored(
    client: AsyncClient, db_session: AsyncSession, directory: dict, name: str
) -> None:
    """The issue's case (23 characters: over the audit column), and the
    longest name the product accepts (over the session column too)."""
    await _provider(db_session, name)
    await db_session.commit()

    r = await client.post(
        "/api/v1/auth/login", json={"username": "jsmith", "password": "correct horse"}
    )

    assert r.status_code == 200, r.text
    assert r.json()["access_token"]
    (user,) = await _rows(db_session, User, User.username == "jsmith")
    uid = user.id  # read once: _rows expires the session between queries
    assert user.last_login_at is not None
    (session,) = await _rows(db_session, UserSession, UserSession.user_id == uid)
    assert session.auth_source == name
    logins = await _rows(
        db_session,
        AuditLog,
        AuditLog.action == "login",
        AuditLog.user_id == uid,
        AuditLog.result == "success",
    )
    assert [a.auth_source for a in logins] == [name]


@pytest.mark.asyncio
async def test_an_unreachable_long_named_provider_does_not_stop_the_next_one(
    client: AsyncClient, db_session: AsyncSession, directory: dict
) -> None:
    """The first provider (long name) is down; its error row is written and
    the next provider signs the user in. Before, the error row's own insert
    failed and the whole login answered 422."""
    down = await _provider(db_session, NAME_23, priority=1)
    await _provider(db_session, "fx-ldap-beta", priority=2)
    await db_session.commit()
    down_id = str(down.id)
    directory[NAME_23] = _unreachable

    r = await client.post(
        "/api/v1/auth/login", json={"username": "jsmith", "password": "correct horse"}
    )

    assert r.status_code == 200, r.text
    errors = await _rows(
        db_session,
        AuditLog,
        AuditLog.action == "login",
        AuditLog.resource_id == down_id,
        AuditLog.result == "error",
    )
    assert [(a.auth_source, (a.new_value or {}).get("reason")) for a in errors] == [
        (NAME_23, "service_error")
    ]
    (user,) = await _rows(db_session, User, User.username == "jsmith")
    uid = user.id
    (session,) = await _rows(db_session, UserSession, UserSession.user_id == uid)
    assert session.auth_source == "fx-ldap-beta"


@pytest.mark.asyncio
async def test_a_refused_sign_in_through_a_long_named_provider_is_audited(
    client: AsyncClient, db_session: AsyncSession, directory: dict
) -> None:
    """The directory accepts the password but no group maps: 401, and the
    refusal is in the audit log under the provider's name."""
    await _provider(db_session, NAME_23)
    await db_session.commit()
    directory[NAME_23] = lambda p, u, pw: ExternalAuthResult(
        external_id=f"uid={u},ou=people,dc=alpha,dc=example,dc=test",
        username=u,
        email=f"{u}@alpha.example.test",
        groups=["cn=nobody,ou=groups,dc=alpha,dc=example,dc=test"],
    )

    r = await client.post(
        "/api/v1/auth/login", json={"username": "nogroup", "password": "anything"}
    )

    assert r.status_code == 401, r.text
    refusals = await _rows(
        db_session,
        AuditLog,
        AuditLog.action == "login",
        AuditLog.resource_display == "nogroup",
        AuditLog.result == "failure",
    )
    assert [(a.auth_source, (a.new_value or {}).get("reason")) for a in refusals] == [
        (NAME_23, "no_group_mapping_match")
    ]


@pytest.mark.asyncio
async def test_both_columns_hold_a_provider_name_of_the_full_length(
    db_session: AsyncSession,
) -> None:
    """Every writer of a provider name (the password, OIDC and SAML sign-ins,
    their error and refusal rows, the session) lands in one of these two
    columns, so each must hold what ``auth_provider.name`` holds."""
    width = AuthProvider.__table__.c.name.type.length
    assert width == 255
    assert AuditLog.__table__.c.auth_source.type.length == width
    assert UserSession.__table__.c.auth_source.type.length == width
