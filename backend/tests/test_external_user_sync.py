"""External logins belong to a provider, not a provider type (#1235).

``sync_external_user`` looked an account up by ``(auth_source, external_id)``,
where ``auth_source`` is the provider TYPE, and on a miss adopted any account
of the same type with the same username. So with two LDAP domains or two
OIDC IdPs configured, whoever held ``jsmith`` in the second one signed in as
the first one's ``jsmith``, superadmin flag included. These pin that the
match is on the provider, that a username never adopts an account, and how
accounts from before the provider column are attributed.
"""

from __future__ import annotations

import importlib.util
import pathlib
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.user_sync import (
    ExternalAuthResult,
    ExternalSyncRejected,
    sync_external_user,
)
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, User, UserSession
from app.models.auth_provider import AuthGroupMapping, AuthProvider

_MIGRATION = (
    pathlib.Path(__file__).resolve().parents[1]
    / "alembic"
    / "versions"
    / "f4a8c2e71d09_user_auth_provider_id.py"
)


async def _group(db: AsyncSession) -> Group:
    group = Group(name=f"g-{uuid.uuid4().hex[:8]}", description="")
    db.add(group)
    await db.flush()
    return group


async def _provider(db: AsyncSession, group: Group, ptype: str = "ldap") -> AuthProvider:
    provider = AuthProvider(
        name=f"{ptype}-{uuid.uuid4().hex[:8]}",
        type=ptype,
        is_enabled=True,
        config={},
        auto_create_users=True,
        auto_update_users=True,
    )
    db.add(provider)
    await db.flush()
    db.add(
        AuthGroupMapping(
            provider_id=provider.id, external_group="staff", internal_group_id=group.id
        )
    )
    await db.flush()
    return provider


def _subject(external_id: str, username: str = "jsmith") -> ExternalAuthResult:
    return ExternalAuthResult(
        external_id=external_id,
        username=username,
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name=username,
        groups=["staff"],
    )


async def _legacy_user(db: AsyncSession, *, auth_source: str, external_id: str) -> User:
    """An external account from before auth_provider_id existed."""
    user = User(
        username="jsmith",
        email="jsmith@example.com",
        display_name="J Smith",
        hashed_password=None,
        auth_source=auth_source,
        external_id=external_id,
        auth_provider_id=None,
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user


# ── The takeover ─────────────────────────────────────────────────────────────


async def test_a_second_provider_of_the_same_type_cannot_take_over_an_account(
    db_session: AsyncSession,
) -> None:
    group = await _group(db_session)
    domain_a = await _provider(db_session, group)
    domain_b = await _provider(db_session, group)
    victim = await sync_external_user(db_session, domain_a, _subject("CN=jsmith,DC=a,DC=example"))
    victim.is_superadmin = True
    await db_session.flush()

    with pytest.raises(ExternalSyncRejected) as exc:
        await sync_external_user(db_session, domain_b, _subject("CN=jsmith,DC=b,DC=example"))
    assert exc.value.reason == "username_collision"

    await db_session.refresh(victim)
    assert victim.auth_provider_id == domain_a.id
    assert victim.external_id == "CN=jsmith,DC=a,DC=example"
    assert victim.is_superadmin is True


async def test_an_identical_subject_at_another_provider_is_a_different_person(
    db_session: AsyncSession,
) -> None:
    """Two OIDC IdPs can issue the same ``sub``; it names a person only
    within its issuer."""
    group = await _group(db_session)
    idp_a = await _provider(db_session, group, "oidc")
    idp_b = await _provider(db_session, group, "oidc")
    await sync_external_user(db_session, idp_a, _subject("248289761001"))

    with pytest.raises(ExternalSyncRejected) as exc:
        await sync_external_user(db_session, idp_b, _subject("248289761001"))
    assert exc.value.reason == "username_collision"


async def test_the_same_subject_signs_in_as_its_own_account_again(
    db_session: AsyncSession,
) -> None:
    group = await _group(db_session)
    provider = await _provider(db_session, group)
    first = await sync_external_user(db_session, provider, _subject("CN=jsmith,DC=a"))
    again = await sync_external_user(db_session, provider, _subject("CN=jsmith,DC=a"))
    assert again.id == first.id
    assert again.auth_provider_id == provider.id


async def test_a_new_subject_is_provisioned_under_its_provider(db_session: AsyncSession) -> None:
    group = await _group(db_session)
    provider = await _provider(db_session, group)
    user = await sync_external_user(db_session, provider, _subject("CN=new,DC=a", "newbie"))
    assert user.auth_provider_id == provider.id
    assert user.auth_source == "ldap"
    assert user.external_id == "CN=new,DC=a"


async def test_a_local_account_is_never_adopted(db_session: AsyncSession) -> None:
    group = await _group(db_session)
    provider = await _provider(db_session, group)
    db_session.add(
        User(
            username="jsmith",
            email="local@example.com",
            display_name="Local",
            hashed_password=hash_password("pw-1235"),
            auth_source="local",
        )
    )
    await db_session.flush()
    with pytest.raises(ExternalSyncRejected) as exc:
        await sync_external_user(db_session, provider, _subject("CN=jsmith,DC=a"))
    assert exc.value.reason == "username_collision"


async def test_a_changed_identifier_at_the_same_provider_is_not_adopted_by_username(
    db_session: AsyncSession,
) -> None:
    """An LDAP DN changes when the user moves OU. The username alone does not
    prove it is the same person, so an administrator links the account."""
    group = await _group(db_session)
    provider = await _provider(db_session, group)
    await sync_external_user(db_session, provider, _subject("CN=jsmith,OU=old,DC=a"))
    with pytest.raises(ExternalSyncRejected) as exc:
        await sync_external_user(db_session, provider, _subject("CN=jsmith,OU=new,DC=a"))
    assert exc.value.reason == "username_collision"


# ── Accounts from before the provider column ─────────────────────────────────


async def test_a_legacy_account_is_refused_even_while_its_type_has_one_provider(
    db_session: AsyncSession,
) -> None:
    """One provider of the type existing NOW does not mean only one ever did:
    released builds kept a deleted provider's accounts with their external id
    intact, so the survivor's subject with the same identifier would sign in
    as them (found by QA on #1289). Whatever the backfill could not attribute waits for
    an administrator's link."""
    group = await _group(db_session)
    provider = await _provider(db_session, group)
    legacy = await _legacy_user(db_session, auth_source="ldap", external_id="CN=jsmith,DC=a")

    with pytest.raises(ExternalSyncRejected) as exc:
        await sync_external_user(db_session, provider, _subject("CN=jsmith,DC=a"))
    assert exc.value.reason == "account_link_required"
    # Carried so the login audit row names the account that was refused.
    assert exc.value.user is not None and exc.value.user.id == legacy.id
    await db_session.refresh(legacy)
    assert legacy.auth_provider_id is None


async def test_a_legacy_account_is_refused_when_several_providers_could_own_it(
    db_session: AsyncSession,
) -> None:
    group = await _group(db_session)
    domain_a = await _provider(db_session, group)
    await _provider(db_session, group)
    legacy = await _legacy_user(db_session, auth_source="ldap", external_id="CN=jsmith,DC=a")

    with pytest.raises(ExternalSyncRejected) as exc:
        await sync_external_user(db_session, domain_a, _subject("CN=jsmith,DC=a"))
    assert exc.value.reason == "account_link_required"
    await db_session.refresh(legacy)
    assert legacy.auth_provider_id is None


# ── The admin link ───────────────────────────────────────────────────────────


async def _superadmin_headers(db: AsyncSession) -> dict[str, str]:
    admin = User(
        username=f"admin-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Admin",
        hashed_password=hash_password("pw-1235"),
        is_superadmin=True,
    )
    db.add(admin)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(admin.id))}"}


async def test_an_admin_link_lets_the_next_login_claim_the_account(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    group = await _group(db_session)
    domain_a = await _provider(db_session, group)
    await _provider(db_session, group)
    legacy = await _legacy_user(db_session, auth_source="ldap", external_id="CN=jsmith,DC=a")
    headers = await _superadmin_headers(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/users/{legacy.id}/link-provider",
        headers=headers,
        json={"auth_provider_id": str(domain_a.id)},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["auth_provider_id"] == str(domain_a.id)

    user = await sync_external_user(db_session, domain_a, _subject("CN=jsmith,OU=moved,DC=a"))
    assert user.id == legacy.id
    assert user.external_id == "CN=jsmith,OU=moved,DC=a"

    audit = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "user.provider_linked",
                AuditLog.resource_id == str(legacy.id),
            )
        )
    ).scalar_one()
    assert audit.old_value["external_id"] == "CN=jsmith,DC=a"
    assert audit.new_value["auth_provider_id"] == str(domain_a.id)


async def test_the_link_only_authorises_its_own_provider(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    group = await _group(db_session)
    domain_a = await _provider(db_session, group)
    domain_b = await _provider(db_session, group)
    legacy = await _legacy_user(db_session, auth_source="ldap", external_id="CN=jsmith,DC=a")
    headers = await _superadmin_headers(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/users/{legacy.id}/link-provider",
        headers=headers,
        json={"auth_provider_id": str(domain_a.id)},
    )
    assert resp.status_code == 200, resp.text
    with pytest.raises(ExternalSyncRejected) as exc:
        await sync_external_user(db_session, domain_b, _subject("CN=jsmith,DC=b"))
    assert exc.value.reason == "username_collision"


async def test_a_local_account_cannot_be_linked(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    group = await _group(db_session)
    provider = await _provider(db_session, group)
    local = User(
        username="jsmith",
        email="local@example.com",
        display_name="Local",
        hashed_password=hash_password("pw-1235"),
        auth_source="local",
    )
    db_session.add(local)
    headers = await _superadmin_headers(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/users/{local.id}/link-provider",
        headers=headers,
        json={"auth_provider_id": str(provider.id)},
    )
    assert resp.status_code == 422, resp.text


async def test_the_link_revokes_the_accounts_sessions(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Re-linking is how an account a second provider signed in as gets
    repaired; a session opened under the old identity must not survive it."""
    group = await _group(db_session)
    domain_a = await _provider(db_session, group)
    await _provider(db_session, group)
    legacy = await _legacy_user(db_session, auth_source="ldap", external_id="CN=jsmith,DC=a")
    now = datetime.now(UTC)
    session_row = UserSession(
        user_id=legacy.id,
        refresh_token_hash=uuid.uuid4().hex,
        created_at=now,
        expires_at=now + timedelta(days=1),
    )
    db_session.add(session_row)
    headers = await _superadmin_headers(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/users/{legacy.id}/link-provider",
        headers=headers,
        json={"auth_provider_id": str(domain_a.id)},
    )
    assert resp.status_code == 200, resp.text
    await db_session.refresh(session_row)
    assert session_row.revoked is True


async def test_a_deleted_providers_accounts_are_not_adopted_by_its_successor(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Deleting a provider orphans its accounts. A new provider of the same
    type issuing the same ``sub`` is a different authority, so it must not
    adopt one through the legacy path, even as the only provider of its type."""
    group = await _group(db_session)
    old_idp = await _provider(db_session, group, "oidc")
    victim = await sync_external_user(db_session, old_idp, _subject("1"))
    victim.is_superadmin = True
    headers = await _superadmin_headers(db_session)
    await db_session.commit()

    resp = await client.delete(f"/api/v1/auth-providers/{old_idp.id}", headers=headers)
    assert resp.status_code == 204, resp.text
    await db_session.refresh(victim)
    assert victim.auth_provider_id is None
    assert victim.external_id is None

    new_idp = await _provider(db_session, group, "oidc")
    with pytest.raises(ExternalSyncRejected) as exc:
        await sync_external_user(db_session, new_idp, _subject("1"))
    assert exc.value.reason == "username_collision"


# ── The migration's backfill ─────────────────────────────────────────────────


def _backfill_sql() -> tuple[str, str]:
    spec = importlib.util.spec_from_file_location("m_f4a8c2e71d09", _MIGRATION)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.BACKFILL_BY_PREFIX, module.BACKFILL_SOLE_PROVIDER


async def test_the_backfill_attributes_only_what_it_can_prove(db_session: AsyncSession) -> None:
    group = await _group(db_session)
    sole_oidc = await _provider(db_session, group, "oidc")
    await _provider(db_session, group, "ldap")
    await _provider(db_session, group, "ldap")
    radius = await _provider(db_session, group, "radius")
    await _provider(db_session, group, "radius")
    await _provider(db_session, group, "tacacs")  # the only TACACS+ provider

    def make(username: str, source: str, external_id: str | None) -> User:
        user = User(
            username=username,
            email=f"{username}@example.com",
            display_name=username,
            hashed_password=None if source != "local" else hash_password("pw"),
            auth_source=source,
            external_id=external_id,
        )
        db_session.add(user)
        return user

    oidc_user = make("o", "oidc", "sub-1")
    ldap_user = make("l", "ldap", "CN=l,DC=a")
    radius_user = make("r", "radius", f"{radius.id}:r")
    orphan_tacacs = make("t", "tacacs", f"{uuid.uuid4()}:t")
    local_user = make("loc", "local", None)
    await db_session.flush()

    by_prefix, sole_provider = _backfill_sql()
    await db_session.execute(text(by_prefix))
    await db_session.execute(text(sole_provider))
    for user in (oidc_user, ldap_user, radius_user, orphan_tacacs, local_user):
        await db_session.refresh(user)

    assert oidc_user.auth_provider_id == sole_oidc.id  # the only OIDC provider
    assert ldap_user.auth_provider_id is None  # two LDAP providers: cannot tell
    assert radius_user.auth_provider_id == radius.id  # named in its external id
    # Names a provider that no longer exists: not handed to the sole TACACS+ one.
    assert orphan_tacacs.auth_provider_id is None
    assert local_user.auth_provider_id is None


def _provider_audit(
    action: str, provider_id: uuid.UUID, ptype: str | None, at: datetime
) -> AuditLog:
    return AuditLog(
        timestamp=at,
        action=action,
        resource_type="auth_provider",
        resource_id=str(provider_id),
        resource_display="idp",
        user_display_name="admin",
        auth_source="local",
        result="success",
        new_value={"type": ptype} if ptype else {"accounts_unlinked": 1},
    )


async def _run_backfill(db: AsyncSession, *users: User) -> None:
    by_prefix, sole_provider = _backfill_sql()
    await db.execute(text(by_prefix))
    await db.execute(text(sole_provider))
    for user in users:
        await db.refresh(user)


def _external(db: AsyncSession, username: str, source: str, created_at: datetime) -> User:
    user = User(
        username=username,
        email=f"{username}@example.com",
        display_name=username,
        hashed_password=None,
        auth_source=source,
        external_id=f"sub-{username}",
        created_at=created_at,
    )
    db.add(user)
    return user


async def test_the_backfill_skips_an_account_older_than_the_sole_provider(
    db_session: AsyncSession,
) -> None:
    """An account made before the surviving provider existed came from some
    other one, whatever the audit log does or does not say about it."""
    group = await _group(db_session)
    sole = await _provider(db_session, group, "oidc")
    older = _external(db_session, "older", "oidc", sole.created_at - timedelta(days=30))
    newer = _external(db_session, "newer", "oidc", sole.created_at + timedelta(days=1))
    await db_session.flush()

    await _run_backfill(db_session, older, newer)
    assert older.auth_provider_id is None
    assert newer.auth_provider_id == sole.id


async def test_the_backfill_skips_an_account_a_deleted_provider_may_have_made(
    db_session: AsyncSession,
) -> None:
    """Found by QA on #1289: domain A is deleted, domain B is added, the upgrade runs.
    Every account made before A's deletion may be A's, so none of those goes
    to B; an account made after it can only be B's."""
    group = await _group(db_session)
    now = datetime.now(UTC)
    survivor = await _provider(db_session, group, "oidc")
    survivor.created_at = now - timedelta(days=60)
    deleted_id = uuid.uuid4()
    db_session.add_all(
        [
            _provider_audit("create", deleted_id, "oidc", now - timedelta(days=90)),
            _provider_audit("delete", deleted_id, None, now - timedelta(days=10)),
        ]
    )
    before = _external(db_session, "before", "oidc", now - timedelta(days=20))
    after = _external(db_session, "after", "oidc", now - timedelta(days=5))
    await db_session.flush()

    await _run_backfill(db_session, before, after)
    assert before.auth_provider_id is None
    assert after.auth_provider_id == survivor.id


async def test_the_backfill_ignores_a_deleted_provider_of_another_type(
    db_session: AsyncSession,
) -> None:
    group = await _group(db_session)
    now = datetime.now(UTC)
    survivor = await _provider(db_session, group, "oidc")
    survivor.created_at = now - timedelta(days=60)
    deleted_id = uuid.uuid4()
    db_session.add_all(
        [
            _provider_audit("create", deleted_id, "ldap", now - timedelta(days=90)),
            _provider_audit("delete", deleted_id, None, now - timedelta(days=10)),
        ]
    )
    user = _external(db_session, "u", "oidc", now - timedelta(days=20))
    await db_session.flush()

    await _run_backfill(db_session, user)
    assert user.auth_provider_id == survivor.id


async def test_the_backfill_treats_a_deletion_of_unknown_type_as_any_type(
    db_session: AsyncSession,
) -> None:
    """No ``create`` row to read the type from: assume it could have been
    this type, which only ever withholds a link."""
    group = await _group(db_session)
    now = datetime.now(UTC)
    survivor = await _provider(db_session, group, "saml")
    survivor.created_at = now - timedelta(days=60)
    db_session.add(_provider_audit("delete", uuid.uuid4(), None, now - timedelta(days=10)))
    user = _external(db_session, "u", "saml", now - timedelta(days=20))
    await db_session.flush()

    await _run_backfill(db_session, user)
    assert user.auth_provider_id is None
