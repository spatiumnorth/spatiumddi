"""An external account without an email, or with one another account holds (#1290).

RADIUS and TACACS+ never report an email, and neither does an LDAP entry with
no ``mail`` or an OIDC token without the claim. Such an account was created
with ``email = ''`` under a plain unique index on ``user.email``, so exactly
one could exist: every later first-time login hit the index and failed. And
an email another account already holds failed the login the same way.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.user_sync import ExternalAuthResult, sync_external_user
from app.models.auth import Group, User
from app.models.auth_provider import AuthGroupMapping, AuthProvider


async def _provider(db: AsyncSession, ptype: str) -> AuthProvider:
    group = Group(name=f"g-{uuid.uuid4().hex[:8]}", description="")
    db.add(group)
    await db.flush()
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


def _subject(username: str, email: str | None) -> ExternalAuthResult:
    return ExternalAuthResult(
        external_id=f"{uuid.uuid4().hex[:8]}:{username}",
        username=username,
        email=email,
        display_name=username,
        groups=["staff"],
    )


@pytest.mark.asyncio
async def test_two_radius_users_both_auto_provision(db_session: AsyncSession) -> None:
    provider = await _provider(db_session, "radius")

    first = await sync_external_user(db_session, provider, _subject("alice", None))
    second = await sync_external_user(db_session, provider, _subject("bob", None))
    await db_session.commit()

    assert (first.email, second.email) == ("", "")
    assert first.id != second.id


@pytest.mark.asyncio
async def test_an_email_another_account_holds_provisions_without_it(
    db_session: AsyncSession,
) -> None:
    ldap = await _provider(db_session, "ldap")
    oidc = await _provider(db_session, "oidc")
    holder = await sync_external_user(db_session, ldap, _subject("jsmith", "shared@example.com"))

    newcomer = await sync_external_user(db_session, oidc, _subject("jsmith2", "shared@example.com"))
    await db_session.commit()

    assert holder.email == "shared@example.com"
    assert newcomer.email == ""
    assert newcomer.id != holder.id


@pytest.mark.asyncio
async def test_an_update_to_an_email_another_account_holds_is_skipped(
    db_session: AsyncSession,
) -> None:
    provider = await _provider(db_session, "ldap")
    holder = await sync_external_user(db_session, provider, _subject("one", "one@example.com"))
    subject = _subject("two", "two@example.com")
    other = await sync_external_user(db_session, provider, subject)

    # The directory now reports the first account's email for the second.
    subject.email = "one@example.com"
    again = await sync_external_user(db_session, provider, subject)
    await db_session.commit()

    assert again.id == other.id
    assert again.email == "two@example.com"
    assert holder.email == "one@example.com"


@pytest.mark.asyncio
async def test_real_emails_stay_unique(db_session: AsyncSession) -> None:
    from sqlalchemy.exc import IntegrityError

    db_session.add(User(username="a", email="dup@example.com", display_name="a"))
    await db_session.flush()
    db_session.add(User(username="b", email="dup@example.com", display_name="b"))
    with pytest.raises(IntegrityError):
        await db_session.flush()
