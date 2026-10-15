"""The step-up for STARTING an MFA enrolment, per account type (#1241, #1354).

Starting an enrolment decides whose authenticator the account trusts from
then on, so it asks for something a hijacked session does not hold:

========================  ====================================================
account                   proves
========================  ====================================================
local                     the local password
LDAP / RADIUS / TACACS+   the password, re-verified against THAT account's own
                          provider (``user.auth_provider_id``)
OIDC / SAML               a fresh re-authentication at its own IdP, forced
                          (``prompt=login`` + ``max_age=0`` / ``ForceAuthn``),
                          arriving as a single-use proof bound to this session
anything else             a sign-in within :data:`MFA_ENROL_SIGN_IN_WINDOW`
========================  ====================================================

"Anything else" is the one place the time window survives: an external account
whose provider is gone, disabled, or of a type that can do neither check. Such
an account cannot sign in again either, so there is nothing stronger to ask.

Never raises on a bad credential; the caller keeps its own budget and audit.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from enum import StrEnum

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.ldap import LDAPServiceError, authenticate_ldap
from app.core.auth.radius import RADIUSServiceError, authenticate_radius
from app.core.auth.tacacs import TACACSServiceError, authenticate_tacacs
from app.core.mfa_enrol_proof import consume_proof, session_key
from app.models.auth import User
from app.models.auth_provider import PASSWORD_PROVIDER_TYPES, AuthProvider
from app.services.reauth import (
    ReauthOutcome,
    reverify_for_mfa_enrolment,
    uses_local_password,
)

logger = structlog.get_logger(__name__)

_PROVIDER_TIMEOUT_SECONDS = 20

#: type -> (authenticate function, the ServiceError it raises). Looked up at
#: call time so a provider type is added in one place.
_PASSWORD_AUTH = {
    "ldap": (authenticate_ldap, LDAPServiceError),
    "radius": (authenticate_radius, RADIUSServiceError),
    "tacacs": (authenticate_tacacs, TACACSServiceError),
}


class EnrolStepup(StrEnum):
    PASSWORD = "password"
    PROVIDER_PASSWORD = "provider_password"
    PROVIDER_REAUTH = "provider_reauth"
    RECENT_SIGN_IN = "recent_sign_in"


async def resolve_enrol_stepup(
    db: AsyncSession, user: User
) -> tuple[EnrolStepup, AuthProvider | None]:
    """Which step-up ``user`` owes, and the provider it runs against."""
    if uses_local_password(user):
        return EnrolStepup.PASSWORD, None
    provider = (
        await db.get(AuthProvider, user.auth_provider_id)
        if user.auth_provider_id is not None
        else None
    )
    # The provider must still be on, and still be the kind of authority the
    # account was created by. Anything less falls back to the window.
    if provider is None or not provider.is_enabled or provider.type != user.auth_source:
        return EnrolStepup.RECENT_SIGN_IN, None
    if provider.type in PASSWORD_PROVIDER_TYPES and provider.type in _PASSWORD_AUTH:
        return EnrolStepup.PROVIDER_PASSWORD, provider
    if provider.type in ("oidc", "saml"):
        return EnrolStepup.PROVIDER_REAUTH, provider
    return EnrolStepup.RECENT_SIGN_IN, None


async def _verify_provider_password(
    user: User, provider: AuthProvider, password: str | None
) -> ReauthOutcome:
    """Re-verify ``password`` against the account's own provider.

    The provider's own authenticate function is used as-is, so its backup
    servers and fail-over rules apply. The answer must also be for THIS
    account: the same username and password at the provider has to resolve to
    the external id the account is linked on, or it proves nothing about it."""
    if not password or not user.external_id:
        return ReauthOutcome.BAD_CREDENTIAL
    authenticate, service_exc = _PASSWORD_AUTH[provider.type]
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(authenticate, provider, user.username, password),
            timeout=_PROVIDER_TIMEOUT_SECONDS,
        )
    except service_exc as exc:
        logger.warning("mfa_enrol_provider_unavailable", provider=provider.name, type=provider.type)
        logger.debug("mfa_enrol_provider_error", error=str(exc)[:200])
        return ReauthOutcome.PROVIDER_UNAVAILABLE
    except TimeoutError:
        logger.warning("mfa_enrol_provider_timeout", provider=provider.name)
        return ReauthOutcome.PROVIDER_UNAVAILABLE
    if result is None or (result.external_id or "").strip() != user.external_id:
        return ReauthOutcome.BAD_CREDENTIAL
    return ReauthOutcome.OK


async def verify_enrol_stepup(
    db: AsyncSession,
    user: User,
    *,
    password: str | None,
    signed_in_at: datetime | None,
) -> tuple[EnrolStepup, ReauthOutcome]:
    """Run the step-up ``user`` owes. Raises
    :class:`app.core.mfa_enrol_proof.ProofUnavailable` when a proof could not
    be read (the caller answers 503)."""
    kind, provider = await resolve_enrol_stepup(db, user)
    if kind is EnrolStepup.PROVIDER_PASSWORD:
        assert provider is not None
        return kind, await _verify_provider_password(user, provider, password)
    if kind is EnrolStepup.PROVIDER_REAUTH:
        # An API token has no sign-in time, so it can never hold a proof.
        session = session_key(signed_in_at)
        if session is not None and await consume_proof(user.id, session):
            return kind, ReauthOutcome.OK
        return kind, ReauthOutcome.REAUTH_REQUIRED
    return kind, reverify_for_mfa_enrolment(user, password=password, signed_in_at=signed_in_at)
