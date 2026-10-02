"""Operator step-up for actions that mint or expose a credential (#1355).

#408 put a step-up on secret reveals so a stolen session cannot simply read
them. That only holds if a session cannot mint itself a fresh credential
without one, so the same step-up guards creating or promoting a superadmin,
resetting a superadmin's password, minting an API token, and reading an auth
provider's secrets.

The check is :func:`app.services.reauth.reverify_operator`: a local user's
password, or an external user's TOTP code. Wrong answers spend the
per-account step-up budget (#1241), which fails closed while it cannot be
read; an omitted answer is refused without spending it. Every attempt is
audited with the method used.
"""

from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth_throttle import (
    StepupThrottleUnavailable,
    record_stepup_password_failure,
    stepup_password_blocked,
)
from app.models.audit import AuditLog
from app.models.auth import User
from app.services.reauth import ReauthOutcome, reverify_operator, uses_local_password


def stepup_method(user: User) -> str:
    """What the user proves at a step-up: ``password`` or ``totp``."""
    return "password" if uses_local_password(user) else "totp"


async def require_operator_stepup(
    db: AsyncSession,
    user: User,
    *,
    password: str | None,
    totp_code: str | None,
    action: str,
    resource_type: str,
    resource_id: str,
    resource_display: str,
) -> str:
    """Re-confirm ``user`` or raise. Returns the method used, for the
    caller's success audit row. A refusal is audited and committed here,
    since the caller's transaction never reaches its own commit."""
    try:
        blocked = await stepup_password_blocked(user.id)
    except StepupThrottleUnavailable:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "This needs a password or authenticator check, and the attempt "
                "limiter is unavailable. Try again in a minute."
            ),
            headers={"Retry-After": "60"},
        ) from None
    if blocked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many incorrect attempts. Try again in 15 minutes.",
        )

    outcome = reverify_operator(user, password=password, totp_code=totp_code)
    if outcome is ReauthOutcome.OK:
        return stepup_method(user)

    # An omitted step-up is not a guess, so it does not spend the budget: a
    # client that predates #1355 (or an empty dialog) would otherwise lock
    # the account out of every step-up, MFA changes included, for 15 min.
    missing = not password and not totp_code
    if outcome is ReauthOutcome.BAD_CREDENTIAL and not missing:
        await record_stepup_password_failure(user.id)
    if outcome is ReauthOutcome.MFA_REQUIRED:
        reason = "mfa_required"
    elif missing:
        reason = "stepup_missing"
    else:
        reason = "bad_credential"
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_display=resource_display,
            result="denied",
            error_detail=reason,
            new_value={"stepup_method": stepup_method(user)},
        )
    )
    await db.commit()
    if outcome is ReauthOutcome.MFA_REQUIRED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "This needs re-confirmation with an authenticator code. Your account "
                "has no local password: enrol TOTP under Account → Two-factor, then retry."
            ),
        )
    # 403, not 401: the SPA reads any 401 off a non-login path as an expired
    # token and resubmits, which would spend two attempts on one typo.
    if missing:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "This needs re-confirmation: send your password, or an authenticator "
                "code if your account has no local password."
            ),
        )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Password or authenticator code is incorrect",
    )
