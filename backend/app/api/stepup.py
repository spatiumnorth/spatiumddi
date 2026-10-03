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
audited with the method used, including one refused because the budget is
already spent.

:func:`refuse_if_stepup_blocked` is the budget gate on its own. The #408
secret reveals go through :func:`require_operator_stepup` (#1413); the MFA
endpoints in ``api/v1/auth/router.py`` check more than one factor, so they
use the gate directly. Either way the budget logic exists once.
"""

from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth_throttle import (
    StepupThrottleUnavailable,
    claim_stepup_attempt,
    record_stepup_password_failure,
    stepup_block_seconds_left,
    stepup_password_blocked,
)
from app.models.audit import AuditLog
from app.models.auth import User
from app.services.reauth import ReauthOutcome, reverify_operator, uses_local_password


def stepup_method(user: User) -> str:
    """What the user proves at a step-up: ``password`` or ``totp``."""
    return "password" if uses_local_password(user) else "totp"


_UNAVAILABLE_DETAIL = (
    "This needs a password or authenticator check, and the attempt "
    "limiter is unavailable. Try again in a minute."
)


async def refuse_if_stepup_blocked(
    user: User, *, claim: bool = False, unavailable_detail: str = _UNAVAILABLE_DETAIL
) -> None:
    """429 once the account has spent its wrong-answer budget (#1241).

    A step-up runs for a caller who already holds a session, which is the
    hijacked session it exists to stop, so unthrottled each one is an oracle
    for the password or TOTP code.

    ``claim=True`` spends an attempt atomically up front instead of only
    reading the count (#1354); the caller refunds it on a right answer.

    503 while the budget cannot be read: the throttle fails closed, so a
    Redis outage pauses step-ups rather than lifting the limit. The 429
    carries ``Retry-After`` with the time left on the block (#1413).
    """
    try:
        if claim:
            blocked = not await claim_stepup_attempt(user.id)
        else:
            blocked = await stepup_password_blocked(user.id)
    except StepupThrottleUnavailable:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=unavailable_detail,
            headers={"Retry-After": "60"},
        ) from None
    if blocked:
        seconds = await stepup_block_seconds_left(user.id)
        minutes = max(1, -(-seconds // 60))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many incorrect attempts. Try again in {minutes} minute(s).",
            headers={"Retry-After": str(seconds)},
        )


def _denied_row(
    user: User,
    *,
    action: str,
    resource_type: str,
    resource_id: str,
    resource_display: str,
    reason: str,
) -> AuditLog:
    return AuditLog(
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
    audit = {
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "resource_display": resource_display,
    }
    try:
        await refuse_if_stepup_blocked(user)
    except HTTPException as exc:
        # A refusal because the budget is spent is still an attempt, and the
        # one most worth seeing in the log (#1413). A limiter outage (503) is
        # not an attempt at all, so it is not audited.
        if exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            db.add(_denied_row(user, reason="stepup_blocked", **audit))
            await db.commit()
        raise

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
    db.add(_denied_row(user, reason=reason, **audit))
    await db.commit()
    if outcome is ReauthOutcome.MFA_REQUIRED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "This needs re-confirmation with an authenticator code. Your account "
                "has no local password: enrol two-factor (MFA) under Account → Two-factor, "
                "then retry."
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
