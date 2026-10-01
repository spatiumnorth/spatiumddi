"""Operator re-confirmation for sensitive actions (#408).

Sensitive surfaces (secret reveals, and — later — destructive ops) re-confirm
the operator's identity right before proceeding. Historically each did a local
``verify_password`` and hard-rejected any ``auth_source != "local"`` account —
so an OIDC / SAML / LDAP / RADIUS / TACACS+ superadmin (who has no local
password) could never reveal an appliance kubeconfig, a pairing code, an agent
bootstrap key, or the SNMP community.

This helper unifies the re-confirmation:

* **Local users** (have a password): only a correct password passes — TOTP is
  NOT accepted in lieu of it. Local users already hold the strongest factor,
  and accepting TOTP-instead-of-password would downgrade the reveal step-up
  (TOTP proves only what was enrolled, and before #1241 enrolment needed only
  a session). See the SECURITY note in reverify_operator.
* **External-auth users** (no local password): a correct TOTP code passes. MFA
  enrolment is now open to every auth source (#408), so an SSO superadmin can
  enrol TOTP and then re-confirm with it. Enrolment itself is gated by
  :func:`reverify_for_mfa_enrolment` (#1241): a password for local users, a
  recent sign-in for external ones. If they have NOT enrolled, the helper
  returns ``MFA_REQUIRED`` so the caller can tell them to enrol rather than
  dead-ending on a password they don't have.

The helper is intentionally stateless: it verifies a live TOTP code only (no
recovery-code consumption, which would mutate the user row) — recovery codes
are the lost-authenticator path for *login*, not per-action re-confirmation.
A single-use replay guard on the reveal TOTP (mirroring the login MFA
challenge) is a possible follow-up; the reveal endpoints are superadmin-gated
and audited, so a 30 s TOTP window is low-risk in the meantime.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING

from app.core.security import verify_password
from app.services.mfa import decrypt_secret, verify_totp

if TYPE_CHECKING:
    from app.models.auth import User


class ReauthOutcome(Enum):
    """Result of an operator re-confirmation attempt. Compared by identity
    (``is``) at the call sites, so plain ``Enum`` (no ``str`` mixin)."""

    OK = "ok"
    BAD_CREDENTIAL = "bad_credential"  # wrong password / wrong or missing TOTP
    MFA_REQUIRED = "mfa_required"  # external-auth user with no MFA enrolled
    SIGN_IN_TOO_OLD = "sign_in_too_old"  # external-auth user; sign in again (#1241)


def _totp_ok(user: User, code: str | None) -> bool:
    """True iff ``code`` is a currently-valid TOTP for an MFA-enrolled user."""
    if not code or not user.totp_enabled or user.totp_secret_encrypted is None:
        return False
    try:
        return verify_totp(decrypt_secret(user.totp_secret_encrypted), code)
    except Exception:  # noqa: BLE001 — a decrypt/parse failure is just "no"
        return False


def uses_local_password(user: User) -> bool:
    """True for an account whose step-ups prove a local password."""
    return bool(user.auth_source == "local" and user.hashed_password)


def reverify_operator(
    user: User,
    *,
    password: str | None = None,
    totp_code: str | None = None,
) -> ReauthOutcome:
    """Re-confirm ``user`` for a sensitive action. See module docstring.

    Never raises on a bad credential — returns an outcome so the caller keeps
    its own audit-on-denial + friction-sleep behaviour.
    """
    if uses_local_password(user):
        # SECURITY (review of #408): a local user must prove their PASSWORD —
        # TOTP is NOT accepted as a substitute here. Accepting TOTP-in-lieu-of-
        # password would be a defense-in-depth downgrade: TOTP proves only
        # what was enrolled, so the reveal step-up would be as strong as the
        # enrolment gate rather than the password it exists to demand. Local
        # users already hold the strongest factor (password); only
        # password-less SSO users fall back to TOTP below — which is why
        # enrolment itself now needs a step-up (#1241).
        assert user.hashed_password is not None  # narrowed by uses_local_password
        if password and verify_password(password, user.hashed_password):
            return ReauthOutcome.OK
        return ReauthOutcome.BAD_CREDENTIAL

    # External-auth (or a local account with no password set) — TOTP only,
    # since there is no password to prove. A "local" row with a NULL password
    # is a misconfiguration that cannot hold a session today (login rejects
    # it); it falls here and still requires enrolled MFA + a valid code, so
    # the password check is never silently skipped for a credentialed account.
    if not user.totp_enabled:
        return ReauthOutcome.MFA_REQUIRED
    if _totp_ok(user, totp_code):
        return ReauthOutcome.OK
    return ReauthOutcome.BAD_CREDENTIAL


#: How recent an external-auth user's sign-in must be to enrol MFA (#1241).
MFA_ENROL_SIGN_IN_WINDOW = timedelta(minutes=10)


def sign_in_is_recent(signed_in_at: datetime | None, *, now: datetime | None = None) -> bool:
    if signed_in_at is None:
        return False
    return (now or datetime.now(UTC)) - signed_in_at <= MFA_ENROL_SIGN_IN_WINDOW


def reverify_for_mfa_enrolment(
    user: User,
    *,
    password: str | None,
    signed_in_at: datetime | None,
    now: datetime | None = None,
) -> ReauthOutcome:
    """Step-up for STARTING an MFA enrolment (#1241).

    Enrolment used to need only a session, and it is the one step-up that
    cannot fall back on TOTP — there is none yet. So a hijacked session
    could enrol the attacker's authenticator and then: for an external-auth
    superadmin, pass every TOTP reveal step-up above; for a local user, lock
    the real owner out, since disabling MFA needs a code only the attacker
    has.

    * **Local users** prove their password, as every other step-up does.
    * **External-auth users** have no password here, so they prove a RECENT
      sign-in with their identity provider: the session must have been
      created by a real login within :data:`MFA_ENROL_SIGN_IN_WINDOW`. A
      refresh does not count — it carries the original sign-in time forward
      — so a stolen session cannot make itself look fresh. No sign-in time
      at all (an API token) fails closed.
    """
    if uses_local_password(user):
        assert user.hashed_password is not None  # narrowed by uses_local_password
        if password and verify_password(password, user.hashed_password):
            return ReauthOutcome.OK
        return ReauthOutcome.BAD_CREDENTIAL
    if sign_in_is_recent(signed_in_at, now=now):
        return ReauthOutcome.OK
    return ReauthOutcome.SIGN_IN_TOO_OLD
