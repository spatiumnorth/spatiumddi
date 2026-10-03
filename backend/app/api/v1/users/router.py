"""User management endpoints (superadmin only)."""

import re
import uuid
from datetime import UTC, datetime

import structlog
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, field_validator, model_validator
from sqlalchemy import inspect as sa_inspect
from sqlalchemy import select, update

from app.api.deps import DB, SuperAdmin
from app.api.stepup import require_operator_stepup
from app.core.demo_mode import forbid_in_demo_mode
from app.core.permissions import is_effective_superadmin
from app.core.security import hash_password
from app.models.audit import AuditLog
from app.models.auth import User, UserSession
from app.models.auth_provider import AuthProvider
from app.models.settings import PlatformSettings
from app.services.account_lockout import (
    is_locked as is_user_locked,
)
from app.services.account_lockout import (
    unlock as unlock_user,
)
from app.services.mfa import clear_pending_enrolment
from app.services.password_policy import (
    PasswordPolicy,
    push_history,
)
from app.services.password_policy import (
    validate as validate_password_policy,
)

logger = structlog.get_logger(__name__)
router = APIRouter()


# ── Schemas ───────────────────────────────────────────────────────────────────


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    display_name: str
    is_active: bool
    is_superadmin: bool
    force_password_change: bool
    auth_source: str
    # The provider an external account belongs to (#1235); null for a local
    # account, and for an external one not attributed to a provider, which
    # cannot sign in until it is linked (POST /users/{id}/link-provider).
    auth_provider_id: str | None = None
    # Real ``datetime``s (#907); see the audit router for why.
    last_login_at: datetime | None = None
    # Lockout state (issue #71). ``locked`` mirrors the live time
    # check so the UI doesn't have to compare timestamps in JS;
    # ``failed_login_count`` + ``failed_login_locked_until`` are
    # surfaced for triage / admin display.
    failed_login_count: int = 0
    failed_login_locked_until: datetime | None = None
    locked: bool = False
    # #1355 — the flag OR a wildcard role. Resetting such an account's
    # password needs the caller's step-up, and the UI reads this to ask for
    # it (the flag alone misses a local user in a Superadmin-role group).
    is_effective_superadmin: bool = False

    model_config = {"from_attributes": True}

    @field_validator("id", mode="before")
    @classmethod
    def coerce_id(cls, v: object) -> str:
        return str(v)

    @field_validator("auth_provider_id", mode="before")
    @classmethod
    def coerce_provider_id(cls, v: object) -> str | None:
        return None if v is None else str(v)

    @model_validator(mode="before")
    @classmethod
    def _compute_locked(cls, data: object) -> object:
        # Fold the ORM ``User`` into a dict so we can attach the
        # computed ``locked`` flag without needing a relationship-side
        # property. Mirrors ``account_lockout.is_locked``.
        if isinstance(data, User):
            cols: dict[str, object] = {
                c.name: getattr(data, c.name) for c in data.__table__.columns
            }
            cols["locked"] = is_user_locked(data)
            # ``groups`` is selectin-loaded; never trigger an async lazy load
            # from this sync validator if a path skipped it.
            if "groups" in sa_inspect(data).unloaded:
                cols["is_effective_superadmin"] = bool(data.is_superadmin)
            else:
                cols["is_effective_superadmin"] = is_effective_superadmin(data)
            return cols
        return data


# Pragmatic email shape check for local-user create/edit (#14). Not full
# RFC 5322 — just enough to reject the malformed values that confuse
# outbound mail (password reset, alerts): one ``@``, a non-empty local
# part, and a dotted domain with no whitespace. External-auth-synced
# users bypass this surface (they're provisioned by user_sync, not this
# API), so a sloppy LDAP attr can still land — but operator-entered
# locals are validated here.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _validate_email(v: str) -> str:
    v = v.strip()
    if not _EMAIL_RE.match(v):
        raise ValueError("Invalid email address")
    return v


class CreateUserRequest(BaseModel):
    username: str
    email: str
    display_name: str
    password: str
    is_superadmin: bool = False
    force_password_change: bool = True
    # #1355 — the caller's own step-up (password, or authenticator code for
    # an account without one). Required to create or promote a superadmin,
    # or to reset a superadmin's password: each hands out a credential that
    # passes every later step-up.
    stepup_password: str | None = None
    stepup_totp_code: str | None = None

    @field_validator("password")
    @classmethod
    def password_length(cls, v: str) -> str:
        # #1004 — NOT a length policy. This is the "obviously empty" floor
        # that keeps a legacy client getting a 422 instead of reaching the
        # handler; every length verdict belongs to the configured policy,
        # which the handler enforces against PlatformSettings.
        #
        # It used to be 8, which was a SECOND minimum contradicting the
        # operator's setting (12 by default) — and the only source of the
        # number 8 anywhere in the flow. Worse, it fired as a pydantic 422
        # whose detail is an error ARRAY, a shape the change-password screen
        # did not parse, so a 7-character password was reported as "check
        # your current password". A floor of 1 cannot collide with a policy
        # minimum (settings clamp it to 6..128), so the two can never
        # disagree again.
        if not v:
            raise ValueError("Password cannot be empty")
        return v

    @field_validator("username")
    @classmethod
    def username_nonempty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Username cannot be empty")
        return v

    @field_validator("email")
    @classmethod
    def email_valid(cls, v: str) -> str:
        return _validate_email(v)


class UpdateUserRequest(BaseModel):
    display_name: str | None = None
    email: str | None = None
    is_active: bool | None = None
    is_superadmin: bool | None = None
    force_password_change: bool | None = None
    # #1355 — the caller's own step-up (password, or authenticator code for
    # an account without one). Required to create or promote a superadmin,
    # or to reset a superadmin's password: each hands out a credential that
    # passes every later step-up.
    stepup_password: str | None = None
    stepup_totp_code: str | None = None

    @field_validator("email")
    @classmethod
    def email_valid(cls, v: str | None) -> str | None:
        return None if v is None else _validate_email(v)


class LinkProviderRequest(BaseModel):
    auth_provider_id: uuid.UUID


class ResetPasswordRequest(BaseModel):
    new_password: str
    # #1355 — the caller's own step-up (password, or authenticator code for
    # an account without one). Required to create or promote a superadmin,
    # or to reset a superadmin's password: each hands out a credential that
    # passes every later step-up.
    stepup_password: str | None = None
    stepup_totp_code: str | None = None

    @field_validator("new_password")
    @classmethod
    def password_length(cls, v: str) -> str:
        # #1004 — NOT a length policy. This is the "obviously empty" floor
        # that keeps a legacy client getting a 422 instead of reaching the
        # handler; every length verdict belongs to the configured policy,
        # which the handler enforces against PlatformSettings.
        #
        # It used to be 8, which was a SECOND minimum contradicting the
        # operator's setting (12 by default) — and the only source of the
        # number 8 anywhere in the flow. Worse, it fired as a pydantic 422
        # whose detail is an error ARRAY, a shape the change-password screen
        # did not parse, so a 7-character password was reported as "check
        # your current password". A floor of 1 cannot collide with a policy
        # minimum (settings clamp it to 6..128), so the two can never
        # disagree again.
        if not v:
            raise ValueError("Password cannot be empty")
        return v


def _audit(actor: User, action: str, resource_id: str, summary: str) -> AuditLog:
    return AuditLog(
        user_id=actor.id,
        user_display_name=actor.display_name,
        action=action,
        resource_type="user",
        resource_id=resource_id,
        resource_display=summary,
    )


# ── Routes ────────────────────────────────────────────────────────────────────


@router.get("", response_model=list[UserResponse])
async def list_users(current_user: SuperAdmin, db: DB) -> list[User]:
    result = await db.execute(select(User).order_by(User.username))
    return list(result.scalars().all())


async def _enforce_policy(db: DB, password: str) -> tuple[PasswordPolicy, str]:
    """Validate the candidate password against the active policy and
    return ``(policy, hash)``. Raises 400 on violation. Reused across
    the create-user + reset-password paths so the rules can't drift."""
    settings_row = await db.get(PlatformSettings, 1)
    policy = PasswordPolicy.from_row(settings_row)
    result = validate_password_policy(password, policy)
    if not result.ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"reason": "password_policy", "errors": result.errors},
        )
    return policy, hash_password(password)


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(body: CreateUserRequest, current_user: SuperAdmin, db: DB) -> User:
    # Check uniqueness
    existing = await db.execute(
        select(User).where((User.username == body.username) | (User.email == body.email))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already in use",
        )

    method = None
    if body.is_superadmin:
        method = await require_operator_stepup(
            db,
            current_user,
            password=body.stepup_password,
            totp_code=body.stepup_totp_code,
            action="create",
            resource_type="user",
            resource_id=body.username,
            resource_display=f"superadmin {body.username}",
        )
    policy, hashed = await _enforce_policy(db, body.password)
    history = push_history(hashed, None, policy.history_count)
    user = User(
        username=body.username,
        email=body.email,
        display_name=body.display_name,
        hashed_password=hashed,
        is_superadmin=body.is_superadmin,
        force_password_change=body.force_password_change,
        auth_source="local",
        is_active=True,
        password_changed_at=datetime.now(UTC),
        password_history_encrypted=history,
    )
    db.add(user)
    await db.flush()
    audit = _audit(current_user, "create", str(user.id), f"Created user {body.username}")
    if method:
        audit.new_value = {"is_superadmin": True, "stepup_method": method}
    db.add(audit)
    await db.commit()
    await db.refresh(user)
    logger.info("user_created", username=body.username, by=current_user.username)
    return user


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(user_id: uuid.UUID, current_user: SuperAdmin, db: DB) -> User:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: uuid.UUID,
    body: UpdateUserRequest,
    current_user: SuperAdmin,
    db: DB,
) -> User:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Prevent removing superadmin from own account
    if user.id == current_user.id and body.is_superadmin is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove your own superadmin status",
        )

    # #1242 — an external account has no local password, so the flag would
    # lock it out of everything until an admin cleared it again. Clearing it
    # stays allowed, which is how a row set before this check gets tidied
    # up. Refused before any field is touched, so a 400 changes nothing.
    if body.force_password_change and user.auth_source != "local":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"'{user.username}' signs in through {user.auth_source}; its password is "
                "managed by the identity provider, so it cannot be required to change it here."
            ),
        )

    method = None
    if body.is_superadmin and not user.is_superadmin:
        method = await require_operator_stepup(
            db,
            current_user,
            password=body.stepup_password,
            totp_code=body.stepup_totp_code,
            action="update",
            resource_type="user",
            resource_id=str(user.id),
            resource_display=f"promote {user.username} to superadmin",
        )

    if body.display_name is not None:
        user.display_name = body.display_name
    if body.email is not None:
        user.email = body.email
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.is_superadmin is not None:
        user.is_superadmin = body.is_superadmin
    if body.force_password_change is not None:
        user.force_password_change = body.force_password_change

    audit = _audit(current_user, "update", str(user.id), f"Updated user {user.username}")
    if method:
        audit.new_value = {"is_superadmin": True, "stepup_method": method}
    db.add(audit)
    await db.commit()
    await db.refresh(user)
    return user


@router.post("/{user_id}/reset-password", status_code=status.HTTP_204_NO_CONTENT)
async def reset_password(
    user_id: uuid.UUID,
    body: ResetPasswordRequest,
    current_user: SuperAdmin,
    db: DB,
) -> None:
    forbid_in_demo_mode("Admin password reset is disabled")
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.auth_source != "local":
        # #1242 — a local password on an external account is never used to
        # sign in (login goes to the provider), and the reset also sets
        # ``force_password_change``, which would lock the account out.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"'{user.username}' signs in through {user.auth_source}; reset the password "
                "in the identity provider. To end its sessions here, disable the account or "
                "revoke them from Sessions."
            ),
        )

    # Admin reset bypasses history (an admin reset is by definition out
    # of band — the user's prior choices are not in scope) but still
    # honours the complexity rules so an operator can't side-step the
    # policy via the admin path.
    method = None
    # A superadmin's password passes every step-up, so choosing it for them
    # needs one (#1355). Effective superadmin: the flag or a wildcard role.
    # The role path reads ``user.groups``: load it explicitly, since a row
    # already in this session's identity map may not have it yet. No
    # exemption for the caller's own account: a stolen session resetting its
    # own password would end up holding the password every step-up asks for.
    await db.refresh(user, ["groups"])
    if is_effective_superadmin(user):
        method = await require_operator_stepup(
            db,
            current_user,
            password=body.stepup_password,
            totp_code=body.stepup_totp_code,
            action="reset_password",
            resource_type="user",
            resource_id=str(user.id),
            resource_display=f"reset password for superadmin {user.username}",
        )
    policy, hashed = await _enforce_policy(db, body.new_password)
    user.hashed_password = hashed
    user.force_password_change = True
    user.password_changed_at = datetime.now(UTC)
    user.password_history_encrypted = push_history(
        hashed, user.password_history_encrypted, policy.history_count
    )
    # #1354 — like a self-service change, an admin reset discards a started
    # MFA enrolment: a reset usually means the account was compromised, and
    # the enrolment may have been started by whoever compromised it.
    clear_pending_enrolment(user)
    # SECURITY (#400 / M3): an admin password reset must revoke every
    # outstanding session + refresh token for the target user — the whole
    # reason an admin resets a password is usually that the account is
    # compromised or being handed over, so leaving live sessions running
    # against the old credential defeats the reset. No session is spared
    # here (unlike the self-service path): the admin is acting on someone
    # else's account, so all of the target's sessions die. Same revocation
    # statement ``/auth/logout`` uses.
    await db.execute(
        update(UserSession)
        .where(UserSession.user_id == user.id, UserSession.revoked.is_(False))
        .values(revoked=True)
    )
    audit = _audit(
        current_user, "reset_password", str(user.id), f"Reset password for {user.username}"
    )
    if method:
        audit.new_value = {"stepup_method": method}
    db.add(audit)
    await db.commit()
    logger.info("password_reset", target=user.username, by=current_user.username)


@router.post("/{user_id}/unlock", status_code=status.HTTP_204_NO_CONTENT)
async def unlock_account(
    user_id: uuid.UUID,
    current_user: SuperAdmin,
    db: DB,
) -> None:
    """Clear an account's failed-login counter + locked-until (issue
    #71). Idempotent: if the user wasn't locked, returns 204 without
    writing an audit row."""
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    changed = unlock_user(user)
    if changed:
        db.add(
            AuditLog(
                user_id=current_user.id,
                user_display_name=current_user.display_name,
                auth_source=current_user.auth_source,
                action="account.unlocked",
                resource_type="user",
                resource_id=str(user.id),
                resource_display=user.username,
                result="success",
            )
        )
    await db.commit()
    logger.info("account_unlocked", target=user.username, by=current_user.username)


@router.post("/{user_id}/link-provider", response_model=UserResponse)
async def link_provider(
    user_id: uuid.UUID,
    body: LinkProviderRequest,
    current_user: SuperAdmin,
    db: DB,
) -> User:
    """Link an external account to the provider it signs in through (#1235).

    External accounts are keyed on their provider. An account that predates
    that, and that cannot be attributed because several providers of its
    type exist, is refused at login until it is linked here; so is a user
    whose identifier at the provider changed (an LDAP DN after an OU move),
    since the account is never adopted by username alone.

    The link clears the stored external id: the next login through this
    provider with the account's username claims it and records the
    provider's id for the subject. Only this administrator action
    authorises that username match. Every session the account holds is
    revoked, so nothing opened under the previous identity survives it.

    A local account cannot be linked. It has a password, and linking it
    would hand it to whoever holds that username at the provider, which is
    the takeover #1235 closes.
    """
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    provider = await db.get(AuthProvider, body.auth_provider_id)
    if provider is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Auth provider not found"
        )
    if user.auth_source == "local":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "A local account cannot be linked to an external provider: whoever holds "
                "the same username there would sign in as it."
            ),
        )
    old = {
        "auth_source": user.auth_source,
        "auth_provider_id": str(user.auth_provider_id) if user.auth_provider_id else None,
        "external_id": user.external_id,
    }
    user.auth_source = provider.type
    user.auth_provider_id = provider.id
    user.external_id = None
    # The link changes who the account belongs to, and it is how an
    # administrator repairs one a second provider signed in as before #1235.
    # Sessions opened under the old identity must not outlive that, the
    # same reasoning as the admin password reset above (#400).
    await db.execute(
        update(UserSession)
        .where(UserSession.user_id == user.id, UserSession.revoked.is_(False))
        .values(revoked=True)
    )
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="user.provider_linked",
            resource_type="user",
            resource_id=str(user.id),
            resource_display=user.username,
            result="success",
            old_value=old,
            new_value={
                "auth_source": provider.type,
                "auth_provider_id": str(provider.id),
                "auth_provider": provider.name,
            },
        )
    )
    await db.commit()
    await db.refresh(user)
    logger.info(
        "user_provider_linked",
        target=user.username,
        provider=provider.name,
        by=current_user.username,
    )
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: uuid.UUID, current_user: SuperAdmin, db: DB) -> None:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )

    db.add(_audit(current_user, "delete", str(user.id), f"Deleted user {user.username}"))
    await db.delete(user)
    await db.commit()
    logger.info("user_deleted", username=user.username, by=current_user.username)
